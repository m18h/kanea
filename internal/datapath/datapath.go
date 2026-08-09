package datapath

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/network"
)

// HostInterface is the host anchor device: a dummy that carries the node's
// datapath address (the .1 of the node CIDR) and gives the service-CIDR
// blackhole route somewhere to live.
const HostInterface = "kanea0"

// Config configures the datapath driver.
type Config struct {
	// NodeCIDR is the pool alloc addresses are drawn from. The network
	// address, the broadcast address and the .1 (the host anchor) are never
	// allocated.
	NodeCIDR netip.Prefix
	// ClusterCIDR is what the masquerade rule treats as internal: traffic
	// from it to anywhere outside it is NATed on the way out.
	ClusterCIDR netip.Prefix
	// ServiceCIDR is the VIP pool. It is written to the config map so the
	// egress program can refuse service-CIDR traffic that escaped
	// connect-time rewrite, and blackholed on the host for the same reason.
	ServiceCIDR netip.Prefix
	// BPFDir is the bpffs pin root. Empty means dpmap.PinRoot.
	BPFDir string
	// Store allocates the numeric project/service ids behind the maps. They
	// are monotonic and never reused — reuse would make a pinned map lie
	// after a restart.
	Store IDStore
	// DNS, when set, has its zone republished on every service sync: a
	// frontend and the name that resolves to it should never disagree, so
	// they are published from one call.
	DNS *network.DNS
	// Logger receives attach/detach events.
	Logger *slog.Logger
}

// zoneSetter is the slice of network.DNS SyncServices needs; an interface so
// tests can observe the call without standing up a resolver.
type zoneSetter interface {
	SetZone(services []network.Service)
}

// appliedService is what SyncServices remembers having programmed for one
// frontend, so an unchanged service costs no map writes on the next pass.
type appliedService struct {
	id       uint16
	backends []dpmap.Backend
}

func (a appliedService) equal(b appliedService) bool {
	if a.id != b.id || len(a.backends) != len(b.backends) {
		return false
	}
	for i := range a.backends {
		if a.backends[i] != b.backends[i] {
			return false
		}
	}
	return true
}

// Datapath implements the reconciler's network seams — Network,
// NetworkInspector, LoadBalancer and PolicySyncer — over the eBPF datapath.
type Datapath struct {
	nodeCIDR    netip.Prefix
	clusterCIDR netip.Prefix
	serviceCIDR netip.Prefix
	hostIP      netip.Addr

	nl       Nl
	maps     Maps
	fw       Firewall
	netns    Netns
	counters Counters // optional; nil when the platform has none

	ids *idAllocator
	dns zoneSetter
	log *slog.Logger

	mu      sync.Mutex
	ipam    *ipam
	applied map[dpmap.SvcKey]appliedService
}

// seams bundles the platform implementations a Datapath runs on. The real set
// is built by New (linux); tests build recorders.
type seams struct {
	nl       Nl
	maps     Maps
	fw       Firewall
	netns    Netns
	counters Counters
}

// newDatapath wires the portable core to a set of seams. It performs no I/O;
// Init is what touches the node.
func newDatapath(cfg Config, s seams) (*Datapath, error) {
	for _, p := range []struct {
		name   string
		prefix netip.Prefix
	}{
		{"node CIDR", cfg.NodeCIDR},
		{"cluster CIDR", cfg.ClusterCIDR},
		{"service CIDR", cfg.ServiceCIDR},
	} {
		if !p.prefix.IsValid() || !p.prefix.Addr().Is4() {
			return nil, fmt.Errorf("datapath: %s %q is not a valid IPv4 prefix", p.name, p.prefix)
		}
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("datapath: a store is required for id allocation")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	node := cfg.NodeCIDR.Masked()
	d := &Datapath{
		nodeCIDR:    node,
		clusterCIDR: cfg.ClusterCIDR.Masked(),
		serviceCIDR: cfg.ServiceCIDR.Masked(),
		hostIP:      node.Addr().Next(),
		nl:          s.nl,
		maps:        s.maps,
		fw:          s.fw,
		netns:       s.netns,
		counters:    s.counters,
		ids:         newIDAllocator(cfg.Store),
		log:         cfg.Logger,
		ipam:        newIPAM(node),
		applied:     map[dpmap.SvcKey]appliedService{},
	}
	if cfg.DNS != nil {
		d.dns = cfg.DNS
	}
	return d, nil
}

// Init brings the node-level datapath state up: the host anchor and its
// identity, the service CIDR in the config map, the masquerade rule, and the
// IPAM state rebuilt from the marked veths. It is idempotent and runs before
// the first reconcile pass.
//
// The host identity is written before anything else can pass traffic: the tc
// program reads an identity miss as a drop, so host traffic toward allocs
// depends on this entry existing.
func (d *Datapath) Init(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.nl.EnsureHost(d.hostIP); err != nil {
		return fmt.Errorf("datapath: host interface: %w", err)
	}
	if err := d.maps.PutIdentity(d.hostIP, dpmap.Identity{Flags: dpmap.IdentityFlagHost}); err != nil {
		return fmt.Errorf("datapath: host identity: %w", err)
	}
	if err := d.maps.SetConfig(configFor(d.serviceCIDR)); err != nil {
		return fmt.Errorf("datapath: config map: %w", err)
	}
	if err := d.fw.EnsureMasquerade(d.clusterCIDR, HostInterface); err != nil {
		return fmt.Errorf("datapath: masquerade: %w", err)
	}

	links, err := d.nl.List()
	if err != nil {
		return fmt.Errorf("datapath: list links: %w", err)
	}
	d.mu.Lock()
	d.ipam.Rebuild(links)
	reserved := d.ipam.Len()
	d.mu.Unlock()
	d.log.Info("datapath initialised",
		"host_ip", d.hostIP, "node_cidr", d.nodeCIDR, "service_cidr", d.serviceCIDR,
		"reserved", reserved)
	return nil
}

// CounterSource returns the east-west metrics view, or nil when the platform
// seams carry no counters (which is every non-linux build).
func (d *Datapath) CounterSource() *CounterSource {
	if d.counters == nil {
		return nil
	}
	return &CounterSource{counters: d.counters, ids: d.ids}
}

// configFor renders a service CIDR into the config map's value.
func configFor(p netip.Prefix) dpmap.Config {
	var cfg dpmap.Config
	cfg.ServiceCIDRNet = p.Masked().Addr().As4()
	mask := maskFor(p)
	copy(cfg.ServiceCIDRMask[:], mask[:])
	return cfg
}

// maskFor renders a prefix length as the four network-order mask bytes.
func maskFor(p netip.Prefix) [4]byte {
	var m [4]byte
	bits := p.Bits()
	for i := 0; i < 4; i++ {
		if bits >= 8 {
			m[i] = 0xFF
			bits -= 8
			continue
		}
		if bits > 0 {
			m[i] = byte(0xFF << (8 - bits))
			bits = 0
		}
	}
	return m
}
