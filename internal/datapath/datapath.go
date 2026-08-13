package datapath

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/network"
)

// HostInterface is the host anchor device: a dummy that carries the node's
// datapath address (the .1 of the node CIDR) and gives the service-CIDR
// blackhole route somewhere to live.
const HostInterface = "kanea0"

// NFTableName is the one nftables table Kanea owns (the masquerade rule
// lives in it). Exported for `kanea doctor`, which checks its presence — a
// missing table on a running node means a firewall manager flushed the
// ruleset (PRD v1.65).
const NFTableName = "kanea"

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
	// NodeCIDR6, ClusterCIDR6 and ServiceCIDR6 are the opt-in dual-stack trio
	// (PRD v1.41): all three set, or none — parseAgentCIDRs refuses anything
	// else by name, and newDatapath re-checks. Invalid (zero) prefixes mean
	// v4-only, which is the default and today's behavior — except that the tc
	// programs then drop IPv6 instead of passing it unpoliced.
	NodeCIDR6    netip.Prefix
	ClusterCIDR6 netip.Prefix
	ServiceCIDR6 netip.Prefix
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
// The applied cache is keyed by dpmap.SvcAddr, so one entry per family per
// port — a v6 twin is its own frontend programming.
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

	// The dual-stack trio (v1.41); invalid prefixes and a zero hostIP6 mean
	// v4-only.
	nodeCIDR6    netip.Prefix
	clusterCIDR6 netip.Prefix
	serviceCIDR6 netip.Prefix
	hostIP6      netip.Addr

	nl       Nl
	maps     Maps
	fw       Firewall
	netns    Netns
	counters Counters // optional; nil when the platform has none

	ids *idAllocator
	dns zoneSetter
	log *slog.Logger

	mu   sync.Mutex
	ipam *ipam
	// ipam6 is nil when v6 is disabled. Reservations move in lockstep with
	// ipam's under the Datapath mutex; the dual alias is the one durable
	// record for both.
	ipam6   *ipam
	applied map[dpmap.SvcAddr]appliedService
	// egressEnsured is when EnsureEgress last ran the real work; the
	// reconciler calls it every pass and the throttle keeps that from
	// becoming an nftables transaction per pass.
	egressEnsured time.Time
}

// v6Enabled reports whether the dual-stack trio was configured.
func (d *Datapath) v6Enabled() bool { return d.ipam6 != nil }

// egressEnsureInterval throttles EnsureEgress: often enough that a firewall
// reload's damage lasts seconds, rare enough that reconcile passes are free.
const egressEnsureInterval = 30 * time.Second

// EnsureEgress re-asserts the node-level egress plumbing that something else
// on the node can destroy while kanead runs (PRD v1.65): a firewalld reload
// or `ufw enable` flushes the ruleset — the `kanea` table and its masquerade
// rule with it — and previously nothing noticed until the next kanead
// restart. The reconciler calls this every pass; the rebuild is one atomic
// nftables transaction, throttled here.
func (d *Datapath) EnsureEgress(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	if time.Since(d.egressEnsured) < egressEnsureInterval {
		d.mu.Unlock()
		return nil
	}
	d.egressEnsured = time.Now()
	d.mu.Unlock()

	if err := d.fw.EnsureMasquerade(d.clusterCIDR, HostInterface); err != nil {
		return fmt.Errorf("datapath: masquerade: %w", err)
	}
	return nil
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

	// The v6 trio is all-or-nothing (PRD v1.41): a v6 alloc address without a
	// v6 VIP pool is a half-configured stack whose failures are silent.
	v6Count := 0
	for _, p := range []netip.Prefix{cfg.NodeCIDR6, cfg.ClusterCIDR6, cfg.ServiceCIDR6} {
		if p.IsValid() {
			v6Count++
		}
	}
	if v6Count != 0 && v6Count != 3 {
		return nil, fmt.Errorf("datapath: --node-cidr6, --cluster-cidr6 and --service-cidr6 come as a trio: all three or none")
	}
	if v6Count == 3 {
		for _, p := range []struct {
			name   string
			prefix netip.Prefix
		}{
			{"node CIDR6", cfg.NodeCIDR6},
			{"cluster CIDR6", cfg.ClusterCIDR6},
			{"service CIDR6", cfg.ServiceCIDR6},
		} {
			if !p.prefix.Addr().Is6() || p.prefix.Addr().Is4In6() {
				return nil, fmt.Errorf("datapath: %s %q is not a valid IPv6 prefix", p.name, p.prefix)
			}
		}
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
		applied:     map[dpmap.SvcAddr]appliedService{},
	}
	if v6Count == 3 {
		node6 := cfg.NodeCIDR6.Masked()
		d.nodeCIDR6 = node6
		d.clusterCIDR6 = cfg.ClusterCIDR6.Masked()
		d.serviceCIDR6 = cfg.ServiceCIDR6.Masked()
		d.hostIP6 = node6.Addr().Next()
		d.ipam6 = newIPAM(node6)
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
	if err := d.nl.EnsureHost(d.hostIP, d.hostIP6); err != nil {
		return fmt.Errorf("datapath: host interface: %w", err)
	}
	if err := d.maps.PutIdentity(d.hostIP, dpmap.Identity{Flags: dpmap.IdentityFlagHost}); err != nil {
		return fmt.Errorf("datapath: host identity: %w", err)
	}
	if d.v6Enabled() {
		if err := d.maps.PutIdentity(d.hostIP6, dpmap.Identity{Flags: dpmap.IdentityFlagHost}); err != nil {
			return fmt.Errorf("datapath: host v6 identity: %w", err)
		}
	}
	if err := d.maps.SetConfig(configFor(d.serviceCIDR)); err != nil {
		return fmt.Errorf("datapath: config map: %w", err)
	}
	// config6 is written unconditionally: its all-zero mask is the v6 enable
	// switch, and a node whose v6 was turned off must overwrite whatever an
	// earlier process left in the pinned map.
	if err := d.maps.SetConfig6(configFor6(d.serviceCIDR6)); err != nil {
		return fmt.Errorf("datapath: config6 map: %w", err)
	}
	// The cluster maps (v1.65): until these are written the programs keep the
	// pre-v1.65 deny — external return traffic drops — so they land here,
	// before any veth exists to carry traffic.
	if err := d.maps.SetClusterCIDR(cidrFor(d.clusterCIDR)); err != nil {
		return fmt.Errorf("datapath: cluster map: %w", err)
	}
	if err := d.maps.SetClusterCIDR6(cidrFor6(d.clusterCIDR6)); err != nil {
		return fmt.Errorf("datapath: cluster6 map: %w", err)
	}
	if err := d.fw.EnsureMasquerade(d.clusterCIDR, HostInterface); err != nil {
		return fmt.Errorf("datapath: masquerade: %w", err)
	}
	d.mu.Lock()
	d.egressEnsured = time.Now()
	d.mu.Unlock()

	links, err := d.nl.List()
	if err != nil {
		return fmt.Errorf("datapath: list links: %w", err)
	}
	// Re-attach the tc programs to every owned veth (v1.65): FilterReplace is
	// atomic, so an upgraded kanead delivers its current programs to
	// attachments the previous process made — without this, a datapath fix
	// reaches only allocs created after the upgrade. Best effort per link: a
	// veth mid-teardown must not fail Init.
	for _, l := range links {
		if _, _, _, ok := parseAlias(l.Alias); !ok {
			continue
		}
		if err := d.nl.AttachPrograms(l.Name); err != nil {
			d.log.Warn("refresh tc programs", "dev", l.Name, "error", err)
		}
	}
	d.mu.Lock()
	d.ipam.Rebuild(links)
	if d.ipam6 != nil {
		d.ipam6.Rebuild(links)
	}
	reserved := d.ipam.Len()
	d.mu.Unlock()
	d.log.Info("datapath initialised",
		"host_ip", d.hostIP, "node_cidr", d.nodeCIDR, "service_cidr", d.serviceCIDR,
		"node_cidr6", d.nodeCIDR6, "reserved", reserved)
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

// cidrFor renders a v4 prefix as a cluster-map value. Only ever called with
// the validated cluster CIDR, which newDatapath refused if invalid.
func cidrFor(p netip.Prefix) dpmap.CIDR {
	var cfg dpmap.CIDR
	cfg.Net = p.Masked().Addr().As4()
	cfg.Mask = maskFor(p)
	return cfg
}

// cidrFor6 renders the v6 cluster prefix, or the all-zero "not configured"
// value when v6 is off — which the programs read as the fail-closed deny.
func cidrFor6(p netip.Prefix) dpmap.CIDR6 {
	var cfg dpmap.CIDR6
	if !p.IsValid() {
		return cfg
	}
	cfg.Net = p.Masked().Addr().As16()
	cfg.Mask = maskFor16(p)
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

// configFor6 renders the v6 service CIDR into config6's value. An invalid
// prefix renders all-zero, which the programs read as "v6 disabled" — the
// deliberate coupling that makes writing it unconditionally correct.
func configFor6(p netip.Prefix) dpmap.Config6 {
	var cfg dpmap.Config6
	if !p.IsValid() {
		return cfg
	}
	cfg.ServiceCIDRNet = p.Masked().Addr().As16()
	cfg.ServiceCIDRMask = maskFor16(p)
	return cfg
}

// maskFor16 renders a v6 prefix length as the sixteen network-order mask
// bytes.
func maskFor16(p netip.Prefix) [16]byte {
	var m [16]byte
	bits := p.Bits()
	for i := 0; i < 16; i++ {
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
