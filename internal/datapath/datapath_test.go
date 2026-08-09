package datapath

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/network"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/store"
)

// The whole point of the package: it slots into the reconciler's seams.
var (
	_ reconciler.Network          = (*Datapath)(nil)
	_ reconciler.NetworkInspector = (*Datapath)(nil)
	_ reconciler.LoadBalancer     = (*Datapath)(nil)
	_ reconciler.PolicySyncer     = (*Datapath)(nil)
)

// oplog records what the seams were asked to do, in order. Only writes are
// recorded: the ordering of *effects* is the contract, reads are free.
type oplog struct {
	mu    sync.Mutex
	steps []string
}

func (l *oplog) rec(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.steps = append(l.steps, fmt.Sprintf(format, args...))
}

func (l *oplog) taken() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.steps)
}

func (l *oplog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.steps = nil
}

// indexOf returns the position of the first step starting with prefix, or -1.
func (l *oplog) indexOf(prefix string) int {
	for i, s := range l.taken() {
		if strings.HasPrefix(s, prefix) {
			return i
		}
	}
	return -1
}

// fakeNl is an Nl that records writes and keeps a link table.
type fakeNl struct {
	log  *oplog
	mu   sync.Mutex
	link map[string]Link
	fail map[string]error // step name -> injected error
}

func newFakeNl(log *oplog) *fakeNl {
	return &fakeNl{log: log, link: map[string]Link{}, fail: map[string]error{}}
}

func (f *fakeNl) failAt(step string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[step] = err
}

func (f *fakeNl) failure(step string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fail[step]
}

func (f *fakeNl) EnsureHost(hostIP netip.Addr) error {
	f.log.rec("ensure-host %s", hostIP)
	return f.failure("ensure-host")
}

func (f *fakeNl) CreateVeth(host, _, alias string) (string, string, error) {
	f.log.rec("create-veth %s", host)
	if err := f.failure("create-veth"); err != nil {
		return "", "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.link[host] = Link{Name: host, Alias: alias}
	return "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", nil
}

func (f *fakeNl) AttachPrograms(hostDev string) error {
	f.log.rec("attach-programs %s", hostDev)
	return f.failure("attach-programs")
}

func (f *fakeNl) MovePeer(peer, netnsPath string) error {
	f.log.rec("move-peer %s", peer)
	if netnsPath == "" {
		return fmt.Errorf("move-peer without a netns")
	}
	return f.failure("move-peer")
}

func (f *fakeNl) ConfigurePeer(_ string, ip, _ netip.Addr, hostMAC string) error {
	f.log.rec("configure-peer %s", ip)
	if hostMAC == "" {
		return fmt.Errorf("configure-peer without the host mac")
	}
	return f.failure("configure-peer")
}

func (f *fakeNl) SetHostUp(hostDev string, _ netip.Addr, podMAC string) error {
	f.log.rec("set-host-up %s", hostDev)
	if podMAC == "" {
		return fmt.Errorf("set-host-up without the pod mac")
	}
	return f.failure("set-host-up")
}

func (f *fakeNl) InstallRoute(podIP netip.Addr, _ string, _ netip.Addr) error {
	f.log.rec("install-route %s", podIP)
	return f.failure("install-route")
}

func (f *fakeNl) DeleteVeth(hostDev string) error {
	f.log.rec("delete-veth %s", hostDev)
	if err := f.failure("delete-veth"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.link, hostDev) // absent is success
	return nil
}

func (f *fakeNl) List() ([]Link, error) {
	if err := f.failure("list"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Link, 0, len(f.link))
	for _, l := range f.link {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// addLink plants a link, e.g. a foreign one, directly.
func (f *fakeNl) addLink(name, alias string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.link[name] = Link{Name: name, Alias: alias}
}

// fakeMaps is a Maps over Go maps, recording writes.
type fakeMaps struct {
	log      *oplog
	mu       sync.Mutex
	idents   map[netip.Addr]dpmap.Identity
	services map[dpmap.SvcKey]dpmap.SvcVal
	backends map[dpmap.BackendKey]dpmap.BackendVal
	allows   map[dpmap.AllowKey]struct{}
	cfg      dpmap.Config
	flips    [][]dpmap.Op
	fail     map[string]error
}

func newFakeMaps(log *oplog) *fakeMaps {
	return &fakeMaps{
		log:      log,
		idents:   map[netip.Addr]dpmap.Identity{},
		services: map[dpmap.SvcKey]dpmap.SvcVal{},
		backends: map[dpmap.BackendKey]dpmap.BackendVal{},
		allows:   map[dpmap.AllowKey]struct{}{},
		fail:     map[string]error{},
	}
}

func (f *fakeMaps) failure(step string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fail[step]
}

func (f *fakeMaps) PutIdentity(ip netip.Addr, id dpmap.Identity) error {
	f.log.rec("put-identity %s", ip)
	if err := f.failure("put-identity"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idents[ip] = id
	return nil
}

func (f *fakeMaps) DeleteIdentity(ip netip.Addr) error {
	f.log.rec("delete-identity %s", ip)
	if err := f.failure("delete-identity"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.idents, ip)
	return nil
}

func (f *fakeMaps) ApplyFlip(key dpmap.SvcKey, ops []dpmap.Op) error {
	f.log.rec("apply-flip %s:%d", netip.AddrFrom4(key.VIP), key.Port)
	if err := f.failure("apply-flip"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flips = append(f.flips, slices.Clone(ops))
	for _, op := range ops {
		switch op.Kind {
		case dpmap.OpPutBackend:
			f.backends[op.Key] = op.Val
		case dpmap.OpCommitService:
			f.services[key] = op.Svc
		case dpmap.OpDeleteBackend:
			delete(f.backends, op.Key)
		}
	}
	return nil
}

func (f *fakeMaps) DeleteService(key dpmap.SvcKey) error {
	f.log.rec("delete-service %s:%d", netip.AddrFrom4(key.VIP), key.Port)
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.services, key)
	return nil
}

func (f *fakeMaps) PutAllow(dst, src uint32) error {
	f.log.rec("put-allow %d<-%d", dst, src)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allows[dpmap.AllowKey{DstServiceID: dst, SrcServiceID: src}] = struct{}{}
	return nil
}

func (f *fakeMaps) DeleteAllow(dst, src uint32) error {
	f.log.rec("delete-allow %d<-%d", dst, src)
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.allows, dpmap.AllowKey{DstServiceID: dst, SrcServiceID: src})
	return nil
}

func (f *fakeMaps) Allows() (map[dpmap.AllowKey]struct{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneMap(f.allows), nil
}

func (f *fakeMaps) Identities() (map[netip.Addr]dpmap.Identity, error) {
	if err := f.failure("identities"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneMap(f.idents), nil
}

func (f *fakeMaps) Services() (map[dpmap.SvcKey]dpmap.SvcVal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneMap(f.services), nil
}

func (f *fakeMaps) SetConfig(cfg dpmap.Config) error {
	f.log.rec("set-config")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg = cfg
	return nil
}

func cloneMap[K comparable, V any](m map[K]V) map[K]V {
	out := make(map[K]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// fakeFw records the masquerade call.
type fakeFw struct{ log *oplog }

func (f fakeFw) EnsureMasquerade(clusterCIDR netip.Prefix, hostDev string) error {
	f.log.rec("masquerade %s via %s", clusterCIDR, hostDev)
	return nil
}
func (f fakeFw) Teardown() error { return nil }

// fakeNetns records namespace lifecycle.
type fakeNetns struct {
	log  *oplog
	mu   sync.Mutex
	ns   map[string]bool
	fail map[string]error
}

func newFakeNetns(log *oplog) *fakeNetns {
	return &fakeNetns{log: log, ns: map[string]bool{}, fail: map[string]error{}}
}

func (f *fakeNetns) Create(allocID string) (string, error) {
	f.log.rec("netns-create %s", allocID)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail["netns-create"]; err != nil {
		return "", err
	}
	f.ns[allocID] = true
	return "/run/netns/" + allocID, nil
}

func (f *fakeNetns) Path(allocID string) string { return "/run/netns/" + allocID }

func (f *fakeNetns) Delete(allocID string) error {
	f.log.rec("netns-delete %s", allocID)
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ns, allocID) // missing is success
	return nil
}

// fakeCounters is a Counters with fixed contents.
type fakeCounters struct {
	connects map[uint16]uint64
	drops    map[dpmap.DropKey]uint64
	ep       map[netip.Addr]dpmap.EpStats
}

func (f fakeCounters) ServiceConnects() (map[uint16]uint64, error)          { return f.connects, nil }
func (f fakeCounters) Drops() (map[dpmap.DropKey]uint64, error)             { return f.drops, nil }
func (f fakeCounters) EndpointStats() (map[netip.Addr]dpmap.EpStats, error) { return f.ep, nil }

// fakeStore is an in-memory IDStore.
type fakeStore struct {
	mu    sync.Mutex
	kv    map[string][]byte
	index uint64
}

func newFakeStore() *fakeStore { return &fakeStore{kv: map[string][]byte{}} }

func (s *fakeStore) Get(_ context.Context, _ store.Kind, key string) (store.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.kv[key]
	if !ok {
		return store.Record{}, store.ErrNotFound
	}
	return store.Record{Kind: store.KindKV, Key: key, Value: v}, nil
}

func (s *fakeStore) List(_ context.Context, _ store.Kind, opts store.ListOptions) (store.Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.kv))
	for k := range s.kv {
		if strings.HasPrefix(k, opts.Prefix) && k > opts.After {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	page := store.Page{}
	for _, k := range keys {
		page.Records = append(page.Records, store.Record{Kind: store.KindKV, Key: k, Value: s.kv[k]})
	}
	return page, nil
}

func (s *fakeStore) Apply(_ context.Context, muts ...store.Mutation) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range muts {
		switch m.Op {
		case store.OpPut:
			s.kv[m.Key] = m.Value
		case store.OpDelete:
			delete(s.kv, m.Key)
		}
	}
	s.index++
	return s.index, nil
}

// seed writes a JSON value directly, for preloading state.
func (s *fakeStore) seed(t *testing.T, key string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("seed %s: %v", key, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kv[key] = b
}

// fixture bundles a Datapath with its fakes.
type fixture struct {
	d     *Datapath
	log   *oplog
	nl    *fakeNl
	maps  *fakeMaps
	netns *fakeNetns
	store *fakeStore
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWithStore(t, newFakeStore())
}

func newFixtureWithStore(t *testing.T, st *fakeStore) *fixture {
	t.Helper()
	log := &oplog{}
	f := &fixture{
		log:   log,
		nl:    newFakeNl(log),
		maps:  newFakeMaps(log),
		netns: newFakeNetns(log),
		store: st,
	}
	d, err := newDatapath(Config{
		NodeCIDR:    netip.MustParsePrefix("10.200.0.0/24"),
		ClusterCIDR: netip.MustParsePrefix("10.200.0.0/16"),
		ServiceCIDR: netip.MustParsePrefix("10.201.0.0/16"),
		Store:       st,
	}, seams{
		nl:    f.nl,
		maps:  f.maps,
		fw:    fakeFw{log: log},
		netns: f.netns,
	})
	if err != nil {
		t.Fatalf("newDatapath: %v", err)
	}
	f.d = d
	return f
}

func TestInitBringsUpTheHostBeforeAnythingElse(t *testing.T) {
	f := newFixture(t)
	if err := f.d.Init(t.Context()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	want := []string{
		"ensure-host 10.200.0.1",
		"put-identity 10.200.0.1",
		"set-config",
		"masquerade 10.200.0.0/16 via " + HostInterface,
	}
	if got := f.log.taken(); !slices.Equal(got, want) {
		t.Fatalf("init steps = %v, want %v", got, want)
	}
	id, ok := f.maps.idents[netip.MustParseAddr("10.200.0.1")]
	if !ok || id.Flags&dpmap.IdentityFlagHost == 0 {
		t.Fatalf("host identity = %+v (present=%v), want the host flag set", id, ok)
	}
}

func TestInitRebuildsIPAMFromMarkedVeths(t *testing.T) {
	f := newFixture(t)
	// A surviving attachment holds 10.200.0.2; a foreign link must not count.
	f.nl.addLink(hostDevName("shop-web-0"), aliasFor("shop-web-0", netip.MustParseAddr("10.200.0.2")))
	f.nl.addLink("eth0", "not ours")
	if err := f.d.Init(t.Context()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	f.d.mu.Lock()
	defer f.d.mu.Unlock()
	if got, ok := f.d.ipam.Lookup("shop-web-0"); !ok || got != netip.MustParseAddr("10.200.0.2") {
		t.Fatalf("rebuilt reservation = %v (ok=%v), want 10.200.0.2", got, ok)
	}
	if f.d.ipam.Len() != 1 {
		t.Fatalf("ipam holds %d reservations, want 1", f.d.ipam.Len())
	}
}

func TestCounterSourceJoinsIdsToNames(t *testing.T) {
	log := &oplog{}
	st := newFakeStore()
	f := &fixture{log: log, nl: newFakeNl(log), maps: newFakeMaps(log), netns: newFakeNetns(log), store: st}
	counters := fakeCounters{connects: map[uint16]uint64{}}
	d, err := newDatapath(Config{
		NodeCIDR:    netip.MustParsePrefix("10.200.0.0/24"),
		ClusterCIDR: netip.MustParsePrefix("10.200.0.0/16"),
		ServiceCIDR: netip.MustParsePrefix("10.201.0.0/16"),
		Store:       st,
	}, seams{nl: f.nl, maps: f.maps, fw: fakeFw{log: log}, netns: f.netns, counters: counters})
	if err != nil {
		t.Fatalf("newDatapath: %v", err)
	}

	// Two port frontends of one service fold into one number; an unknown id
	// is skipped, not invented a name for.
	http, err := d.ids.FrontendID(t.Context(), "shop", "web", "http")
	if err != nil {
		t.Fatal(err)
	}
	grpc, err := d.ids.FrontendID(t.Context(), "shop", "web", "grpc")
	if err != nil {
		t.Fatal(err)
	}
	counters.connects[http] = 5
	counters.connects[grpc] = 7
	counters.connects[9999] = 100

	src := d.CounterSource()
	if src == nil {
		t.Fatal("CounterSource = nil with counters wired")
	}
	got, err := src.ServiceConnects(t.Context())
	if err != nil {
		t.Fatalf("ServiceConnects: %v", err)
	}
	want := map[string]uint64{"shop/web": 12}
	if len(got) != 1 || got["shop/web"] != want["shop/web"] {
		t.Fatalf("ServiceConnects = %v, want %v", got, want)
	}
}

func TestCounterSourceIsNilWithoutCounters(t *testing.T) {
	f := newFixture(t)
	if src := f.d.CounterSource(); src != nil {
		t.Fatalf("CounterSource = %v, want nil on a platform without counters", src)
	}
}

// zoneRecorder observes SetZone without standing up a resolver.
type zoneRecorder struct {
	mu    sync.Mutex
	calls [][]network.Service
}

func (z *zoneRecorder) SetZone(services []network.Service) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.calls = append(z.calls, services)
}
