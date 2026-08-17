package edge

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"sync"
	"time"
)

// DefaultMaxPublishedConns is the process-wide ceiling on live connections
// across every published tcp listener.
//
// 1024, roughly 24 MiB at ~24 KiB a connection. Not 4096: ~96 MiB is a tenth of
// the whole §21 control-plane budget for a feature most nodes never turn on,
// and the ceiling is there to bound a surprise rather than to be reached.
const DefaultMaxPublishedConns = 1024

// listenerState is what a published port is currently doing, for the status
// endpoint. A bind that failed is a state, not an absence: something else on
// the node holds the port and an operator needs to be told which.
type listenerState struct {
	Listener Listener `json:"listener"`
	Bound    bool     `json:"bound"`
	Error    string   `json:"error,omitempty"`
	Conns    int      `json:"conns"`
}

// listenerSet owns the published ports (PRD §7.2.2).
//
// Keyed by node port, because a node port is what a bind contends for: two
// services cannot hold 8096 whatever they are called.
type listenerSet struct {
	log     *slog.Logger
	proxy   *Proxy
	limiter *connLimiter
	// timeouts are the same bounds the public listeners use. A published HTTP
	// port is the same server on a different socket, so it gets the same
	// slowloris and header-size protections rather than its own.
	readHeaderTimeout time.Duration
	idleTimeout       time.Duration
	maxHeaderBytes    int
	// listen, listenPacket and dial are injectable so tests can run on :0 and
	// against a fake upstream without a real network.
	listen       func(network, address string) (net.Listener, error)
	listenPacket func(network, address string) (net.PacketConn, error)
	dial         func(network, address string) (net.Conn, error)

	mu      sync.Mutex
	entries map[entryKey]*listenerEntry
	failed  map[entryKey]failedBind
}

// entryKey is what a bind contends for: a node port *within one L4 family*
// (v1.42). A stream socket and a datagram socket on one number coexist, so 53
// over both tcp and udp is two entries, not a collision.
type entryKey struct {
	udp  bool
	port int
}

func keyFor(l Listener) entryKey { return entryKey{udp: l.Mode == ListenerUDP, port: l.Port} }

type failedBind struct {
	listener Listener
	err      error
}

// listenerEntry is one bound port.
type listenerEntry struct {
	cfg Listener
	// ln is set for the stream kinds, pc for udp.
	ln net.Listener
	pc net.PacketConn
	// srv is set for an http listener, relay for a tcp one, udp for a udp
	// one. Exactly one is non-nil: the kind is what a rebind is for.
	srv   *http.Server
	relay *relay
	udp   *udpRelay
}

func newListenerSet(proxy *Proxy, cfg Config) *listenerSet {
	maxConns := cfg.MaxPublishedConns
	if maxConns <= 0 {
		maxConns = DefaultMaxPublishedConns
	}
	return &listenerSet{
		log: cfg.Logger, proxy: proxy, limiter: newConnLimiter(maxConns),
		readHeaderTimeout: cfg.ReadHeaderTimeout,
		idleTimeout:       cfg.IdleTimeout,
		maxHeaderBytes:    cfg.MaxHeaderBytes,
		listen:            net.Listen,
		listenPacket:      net.ListenPacket,
		entries:           map[entryKey]*listenerEntry{},
		failed:            map[entryKey]failedBind{},
	}
}

// Apply reconciles the bound ports against what the snapshot asks for.
//
// It deliberately returns no error. It is called from the watcher, where an
// error means "reject this file and keep the last one", and a port held by
// something else on the node must not freeze the whole route table. The rest of
// the snapshot takes effect, the failure is recorded and logged, and the next
// poll retries the bind.
func (s *listenerSet) Apply(want []Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()

	wanted := make(map[entryKey]Listener, len(want))
	for _, l := range want {
		wanted[keyFor(l)] = l
	}

	// Withdrawn first, so a listener moving from one service to another frees
	// the port before the new one tries to bind it.
	for key, entry := range s.entries {
		if _, keep := wanted[key]; keep {
			continue
		}
		s.log.Info("withdrawing published port", "port", key.port, "service", entry.cfg.Name())
		s.stop(entry)
		delete(s.entries, key)
	}
	for key := range s.failed {
		if _, keep := wanted[key]; !keep {
			delete(s.failed, key)
		}
	}

	keys := make([]entryKey, 0, len(wanted))
	for key := range wanted {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].port != keys[j].port {
			return keys[i].port < keys[j].port
		}
		return !keys[i].udp && keys[j].udp
	})

	for _, key := range keys {
		cfg := wanted[key]
		entry, bound := s.entries[key]
		switch {
		case !bound:
			s.bind(cfg)
		case rebindRequired(entry.cfg, cfg):
			s.log.Info("rebinding published port",
				"port", key.port, "from", entry.cfg.Mode, "to", cfg.Mode)
			s.stop(entry)
			delete(s.entries, key)
			s.bind(cfg)
		default:
			s.reconfigure(entry, cfg)
		}
	}

	// A withdrawn port must stop being reported, or its entrypoint's gauges sit
	// at whatever they held when the listener went away: a connection count
	// that never returns to zero because nothing is left to decrement it. The
	// two well-known entrypoints are always kept: they belong to the main
	// server, which this set does not own.
	keep := map[string]bool{EntrypointWeb: true, EntrypointWebSecure: true}
	for key := range wanted {
		keep[EntrypointForPort(key.port)] = true
	}
	s.proxy.Metrics().RetainEntrypoints(keep)
}

// rebindRequired is deliberately narrow.
//
// A changed upstream, CIDR or connection cap is a configuration swap behind an
// atomic pointer: the socket stays open and live connections finish against
// what they started with. Only a change of listener *kind* forces a rebind,
// which drops every connection on that port: far too much to charge for fixing
// a typo in a CIDR.
func rebindRequired(old, want Listener) bool { return old.Mode != want.Mode }

// bind opens the socket and starts serving.
func (s *listenerSet) bind(cfg Listener) {
	if cfg.Mode == ListenerUDP {
		s.bindUDP(cfg)
		return
	}
	ln, err := s.listen("tcp", cfg.Bind())
	if err != nil {
		// Recorded rather than retried in a loop here: the next snapshot poll
		// is the retry, and it arrives on its own schedule.
		s.failed[keyFor(cfg)] = failedBind{listener: cfg, err: err}
		s.log.Error("cannot bind a published port",
			"service", cfg.Name(), "port", cfg.Port, "error", err,
			"detail", "the rest of the snapshot is serving; the next poll retries this one")
		return
	}
	delete(s.failed, keyFor(cfg))

	entry := &listenerEntry{cfg: cfg, ln: ln}
	switch cfg.Mode {
	case ListenerTCP:
		relay, err := newRelay(cfg, s.limiter, s.log, s.proxy.Metrics(), s.dial)
		if err != nil {
			// Validate compiled this already, so it cannot normally fail. If it
			// somehow does, the port stays unbound rather than open and unruled.
			_ = ln.Close() //nolint:errcheck // cleanup path
			s.failed[keyFor(cfg)] = failedBind{listener: cfg, err: err}
			s.log.Error("cannot serve a published tcp port",
				"service", cfg.Name(), "port", cfg.Port, "error", err)
			return
		}
		entry.relay = relay
		go relay.serve(ln)
	default:
		entry.srv = s.httpServer(cfg)
		// Serve errors are logged and dropped, never fed to the process's error
		// channel. An accept loop dying on :25565 must not take :443 with it.
		go func(srv *http.Server, ln net.Listener, cfg Listener) {
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				s.log.Error("published http listener stopped",
					"service", cfg.Name(), "port", cfg.Port, "error", err)
			}
		}(entry.srv, ln, cfg)
	}

	s.entries[keyFor(cfg)] = entry
	s.log.Info("published port bound",
		"service", cfg.Name(), "port", cfg.Port, "mode", cfg.Mode, "upstream", cfg.Address())
}

// bindUDP opens the datagram socket and starts the relay (v1.42).
func (s *listenerSet) bindUDP(cfg Listener) {
	pc, err := s.listenPacket("udp", cfg.Bind())
	if err != nil {
		s.failed[keyFor(cfg)] = failedBind{listener: cfg, err: err}
		s.log.Error("cannot bind a published udp port",
			"service", cfg.Name(), "port", cfg.Port, "error", err,
			"detail", "the rest of the snapshot is serving; the next poll retries this one")
		return
	}
	delete(s.failed, keyFor(cfg))

	relay, err := newUDPRelay(cfg, pc, s.limiter, s.log, s.proxy.Metrics(), s.dial)
	if err != nil {
		// Validate compiled this already, so it cannot normally fail; the port
		// stays unbound rather than open and unruled.
		_ = pc.Close() //nolint:errcheck // cleanup path
		s.failed[keyFor(cfg)] = failedBind{listener: cfg, err: err}
		s.log.Error("cannot serve a published udp port",
			"service", cfg.Name(), "port", cfg.Port, "error", err)
		return
	}
	s.entries[keyFor(cfg)] = &listenerEntry{cfg: cfg, pc: pc, udp: relay}
	go relay.serve()
	s.log.Info("published port bound",
		"service", cfg.Name(), "port", cfg.Port, "mode", cfg.Mode,
		"backends", len(cfg.Backends))
}

// reconfigure swaps a listener's configuration without touching its socket.
func (s *listenerSet) reconfigure(entry *listenerEntry, cfg Listener) {
	if listenersSame(entry.cfg, cfg) {
		return
	}
	if entry.relay != nil {
		if err := entry.relay.update(cfg); err != nil {
			s.log.Error("cannot apply the new configuration to a published port",
				"service", cfg.Name(), "port", cfg.Port, "error", err)
			return
		}
	}
	if entry.udp != nil {
		if err := entry.udp.update(cfg); err != nil {
			s.log.Error("cannot apply the new configuration to a published udp port",
				"service", cfg.Name(), "port", cfg.Port, "error", err)
			return
		}
	}
	entry.cfg = cfg
	s.log.Info("published port reconfigured",
		"service", cfg.Name(), "port", cfg.Port, "upstream", cfg.Address())
}

// httpServer builds the alternate-port HTTP listener.
//
// The route is fixed here, at bind time, and not looked up per request: a
// published port is reached by address, so the Host header on it is an IP
// literal that would match no domain.
func (s *listenerSet) httpServer(cfg Listener) *http.Server {
	scope := fmt.Sprintf("p%d", cfg.Port)
	route, err := compile(cfg.asRoute())
	if err != nil {
		// Unreachable via Apply (Validate compiles every listener first) but
		// a handler that answered 500 would be less confusing than one that
		// silently served without the middleware it was told to apply.
		s.log.Error("cannot compile a published port's middleware",
			"service", cfg.Name(), "port", cfg.Port, "error", err)
		return &http.Server{
			ReadHeaderTimeout: s.readHeaderTimeout,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "misconfigured listener", http.StatusInternalServerError)
			}),
		}
	}
	return &http.Server{
		ReadHeaderTimeout: s.readHeaderTimeout,
		IdleTimeout:       s.idleTimeout,
		MaxHeaderBytes:    s.maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		ConnState:         connStateCounter(s.proxy.Metrics(), EntrypointForPort(cfg.Port)),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			s.proxy.serveRoute(w, r, route, scope, EntrypointForPort(cfg.Port))
		}),
	}
}

// connStateCounter tracks open connections on an entrypoint (§9.1.1).
//
// http.Server's ConnState hook is the only place a *connection* is visible:
// the handler sees requests, and keep-alive means those are not the same thing.
// StateNew and StateClosed are the pair; StateHijacked is also terminal, since
// a hijacked connection leaves the server's accounting for good and would
// otherwise never be decremented.
func connStateCounter(m *Metrics, entrypoint string) func(net.Conn, http.ConnState) {
	return func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			m.ConnOpened(entrypoint)
		case http.StateClosed, http.StateHijacked:
			m.ConnClosed(entrypoint)
		}
	}
}

// stop closes one listener.
func (s *listenerSet) stop(entry *listenerEntry) {
	if entry.srv != nil {
		_ = entry.srv.Close() //nolint:errcheck // cleanup path
		return
	}
	if entry.udp != nil {
		_ = entry.pc.Close() //nolint:errcheck // cleanup path
		entry.udp.closeLive()
		return
	}
	_ = entry.ln.Close() //nolint:errcheck // cleanup path
	if entry.relay != nil {
		entry.relay.closeLive()
	}
}

// Shutdown closes every listener, gives live connections `grace` to finish, and
// then closes what is left.
//
// http.Server.Shutdown's semantics do not carry over to a relay: a stream has
// no natural completion point, so there is nothing to wait for except a clock.
// A game session is not an HTTP request, which is why this deadline is separate
// from the edge's own.
func (s *listenerSet) Shutdown(grace time.Duration) {
	s.mu.Lock()
	entries := make([]*listenerEntry, 0, len(s.entries))
	for key, entry := range s.entries {
		entries = append(entries, entry)
		delete(s.entries, key)
	}
	s.mu.Unlock()

	var relays []*relay
	var udpRelays []*udpRelay
	for _, entry := range entries {
		if entry.pc != nil {
			// The socket closes now (no new sessions) but live sessions
			// drain like tcp connections: a game tick has no natural
			// completion point either.
			_ = entry.pc.Close() //nolint:errcheck // cleanup path
			if entry.udp != nil {
				udpRelays = append(udpRelays, entry.udp)
			}
			continue
		}
		_ = entry.ln.Close() //nolint:errcheck // cleanup path
		if entry.srv != nil {
			_ = entry.srv.Close() //nolint:errcheck // cleanup path
			continue
		}
		if entry.relay != nil {
			relays = append(relays, entry.relay)
		}
	}
	if len(relays) == 0 && len(udpRelays) == 0 {
		return
	}
	deadline := time.After(grace)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		live := 0
		for _, r := range relays {
			live += r.liveCount()
		}
		for _, u := range udpRelays {
			live += u.liveCount()
		}
		if live == 0 {
			return
		}
		select {
		case <-deadline:
			closed := 0
			for _, r := range relays {
				closed += r.closeLive()
			}
			for _, u := range udpRelays {
				closed += u.closeLive()
			}
			s.log.Warn("closing published connections that outlived the drain",
				"connections", closed, "grace", grace)
			return
		case <-tick.C:
		}
	}
}

// States reports what every published port is doing, for /listeners.
func (s *listenerSet) States() []listenerState {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]listenerState, 0, len(s.entries)+len(s.failed))
	for _, entry := range s.entries {
		state := listenerState{Listener: entry.cfg, Bound: true}
		if entry.relay != nil {
			state.Conns = entry.relay.liveCount()
		}
		if entry.udp != nil {
			state.Conns = entry.udp.liveCount()
		}
		out = append(out, state)
	}
	for _, f := range s.failed {
		out = append(out, listenerState{Listener: f.listener, Error: f.err.Error()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Listener.Port != out[j].Listener.Port {
			return out[i].Listener.Port < out[j].Listener.Port
		}
		return out[i].Listener.Mode < out[j].Listener.Mode
	})
	return out
}

// InFlight is the node-wide live connection count across published tcp ports.
func (s *listenerSet) InFlight() int { return s.limiter.inFlight() }

// listenersSame reports whether two listener configurations are identical.
func listenersSame(a, b Listener) bool {
	if a.Project != b.Project || a.Service != b.Service ||
		a.Port != b.Port || a.Mode != b.Mode ||
		a.Upstream != b.Upstream || a.UpstreamPort != b.UpstreamPort ||
		a.MaxConns != b.MaxConns {
		return false
	}
	// Backends are how a udp listener reaches anything (v1.42): a changed set
	// must reconfigure, or new sessions keep landing on departed allocs.
	return slices.Equal(a.Backends, b.Backends) &&
		reflect.DeepEqual(a.IPRestriction, b.IPRestriction) &&
		reflect.DeepEqual(a.RateLimit, b.RateLimit) &&
		reflect.DeepEqual(a.Headers, b.Headers)
}
