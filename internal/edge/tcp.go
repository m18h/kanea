package edge

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DefaultMaxConns bounds live connections on one tcp listener when the spec
// does not say.
//
// 256 is a per-listener figure; --max-published-conns bounds the whole process.
// A connection costs roughly 24 KiB — two goroutines and a connSet entry — and
// the splice buffers io.Copy uses for TCP→TCP are kernel pipes, not Go heap.
const DefaultMaxConns = 256

// dialTimeout bounds the connection to the upstream VIP.
//
// Five seconds: the upstream is a service VIP on this node, so a dial that
// takes longer is a service that is down rather than one that is far away.
const dialTimeout = 5 * time.Second

// ErrTooManyConns is returned to nothing — a refused connection is simply
// closed, because there is no protocol-independent way to say "busy" on a
// stream the edge does not parse. It exists so the refusal is countable.
var ErrTooManyConns = errors.New("edge: listener is at its connection limit")

// relay is a running tcp listener: a socket, its current configuration, and the
// connections it is holding.
//
// The configuration sits behind a mutex-guarded pointer rather than in the
// struct, because a changed upstream or CIDR must not close the socket. Live
// connections finish against what they started with; only a change of listener
// *kind* forces a rebind, and that is visible to every client on the port.
type relay struct {
	log     *slog.Logger
	limiter *connLimiter
	// metrics is the §7.2.2 counter set. Published ports had none before
	// v1.35, which is why ErrTooManyConns above says it exists "so the refusal
	// is countable" while nothing counted it.
	metrics *Metrics

	mu     sync.Mutex
	cfg    Listener
	rules  compiled
	dial   func(network, address string) (net.Conn, error)
	live   map[net.Conn]struct{}
	closed bool
}

// connLimiter is the process-wide ceiling shared by every relay.
type connLimiter struct {
	mu    sync.Mutex
	max   int
	inUse int
}

func newConnLimiter(limit int) *connLimiter { return &connLimiter{max: limit} }

// acquire takes one slot, or reports that there is none.
//
// Refused when full, never queued — the discipline internal/gitops uses for
// builds. A queued TCP connection looks connected to the client and is not, and
// a client that thinks it has a session will wait out its own timeout rather
// than failing over.
func (c *connLimiter) acquire() bool {
	if c == nil || c.max <= 0 {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inUse >= c.max {
		return false
	}
	c.inUse++
	return true
}

func (c *connLimiter) release() {
	if c == nil || c.max <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inUse > 0 {
		c.inUse--
	}
}

func (c *connLimiter) inFlight() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inUse
}

// newRelay builds a relay for one listener.
func newRelay(cfg Listener, limiter *connLimiter, log *slog.Logger, metrics *Metrics,
	dial func(network, address string) (net.Conn, error),
) (*relay, error) {
	rules, err := compile(cfg.asRoute())
	if err != nil {
		return nil, err
	}
	if dial == nil {
		dial = func(network, address string) (net.Conn, error) {
			return net.DialTimeout(network, address, dialTimeout)
		}
	}
	if metrics == nil {
		// A relay with no collector is a test's relay. Counting into a discarded
		// one keeps every call site below unconditional, which is what stops a
		// nil check from being forgotten on the path that matters.
		metrics = NewMetrics()
	}
	return &relay{
		log: log, limiter: limiter, metrics: metrics, cfg: cfg, rules: rules, dial: dial,
		live: map[net.Conn]struct{}{},
	}, nil
}

// update swaps the configuration behind the socket.
func (t *relay) update(cfg Listener) error {
	rules, err := compile(cfg.asRoute())
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg, t.rules = cfg, rules
	return nil
}

// config returns the current configuration and rules together, so a connection
// is served against one consistent snapshot rather than a half-swapped pair.
func (t *relay) config() (Listener, compiled) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg, t.rules
}

// serve accepts until the listener is closed.
func (t *relay) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// A closed listener is the normal way out. Anything else on an
			// accept loop is worth a line, but never worth taking the process
			// down: an accept failure on :25565 must not stop :443.
			if !errors.Is(err, net.ErrClosed) {
				t.log.Error("published listener stopped accepting",
					"service", t.cfg.Name(), "port", t.cfg.Port, "error", err)
			}
			return
		}
		go t.handle(conn)
	}
}

// handle relays one connection.
func (t *relay) handle(client net.Conn) {
	cfg, rules := t.config()
	name := cfg.Name()
	entrypoint := EntrypointForPort(cfg.Port)

	// The address check comes first, before the upstream is dialled. It has to:
	// the upstream sees the edge's address rather than the client's, so it
	// cannot make this decision itself, and on a tcp listener this is the only
	// ingress control there is.
	if !rules.allowsAddress(connAddr(client)) {
		t.log.Debug("address refused by ip_restriction",
			"service", name, "port", cfg.Port, "remote", client.RemoteAddr().String())
		t.metrics.TCPRefused(name, entrypoint, ReasonIPRestriction)
		_ = client.Close() //nolint:errcheck // cleanup path
		return
	}

	limit := cfg.MaxConns
	if limit <= 0 {
		limit = DefaultMaxConns
	}
	// Registered in the same critical section the limit is checked in: two
	// connections arriving together must not both see room for one.
	if !t.take(client, limit) {
		t.log.Warn("published listener refused a connection at its limit",
			"service", name, "port", cfg.Port, "max_conns", limit)
		t.metrics.TCPRefused(name, entrypoint, ReasonListenerLimit)
		_ = client.Close() //nolint:errcheck // cleanup path
		return
	}
	defer t.done(client)
	defer func() { _ = client.Close() }() //nolint:errcheck // cleanup path

	if !t.limiter.acquire() {
		t.log.Warn("published connection refused: the node-wide limit is full",
			"service", name, "port", cfg.Port)
		t.metrics.TCPRefused(name, entrypoint, ReasonNodeLimit)
		return
	}
	defer t.limiter.release()

	// Counted from here, past every refusal: a connection that was turned away
	// was never relayed, and folding the two together would make a listener at
	// its ceiling look busy rather than full.
	t.metrics.TCPAccepted(name, entrypoint)
	var in, out int64
	defer func() { t.metrics.TCPClosed(name, entrypoint, in, out) }()

	upstream, err := t.dial("tcp", cfg.Address())
	if err != nil {
		t.log.Warn("cannot reach the upstream for a published port",
			"service", name, "port", cfg.Port, "upstream", cfg.Address(), "error", err)
		return
	}
	defer func() { _ = upstream.Close() }() //nolint:errcheck // cleanup path

	in, out = relayBytes(client, upstream)
}

// take registers a connection if the per-listener limit allows it.
func (t *relay) take(conn net.Conn, limit int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || len(t.live) >= limit {
		return false
	}
	t.live[conn] = struct{}{}
	return true
}

func (t *relay) done(conn net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.live, conn)
}

// liveCount is how many connections this listener is holding.
func (t *relay) liveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.live)
}

// closeLive tears down whatever is still connected, and reports how many.
//
// Called only after the drain deadline. http.Server.Shutdown's semantics do not
// apply to a relay: a stream has no natural completion point, so there is
// nothing to wait for except a clock.
func (t *relay) closeLive() int {
	t.mu.Lock()
	conns := make([]net.Conn, 0, len(t.live))
	for conn := range t.live {
		conns = append(conns, conn)
	}
	t.closed = true
	t.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close() //nolint:errcheck // cleanup path
	}
	return len(conns)
}

// relayBytes copies in both directions and closes each write side when its
// source ends.
//
// The half-close is mandatory, not a nicety. Postgres and most line protocols
// rely on seeing EOF while still writing back; without CloseWrite a client that
// has finished sending waits for a response that the upstream will not produce
// because it is still waiting for input.
// It reports the bytes moved in each direction: in is client→upstream, out is
// upstream→client. The counts come from io.Copy's own return rather than from a
// wrapping reader, so the splice fast path below is preserved — a wrapper would
// force every byte through the Go heap purely to be counted.
func relayBytes(client, upstream net.Conn) (in, out int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		in = copyAndCloseWrite(upstream, client)
	}()
	go func() {
		defer wg.Done()
		out = copyAndCloseWrite(client, upstream)
	}()
	wg.Wait()
	return in, out
}

// copyAndCloseWrite copies src into dst and then half-closes dst.
//
// For TCP→TCP io.Copy dispatches to internal/poll.Splice, so payload bytes move
// kernel-to-kernel and never enter the Go heap. That is the whole cost of a
// published port: one userspace hop that touches no user data.
// It returns the bytes copied, which io.Copy reports even when it stops on an
// error — a connection reset partway through still moved everything before it.
func copyAndCloseWrite(dst, src net.Conn) int64 {
	n, _ := io.Copy(dst, src) //nolint:errcheck // cleanup path
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite() //nolint:errcheck // cleanup path
		return n
	}
	// Not half-closeable — a fake in a test, or a wrapped connection. Closing
	// outright is the honest fallback: leaving it open would hang the peer.
	_ = dst.Close() //nolint:errcheck // cleanup path
	return n
}

// connAddr is a connection's source address, unmapped.
//
// The Unmap matters for the same reason it does on the HTTP path: a v4-mapped
// v6 address must compare against v4 prefixes, or a rule written 10.0.0.0/8
// silently matches nothing on a dual-stack listener.
func connAddr(conn net.Conn) netip.Addr {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}
