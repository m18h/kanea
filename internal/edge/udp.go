package edge

import (
	"errors"
	"hash/fnv"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultMaxSessions bounds live sessions on one udp listener when the spec
// does not say. The same figure as DefaultMaxConns, for the same reason: a
// per-listener bound whose job is to make a surprise finite, under the shared
// --max-published-conns process ceiling.
const DefaultMaxSessions = 256

// udpIdleTimeout ends a session that has moved nothing in either direction.
//
// 90 seconds sits above every keepalive interval a real UDP protocol uses
// (game heartbeats and DTLS retransmits are seconds apart) and below the point
// where a table of dead clients costs anything. Expiry is cheap to be wrong
// about: the client's next datagram re-creates the session, and the rendezvous
// hash lands it on the same backend, so an expired-but-alive conversation
// resumes without noticing.
const udpIdleTimeout = 90 * time.Second

// udpSweepInterval is how often the janitor looks for idle sessions.
const udpSweepInterval = 15 * time.Second

// udpBufferSize is the read buffer for both directions. The theoretical UDP
// maximum: ReadFrom silently truncates a datagram larger than its buffer, and
// a truncated datagram is protocol corruption, not backpressure.
const udpBufferSize = 64 * 1024

// udpRelay is a running udp listener: one socket, a session per client
// address, and an idle janitor (PRD v1.42, §7.2.2).
//
// A session is a connected socket to one backend. Connected on purpose: the
// kernel then filters inbound datagrams to that peer, and a reply loop per
// session needs no demultiplexing. The backend is chosen by rendezvous hash of
// the client IP over the live backend set, so a client keeps its backend
// across an edge restart, a session expiry and other backends' churn: a
// stateful UDP conversation must not migrate mid-exchange.
type udpRelay struct {
	log     *slog.Logger
	limiter *connLimiter
	metrics *Metrics
	// dial is injectable so tests can relay to an in-process fake backend.
	dial func(network, address string) (net.Conn, error)

	conn net.PacketConn

	mu       sync.Mutex
	cfg      Listener
	rules    compiled
	sessions map[string]*udpSession
	closed   bool
	// now is the janitor's clock, mutex-guarded so a test can advance it
	// while the relay is serving. Read through clock().
	now func() time.Time
}

// clock reads the injectable clock without racing a test that resets it.
func (u *udpRelay) clock() time.Time {
	u.mu.Lock()
	fn := u.now
	u.mu.Unlock()
	return fn()
}

// udpSession is one client's conversation with its backend.
type udpSession struct {
	client  net.Addr
	backend string
	// upstream is the connected socket to the backend. Closing it is how a
	// session ends: the reply loop's blocked Read returns and cleans up.
	upstream net.Conn
	// lastActive is unix nanos of the last datagram in either direction.
	lastActive atomic.Int64
	// expired marks a janitor kill, so the close is counted as an expiry
	// rather than as an upstream failure.
	expired atomic.Bool
	// bytesIn/bytesOut mirror the tcp relay's accounting: reported once, when
	// the session closes.
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

func (s *udpSession) touch(now time.Time) { s.lastActive.Store(now.UnixNano()) }

// newUDPRelay builds a relay for one udp listener.
func newUDPRelay(cfg Listener, conn net.PacketConn, limiter *connLimiter, log *slog.Logger,
	metrics *Metrics, dial func(network, address string) (net.Conn, error),
) (*udpRelay, error) {
	rules, err := compile(cfg.asRoute())
	if err != nil {
		return nil, err
	}
	if dial == nil {
		dial = net.Dial
	}
	if metrics == nil {
		metrics = NewMetrics()
	}
	return &udpRelay{
		log: log, limiter: limiter, metrics: metrics, dial: dial, now: time.Now,
		conn: conn, cfg: cfg, rules: rules,
		sessions: map[string]*udpSession{},
	}, nil
}

// update swaps the configuration behind the socket.
//
// Sessions to a backend that left the set are ended: their allocs are stopping
// or gone, and a client re-hashing onto a live backend beats one talking to a
// void until the idle expiry notices.
func (u *udpRelay) update(cfg Listener) error {
	rules, err := compile(cfg.asRoute())
	if err != nil {
		return err
	}
	keep := make(map[string]bool, len(cfg.Backends))
	for _, b := range cfg.Backends {
		keep[b] = true
	}

	u.mu.Lock()
	u.cfg, u.rules = cfg, rules
	var orphaned []*udpSession
	for _, s := range u.sessions {
		if !keep[s.backend] {
			orphaned = append(orphaned, s)
		}
	}
	u.mu.Unlock()

	for _, s := range orphaned {
		_ = s.upstream.Close() //nolint:errcheck // cleanup path
	}
	return nil
}

// serve reads client datagrams until the socket is closed.
//
// One reader, deliberately: a datagram socket has no accept loop to fan out,
// and the per-datagram work is a map lookup and a Write. Session creation is
// the slow path and UDP dials do not block (no handshake).
func (u *udpRelay) serve() {
	buf := make([]byte, udpBufferSize)
	sweep := time.NewTicker(udpSweepInterval)
	defer sweep.Stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-sweep.C:
				u.expireIdle()
			}
		}
	}()

	for {
		n, addr, err := u.conn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				u.log.Error("published udp listener stopped reading",
					"service", u.cfg.Name(), "port", u.cfg.Port, "error", err)
			}
			return
		}
		u.handle(buf[:n], addr)
	}
}

// handle relays one client datagram, creating its session if it is new.
func (u *udpRelay) handle(payload []byte, addr net.Addr) {
	key := addr.String()

	u.mu.Lock()
	session, ok := u.sessions[key]
	u.mu.Unlock()

	if !ok {
		session = u.openSession(addr, key)
		if session == nil {
			return // refused, and counted by openSession
		}
	}

	session.touch(u.clock())
	n, err := session.upstream.Write(payload)
	session.bytesIn.Add(int64(n))
	if err != nil {
		// The backend is unreachable (ICMP refused surfaces here on a
		// connected socket). End the session; the client's next datagram
		// re-creates it against the then-current backend set.
		_ = session.upstream.Close() //nolint:errcheck // cleanup path
	}
}

// openSession admits one new client, or refuses with the reason counted.
//
// This is the accept-time hook a datagram socket lacks, recovered at the only
// moment there is: ip_restriction and both session caps are checked here,
// before a byte is forwarded, exactly as the tcp relay checks before dialling.
func (u *udpRelay) openSession(addr net.Addr, key string) *udpSession {
	cfg, rules := u.config()
	name := cfg.Name()
	entrypoint := EntrypointForPort(cfg.Port)

	clientIP := packetAddr(addr)
	if !rules.allowsAddress(clientIP) {
		u.log.Debug("address refused by ip_restriction",
			"service", name, "port", cfg.Port, "remote", key)
		u.metrics.UDPRefused(name, entrypoint, ReasonIPRestriction)
		return nil
	}

	backends := cfg.Backends
	if len(backends) == 0 {
		// A service that is starting, or scaled to zero. Dropped and counted:
		// a refusal a client can *see* does not exist in UDP, but one an
		// operator can see does.
		u.metrics.UDPRefused(name, entrypoint, ReasonNoBackends)
		return nil
	}
	backend := pickBackend(clientIP.String(), backends)

	if !u.limiter.acquire() {
		u.log.Warn("published udp session refused: the node-wide limit is full",
			"service", name, "port", cfg.Port)
		u.metrics.UDPRefused(name, entrypoint, ReasonNodeLimit)
		return nil
	}

	upstream, err := u.dial("udp", net.JoinHostPort(backend, strconv.Itoa(cfg.UpstreamPort)))
	if err != nil {
		u.limiter.release()
		u.log.Warn("cannot reach a backend for a published udp port",
			"service", name, "port", cfg.Port, "backend", backend, "error", err)
		return nil
	}

	session := &udpSession{client: addr, backend: backend, upstream: upstream}
	session.touch(u.clock())

	limit := cfg.MaxConns
	if limit <= 0 {
		limit = DefaultMaxSessions
	}
	// Registered in the same critical section the limit is checked in, like
	// the tcp relay's take(): two datagrams arriving together must not both
	// see room for one session.
	u.mu.Lock()
	if u.closed || len(u.sessions) >= limit {
		full := !u.closed
		u.mu.Unlock()
		u.limiter.release()
		_ = upstream.Close() //nolint:errcheck // cleanup path
		if full {
			u.log.Warn("published udp listener refused a session at its limit",
				"service", name, "port", cfg.Port, "max_conns", limit)
			u.metrics.UDPRefused(name, entrypoint, ReasonListenerLimit)
		}
		return nil
	}
	if raced, ok := u.sessions[key]; ok {
		// Another goroutine won the create. Impossible with the single read
		// loop, cheap to be safe against anyway.
		u.mu.Unlock()
		u.limiter.release()
		_ = upstream.Close() //nolint:errcheck // cleanup path
		return raced
	}
	u.sessions[key] = session
	u.mu.Unlock()

	u.metrics.UDPSessionOpened(name, entrypoint)
	go u.replyLoop(session, key, name, entrypoint)
	return session
}

// replyLoop copies backend datagrams back to the client, and owns the
// session's teardown: whoever closes the upstream socket (janitor, config
// update, shutdown, or a write error) lands here.
func (u *udpRelay) replyLoop(s *udpSession, key, name, entrypoint string) {
	buf := make([]byte, udpBufferSize)
	for {
		n, err := s.upstream.Read(buf)
		if n > 0 {
			s.touch(u.clock())
			written, werr := u.conn.WriteTo(buf[:n], s.client)
			s.bytesOut.Add(int64(written))
			if werr != nil && errors.Is(werr, net.ErrClosed) {
				break // the listener itself is going away
			}
		}
		if err != nil {
			break
		}
	}

	u.mu.Lock()
	if u.sessions[key] == s {
		delete(u.sessions, key)
	}
	u.mu.Unlock()
	_ = s.upstream.Close() //nolint:errcheck // idempotent cleanup
	u.limiter.release()
	u.metrics.UDPSessionClosed(name, entrypoint, s.bytesIn.Load(), s.bytesOut.Load(), s.expired.Load())
}

// expireIdle ends sessions that have moved nothing for udpIdleTimeout.
func (u *udpRelay) expireIdle() {
	deadline := u.clock().Add(-udpIdleTimeout).UnixNano()

	u.mu.Lock()
	var idle []*udpSession
	for _, s := range u.sessions {
		if s.lastActive.Load() < deadline {
			idle = append(idle, s)
		}
	}
	u.mu.Unlock()

	for _, s := range idle {
		s.expired.Store(true)
		_ = s.upstream.Close() //nolint:errcheck // cleanup path
	}
}

// config returns the configuration and rules together, like the tcp relay's.
func (u *udpRelay) config() (Listener, compiled) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.cfg, u.rules
}

// liveCount is how many sessions this listener is holding.
func (u *udpRelay) liveCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.sessions)
}

// closeLive tears down whatever is still talking, and reports how many.
func (u *udpRelay) closeLive() int {
	u.mu.Lock()
	sessions := make([]*udpSession, 0, len(u.sessions))
	for _, s := range u.sessions {
		sessions = append(sessions, s)
	}
	u.closed = true
	u.mu.Unlock()

	for _, s := range sessions {
		_ = s.upstream.Close() //nolint:errcheck // cleanup path
	}
	return len(sessions)
}

// pickBackend chooses by rendezvous (highest-random-weight) hash.
//
// Rendezvous rather than modulo: when a backend leaves, only the clients it
// owned move, and when it returns they come back. Modulo would reshuffle every
// client on every backend change, which for a stateful protocol is an outage
// dressed as a deploy.
func pickBackend(clientIP string, backends []string) string {
	best, bestScore := "", uint64(0)
	for _, backend := range backends {
		h := fnv.New64a()
		_, _ = h.Write([]byte(clientIP)) //nolint:errcheck // fnv cannot fail
		_, _ = h.Write([]byte{0})        //nolint:errcheck // fnv cannot fail
		_, _ = h.Write([]byte(backend))  //nolint:errcheck // fnv cannot fail
		if score := h.Sum64(); best == "" || score > bestScore {
			best, bestScore = backend, score
		}
	}
	return best
}

// packetAddr is a datagram's source address, unmapped: connAddr's rule, for
// an address that never came from a net.Conn.
func packetAddr(addr net.Addr) netip.Addr {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			host = addr.String()
		}
		parsed, err := netip.ParseAddr(host)
		if err != nil {
			return netip.Addr{}
		}
		return parsed.Unmap()
	}
	parsed, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return netip.Addr{}
	}
	return parsed.Unmap()
}
