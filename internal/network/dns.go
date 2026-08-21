package network

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// InternalZone is the suffix Kanea is authoritative for (PRD §7.1).
const InternalZone = "kanea"

// DNS defaults.
const (
	// DefaultDNSPort is the standard port; the listener binds a node-local
	// address, never a public one.
	DefaultDNSPort = 53
	// DefaultRecordTTL is short on purpose. Records follow allocs, and an alloc
	// can move within one reconcile interval, so a long TTL would mostly serve
	// to keep clients pointed at addresses that no longer exist. VIPs are
	// stable, but a resolver cannot tell the two kinds of name apart.
	DefaultRecordTTL = 30 * time.Second
	// DefaultForwardTimeout bounds one upstream query.
	DefaultForwardTimeout = 2 * time.Second
	// DefaultMaxForwards caps concurrent upstream queries. DNS sits in the path
	// of every service call: when this is exhausted the answer is an immediate
	// SERVFAIL, never a queue. A client that gets SERVFAIL retries; a client
	// stuck behind a queue holds a connection open and takes the caller with it.
	DefaultMaxForwards = 64
	// DefaultMaxTCPConns caps concurrent TCP clients (v1.86). A datagram
	// server holds nothing between queries; a stream server holds a socket and
	// a goroutine per client, so the transport that makes truncation
	// answerable is also the one that can be held open. The excess is closed
	// immediately and counted, never queued: the forwardSlots discipline
	// applied to connections.
	DefaultMaxTCPConns = 32
	// allocLabelPrefix names a single alloc: alloc-<id>.<service>.<project>.kanea
	allocLabelPrefix = "alloc-"
)

// TCP timeouts (v1.86). A DNS exchange is one round trip against a resolver on
// the same node, so these are short by design: they bound a client that opens a
// connection and stops, which is the whole reason the TCP half needs bounding
// at all.
const (
	// tcpIdleTimeout is how long a connection may sit between messages. RFC
	// 7766 encourages connection reuse, so this is not one-shot; it is the
	// point past which an idle socket is someone else's slot.
	tcpIdleTimeout = 10 * time.Second
	// tcpIOTimeout bounds one message in or out once it has started.
	tcpIOTimeout = 5 * time.Second
)

// DNSConfig configures the embedded resolver.
type DNSConfig struct {
	// Listen is the address to serve on, e.g. "10.200.1.1:53".
	//
	// It must be node-local. Binding a wildcard address would publish an open
	// resolver on every interface the node has, which is both an amplification
	// vector and a way for anything on the network to enumerate the services
	// running here.
	Listen string
	// Upstreams are the resolvers external names are forwarded to. Empty means
	// no forwarding: queries outside the internal zone get REFUSED.
	Upstreams []string
	// TTL for records this server is authoritative for.
	TTL time.Duration
	// ForwardTimeout bounds one upstream query.
	ForwardTimeout time.Duration
	// MaxForwards caps concurrent upstream queries.
	MaxForwards int
	// MaxTCPConns caps concurrent TCP clients (v1.86).
	MaxTCPConns int
	// Logger receives lifecycle events. Individual queries are not logged:
	// at one lookup per service call the volume is enormous and the content is
	// a record of what every workload talks to.
	Logger *slog.Logger
}

// DNS is the embedded authoritative resolver for the internal zone.
//
// It answers `<service>.<project>.kanea` with the service's frontend VIP and
// `alloc-<id>.<service>.<project>.kanea` with that alloc's address, and
// forwards everything else. Names are injected into each alloc's resolv.conf,
// so this is what makes `${service.x.host}` resolve to something stable:
// the whole reason service references are DNS names and never IPs (PRD §7.1.1).
//
// The design constraint is that it must degrade rather than stall. Every
// upstream query is bounded by a timeout and by a concurrency cap, and neither
// a slow upstream nor a flood of external lookups can delay an answer for an
// internal name: those are served from memory with no I/O at all.
type DNS struct {
	listen         string
	upstreams      []string
	ttl            time.Duration
	forwardTimeout time.Duration
	log            *slog.Logger

	// zone is swapped wholesale on update, so a lookup never holds a lock
	// across anything but a map read.
	zone atomic.Pointer[zone]

	// forwardSlots is a counting semaphore over in-flight upstream queries,
	// taken in the read loop before the goroutine is born (K-26).
	forwardSlots chan struct{}
	// forwardDrops counts queries refused because every slot was taken: a cap
	// nobody can see reads as packet loss (the v1.42 rule).
	forwardDrops atomic.Uint64

	// tcpSlots bounds concurrent TCP clients and tcpRefused counts the ones
	// turned away, for the reason forwardDrops exists: a cap nobody can see is
	// indistinguishable from packet loss.
	tcpSlots   chan struct{}
	tcpRefused atomic.Uint64

	conn     atomic.Pointer[net.UDPConn]
	listener atomic.Pointer[net.TCPListener]
	wg       sync.WaitGroup
}

// zone is an immutable snapshot of the internal namespace.
type zone struct {
	// records maps a fully-qualified name to its addresses.
	records map[string][]netip.Addr
}

// NewDNS builds the resolver. It does not bind: call Serve.
func NewDNS(cfg DNSConfig) (*DNS, error) {
	if cfg.Listen == "" {
		return nil, errors.New("dns: listen address is required")
	}
	if err := validateNodeLocal(cfg.Listen); err != nil {
		return nil, err
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultRecordTTL
	}
	if cfg.ForwardTimeout <= 0 {
		cfg.ForwardTimeout = DefaultForwardTimeout
	}
	if cfg.MaxForwards <= 0 {
		cfg.MaxForwards = DefaultMaxForwards
	}
	if cfg.MaxTCPConns <= 0 {
		cfg.MaxTCPConns = DefaultMaxTCPConns
	}

	// An upstream that is this resolver forwards every external name to
	// itself: the query loops until the forward timeout and comes back
	// SERVFAIL, which reads as "the internet is broken" rather than as a
	// configuration mistake. It is reachable by two ordinary routes - a
	// loopback bind beside a loopback nameserver, and a node whose own
	// resolv.conf was pointed at Kanea's resolver on purpose - so it is
	// dropped by name here rather than left to be diagnosed by timeout.
	// Dropped, not refused: the other upstreams in the list still work, and
	// only an empty result is fatal.
	upstreams := make([]string, 0, len(cfg.Upstreams))
	var selfForward []string
	for _, u := range cfg.Upstreams {
		normalized, err := normalizeUpstream(u)
		if err != nil {
			return nil, err
		}
		if sameEndpoint(normalized, cfg.Listen) {
			selfForward = append(selfForward, normalized)
			continue
		}
		upstreams = append(upstreams, normalized)
	}
	if len(selfForward) > 0 {
		if len(upstreams) == 0 {
			return nil, fmt.Errorf("dns: every upstream is this resolver's own address (%s); "+
				"forwarding there is a loop - set --dns-upstream, or a dns stanza, to a real resolver",
				cfg.Listen)
		}
		cfg.Logger.Warn("dropping upstreams that point at this resolver",
			"dropped", selfForward, "listen", cfg.Listen, "remaining", upstreams)
	}

	d := &DNS{
		listen:         cfg.Listen,
		upstreams:      upstreams,
		ttl:            cfg.TTL,
		forwardTimeout: cfg.ForwardTimeout,
		log:            cfg.Logger,
		forwardSlots:   make(chan struct{}, cfg.MaxForwards),
		tcpSlots:       make(chan struct{}, cfg.MaxTCPConns),
	}
	d.zone.Store(&zone{records: map[string][]netip.Addr{}})
	return d, nil
}

// validateNodeLocal refuses a wildcard or public bind.
//
// An open resolver on a public interface is a DNS amplification source and an
// inventory of everything running on the node. This is cheap to get wrong in a
// config file and expensive to notice, so it is refused at construction:
// loopback, private and link-local addresses only (K-27). The cluster CIDRs
// are private by construction (ULA for v6), so a node-local resolver address
// always qualifies.
func validateNodeLocal(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("dns: listen address %q: %w", listen, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("dns: listen address %q must be an IP, not a name: %w", listen, err)
	}
	if addr.IsUnspecified() {
		return fmt.Errorf("dns: refusing to listen on %s; bind a node-local address, "+
			"a wildcard bind publishes an open resolver on every interface", host)
	}
	if !addr.IsLoopback() && !addr.IsPrivate() && !addr.IsLinkLocalUnicast() {
		return fmt.Errorf("dns: refusing to listen on %s; a public address publishes an "+
			"open resolver and the node's service inventory", host)
	}
	return nil
}

func normalizeUpstream(u string) (string, error) {
	if _, _, err := net.SplitHostPort(u); err == nil {
		return u, nil
	}
	if _, err := netip.ParseAddr(u); err != nil {
		return "", fmt.Errorf("dns: upstream %q is not an address: %w", u, err)
	}
	return net.JoinHostPort(u, "53"), nil
}

// sameEndpoint reports whether two host:port strings name the same address.
// Compared as parsed addresses rather than as text, because "[::1]:53" and
// "[0:0:0:0:0:0:0:1]:53" are the same resolver spelled two ways and a string
// comparison would forward one of them to itself. A name (rather than an
// address) cannot be this resolver, whose bind validateNodeLocal requires to
// be an IP, so an unparseable side is simply not a match.
func sameEndpoint(a, b string) bool {
	left, err := netip.ParseAddrPort(a)
	if err != nil {
		return false
	}
	right, err := netip.ParseAddrPort(b)
	if err != nil {
		return false
	}
	return left.Addr().Unmap() == right.Addr().Unmap() && left.Port() == right.Port()
}

// SetZone replaces the served records with those derived from the given
// services. It is safe to call while serving.
func (d *DNS) SetZone(services []Service) {
	records := make(map[string][]netip.Addr, len(services)*2)

	for _, svc := range services {
		if svc.Project == "" || svc.Service == "" {
			continue
		}
		base := ServiceName(svc.Project, svc.Service)

		// The service name resolves to the frontend, not to the backends. A
		// client that resolves to alloc addresses would load balance in its own
		// resolver cache and keep using an address after the alloc behind it
		// went away; the VIP is what the datapath keeps honest.
		if vip, err := netip.ParseAddr(svc.VIP); err == nil && vip.Is4() {
			records[base] = []netip.Addr{vip}
		}
		// The v6 twin joins the same name (v1.41); answerInternal filters per
		// query type, so an A query never sees it and an AAAA never sees v4.
		if vip6, err := netip.ParseAddr(svc.VIP6); err == nil && vip6.Is6() && !vip6.Is4In6() {
			records[base] = append(records[base], vip6)
		}

		for _, backend := range svc.Backends {
			name := AllocName(svc.Project, svc.Service, backend.AllocID)
			if ip, err := netip.ParseAddr(backend.IPv4); err == nil && ip.Is4() {
				records[name] = append(records[name], ip)
			}
			if ip6, err := netip.ParseAddr(backend.IPv6); err == nil && ip6.Is6() && !ip6.Is4In6() {
				records[name] = append(records[name], ip6)
			}
		}
	}
	d.zone.Store(&zone{records: records})
}

// ServiceName is the internal name of a service: <service>.<project>.kanea.
func ServiceName(project, service string) string {
	return service + "." + project + "." + InternalZone
}

// AllocName is the internal name of one alloc (PRD §7.1).
func AllocName(project, service, allocID string) string {
	return allocLabelPrefix + allocID + "." + service + "." + project + "." + InternalZone
}

// Serve binds the listener and answers queries until ctx is cancelled.
func (d *DNS) Serve(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", d.listen)
	if err != nil {
		return fmt.Errorf("dns: resolve %s: %w", d.listen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dns: listen %s: %w", d.listen, err)
	}
	d.conn.Store(conn)

	// TCP on the *bound* UDP address, not on d.listen: a configured port of 0
	// resolves to an ephemeral one, and two independent binds would answer on
	// two different ports. A client that got TC on one and retried on the other
	// would find nothing there, which is the failure this listener exists to
	// remove. A bind failure is fatal exactly as the UDP one is: half a
	// resolver is not a resolver.
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = conn.Close() //nolint:errcheck // the bind is being abandoned
		return fmt.Errorf("dns: listener on %s is not a UDP address", d.listen)
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: udpAddr.IP, Port: udpAddr.Port, Zone: udpAddr.Zone})
	if err != nil {
		_ = conn.Close() //nolint:errcheck // the bind is being abandoned
		return fmt.Errorf("dns: listen tcp %s: %w", udpAddr, err)
	}
	d.listener.Store(listener)

	d.log.Info("internal dns listening", "address", udpAddr.String(), "zone", InternalZone,
		"upstreams", len(d.upstreams), "transports", "udp+tcp")

	go func() {
		<-ctx.Done()
		// Closing is what unblocks ReadFromUDP and Accept; a failure here means
		// the socket was already gone, which is the state we were aiming for
		// anyway.
		if err := conn.Close(); err != nil {
			d.log.Debug("closing dns listener", "error", err)
		}
		if err := listener.Close(); err != nil {
			d.log.Debug("closing dns tcp listener", "error", err)
		}
	}()

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.acceptTCP(ctx, listener)
	}()

	buf := make([]byte, maxUDPPayload*2)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				d.wg.Wait()
				d.log.Info("internal dns stopped")
				return ctx.Err()
			}
			// A read error on a UDP socket is per-datagram, not fatal: dropping
			// the whole resolver because one packet was malformed would take
			// every service call on the node with it.
			d.log.Warn("dns read failed", "error", err)
			continue
		}

		// Copied because the buffer is reused by the next read.
		request := make([]byte, n)
		copy(request, buf[:n])

		// K-26: an answer from the zone is a memory lookup, so it is served
		// inline from the read loop - a flood of internal queries costs a
		// memcpy, never a goroutine. A forward is a network wait, so it gets a
		// goroutine, but only after winning a slot: a flood of external
		// queries then drops on full rather than spawning without bound (the
		// same discipline as forwardSlots, moved to where the goroutine is
		// born). A parse failure is the cheap error-response path and stays
		// inline too.
		q, needsForward := willForward(request)
		if !needsForward {
			d.handle(ctx, conn, client, request)
			continue
		}

		select {
		case d.forwardSlots <- struct{}{}:
		default:
			// Full: fail the query, count the drop, never queue. A queue is
			// the failure mode this design exists to avoid.
			d.forwardDrops.Add(1)
			if response := newResponse(request, q, rcodeServFail, false).finish(); len(response) > 0 {
				if _, err := conn.WriteToUDP(response, client); err != nil && ctx.Err() == nil {
					d.log.Debug("dns drop-answer write failed", "error", err)
				}
			}
			continue
		}

		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer func() { <-d.forwardSlots }()
			d.handle(ctx, conn, client, request)
		}()
	}
}

// willForward parses a request and reports whether answering it needs an
// upstream query. Shared by both read loops, because the slot has to be taken
// before the work starts and each transport starts the work differently: a
// second copy of this predicate would be a second answer to "is this ours".
//
// A request that does not parse is not a forward: it is the cheap error
// response, and the zero query is what the caller writes it from.
func willForward(request []byte) (query, bool) {
	parsed, err := parseQuery(request)
	if err != nil {
		return query{}, false
	}
	return parsed, parsed.opcode() == 0 &&
		(parsed.Class == classIN || parsed.Class == typeANY) &&
		!isInternalName(parsed.Name)
}

// acceptTCP serves the stream half until the listener is closed.
//
// The connection cap is taken here rather than inside the handler, because the
// thing being bounded is the socket, and a connection accepted to be told it is
// refused has already cost the slot it was refused for. Over the cap the socket
// is closed immediately: refused, never queued, the forwardSlots rule applied
// one layer out.
func (d *DNS) acceptTCP(ctx context.Context, listener *net.TCPListener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// An accept error is per-connection (a peer that vanished between
			// SYN and accept), not a reason to stop serving TCP entirely.
			d.log.Warn("dns tcp accept failed", "error", err)
			continue
		}

		select {
		case d.tcpSlots <- struct{}{}:
		default:
			d.tcpRefused.Add(1)
			if err := conn.Close(); err != nil {
				d.log.Debug("closing refused dns tcp connection", "error", err)
			}
			continue
		}

		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer func() { <-d.tcpSlots }()
			d.serveConn(ctx, conn)
		}()
	}
}

// serveConn answers messages on one TCP connection until it goes idle, errors,
// or the server shuts down.
//
// Framing is RFC 1035's: a two-byte big-endian length ahead of each message,
// which is also what bounds a request; a client cannot describe more than 65535
// bytes, so there is no size to police beyond the one the frame states.
func (d *DNS) serveConn(ctx context.Context, conn net.Conn) {
	// Closing the connection is what unblocks a read sitting on it, exactly as
	// closing the listener unblocks Accept. Without this, shutdown waits out
	// the idle timeout of every client that happens to be holding one, and
	// Serve's wg.Wait() is where that shows up.
	var once sync.Once
	closeConn := func() {
		once.Do(func() {
			if err := conn.Close(); err != nil {
				d.log.Debug("closing dns tcp connection", "error", err)
			}
		})
	}
	finished := make(chan struct{})
	defer func() {
		close(finished)
		closeConn()
	}()
	go func() {
		select {
		case <-ctx.Done():
			closeConn()
		case <-finished:
		}
	}()

	for {
		if err := conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout)); err != nil {
			return
		}
		var header [2]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return // EOF, idle timeout, or the listener closing under us
		}
		size := binary.BigEndian.Uint16(header[:])
		if size == 0 {
			return // a zero-length message is not a query; nothing to answer
		}
		if err := conn.SetReadDeadline(time.Now().Add(tcpIOTimeout)); err != nil {
			return
		}
		request := make([]byte, size)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}

		response := d.respondTCP(ctx, request)
		if len(response) == 0 {
			return // unanswerable: the connection has nothing left to carry
		}
		if err := conn.SetWriteDeadline(time.Now().Add(tcpIOTimeout)); err != nil {
			return
		}
		framed := make([]byte, 0, 2+len(response))
		framed = binary.BigEndian.AppendUint16(framed, uint16(len(response))) // #nosec G115: response is capped at maxTCPPayload
		framed = append(framed, response...)
		if _, err := conn.Write(framed); err != nil {
			return
		}
	}
}

// respondTCP answers one message, taking a forward slot first when the name is
// not ours: the same drop-on-full discipline the UDP loop applies, at the point
// where this transport learns it is about to wait on the network.
func (d *DNS) respondTCP(ctx context.Context, request []byte) []byte {
	q, needsForward := willForward(request)
	if !needsForward {
		return d.respond(ctx, request, tcpTransport)
	}
	select {
	case d.forwardSlots <- struct{}{}:
	default:
		d.forwardDrops.Add(1)
		return newResponse(request, q, rcodeServFail, false).finish()
	}
	defer func() { <-d.forwardSlots }()
	return d.respond(ctx, request, tcpTransport)
}

// Listen reports the configured listen address, available before Serve binds.
func (d *DNS) Listen() string { return d.listen }

// Addr reports the bound address, or the empty string before Serve binds.
func (d *DNS) Addr() string {
	if conn := d.conn.Load(); conn != nil {
		return conn.LocalAddr().String()
	}
	return ""
}

// handle answers one datagram.
func (d *DNS) handle(ctx context.Context, conn *net.UDPConn, client *net.UDPAddr, request []byte) {
	response := d.respond(ctx, request, udpTransport)
	if len(response) == 0 {
		return
	}
	if _, err := conn.WriteToUDP(response, client); err != nil && ctx.Err() == nil {
		d.log.Warn("dns write failed", "client", client.String(), "error", err)
	}
}

// respond produces the reply bytes for a request.
//
// tp is how the query arrived, and it decides two things a datagram server
// never had to decide: how large an answer may be, and whether a forward is
// made over TCP. Both matter for the same reason - a client told to retry over
// TCP has to get more the second time, or the retry is a slower way to fail.
func (d *DNS) respond(ctx context.Context, request []byte, tp transport) []byte {
	q, err := parseQuery(request)
	if err != nil {
		return errorResponse(request, rcodeFormErr)
	}
	if q.opcode() != 0 {
		return errorResponse(request, rcodeNotImpl)
	}
	if q.Class != classIN && q.Class != typeANY {
		return newResponse(request, q, rcodeNotImpl, false).finish()
	}

	if isInternalName(q.Name) {
		return d.answerInternal(request, q, tp)
	}
	return d.forward(ctx, request, q, tp)
}

// isInternalName reports whether a name falls inside the zone this server owns.
func isInternalName(name string) bool {
	return name == InternalZone || strings.HasSuffix(name, "."+InternalZone)
}

// answerInternal serves a name from the zone snapshot, with no I/O.
func (d *DNS) answerInternal(request []byte, q query, tp transport) []byte {
	addrs := d.zone.Load().records[q.Name]

	if len(addrs) == 0 {
		// Authoritative: the name is in our zone and we do not have it.
		return newResponse(request, q, rcodeNXDomain, true).finish()
	}

	// The name exists; the answer set is filtered per query type (v1.41):
	// A sees the v4 addresses, AAAA the v6 ones, ANY both. For a type we do
	// not hold (AAAA on a v4-only node being the one that matters) the
	// answer stays NODATA: NOERROR with no records. NXDOMAIN here would be a
	// lie about the name itself, and a dual-stack client that believes it may
	// never try the A query at all.
	matches := func(addr netip.Addr) bool {
		switch q.Type {
		case typeA:
			return addr.Is4()
		case typeAAAA:
			return addr.Is6() && !addr.Is4In6()
		case typeANY:
			return true
		default:
			return false
		}
	}

	b := newResponse(request, q, rcodeNoError, true).limitTo(tp.maxPayload)
	answered := false
	for _, addr := range addrs {
		if !matches(addr) {
			continue
		}
		var err error
		if addr.Is4() {
			err = b.addA(q.Name, addr, uint32(d.ttl.Seconds()))
		} else {
			err = b.addAAAA(q.Name, addr, uint32(d.ttl.Seconds()))
		}
		if err != nil {
			return newResponse(request, q, rcodeServFail, true).finish()
		}
		answered = true
	}
	if !answered {
		// NODATA, the deliberate answer since v1: now per type instead of
		// blanket for everything that is not A.
		return newResponse(request, q, rcodeNoError, true).finish()
	}
	return b.finish()
}

// forward relays a query for a name outside the internal zone.
//
// The request is passed through and the reply returned as opaque bytes: this
// server has no reason to understand an external answer, and not parsing it
// means a hostile or broken upstream cannot reach the parser at all.
func (d *DNS) forward(ctx context.Context, request []byte, q query, tp transport) []byte {
	if len(d.upstreams) == 0 {
		return newResponse(request, q, rcodeRefused, false).finish()
	}
	if !q.recursionDesired() {
		// We are not authoritative for this name and were asked not to recurse.
		return newResponse(request, q, rcodeRefused, false).finish()
	}

	// The caller (the read loop) already holds a forward slot (K-26): it is
	// taken before the goroutine is born, so a flood drops on full rather than
	// spawning without bound.

	for _, upstream := range d.upstreams {
		reply, err := d.queryUpstream(ctx, upstream, request, tp)
		if errors.Is(err, errUpstreamTruncated) {
			// The reply did not fit the read buffer: header+question with TC,
			// so the resolver retries over TCP (K-28).
			return newResponse(request, q, 0, false).truncatedAnswers()
		}
		if err == nil {
			return reply
		}
	}
	return newResponse(request, q, rcodeServFail, false).finish()
}

// queryUpstream sends one query and waits for a reply, bounded by the timeout.
//
// tp decides the wire: a query that arrived over TCP is forwarded over TCP, or
// the answer is read into the same 4 KiB datagram buffer and the client's
// retry gains nothing over the attempt that provoked it.
func (d *DNS) queryUpstream(ctx context.Context, upstream string, request []byte, tp transport) ([]byte, error) {
	if tp.stream {
		return d.queryUpstreamTCP(ctx, upstream, request)
	}
	ctx, cancel := context.WithTimeout(ctx, d.forwardTimeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", upstream)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			d.log.Debug("closing upstream socket", "upstream", upstream, "error", err)
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	buf := make([]byte, maxForwardPayload)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n == len(buf) {
		// A reply that fills the buffer may be clipped mid-record (K-28):
		// relaying it with ANCOUNT intact hands the client a parse error.
		// Signal truncation; forward() answers header+question with TC so the
		// resolver retries over TCP.
		return nil, errUpstreamTruncated
	}
	if n < dnsHeaderLen {
		return nil, fmt.Errorf("dns: upstream %s returned %d bytes", upstream, n)
	}
	// Match the transaction id, so a spoofed or stale datagram is not passed
	// back to the client as an answer.
	if string(buf[0:2]) != string(request[0:2]) {
		return nil, fmt.Errorf("dns: upstream %s replied to a different query", upstream)
	}
	return buf[:n], nil
}

// queryUpstreamTCP is queryUpstream's stream half (v1.86): the same one query,
// one reply exchange, framed with RFC 1035's two-byte length.
//
// It has no truncation branch, and that is the point of it: the frame states
// the reply's size, so the reply is read whole or the read fails. Nothing here
// can produce errUpstreamTruncated, which is why a client that retried over
// TCP after a UDP TC finally gets a different answer.
func (d *DNS) queryUpstreamTCP(ctx context.Context, upstream string, request []byte) ([]byte, error) {
	if len(request) > maxTCPPayload {
		return nil, fmt.Errorf("dns: request of %d bytes exceeds the TCP frame", len(request))
	}
	ctx, cancel := context.WithTimeout(ctx, d.forwardTimeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", upstream)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			d.log.Debug("closing upstream socket", "upstream", upstream, "error", err)
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}

	framed := make([]byte, 0, 2+len(request))
	framed = binary.BigEndian.AppendUint16(framed, uint16(len(request))) // #nosec G115: bounded above
	framed = append(framed, request...)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size < dnsHeaderLen {
		return nil, fmt.Errorf("dns: upstream %s returned %d bytes", upstream, size)
	}
	reply := make([]byte, size)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	// Match the transaction id, as the datagram path does: an upstream that
	// answers a different query is not answering this one, whatever carried it.
	if string(reply[0:2]) != string(request[0:2]) {
		return nil, fmt.Errorf("dns: upstream %s replied to a different query", upstream)
	}
	return reply, nil
}
