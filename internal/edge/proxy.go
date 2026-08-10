package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/m18h/kanea/internal/ratelimit"
)

// Proxy is the request path: Host match → upstream.
//
// The route table is held behind an atomic pointer because it is replaced
// wholesale on every reload while requests are in flight (see Table).
type Proxy struct {
	table atomic.Pointer[Table]
	// auth is the compiled R27 verifier table, swapped whole when the
	// restricted bundle reloads — the route table's discipline, applied to
	// the material that arrives on the other file.
	auth atomic.Pointer[authTable]
	rp   *httputil.ReverseProxy
	log  *slog.Logger

	// limits outlives the table on purpose. Buckets keyed by route name survive
	// a reload, so deploying a service does not hand every client that was
	// being throttled a fresh allowance — which would make the rate limit
	// trivially evadable by anyone who can trigger a redeploy.
	limits *ratelimit.Limiter
	// metrics is the L7 signal §9.1 makes primary for exposed services.
	metrics *Metrics
	now     func() time.Time

	// bodyTimeout bounds how long a request body may take to arrive. Zero
	// disables it.
	bodyTimeout time.Duration
	// securityHeaders installs the §14 A05 response defaults.
	securityHeaders bool
}

// ProxyConfig configures the request path.
type ProxyConfig struct {
	Logger *slog.Logger
	// BodyTimeout bounds the read of a request body (see Proxy.bodyTimeout).
	BodyTimeout time.Duration
	// DialTimeout bounds connecting to an upstream.
	DialTimeout time.Duration
	// ResponseHeaderTimeout bounds how long an upstream may take to start
	// answering. It does not bound the body, so streaming is unaffected.
	ResponseHeaderTimeout time.Duration
	// FlushInterval bounds how long a streamed response sits in the copy
	// buffer. Negative flushes every write.
	FlushInterval time.Duration
	// MaxIdleConnsPerHost bounds the pooled connections held per upstream.
	MaxIdleConnsPerHost int
	// SecurityHeaders installs the §14 A05 response defaults on every proxied
	// response (server config `edge.default_security_headers`, §15.1).
	SecurityHeaders bool
	// LimiterCapacity bounds the rate-limit bucket set. Zero means the default.
	LimiterCapacity int
	// Now is injectable so rate-limit tests do not sleep.
	Now func() time.Time
}

// Proxy defaults. They are all bounds rather than tuning: an unbounded value
// here is a way for one slow upstream or one hostile client to consume the
// edge's connections until nothing else gets served.
const (
	DefaultBodyTimeout           = 5 * time.Minute
	DefaultDialTimeout           = 5 * time.Second
	DefaultResponseHeaderTimeout = 60 * time.Second
	DefaultFlushInterval         = 100 * time.Millisecond
	DefaultMaxIdleConnsPerHost   = 32
	// idleConnTimeout retires pooled upstream connections. Shorter than a
	// typical upstream's own idle timeout, so the edge closes first rather than
	// racing a server that has already gone away.
	idleConnTimeout = 60 * time.Second

	// h2cReadIdleTimeout and h2cPingTimeout are the h2c path's liveness (R28).
	// There is no response-header timeout on that path — x/net exposes one only
	// through the wrapped h1 transport — so a dead upstream is detected by the
	// HTTP/2 ping instead, and the PRD states the limit rather than hiding it.
	h2cReadIdleTimeout = 30 * time.Second
	h2cPingTimeout     = 15 * time.Second
)

// NewProxy builds the request path.
func NewProxy(cfg ProxyConfig) *Proxy {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.BodyTimeout == 0 {
		cfg.BodyTimeout = DefaultBodyTimeout
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.ResponseHeaderTimeout <= 0 {
		cfg.ResponseHeaderTimeout = DefaultResponseHeaderTimeout
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.MaxIdleConnsPerHost <= 0 {
		cfg.MaxIdleConnsPerHost = DefaultMaxIdleConnsPerHost
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	p := &Proxy{
		log:             cfg.Logger,
		limits:          ratelimit.New(cfg.LimiterCapacity, cfg.Now),
		metrics:         NewMetrics(),
		now:             now,
		bodyTimeout:     cfg.BodyTimeout,
		securityHeaders: cfg.SecurityHeaders,
	}
	p.table.Store(EmptyTable())

	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          cfg.MaxIdleConnsPerHost * 8,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:       idleConnTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
		// A proxy passes bodies through. With compression enabled the transport
		// would add its own Accept-Encoding and transparently decompress, which
		// changes the bytes the client asked for and breaks Content-Length.
		DisableCompression: true,
	}

	// The h2c transport for grpc-marked routes (R28): plaintext HTTP/2 to the
	// VIP. AllowHTTP with a TLS dialer that returns a plain connection is
	// x/net's documented h2c spelling — no TLS is negotiated, and the "http"
	// scheme the rewrite sets is accepted.
	h2c := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		DisableCompression: true,
		IdleConnTimeout:    idleConnTimeout,
		ReadIdleTimeout:    h2cReadIdleTimeout,
		PingTimeout:        h2cPingTimeout,
	}

	p.rp = &httputil.ReverseProxy{
		Rewrite: p.rewrite,
		// One shared transport per upstream protocol, selected per request:
		// Rewrite cannot switch transports, and rebuilding one per route would
		// throw its pool away on every deploy (the routeKey discipline).
		Transport:      &transportSwitch{h1: transport, h2c: h2c},
		FlushInterval:  cfg.FlushInterval,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.upstreamError,
		// ReverseProxy logs to this on its own errors; without it they go to
		// the standard logger, which is depguard-banned and unstructured.
		ErrorLog: slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelDebug),
	}
	return p
}

// Metrics is the per-service L7 collector kanead scrapes over the status
// listener (§9.1).
func (p *Proxy) Metrics() *Metrics { return p.metrics }

// SetTable swaps in a new route table. Requests already in flight finish
// against the table they started with.
//
// Counters for services that left the table are dropped with it: the route
// table is the only bound on how many services this collector tracks, and a
// project deleted a hundred times over a year should not still be in it.
func (p *Proxy) SetTable(t *Table) {
	p.table.Store(t)

	keep := make(map[string]bool, t.Len())
	for _, service := range t.Services() {
		keep[service] = true
	}
	p.metrics.Retain(keep)
}

// Table returns the table currently serving.
func (p *Proxy) Table() *Table { return p.table.Load() }

// transportSwitch picks the upstream transport by the matched route (R28).
//
// The outbound request is cloned from the inbound context, so the route
// ServeHTTP stored there is visible here — which is what lets one
// ReverseProxy carry two transports without a second pool per route.
type transportSwitch struct {
	h1, h2c http.RoundTripper
}

func (t *transportSwitch) RoundTrip(r *http.Request) (*http.Response, error) {
	if route, ok := routeFrom(r.Context()); ok && route.Protocol == RouteProtocolGRPC {
		return t.h2c.RoundTrip(r)
	}
	return t.h1.RoundTrip(r)
}

// isGRPCRequest reports whether the request is gRPC on the wire: negotiated
// HTTP/2 and the gRPC content type. Both are connection facts — the protocol
// version comes from ALPN, not the request line — and together they bound the
// places a grpc-specific response or label can appear (§9.1.1).
func isGRPCRequest(r *http.Request) bool {
	return r.ProtoMajor == 2 &&
		strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
}

// routeKey carries the matched route from ServeHTTP to the rewrite hook. A
// context value rather than a per-route ReverseProxy: one proxy holds one
// connection pool, and rebuilding it on every route change would throw the pool
// away every time a service is deployed.
type routeKey struct{}

func routeFrom(ctx context.Context) (compiled, bool) {
	r, ok := ctx.Value(routeKey{}).(compiled)
	return r, ok
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// A reverse proxy is not a forward proxy. CONNECT and absolute-form
	// requests aimed at some other origin would turn the edge into an open
	// relay for whoever can reach port 80.
	if r.Method == http.MethodConnect {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	host := NormalizeHost(r.Host)
	if host == "" {
		http.Error(w, "missing Host header", http.StatusBadRequest)
		return
	}

	// The chain, in the order PRD §7.2.1 specifies: Host match → IP restriction
	// → rate limit → header transforms → upstream. The order is not arbitrary —
	// rate limiting a request that IP restriction would have refused wastes a
	// token on a client that is not allowed to spend one.
	route, ok := p.table.Load().lookup(host)
	if !ok {
		// Unknown Host is a 404 and not a redirect or a default backend. It is
		// also the DNS-rebinding defense for anything else on this address: an
		// attacker who points a name they control at this node reaches nothing
		// (PRD §5.2.6).
		p.log.Debug("no route for host", "host", host, "remote", clientIP(r))
		http.NotFound(w, r)
		return
	}
	// Host-routed traffic scopes its rate-limit buckets under the empty string,
	// which is what keeps every existing key byte-identical.
	p.serveRoute(w, r, route, "", entrypointFor(r))
}

// entrypointFor names the listener a host-routed request arrived on (§9.1.1).
//
// Derived from the connection rather than plumbed through: :80 and :443 share
// one Proxy and one ServeHTTP, and whether the request was terminated with TLS
// is exactly the distinction between the two entrypoints. A published port does
// not come through here — its entrypoint is fixed at bind time.
func entrypointFor(r *http.Request) string {
	if r.TLS != nil {
		return EntrypointWebSecure
	}
	return EntrypointWeb
}

// serveRoute is the chain from IP restriction onward, in the order PRD §7.2.1
// specifies. It is separate from ServeHTTP because a published HTTP listener
// has already decided which service it serves: a published port is reached by
// address, so the Host header on it is an IP literal that would match no
// domain, and the route is therefore fixed at bind time rather than looked up.
//
// What a published listener loses by not going through the lookup is the
// unknown-Host 404, which was a DNS-rebinding defence. On a port that maps to
// exactly one service, a rebinding attacker reaches the service they could have
// reached by connecting to the address directly.
//
// scope namespaces the rate-limit buckets. Without it a client throttled on
// shop.example.com would get a fresh allowance by connecting to the same
// service on :8096.
func (p *Proxy) serveRoute(w http.ResponseWriter, r *http.Request, route compiled, scope, entrypoint string) {
	addr := peerAddr(r)
	if !route.allowsAddress(addr) {
		p.log.Debug("address refused by ip_restriction",
			"service", route.Name(), "host", r.Host, "remote", addr.String())
		p.metrics.Refused(route.Name(), ReasonIPRestriction)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if !p.withinRateLimit(w, r, route, addr, scope) {
		p.metrics.Refused(route.Name(), ReasonRateLimit)
		return
	}

	// Auth after the rate limit (R27): a credential brute force meets 429
	// before it meets bcrypt.
	if route.AuthRequired && !p.authorize(w, r, route) {
		p.metrics.Refused(route.Name(), ReasonAuth)
		return
	}

	p.applyDeadline(w, r, route)

	// Body bytes are counted as they are read rather than taken from
	// Content-Length: a chunked request declares none, and a client that
	// declares one and sends less would be credited with bytes that never
	// arrived.
	body := &countingBody{ReadCloser: r.Body}
	if r.Body != nil {
		r.Body = body
	}

	p.metrics.RequestStarted(route.Name())
	defer p.metrics.RequestFinished(route.Name())

	// Timed around the upstream call only. What §9.1 wants is how long the
	// service takes, and folding the middleware's own microseconds into that
	// would make the edge's own cost look like the service's latency.
	started := p.now()
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	p.rp.ServeHTTP(recorder, r.WithContext(context.WithValue(r.Context(), routeKey{}, route)))

	p.metrics.Observe(Observation{
		Service:       route.Name(),
		Entrypoint:    entrypoint,
		Status:        recorder.status,
		Method:        r.Method,
		Protocol:      protocolOf(r, recorder.hijacked, route),
		Duration:      p.now().Sub(started),
		Hijacked:      recorder.hijacked,
		RequestBytes:  body.n.Load(),
		ResponseBytes: recorder.bytes.Load(),
		TLSVersion:    tlsVersionOf(r),
		TLSCipher:     tlsCipherOf(r),
	})
}

// SetAuth swaps the compiled verifier table in. Called by the bundle watcher
// alongside the keyring swap; nil-safe (a bundle with no auth clears it).
func (p *Proxy) SetAuth(entries []AuthEntry) {
	p.auth.Store(newAuthTable(entries))
}

// authorize enforces a marked route. It writes the refusal itself so the
// response and the reason stay in one place; the caller counts the metric.
//
// Fail closed, both ways: a marked route with no material — the bundle has
// not arrived, the entry failed to compile, the reference stopped resolving —
// answers 503, never open. That is the same rule a missing certificate gets,
// and it is the difference between "misconfigured, fix me" and a spec that
// claims a control nothing applies (R16).
func (p *Proxy) authorize(w http.ResponseWriter, r *http.Request, route compiled) bool {
	table := p.auth.Load()
	var entry *compiledAuth
	if table != nil {
		entry = table.entries[route.Name()]
	}
	if entry == nil || entry.invalid != "" {
		if entry != nil {
			p.log.Warn("auth-marked route has invalid verifier material",
				"service", route.Name(), "reason", entry.invalid)
		} else {
			p.log.Debug("auth-marked route has no verifier material yet", "service", route.Name())
		}
		http.Error(w, "authentication is configured but unavailable", http.StatusServiceUnavailable)
		return false
	}
	if !entry.verify(r, p.now()) {
		w.Header().Set("WWW-Authenticate", entry.challenge())
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// protocolOf derives the `protocol` label (§9.1.1).
//
// Derived, never read from r.Proto: the request line is the client's to write,
// and a label taken from it is a label the client chooses. A hijacked
// connection is a successful upgrade — the only way the edge learns that a
// request became a websocket, since a hijacked response never calls
// WriteHeader and would otherwise be recorded as a plain 200.
//
// grpc requires the route's R28 marker AND the wire to agree: the marker is
// operator-chosen and the version/content-type are connection facts, so the
// set stays closed. A browser's h2 GET to a grpc route stays https.
func protocolOf(r *http.Request, hijacked bool, route compiled) string {
	switch {
	case hijacked:
		return ProtocolWebsocket
	case route.Protocol == RouteProtocolGRPC && isGRPCRequest(r):
		return ProtocolGRPC
	case r.TLS != nil:
		return ProtocolHTTPS
	default:
		return ProtocolHTTP
	}
}

func tlsVersionOf(r *http.Request) string {
	if r.TLS == nil {
		return ""
	}
	return tls.VersionName(r.TLS.Version)
}

func tlsCipherOf(r *http.Request) string {
	if r.TLS == nil {
		return ""
	}
	return tls.CipherSuiteName(r.TLS.CipherSuite)
}

// countingBody counts the request body bytes that actually arrive.
//
// It does not own the body: ReverseProxy closes what it is given, and this
// forwards that through. Closing here as well would close the caller's body
// twice, which net/http tolerates and which would still be wrong.
type countingBody struct {
	io.ReadCloser
	n atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.n.Add(int64(n))
	}
	return n, err
}

// statusRecorder remembers the status for the metrics observation.
//
// It forwards Flush and Hijack rather than swallowing them: a server-sent
// events stream and a websocket upgrade both pass through this proxy, and a
// wrapper that dropped either would break them in a way no metric would show.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
	// bytes counts the response body written. Atomic because a streaming
	// handler may write from a goroutine other than the one that observes.
	bytes atomic.Int64
	// hijacked records that the connection was taken over — a websocket
	// upgrade, which never reaches WriteHeader and would otherwise be counted
	// as an ordinary 200.
	hijacked bool
}

func (w *statusRecorder) WriteHeader(status int) {
	if !w.written {
		w.status, w.written = status, true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	w.written = true
	n, err := w.ResponseWriter.Write(b)
	if n > 0 {
		w.bytes.Add(int64(n))
	}
	return n, err
}

func (w *statusRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("edge: %T cannot be hijacked", w.ResponseWriter)
	}
	conn, rw, err := h.Hijack()
	if err == nil {
		// Only a successful hijack is an upgrade. Marking a failed one would
		// label an error response as a websocket.
		w.hijacked = true
		w.status = http.StatusSwitchingProtocols
	}
	return conn, rw, err
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// withinRateLimit spends a token, answering 429 if there is none. It reports
// whether the request may continue.
func (p *Proxy) withinRateLimit(w http.ResponseWriter, r *http.Request, route compiled,
	addr netip.Addr, scope string,
) bool {
	if route.limit == nil {
		return true
	}
	key := route.rateKey(r, addr)
	if key == "" {
		// Nothing to key the bucket by. Limiting every such request through one
		// shared bucket would let one client throttle everyone, so they pass.
		return true
	}

	// The scope is inserted only when there is one, so every host-routed
	// bucket key stays byte-identical to what it was before published ports
	// existed — a rename here would reset every live limiter on upgrade.
	bucket := route.Name() + "\x00" + key
	if scope != "" {
		bucket = route.Name() + "\x00" + scope + "\x00" + key
	}
	ok, retry := p.limits.Allow(bucket, *route.limit)
	if ok {
		return true
	}

	// Retry-After is required for a 429 to be actionable: without it a client
	// can only guess, and guessing means retrying immediately.
	seconds := int(math.Ceil(retry.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	p.log.Debug("rate limited",
		"service", route.Name(), "host", r.Host, "remote", addr.String(), "retry_after", seconds)
	http.Error(w, "too many requests", http.StatusTooManyRequests)
	return false
}

// peerAddr is the connection's source address, or the zero Addr if it cannot be
// read. It is never taken from a header: the point of the edge owning
// X-Forwarded-For is that the header is a claim, not evidence.
func peerAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	// A v4-mapped v6 address must compare against v4 prefixes, or a rule
	// written as 10.0.0.0/8 silently matches nothing on a dual-stack listener.
	return addr.Unmap()
}

// applyDeadline bounds the read of a request body.
//
// This is per-request rather than a server-wide ReadTimeout, which is what the
// hardening list literally asks for but cannot be used here. A blanket
// ReadTimeout also fires on the background read Go's server issues to detect a
// disconnected client, and that error cancels the request context — so a
// server-side-events response or any long-lived stream dies at the timeout
// regardless of how healthy it is. Bounding only the body keeps the slow-body
// defense and leaves streaming alone.
//
// Upgraded connections are exempt for the same reason, with feeling: after the
// hijack the deadline stays on the raw connection, so a WebSocket would be
// killed mid-session.
//
// gRPC on a marked route is exempt too (v1.41): a client- or bidi-stream is a
// request body held open for as long as the call lives, and the slow-body
// bound would kill it mid-call at the timeout — isUpgrade's reasoning, applied
// to HTTP/2 streams.
func (p *Proxy) applyDeadline(w http.ResponseWriter, r *http.Request, route compiled) {
	rc := http.NewResponseController(w)

	grpcStream := route.Protocol == RouteProtocolGRPC && isGRPCRequest(r)
	deadline := time.Now().Add(p.bodyTimeout)
	if isUpgrade(r) || grpcStream || r.ContentLength == 0 || p.bodyTimeout <= 0 {
		// The zero time clears it: whatever deadline the header read left
		// behind must not leak into a long-lived connection.
		deadline = time.Time{}
	}
	if err := rc.SetReadDeadline(deadline); err != nil {
		// Not fatal — some ResponseWriters do not support it — but worth
		// knowing, because it means the slow-body bound is not in force.
		p.log.Debug("cannot set read deadline", "error", err)
	}
}

// rewrite builds the outbound request.
func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	route, ok := routeFrom(pr.In.Context())
	if !ok {
		// Unreachable: ServeHTTP is the only caller and always sets it. Leaving
		// the outbound URL untouched would send the request somewhere
		// unintended, so fail loudly instead.
		panic("edge: proxy rewrite without a route in context")
	}

	// Everything the client claimed about who it is goes first. These headers
	// are the identity that IP restriction, rate limiting and every access log
	// downstream are keyed on; a client that can set them can be anyone.
	for _, h := range forwardedHeaders {
		pr.Out.Header.Del(h)
	}

	// Then the edge's own statement, from the connection rather than from
	// anything the client sent. SetXForwarded overwrites X-Forwarded-For with
	// the peer address and sets X-Forwarded-Host and X-Forwarded-Proto — the
	// last from whether *this* request arrived over TLS, which is why one proxy
	// can serve both listeners.
	pr.SetXForwarded()
	if _, port, err := net.SplitHostPort(pr.In.Host); err == nil && port != "" {
		pr.Out.Header.Set("X-Forwarded-Port", port)
	} else {
		pr.Out.Header.Set("X-Forwarded-Port", strconv.Itoa(schemePort(pr.In)))
	}

	// The spec's own transforms come last, after everything the edge owns is
	// settled, so a service can add or drop whatever it likes without being
	// able to reach the headers above.
	route.applyRequestHeaders(pr.Out.Header)

	pr.SetURL(&url.URL{Scheme: "http", Host: route.Address()})
	// SetURL rewrites the outbound Host to the upstream address. Put the
	// client's back: a service behind the frontend may serve several names, and
	// an application that builds absolute URLs from Host would otherwise emit
	// links to a private address.
	pr.Out.Host = pr.In.Host
}

// modifyResponse applies the response half of the header middleware.
func (p *Proxy) modifyResponse(resp *http.Response) error {
	route, ok := routeFrom(resp.Request.Context())
	if !ok {
		return nil
	}
	// Defaults first so a service's own headers override them: the operator
	// sets a floor, the service decides what it actually needs.
	p.applySecurityHeaders(resp.Header, resp.Request.TLS != nil)
	route.applyResponseHeaders(resp.Header)
	return nil
}

// applySecurityHeaders adds the §14 A05 defaults the operator asked for,
// without overwriting anything the upstream already set deliberately.
func (p *Proxy) applySecurityHeaders(h http.Header, overTLS bool) {
	if !p.securityHeaders {
		return
	}
	for name, value := range securityHeaderDefaults {
		if h.Get(name) == "" {
			h.Set(name, value)
		}
	}
	// HSTS only over TLS. Sending it on a plaintext response is meaningless —
	// a client that can be intercepted can have it stripped — and promising it
	// before certificates exist would lock users out of an HTTP-only node.
	if overTLS && h.Get("Strict-Transport-Security") == "" {
		h.Set("Strict-Transport-Security", defaultHSTS)
	}
}

// securityHeaderDefaults are the headers `edge.default_security_headers`
// installs (PRD §15.1, §14 A05). Deliberately short: each one is safe for an
// arbitrary application to receive. Anything with a real chance of breaking a
// working service belongs in the service's own `headers` block.
var securityHeaderDefaults = map[string]string{
	"X-Content-Type-Options": "nosniff",
	"X-Frame-Options":        "DENY",
	"Referrer-Policy":        "strict-origin-when-cross-origin",
}

// defaultHSTS is two years, without preload: preload is a one-way door for the
// whole domain and is not a default anyone should get by accident.
const defaultHSTS = "max-age=63072000; includeSubDomains"

// schemePort is the port a client would have used for this request's scheme.
func schemePort(r *http.Request) int {
	if r.TLS != nil {
		return 443
	}
	return 80
}

// forwardedHeaders are the client-identity headers the edge owns. Anything a
// client sends under these names is discarded before the edge sets its own.
var forwardedHeaders = []string{
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Port",
	"X-Forwarded-Proto",
	"X-Forwarded-Server",
	"X-Forwarded-Ssl",
	"X-Original-Forwarded-For",
	"X-Real-Ip",
}

// upstreamError answers when the upstream cannot be reached.
//
// A 502 with no detail: the client learns the request failed, and learns
// nothing about the internal address, the service name, or why. The operator
// gets all of it in the log.
func (p *Proxy) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	route, _ := routeFrom(r.Context())

	// A client that hung up is not an error worth reporting as one; it is the
	// single most common way a proxied request ends.
	if errors.Is(err, context.Canceled) {
		p.log.Debug("client disconnected", "service", route.Name(), "host", r.Host)
		return
	}
	p.log.Warn("upstream request failed",
		"service", route.Name(), "upstream", route.Address(),
		"host", r.Host, "method", r.Method, "error", err)

	// A request that is gRPC on the wire gets the trailers-only refusal:
	// HTTP 200 with grpc-status UNAVAILABLE in the header frame, which is the
	// one shape a gRPC client renders as an error instead of as garbage. The
	// same no-detail discipline as the 502 — status 14 and a generic message,
	// nothing about the address or the reason.
	if route.Protocol == RouteProtocolGRPC && isGRPCRequest(r) {
		h := w.Header()
		h.Set("Content-Type", "application/grpc")
		h.Set("Grpc-Status", "14") // UNAVAILABLE
		h.Set("Grpc-Message", "upstream unavailable")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, "bad gateway", http.StatusBadGateway)
}

// isUpgrade reports whether the request asks to leave HTTP behind — a WebSocket
// handshake being the case that matters.
func isUpgrade(r *http.Request) bool {
	if !headerContainsToken(r.Header, "Connection", "upgrade") {
		return false
	}
	return r.Header.Get("Upgrade") != ""
}

// headerContainsToken reports whether a comma-separated header lists a token,
// case-insensitively.
func headerContainsToken(h http.Header, name, token string) bool {
	for _, value := range h.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// clientIP is the peer address, for logging. It is never read from a header:
// the whole point of the edge owning X-Forwarded-For is that the header is not
// evidence.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
