package edge

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Proxy is the request path: Host match → upstream.
//
// The route table is held behind an atomic pointer because it is replaced
// wholesale on every reload while requests are in flight (see Table).
type Proxy struct {
	table atomic.Pointer[Table]
	rp    *httputil.ReverseProxy
	log   *slog.Logger

	// bodyTimeout bounds how long a request body may take to arrive. Zero
	// disables it.
	bodyTimeout time.Duration
	// tlsTerminated reports whether the listener this proxy serves is HTTPS,
	// which is what X-Forwarded-Proto has to say.
	tlsTerminated bool
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
	// TLSTerminated marks this proxy as serving the HTTPS listener.
	TLSTerminated bool
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

	p := &Proxy{
		log:           cfg.Logger,
		bodyTimeout:   cfg.BodyTimeout,
		tlsTerminated: cfg.TLSTerminated,
	}
	p.table.Store(EmptyTable())

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
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

	p.rp = &httputil.ReverseProxy{
		Rewrite:       p.rewrite,
		Transport:     transport,
		FlushInterval: cfg.FlushInterval,
		ErrorHandler:  p.upstreamError,
		// ReverseProxy logs to this on its own errors; without it they go to
		// the standard logger, which is depguard-banned and unstructured.
		ErrorLog: slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelDebug),
	}
	return p
}

// SetTable swaps in a new route table. Requests already in flight finish
// against the table they started with.
func (p *Proxy) SetTable(t *Table) { p.table.Store(t) }

// Table returns the table currently serving.
func (p *Proxy) Table() *Table { return p.table.Load() }

// routeKey carries the matched route from ServeHTTP to the rewrite hook. A
// context value rather than a per-route ReverseProxy: one proxy holds one
// connection pool, and rebuilding it on every route change would throw the pool
// away every time a service is deployed.
type routeKey struct{}

func routeFrom(ctx context.Context) (Route, bool) {
	r, ok := ctx.Value(routeKey{}).(Route)
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

	route, ok := p.table.Load().Lookup(host)
	if !ok {
		// Unknown Host is a 404 and not a redirect or a default backend. It is
		// also the DNS-rebinding defense for anything else on this address: an
		// attacker who points a name they control at this node reaches nothing
		// (PRD §5.2.6).
		p.log.Debug("no route for host", "host", host, "remote", clientIP(r))
		http.NotFound(w, r)
		return
	}

	p.applyDeadline(w, r)
	p.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), routeKey{}, route)))
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
func (p *Proxy) applyDeadline(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)

	deadline := time.Now().Add(p.bodyTimeout)
	if isUpgrade(r) || r.ContentLength == 0 || p.bodyTimeout <= 0 {
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
	// the peer address and sets X-Forwarded-Host and X-Forwarded-Proto.
	pr.SetXForwarded()
	if p.tlsTerminated {
		pr.Out.Header.Set("X-Forwarded-Proto", "https")
	}
	if _, port, err := net.SplitHostPort(pr.In.Host); err == nil && port != "" {
		pr.Out.Header.Set("X-Forwarded-Port", port)
	} else {
		pr.Out.Header.Set("X-Forwarded-Port", strconv.Itoa(p.defaultPort()))
	}

	pr.SetURL(&url.URL{Scheme: "http", Host: route.Address()})
	// SetURL rewrites the outbound Host to the upstream address. Put the
	// client's back: a service behind the frontend may serve several names, and
	// an application that builds absolute URLs from Host would otherwise emit
	// links to a private address.
	pr.Out.Host = pr.In.Host
}

func (p *Proxy) defaultPort() int {
	if p.tlsTerminated {
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
