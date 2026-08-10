package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Listener and shutdown defaults.
const (
	// DefaultHTTPAddr is the public plaintext listener.
	DefaultHTTPAddr = ":80"
	// DefaultHTTPSAddr is the public TLS listener.
	DefaultHTTPSAddr = ":443"
	// DefaultStatusAddr is the operator-facing listener. Loopback, because it
	// answers questions ("which hosts do you serve?") that the internet has no
	// business asking.
	DefaultStatusAddr = "127.0.0.1:8601"

	// DefaultReadHeaderTimeout is the slowloris bound: a client that opens a
	// connection and dribbles headers holds it for this long and no longer.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultIdleTimeout retires kept-alive connections that go quiet.
	DefaultIdleTimeout = 120 * time.Second
	// DefaultMaxHeaderBytes is well above any real request and well below what
	// it takes to make header parsing expensive. Go's own default is 1 MiB.
	DefaultMaxHeaderBytes = 64 << 10
	// DefaultDrainTimeout bounds the graceful shutdown an upgrade relies on
	// (PRD §15.4): in-flight requests finish, new ones are refused.
	DefaultDrainTimeout = 15 * time.Second
)

// Config configures kanea-edge.
type Config struct {
	// HTTPAddr is the public plaintext listener.
	HTTPAddr string
	// HTTPSAddr is the public TLS listener. Empty disables TLS, which is what a
	// node with no certificates yet wants — it must still serve :80, or the
	// HTTP-01 validation that would produce one cannot complete.
	HTTPSAddr string
	// BundlePath is the certificate projection kanead publishes (see Bundle).
	// Empty disables both TLS and ACME challenge serving.
	BundlePath string
	// StatusAddr serves health and diagnostics. Empty disables it.
	StatusAddr string
	// SnapshotPath is the route table kanead publishes (see Snapshot).
	SnapshotPath string
	// PollInterval is how often the snapshot is re-read.
	PollInterval time.Duration

	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
	DrainTimeout      time.Duration
	// MaxPublishedConns bounds live connections across every published tcp
	// port (PRD §7.2.2). Zero means DefaultMaxPublishedConns.
	MaxPublishedConns int
	// PublishDrain is how long a published tcp listener's live connections get
	// to finish. Zero means DrainTimeout. Separate because a game session is
	// not an HTTP request: an operator may want 60 s here and 15 s on :443.
	PublishDrain time.Duration
	// FunctionsPort is the functions dispatch port (PRD §7.2.3):
	// /<project>/<function>/… for http-triggered functions on a node with no
	// base domain. Zero disables it; a snapshot carrying function routes then
	// warns once rather than serving them.
	FunctionsPort int

	Proxy   ProxyConfig
	Version string
	Logger  *slog.Logger
}

// Server is the kanea-edge process.
type Server struct {
	cfg       Config
	log       *slog.Logger
	proxy     *Proxy
	certs     *certStore
	watchers  []*Watcher
	published *listenerSet
	functions *functionsSet
	http      *http.Server
	https     *http.Server
	status    *http.Server
	listener  net.Listener
	httpsLn   net.Listener
	statusLn  net.Listener
}

// New builds the edge server. It does not bind: call Listen.
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = DefaultHTTPAddr
	}
	if cfg.SnapshotPath == "" {
		return nil, errors.New("edge: no snapshot path")
	}
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.MaxHeaderBytes <= 0 {
		cfg.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if cfg.DrainTimeout <= 0 {
		cfg.DrainTimeout = DefaultDrainTimeout
	}

	cfg.Proxy.Logger = cfg.Logger
	proxy := NewProxy(cfg.Proxy)

	s := &Server{cfg: cfg, log: cfg.Logger, proxy: proxy, certs: newCertStore()}
	s.published = newListenerSet(proxy, cfg)
	s.functions = newFunctionsSet(proxy, cfg)

	routes, err := NewWatcher(WatcherConfig{
		Name:     "routes",
		Path:     cfg.SnapshotPath,
		Interval: cfg.PollInterval,
		Logger:   cfg.Logger,
		Metrics:  proxy.Metrics(),
		Apply: func(body []byte) error {
			table, err := ParseTable(body)
			if err != nil {
				return err
			}
			proxy.SetTable(table)
			// Applied after the table, and never able to reject the file: a
			// port held by something else on the node must not freeze routing.
			s.published.Apply(table.Listeners())
			s.functions.Apply(table.Functions())
			cfg.Logger.Info("route table in force",
				"index", table.Index(), "hosts", table.Len(),
				"published_ports", len(table.Listeners()),
				"functions", len(table.Functions()))
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	s.watchers = append(s.watchers, routes)

	if cfg.BundlePath != "" {
		certs, err := NewWatcher(WatcherConfig{
			Name:     "certificates",
			Path:     cfg.BundlePath,
			Interval: cfg.PollInterval,
			Logger:   cfg.Logger,
			Metrics:  proxy.Metrics(),
			Apply: func(body []byte) error {
				bundle, err := ParseBundle(body)
				if err != nil {
					return err
				}
				ring, err := newKeyring(bundle)
				if err != nil {
					return err
				}
				s.certs.set(ring)
				// The R27 verifier material rides this bundle (v1.40): same
				// restricted file, same poll, one atomic swap beside the
				// keyring's.
				proxy.SetAuth(bundle.Auth)
				// Published from the bundle rather than from the keyring: the
				// keyring is indexed by domain and a wildcard covering forty
				// names would otherwise become forty identical expiry gauges
				// for one certificate.
				proxy.Metrics().SetCertificates(expiriesOf(bundle))
				cfg.Logger.Info("certificates in force",
					"index", bundle.Index, "certificates", ring.len(),
					"pending_challenges", len(ring.challenges))
				return nil
			},
		})
		if err != nil {
			return nil, err
		}
		s.watchers = append(s.watchers, certs)
	}

	s.http = &http.Server{
		Handler: s.plaintextHandler(),
		// The three bounds that are safe to apply to every connection. There is
		// deliberately no ReadTimeout and no WriteTimeout: both would kill
		// WebSockets and streamed responses, so the slow-body bound is applied
		// per request instead (see Proxy.applyDeadline).
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelDebug),
		ConnState:         connStateCounter(proxy.Metrics(), EntrypointWeb),
	}
	if cfg.HTTPSAddr != "" {
		s.https = &http.Server{
			Handler:           proxy,
			TLSConfig:         s.certs.tlsConfig(),
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			IdleTimeout:       cfg.IdleTimeout,
			MaxHeaderBytes:    cfg.MaxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelDebug),
			ConnState:         connStateCounter(proxy.Metrics(), EntrypointWebSecure),
		}
	}
	if cfg.StatusAddr != "" {
		s.status = &http.Server{
			Handler:           s.statusMux(),
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			IdleTimeout:       cfg.IdleTimeout,
			MaxHeaderBytes:    cfg.MaxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelDebug),
		}
	}
	return s, nil
}

// Listen binds the listeners.
//
// Separate from Run so a port collision — the overwhelmingly likely startup
// failure, since :80 is contended — fails immediately and visibly rather than
// inside a goroutine after the process has claimed to be up.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("edge: listen on %s: %w", s.cfg.HTTPAddr, err)
	}
	s.listener = ln

	if s.https != nil {
		httpsLn, err := net.Listen("tcp", s.cfg.HTTPSAddr)
		if err != nil {
			return errors.Join(
				fmt.Errorf("edge: listen on %s: %w", s.cfg.HTTPSAddr, err),
				ln.Close())
		}
		s.httpsLn = httpsLn
	}
	if s.status != nil {
		statusLn, err := net.Listen("tcp", s.cfg.StatusAddr)
		if err != nil {
			return errors.Join(
				fmt.Errorf("edge: listen on %s: %w", s.cfg.StatusAddr, err),
				ln.Close(), closeIf(s.httpsLn))
		}
		s.statusLn = statusLn
	}
	return nil
}

// Addr reports the public listener's address, which is useful when the
// configured one had port 0.
func (s *Server) Addr() string {
	if s.listener == nil {
		return s.cfg.HTTPAddr
	}
	return s.listener.Addr().String()
}

// Proxy exposes the request path, for tests and for wiring TLS later.
func (s *Server) Proxy() *Proxy { return s.proxy }

// Run serves until the context is cancelled, then drains.
func (s *Server) Run(ctx context.Context) error {
	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	s.log.Info("kanea-edge listening",
		"addr", s.Addr(), "tls", s.cfg.HTTPSAddr, "status", s.cfg.StatusAddr,
		"routes", s.cfg.SnapshotPath, "certs", s.cfg.BundlePath)

	errs := make(chan error, 3)
	go func() { errs <- serveHTTP(s.http, s.listener) }()
	if s.https != nil {
		// ServeTLS with empty file arguments: the certificates come from
		// GetCertificate, which is what lets a renewal land without rebuilding
		// the listener and dropping every connection on it.
		go func() { errs <- serveTLS(s.https, s.httpsLn) }()
	}
	if s.status != nil {
		go func() { errs <- serveHTTP(s.status, s.statusLn) }()
	}
	// The watchers run in this process, not the caller's: the projections are
	// useless without the server and vice versa.
	for _, w := range s.watchers {
		go func() {
			if err := w.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				s.log.Error("projection watcher stopped", "error", err)
			}
		}()
	}
	go s.sweepLimiters(ctx)

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	// Drain: in-flight requests finish, new connections are refused. This is
	// what makes `kanea upgrade` restarting the edge first a brief interruption
	// rather than a batch of failed requests (PRD §15.4).
	drainCtx, cancel := context.WithTimeout(context.Background(), s.cfg.DrainTimeout)
	defer cancel()

	// Published ports drain on their own clock. A relay connection has no
	// natural completion point, so there is nothing to wait for except a
	// deadline, and the right deadline for a game session is not the right one
	// for an HTTP request.
	publishDrain := s.cfg.PublishDrain
	if publishDrain <= 0 {
		publishDrain = s.cfg.DrainTimeout
	}
	s.published.Shutdown(publishDrain)
	s.functions.Shutdown()

	err := s.http.Shutdown(drainCtx)
	if s.https != nil {
		err = errors.Join(err, s.https.Shutdown(drainCtx))
	}
	if s.status != nil {
		err = errors.Join(err, s.status.Shutdown(drainCtx))
	}
	if errors.Is(err, context.DeadlineExceeded) {
		s.log.Warn("drain timed out; closing remaining connections",
			"timeout", s.cfg.DrainTimeout)
		err = errors.Join(err, s.http.Close())
	}
	s.log.Info("kanea-edge stopped")
	return err
}

// plaintextHandler is what the :80 listener serves.
//
// Three things in a fixed order, and the order is the whole subtlety:
//
//  1. ACME challenges, always, and never redirected. The validation that would
//     produce a certificate must work on a node that has none.
//  2. HTTP→HTTPS, but only for hosts the edge actually holds a certificate for.
//     Redirecting the rest turns "not issued yet" into "unreachable" — the
//     browser follows the redirect and gets a handshake failure — and takes
//     HTTP-01 down with it, so the situation never resolves itself.
//  3. Otherwise proxy the request in plaintext.
func (s *Server) plaintextHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token, ok := strings.CutPrefix(r.URL.Path, acmeChallengePrefix); ok {
			s.serveChallenge(w, r, token)
			return
		}
		if s.https != nil && s.certs.get().covers(r.Host) {
			s.redirectToHTTPS(w, r)
			return
		}
		s.proxy.ServeHTTP(w, r)
	})
}

// serveChallenge answers an ACME HTTP-01 validation from the published bundle.
func (s *Server) serveChallenge(w http.ResponseWriter, r *http.Request, token string) {
	keyAuth, ok := s.certs.get().challenge(token)
	if !ok {
		// Not an error worth alarming about: the internet scans this path, and
		// a stale validation retry after issuance finished lands here too.
		s.log.Debug("no such acme challenge", "token", token, "remote", clientIP(r))
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	if _, err := io.WriteString(w, keyAuth); err != nil {
		s.log.Debug("cannot write challenge response", "token", token, "error", err)
	}
}

// redirectToHTTPS sends a client to the TLS listener.
//
// 308 rather than 301: a permanent redirect that preserves the method and body,
// so a POST is not silently turned into a GET. The target is built from the
// validated Host and the request URI, never from anything else the client sent.
func (s *Server) redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host := NormalizeHost(r.Host)
	if port := s.httpsPort(); port != "443" {
		// A non-standard TLS port has to survive the redirect, or a development
		// or behind-a-load-balancer setup sends everyone to a closed port.
		host = net.JoinHostPort(host, port)
	}
	target := url.URL{Scheme: "https", Host: host, Opaque: r.URL.Opaque,
		Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
}

// httpsPort reports the port the TLS listener is actually on.
func (s *Server) httpsPort() string {
	addr := s.cfg.HTTPSAddr
	if s.httpsLn != nil {
		addr = s.httpsLn.Addr().String()
	}
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return port
	}
	return "443"
}

// sweepLimiters drops rate-limit buckets that have refilled.
//
// The bucket set is capped, so this is not what prevents exhaustion — eviction
// is. It is what keeps a node that saw a traffic spike from holding the
// high-water mark of buckets for the rest of its life.
func (s *Server) sweepLimiters(ctx context.Context) {
	ticker := time.NewTicker(limiterSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if dropped := s.proxy.limits.Sweep(); dropped > 0 {
				s.log.Debug("swept idle rate limit buckets",
					"dropped", dropped, "remaining", s.proxy.limits.Len())
			}
		}
	}
}

// limiterSweepInterval is deliberately unhurried: the cap is the safety
// property, and sweeping is only housekeeping.
const limiterSweepInterval = time.Minute

func serveHTTP(srv *http.Server, ln net.Listener) error {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func serveTLS(srv *http.Server, ln net.Listener) error {
	if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// closeIf closes a listener that may not have been created.
func closeIf(ln net.Listener) error {
	if ln == nil {
		return nil
	}
	return ln.Close()
}

// statusMux is the loopback diagnostic surface.
func (s *Server) statusMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		table := s.proxy.Table()
		listeners := s.published.States()
		bound := 0
		for _, l := range listeners {
			if l.Bound {
				bound++
			}
		}
		s.writeJSON(w, map[string]any{
			"status":          "ok",
			"version":         s.cfg.Version,
			"index":           table.Index(),
			"hosts":           table.Len(),
			"certificates":    s.certs.get().len(),
			"published_ports": len(listeners),
			"published_bound": bound,
			"published_conns": s.published.InFlight(),
		})
	})
	// The bind state of every published port, and how many connections each is
	// holding. A port something else on the node already owns appears here with
	// its error rather than not appearing at all — "it is not in the list" and
	// "it could not bind" need different fixes.
	mux.HandleFunc("GET /listeners", func(w http.ResponseWriter, _ *http.Request) {
		s.writeJSON(w, map[string]any{"listeners": s.published.States()})
	})
	// The L7 signal §9.1 makes primary for exposed services. It lives on the
	// loopback status listener, not on :80 or :443: request rates and latency
	// percentiles describe how a business is doing, and they are not something
	// the internet gets to read off a public port.
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if _, err := s.proxy.Metrics().WriteTo(w); err != nil {
			// The header is already out, so this cannot become a status code.
			s.log.Debug("write metrics", "error", err)
		}
	})
	// Expiry is the question an operator asks about certificates, and asking it
	// should not mean reading a file full of private keys.
	mux.HandleFunc("GET /certs", func(w http.ResponseWriter, _ *http.Request) {
		ring := s.certs.get()
		names := make([]string, 0, len(ring.expiry))
		for name := range ring.expiry {
			names = append(names, name)
		}
		sort.Strings(names)

		out := make([]map[string]any, 0, len(names))
		for _, name := range names {
			out = append(out, map[string]any{"domain": name, "not_after": ring.expiry[name]})
		}
		s.writeJSON(w, map[string]any{
			"index":              ring.index,
			"certificates":       out,
			"pending_challenges": len(ring.challenges),
		})
	})
	mux.HandleFunc("GET /routes", func(w http.ResponseWriter, _ *http.Request) {
		table := s.proxy.Table()
		hosts := table.Hosts()
		sort.Strings(hosts)

		out := make([]map[string]any, 0, len(hosts))
		for _, host := range hosts {
			route, ok := table.Lookup(host)
			if !ok {
				continue
			}
			out = append(out, map[string]any{
				"host": host, "service": route.Name(), "upstream": route.Address(),
			})
		}
		s.writeJSON(w, map[string]any{"index": table.Index(), "routes": out})
	})
	return mux
}

func (s *Server) writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(body); err != nil {
		// The response is already committed; there is nowhere to report this
		// but the log, and the caller will see a truncated body.
		s.log.Debug("write status response", "error", err)
	}
}
