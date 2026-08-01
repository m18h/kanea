package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"time"
)

// Listener and shutdown defaults.
const (
	// DefaultHTTPAddr is the public plaintext listener.
	DefaultHTTPAddr = ":80"
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
	// HTTPAddr is the public listener.
	HTTPAddr string
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

	Proxy   ProxyConfig
	Version string
	Logger  *slog.Logger
}

// Server is the kanea-edge process.
type Server struct {
	cfg      Config
	log      *slog.Logger
	proxy    *Proxy
	watcher  *Watcher
	http     *http.Server
	status   *http.Server
	listener net.Listener
	statusLn net.Listener
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

	watcher, err := NewWatcher(WatcherConfig{
		Path:     cfg.SnapshotPath,
		Interval: cfg.PollInterval,
		Logger:   cfg.Logger,
		Apply:    proxy.SetTable,
	})
	if err != nil {
		return nil, err
	}

	s := &Server{cfg: cfg, log: cfg.Logger, proxy: proxy, watcher: watcher}
	s.http = &http.Server{
		Handler: proxy,
		// The three bounds that are safe to apply to every connection. There is
		// deliberately no ReadTimeout and no WriteTimeout: both would kill
		// WebSockets and streamed responses, so the slow-body bound is applied
		// per request instead (see Proxy.applyDeadline).
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelDebug),
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

	if s.status != nil {
		statusLn, err := net.Listen("tcp", s.cfg.StatusAddr)
		if err != nil {
			return errors.Join(
				fmt.Errorf("edge: listen on %s: %w", s.cfg.StatusAddr, err),
				ln.Close())
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
		"addr", s.Addr(), "status", s.cfg.StatusAddr, "snapshot", s.cfg.SnapshotPath)

	errs := make(chan error, 2)
	go func() { errs <- serveHTTP(s.http, s.listener) }()
	if s.status != nil {
		go func() { errs <- serveHTTP(s.status, s.statusLn) }()
	}
	// The watcher runs in this process, not the caller's: the route table is
	// useless without the server and vice versa.
	go func() {
		if err := s.watcher.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Error("route watcher stopped", "error", err)
		}
	}()

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

	err := s.http.Shutdown(drainCtx)
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

func serveHTTP(srv *http.Server, ln net.Listener) error {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// statusMux is the loopback diagnostic surface.
func (s *Server) statusMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		table := s.proxy.Table()
		s.writeJSON(w, map[string]any{
			"status":  "ok",
			"version": s.cfg.Version,
			"index":   table.Index(),
			"hosts":   table.Len(),
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
