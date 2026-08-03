package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kanea-dev/kanea/internal/dashboard"
	"github.com/kanea-dev/kanea/internal/ratelimit"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/secrets"
	"github.com/kanea-dev/kanea/internal/store"
)

// Store is the slice of the state store the API needs.
type Store interface {
	Get(ctx context.Context, kind store.Kind, key string) (store.Record, error)
	List(ctx context.Context, kind store.Kind, opts store.ListOptions) (store.Page, error)
	Apply(ctx context.Context, muts ...store.Mutation) (uint64, error)
	Index(ctx context.Context) (uint64, error)
}

// ServerConfig configures the API server.
type ServerConfig struct {
	Store  Store
	Logger *slog.Logger
	// Socket is the unix socket path. Defaults to DefaultSocket.
	Socket string
	// Version is reported by the health endpoint.
	Version string
	// LogDir is where per-alloc log files live.
	LogDir string
	// Notify is signalled after a successful apply so the reconciler converges
	// immediately instead of waiting out its interval.
	Notify chan<- struct{}
	// WSOrigins is the Origin allowlist for the live-data socket (PRD §12.1,
	// §14 A01). Empty rejects every browser Upgrade, which is correct for a
	// daemon with no dashboard origin configured.
	WSOrigins []string
	// WSMaxConns caps concurrent websocket connections. Zero means the default.
	WSMaxConns int
	// ServeDashboard mounts the embedded SPA. Off by default: the API socket is
	// a control channel, and a daemon nobody browses should not be answering
	// HTML on it.
	ServeDashboard bool
	// Secrets backs the write-only secrets surface. Nil disables those routes.
	Secrets SecretStore
	// Auth resolves callers. Nil leaves the unix socket as the only credential
	// the daemon accepts — which is the §13.1 "no auth configured" case, and is
	// why a network listener without it is refused rather than warned about.
	Auth Authenticator
	// Audit is the trail every mutation is written to (§14, A09).
	Audit AuditLog
	// Accounts backs the user and token routes. Nil disables them.
	Accounts Accounts
	// Metrics backs the Prometheus exporter and the live stats topic. Nil
	// disables both.
	Metrics MetricsSource
	// Breaker reports the circuit breaker's state to the exporter.
	Breaker BreakerSource
	// OIDC is the identity provider, when one is configured (§13.2). Nil leaves
	// the provider routes answering 501 rather than 404: "this daemon has no
	// provider" and "this daemon has no such feature" are different answers.
	OIDC Provider
	// Sessions issues a session for an identity another mechanism vouched for.
	// Required with OIDC, which authenticates without a password to check.
	Sessions SessionIssuer
	// Listen is the network address for the API (§15.1, `bind.api_addr`).
	// Empty means the unix socket is the only way in, which is the default and
	// the only configuration that needs no further decisions.
	Listen string
	// TLSCert and TLSKey are the listener's certificate. Required for anything
	// beyond loopback: see listenNetwork.
	TLSCert string
	TLSKey  string
	// AuthConfigured reports whether any account exists. The daemon asks its
	// auth store at startup; the API only needs the answer, and the network
	// listener is refused when it is false (§13.1).
	AuthConfigured bool
	// InsecureCookies drops the Secure attribute from the session cookie. It
	// exists for a daemon reached over plain HTTP on a private network, and is
	// off by default because the safe value should never be the one someone has
	// to remember to ask for.
	InsecureCookies bool
	// PublicLimit and AuthLimit bound requests per source address (§14, A07).
	// Zero values take the defaults; an explicitly invalid spec disables that
	// tier, which is a decision an operator has to make deliberately.
	PublicLimit *ratelimit.Spec
	AuthLimit   *ratelimit.Spec
	// RateLimitBuckets caps how many sources are tracked. Zero means the
	// default; the cap is what keeps the limiter from being its own memory
	// exhaustion vector.
	RateLimitBuckets int
	// Now is injectable for tests of anything time-shaped here.
	Now func() time.Time
}

// SecretStore is the slice of the secrets store the API needs.
//
// Notably it has no Resolve: the API cannot read a secret because the interface
// it holds cannot express it (PRD §13.3, §16.3).
type SecretStore interface {
	Put(ctx context.Context, path string, value []byte) error
	List(ctx context.Context, prefix string) ([]secrets.Info, error)
	Delete(ctx context.Context, path string) error
}

// Server is the control-plane HTTP server.
type Server struct {
	store     Store
	log       *slog.Logger
	socket    string
	version   string
	logDir    string
	notify    chan<- struct{}
	listener  net.Listener
	http      *http.Server
	wsOrigins []string
	ws        *wsHub
	secrets   SecretStore

	auth            Authenticator
	audit           AuditLog
	accounts        Accounts
	metrics         MetricsSource
	breaker         BreakerSource
	oidc            Provider
	sessions        SessionIssuer
	insecureCookies bool

	listenAddr     string
	authConfigured bool
	tls            *tls.Config
	netListener    net.Listener

	limiter     *ratelimit.Limiter
	publicLimit ratelimit.Spec
	authLimit   ratelimit.Spec
}

// NewServer builds the server. It does not listen yet.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("api: store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Socket == "" {
		cfg.Socket = DefaultSocket
	}
	tlsConfig, err := loadTLS(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, err
	}

	publicLimit, authLimit := DefaultPublicLimit, DefaultAuthenticatedLimit
	if cfg.PublicLimit != nil {
		publicLimit = *cfg.PublicLimit
	}
	if cfg.AuthLimit != nil {
		authLimit = *cfg.AuthLimit
	}

	s := &Server{
		limiter:     ratelimit.New(cfg.RateLimitBuckets, cfg.Now),
		publicLimit: publicLimit, authLimit: authLimit,
		listenAddr: cfg.Listen, authConfigured: cfg.AuthConfigured, tls: tlsConfig,
		store: cfg.Store, log: cfg.Logger, socket: cfg.Socket,
		version: cfg.Version, logDir: cfg.LogDir, notify: cfg.Notify,
		wsOrigins: cfg.WSOrigins, ws: newWSHub(cfg.WSMaxConns),
		secrets: cfg.Secrets, auth: cfg.Auth, audit: cfg.Audit,
		accounts: cfg.Accounts, oidc: cfg.OIDC, sessions: cfg.Sessions,
		metrics: cfg.Metrics, breaker: cfg.Breaker,
		insecureCookies: cfg.InsecureCookies,
	}

	// Every route states what it requires next to where it is registered. The
	// two `public: true` entries are the whole exemption list (§5.2.1): health,
	// because a probe must work before anyone can log in, and login itself.
	mux := http.NewServeMux()
	mux.Handle("GET "+PathHealth, s.route(policy{action: "health", public: true}, s.handleHealth))
	mux.Handle("POST "+PathLogin, s.route(policy{action: "auth.login", public: true}, s.handleLogin))
	mux.Handle("POST "+PathLogout,
		s.route(policy{action: "auth.logout", mutates: true, selfService: true}, s.handleLogout))
	mux.Handle("GET "+PathSession, s.route(policy{action: "auth.session"}, s.handleSession))
	// The provider routes are public for the same reason login is: nobody has a
	// credential yet. They are rate limited on the strict public tier, and the
	// callback proves itself with the state, nonce and PKCE verifier this daemon
	// minted rather than with anything the caller supplies (§13.2).
	mux.Handle("GET "+PathOIDCStart,
		s.route(policy{action: "auth.oidc.start", public: true}, s.handleOIDCStart))
	mux.Handle("GET "+PathOIDCCallback,
		s.route(policy{action: "auth.oidc.callback", public: true}, s.handleOIDCCallback))
	mux.Handle("GET "+PathServices, s.route(policy{action: "service.list"}, s.handleListServices))
	mux.Handle("PUT "+PathServices, s.route(policy{action: "service.apply", mutates: true}, s.handleApply))
	mux.Handle("DELETE "+PathServices+"/{project}/{service}",
		s.route(policy{action: "service.delete", mutates: true}, s.handleDeleteService))
	mux.Handle("POST "+PathServices+"/{project}/{service}/scale",
		s.route(policy{action: "service.scale", mutates: true}, s.handleScale))
	mux.Handle("GET "+PathAllocs, s.route(policy{action: "alloc.list"}, s.handleListAllocs))
	mux.Handle("GET "+PathMetrics, s.route(policy{action: "metrics.read"}, s.handleMetrics))
	mux.Handle("GET "+PathLogs, s.route(policy{action: "logs.read"}, s.handleLogs))
	mux.Handle("GET "+PathWS, s.route(policy{action: "ws.connect"}, s.handleWS))
	// The audit log is admin-only to read: it names who did what, and that is
	// not something a viewer needs (§13.3).
	mux.Handle("GET "+PathAudit, s.route(policy{action: "audit.list", adminOnly: true}, s.handleAudit))
	// Accounts. Admin-only throughout: minting a token is minting a credential,
	// and listing users is a list of things worth attacking (§13.3).
	mux.Handle("GET "+PathUsers, s.route(policy{action: "user.list", adminOnly: true}, s.handleListUsers))
	mux.Handle("PUT "+PathUsers+"/{name}", s.route(policy{action: "user.put", mutates: true}, s.handlePutUser))
	mux.Handle("DELETE "+PathUsers+"/{name}",
		s.route(policy{action: "user.delete", mutates: true}, s.handleDeleteUser))
	mux.Handle("GET "+PathTokens, s.route(policy{action: "token.list", adminOnly: true}, s.handleListTokens))
	mux.Handle("POST "+PathTokens, s.route(policy{action: "token.create", mutates: true}, s.handleCreateToken))
	mux.Handle("DELETE "+PathTokens+"/{id}",
		s.route(policy{action: "token.revoke", mutates: true}, s.handleRevokeToken))
	// List and write, never read: there is no GET for an individual secret,
	// and its absence is the enforcement (PRD §13.3).
	mux.Handle("GET "+PathSecrets, s.route(policy{action: "secret.list", adminOnly: true}, s.handleListSecrets))
	mux.Handle("PUT "+PathSecrets+"/{path...}",
		s.route(policy{action: "secret.put", mutates: true}, s.handlePutSecret))
	mux.Handle("DELETE "+PathSecrets+"/{path...}",
		s.route(policy{action: "secret.delete", mutates: true}, s.handleDeleteSecret))
	// The SPA is registered last and on the bare prefix, so it catches
	// everything the API did not claim. A client-side route must reach the app,
	// and ServeMux's longest-pattern-wins rule keeps /v1/* ahead of it.
	if cfg.ServeDashboard {
		// An unmatched API path must not fall through to the SPA. Without this,
		// a mistyped or removed route answers 200 with HTML, and a client sees
		// "success" followed by a JSON decode error somewhere unrelated —
		// including for routes that deliberately do not exist, like reading a
		// secret. Longest-prefix wins, so this claims /v1/* ahead of "/".
		mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound,
				fmt.Errorf("api: no such route: %s %s", r.Method, r.URL.Path))
		})
		// Registered without a method so "/v1/" is unambiguously the more
		// specific pattern. With "GET /" the two conflict: neither matches a
		// strict superset of the other, and ServeMux panics rather than guess.
		// The handler answers non-GET itself.
		mux.Handle("/", dashboard.Handler("/"))
		if !dashboard.Built() {
			cfg.Logger.Warn("serving the dashboard placeholder",
				"detail", "this binary was built without the UI; run `make dashboard && make build`")
		}
	}

	s.http = &http.Server{
		Handler: secureHeaders(cfg.ServeDashboard, mux),
		// The listener decides what "local" means, not the request: a unix
		// connection is one the kernel proved came from a process that could
		// open a 0600 socket, and nothing in a request can forge that.
		ConnContext: withLocalConn,
		// Slowloris defence, even on a unix socket: a stuck CLI must not pin a
		// connection forever (PRD §5.2.6 applies the same rule at the edge).
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s, nil
}

// Handler is the routed, guarded handler this server serves.
//
// Exported because the socket is not the only way these routes are reached: the
// network listener (§15.1 `bind.api_addr`) and the MCP streamable-HTTP transport
// (§16.3) serve the same handler, and a route that is only protected on one
// listener is not protected. Anything mounting it must decide for itself what
// counts as a local connection — see withLocalConn.
func (s *Server) Handler() http.Handler { return s.http.Handler }

// Listen creates the listeners. Separate from Serve so the caller can report a
// bind failure before daemonising.
//
// A refused network listener is not a failed Listen: the socket still binds and
// the daemon still runs, because the socket is where the account that would
// unrefuse it gets created. The caller is told which listeners it actually got.
func (s *Server) Listen() error {
	if err := os.MkdirAll(filepath.Dir(s.socket), 0o750); err != nil {
		return fmt.Errorf("api: socket dir: %w", err)
	}
	// A stale socket from a crashed kanead would block binding. Removing it is
	// safe: if another kanead were live, the store's file lock would already
	// have refused us.
	if err := os.Remove(s.socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("api: remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", s.socket)
	if err != nil {
		return fmt.Errorf("api: listen on %s: %w", s.socket, err)
	}
	// 0600: reaching this socket is the local-root credential of §13.1.
	if err := os.Chmod(s.socket, 0o600); err != nil {
		return errors.Join(fmt.Errorf("api: chmod socket: %w", err), listener.Close())
	}
	s.listener = listener

	network, err := s.listenNetwork()
	switch {
	case errors.Is(err, ErrNoAuthConfigured), errors.Is(err, ErrInsecureListener):
		// The refusals of §13.1/§14 A05. Loud, with the remedy, and not fatal.
		s.log.Error("the network listener was refused; the API is reachable only over the unix socket",
			"listen", s.listenAddr, "error", err,
			"remedy", "create an account with `kanea user add`, then restart kanead")
	case err != nil:
		// A genuine bind failure — port in use, bad address, unreadable
		// certificate — is the operator's configuration not working, and
		// starting anyway would hide it.
		return errors.Join(err, listener.Close())
	default:
		s.netListener = network
	}
	return nil
}

// NetworkAddr reports the network listener's address, or "" when there is none
// — because it was not configured, or because §13.1 refused it.
//
// The resolved address, not the requested one: a caller that asked for port 0
// still needs to know where to point a browser.
func (s *Server) NetworkAddr() string {
	if s.netListener == nil {
		return ""
	}
	return s.netListener.Addr().String()
}

// Close releases the listeners without serving. Serve does this itself; this is
// for a caller that bound early and then failed to start for another reason.
func (s *Server) Close() error {
	var errs []error
	for _, listener := range []net.Listener{s.listener, s.netListener} {
		if listener == nil {
			continue
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(s.socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Serve blocks until the context is cancelled or the server fails.
func (s *Server) Serve(ctx context.Context) error {
	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	s.log.Info("api listening", "socket", s.socket)

	// One http.Server across both listeners: the routes, the middleware and the
	// shutdown are then the same by construction rather than by remembering to
	// keep two copies in step. Serve may be called on several listeners.
	listeners := []net.Listener{s.listener}
	if s.netListener != nil {
		s.log.Info("api listening on the network",
			"listen", s.netListener.Addr().String(), "tls", s.tls != nil)
		if s.tls == nil {
			s.log.Warn("the network listener has no TLS; credentials cross it in clear text",
				"detail", "loopback only — put kanea-edge in front, or pass a certificate")
		}
		listeners = append(listeners, s.netListener)
	}

	stopSweeper := make(chan struct{})
	defer close(stopSweeper)
	go s.sweepLimiter(stopSweeper)

	errs := make(chan error, len(listeners))
	for _, listener := range listeners {
		go func() {
			if err := s.http.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- err
				return
			}
			errs <- nil
		}()
	}

	// Removing the socket on the way out keeps the next start clean. A failure
	// is reported, not swallowed: a socket we cannot remove will confuse the
	// next kanead.
	cleanup := func(cause error) error {
		if err := os.Remove(s.socket); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.Join(cause, fmt.Errorf("api: remove socket: %w", err))
		}
		return cause
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return cleanup(s.http.Shutdown(shutdownCtx))
	case err := <-errs:
		return cleanup(err)
	}
}

// ---- handlers ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	index, err := s.store.Index(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	health := Health{
		Status: "ok", Version: s.version, StoreIndex: index,
		WSConnections: s.ws.count(),
	}
	// What sign-in methods exist is part of what a client needs before it can
	// authenticate, and health is the one route it can ask without a credential.
	// It names the issuer and nothing else: a provider URL is public by
	// definition — every browser sent there sees it.
	if s.oidc != nil {
		health.OIDC = &OIDCStatus{Enabled: true, Issuer: s.oidc.Issuer(), StartPath: PathOIDCStart}
	}
	writeJSON(w, http.StatusOK, health)
}

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	services, err := listAll[reconciler.Desired](r.Context(), s.store, store.KindService)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sort.Slice(services, func(i, j int) bool {
		if services[i].Project != services[j].Project {
			return services[i].Project < services[j].Project
		}
		return services[i].Service < services[j].Service
	})
	writeJSON(w, http.StatusOK, ServicesResponse{Services: services})
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var req ApplyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	if len(req.Services) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("no services in request"))
		return
	}

	muts := make([]store.Mutation, 0, len(req.Services))
	applied := make([]string, 0, len(req.Services))
	for _, svc := range req.Services {
		if svc.Project == "" || svc.Service == "" {
			writeError(w, http.StatusBadRequest, errors.New("every service needs a project and a name"))
			return
		}
		key := svc.Project + "/" + svc.Service
		mut, err := store.PutMutation(store.KindService, key, svc)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		muts = append(muts, mut)
		applied = append(applied, key)
	}

	// One batch: a multi-service apply lands atomically, so the reconciler never
	// sees half a deploy.
	index, err := s.store.Apply(r.Context(), muts...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.wake()
	auditTarget(r, strings.Join(applied, ","))
	s.log.Info("applied services", "services", applied, "index", index)
	writeJSON(w, http.StatusOK, ApplyResponse{Applied: applied, Index: index})
}

func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	service := r.PathValue("service")
	key := project + "/" + service
	// Named before the outcome is known: a delete that is refused should still
	// say what it was aimed at.
	auditTarget(r, key)

	if _, err := s.store.Get(r.Context(), store.KindService, key); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, fmt.Errorf("no such service %s", key))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	index, err := s.store.Apply(r.Context(), store.DeleteMutation(store.KindService, key))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.wake()
	s.log.Info("deleted service", "service", key, "index", index)
	writeJSON(w, http.StatusOK, ApplyResponse{Applied: []string{key}, Index: index})
}

// handleScale sets a service's replica count.
//
// One number, written to the same record everything else reads. A manual scale
// and an autoscaler decision are the same operation by construction, so there
// is no path by which they can disagree about what "the count" means.
func (s *Server) handleScale(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("project") + "/" + r.PathValue("service")
	auditTarget(r, key)

	var req ScaleRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	if req.Count < 0 {
		writeError(w, http.StatusBadRequest, errors.New("count must be zero or more"))
		return
	}

	desired, index, err := store.GetValue[reconciler.Desired](r.Context(), s.store, store.KindService, key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, fmt.Errorf("no such service %s", key))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// A count outside the declared bounds is refused rather than clamped: the
	// autoscaler would undo it within seconds, and silently doing something
	// other than what was asked is worse than saying no.
	if p := desired.Scaling; p != nil && p.Max > 0 && len(p.Metrics) > 0 {
		if req.Count < p.Min || req.Count > p.Max {
			writeError(w, http.StatusConflict, fmt.Errorf(
				"%s autoscales between %d and %d; the autoscaler would undo a count of %d",
				key, p.Min, p.Max, req.Count))
			return
		}
	}

	previous := desired.Count
	desired.Count = req.Count
	mut, err := store.UpdateMutation(store.KindService, key, desired, index)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	appliedIndex, err := s.store.Apply(r.Context(), mut)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Someone else changed the service between the read and the write.
			writeError(w, http.StatusConflict, fmt.Errorf("%s changed while scaling; try again", key))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.wake()
	s.log.Info("scaled service", "service", key, "from", previous, "to", req.Count)
	writeJSON(w, http.StatusOK, ApplyResponse{Applied: []string{key}, Index: appliedIndex})
}

func (s *Server) handleListAllocs(w http.ResponseWriter, r *http.Request) {
	allocs, err := listAll[reconciler.AllocRecord](r.Context(), s.store, store.KindAlloc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	project := r.URL.Query().Get("project")
	service := r.URL.Query().Get("service")
	filtered := allocs[:0]
	for _, a := range allocs {
		if project != "" && a.Project != project {
			continue
		}
		if service != "" && a.Service != service {
			continue
		}
		filtered = append(filtered, a)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Key() < filtered[j].Key() })
	writeJSON(w, http.StatusOK, AllocsResponse{Allocs: filtered})
}

// handleLogs streams alloc logs. Output is plain text, not JSON: it goes
// straight to a terminal, and a human tailing logs should not have to decode
// anything.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := LogOptions{
		Project: q.Get("project"),
		Service: q.Get("service"),
		AllocID: q.Get("alloc"),
		Follow:  q.Get("follow") == "true",
	}
	if n, err := strconv.Atoi(q.Get("tail")); err == nil {
		opts.Tail = n
	}

	allocs, err := s.selectAllocs(r.Context(), opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if len(allocs) == 0 {
		writeError(w, http.StatusNotFound, errors.New("no matching allocs"))
		return
	}
	// One alloc keeps the stream unprefixed; several need attribution.
	prefix := len(allocs) > 1

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	tails := make([]*tailer, 0, len(allocs))
	for _, alloc := range allocs {
		path := filepath.Join(s.logDir, alloc.ID+".log")
		t, err := newTailer(path, alloc.ID, opts.Tail, prefix)
		if err != nil {
			// A missing log file is normal for an alloc that never started.
			s.log.Debug("no log file", "alloc", alloc.ID, "error", err)
			continue
		}
		defer func() {
			if cerr := t.Close(); cerr != nil {
				s.log.Warn("close log tailer", "alloc", t.allocID, "error", cerr)
			}
		}()
		tails = append(tails, t)
	}

	for {
		wrote := false
		for _, t := range tails {
			n, err := t.copyTo(w)
			if err != nil {
				return
			}
			wrote = wrote || n > 0
		}
		if wrote && flusher != nil {
			flusher.Flush()
		}
		if !opts.Follow {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(PollInterval):
		}
	}
}

func (s *Server) selectAllocs(ctx context.Context, opts LogOptions) ([]reconciler.AllocRecord, error) {
	allocs, err := listAll[reconciler.AllocRecord](ctx, s.store, store.KindAlloc)
	if err != nil {
		return nil, err
	}
	var out []reconciler.AllocRecord
	for _, a := range allocs {
		switch {
		case opts.AllocID != "":
			if a.ID == opts.AllocID {
				out = append(out, a)
			}
		case opts.Service != "":
			if a.Service == opts.Service && (opts.Project == "" || a.Project == opts.Project) {
				out = append(out, a)
			}
		case opts.Project != "":
			if a.Project == opts.Project {
				out = append(out, a)
			}
		default:
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

// wake nudges the reconciler. Non-blocking: a missed wake-up only means the
// next tick handles it, whereas blocking here would stall the API.
func (s *Server) wake() {
	if s.notify == nil {
		return
	}
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// ---- helpers ----

// listAll pages through a bucket. Reads are bounded per page (store constraint),
// so "list everything" is a loop, not a single unbounded transaction.
func listAll[T any](ctx context.Context, s Store, kind store.Kind) ([]T, error) {
	var out []T
	opts := store.ListOptions{}
	for {
		values, page, err := store.ListValues[T](ctx, s, kind, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, values...)
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	// Defence in depth for the M5 browser-facing listener: these responses are
	// never a document, and must never be sniffed as one.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// The header is already written, so an encoding failure cannot change the
	// response — log it rather than pretending to return an error.
	if err := json.NewEncoder(w).Encode(body); err != nil {
		encodeFailures.Add(1)
	}
}

// encodeFailures counts responses that could not be written, so the condition
// is observable rather than silent. It is read by tests and, later, by metrics.
var encodeFailures atomic.Int64

// EncodeFailures reports how many responses failed to encode.
func EncodeFailures() int64 { return encodeFailures.Load() }

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, Error{Error: err.Error()})
}

// trimSocketPrefix is used by the client to render a friendlier target.
func trimSocketPrefix(path string) string {
	return strings.TrimPrefix(path, "unix://")
}
