package api

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m18h/kanea/internal/dashboard"
	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/ratelimit"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/scaling"
	"github.com/m18h/kanea/internal/secrets"
	"github.com/m18h/kanea/internal/secretsource"
	"github.com/m18h/kanea/internal/store"
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
	// SecretSync reports external-provider sync status (§5.2.13). Nil means
	// no providers are configured and the route answers 404 naming the flag.
	// Callers must pass untyped nil when unconfigured: a typed nil pointer
	// in an interface field is a non-nil interface (the buildReplication
	// lesson).
	SecretSync SecretSyncStatus
	// Pipelines is optional: a daemon with no builder configured serves the
	// pipeline routes with 503 rather than not routing them at all, so a
	// dashboard can tell "not configured" from "wrong URL".
	Pipelines Pipelines
	// Events backs the notification feed. Nil serves an empty feed rather than
	// an error: a daemon with no notification channels still has a dashboard.
	Events Events
	// NotifyStats reports the dispatcher's counters.
	NotifyStats func() notify.Stats
	// Notifier backs the test action (§11). Nil answers 503 on that route: a
	// daemon with no channels has nothing to test, which is a different answer
	// from "the test failed".
	Notifier Notifier
	// Backups backs the archive routes (§15.3). Nil answers 503 on them: a
	// daemon with no backup destination configured is a supported (if
	// regrettable) state, and it is different from a failure.
	Backups Backups
	// Settings backs the node-settings routes (v1.46, §15.1). Nil answers 503.
	Settings SettingsService
	// LDAPServer names the configured directory (v1.47): audit Detail on
	// directory logins, empty when LDAP is off. A name, never a credential.
	LDAPServer string
	// CA serves this node's self-signed CA certificate (§7.3). Nil answers 404
	// on that route, which is the honest answer for a node that has never
	// issued a self-signed certificate.
	//
	// Pass an explicit nil, never a typed nil pointer: a nil concrete pointer
	// in an interface field is a non-nil interface, and the check above would
	// pass and then panic.
	CA CertificateAuthority
	// PublishPorts is which node ports a spec may claim (R22). The zero value
	// has no ranges, which means publishing is off, so a server built without
	// it refuses rather than permitting everything.
	PublishPorts PortPolicy
	// NodeVars is the node's `variables { }` stanza (R30, v1.63), served over
	// GET /v1/vars. Static after startup: the file is load-once (§15.1). Nil
	// serves an empty map: a node with no stanza has no variables, which is an
	// answer, not an error.
	NodeVars map[string]string
	// MCP is the Model Context Protocol transport (§16.3), mounted at PathMCP
	// behind the same authentication every other route gets.
	//
	// Taken as a bare http.Handler rather than as an *mcp.Server so that this
	// package does not import that one: the MCP server's backend *is* this
	// server's handler, and the dependency has to point one way. Nil leaves the
	// route unregistered.
	MCP http.Handler
	// Publish emits notification events. Nil disables them.
	Publish func(notify.Event)
	// Auth resolves callers. Nil leaves the unix socket as the only credential
	// the daemon accepts, which is the §13.1 "no auth configured" case, and is
	// why a network listener without it is refused rather than warned about.
	Auth Authenticator
	// Audit is the trail every mutation is written to (§14, A09).
	Audit AuditLog
	// Accounts backs the user and token routes. Nil disables them.
	Accounts Accounts
	// Spec renders HCL for the dashboard's editor (v1.38). Implemented in
	// cmd/kanea beside toDesired, the same seam shape as gitops.Applier. Nil
	// means the spec routes answer 503.
	Spec SpecRenderer

	// Metrics backs the Prometheus exporter and the live stats topic. Nil
	// disables both.
	Metrics MetricsSource
	// Invoker reports the function invoker's counters (v1.39). Nil omits them
	// from GET /v1/functions, which still serves the list: a node running
	// no event or cron triggers has an invoker with nothing to say.
	Invoker InvokerSource
	// Usage reports measured volume usage (v1.69). Nil leaves every volume
	// unmeasured, which renders as absent rather than as empty.
	Usage UsageSource
	// VolumeDir is the root of local volume storage, needed to say where a
	// volume actually lives. It is the same value the reconciler was given.
	VolumeDir string
	// Breaker reports the circuit breaker's state to the exporter.
	Breaker BreakerSource
	// EdgeMetrics is the edge's labelled families, republished verbatim by the
	// exporter (§9.1.1). Nil reports kanea_edge_up 0 and nothing else, which is
	// the honest answer for a node whose edge is not being scraped.
	EdgeMetrics EdgeExpositionSource
	// Node reads the machine's own CPU, memory and load (§17). Nil omits them,
	// which is what a non-Linux build gets.
	Node NodeSource
	// Exec attaches a debug shell to an alloc (§16.2). Nil answers 503: a
	// daemon with no runtime driver has nothing to attach to.
	Exec Execer
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
	// TLSGetCertificate serves a certificate a subsystem manages and renews
	// (PRD v1.61, bind.api_tls acme/self-signed): the one listener whose
	// material renews behind its own socket, so it cannot be loaded once at
	// construction. Mutually exclusive with the pair above; the caller
	// resolves which story applies before building the server.
	TLSGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// ListenPlaintext is bind.api_tls = "plaintext": an explicit decision to
	// serve the listener without TLS beyond loopback (PRD v1.61). Off by
	// default, so the beyond-loopback refusal stands unless someone typed the
	// word.
	ListenPlaintext bool
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

// SecretSyncStatus reports external-provider sync state (PRD §5.2.13):
// paths, refs, timestamps and error strings, never values. The write-only
// property is untouched: nothing here can express a read either.
type SecretSyncStatus interface {
	Status() []secretsource.ProviderStatus
}

// Server is the control-plane HTTP server.
type Server struct {
	store      Store
	log        *slog.Logger
	socket     string
	version    string
	logDir     string
	notify     chan<- struct{}
	listener   net.Listener
	http       *http.Server
	wsOrigins  []string
	ws         *wsHub
	secrets    SecretStore
	secretSync SecretSyncStatus
	pipelines  Pipelines
	events     Events
	// notifyStats reports the dispatcher's counters, so the feed can say when
	// it is quiet because nothing happened rather than because the queue
	// overflowed.
	notifyStats  func() notify.Stats
	notifier     Notifier
	backups      Backups
	settings     SettingsService
	ldapServer   string
	ca           CertificateAuthority
	publishPorts PortPolicy
	nodeVars     map[string]string
	publish      func(notify.Event)

	spec SpecRenderer

	auth            Authenticator
	audit           AuditLog
	accounts        Accounts
	metrics         MetricsSource
	invoker         InvokerSource
	usage           UsageSource
	volumeDir       string
	edgeMetrics     EdgeExpositionSource
	breaker         BreakerSource
	node            NodeSource
	exec            Execer
	oidc            Provider
	sessions        SessionIssuer
	insecureCookies bool

	listenAddr      string
	authConfigured  bool
	tls             *tls.Config
	listenPlaintext bool
	netListener     net.Listener

	limiter     *ratelimit.Limiter
	publicLimit ratelimit.Spec
	authLimit   ratelimit.Spec

	// streamSlots bounds concurrent streaming REST responses (K-37): each
	// holds a goroutine and at least one open log fd, so an authenticated
	// caller opening them without bound exhausts kanead's descriptors.
	streamSlots chan struct{}

	// allocCache is the stats feed's per-index cache (K-18): a full alloc
	// listing per subscriber per interval is the same answer until a write
	// moves the store index, so it is computed once per index, not once per
	// asker.
	allocCache struct {
		mu     sync.Mutex
		index  uint64
		valid  bool
		allocs []reconciler.AllocRecord
	}

	// nodeSummaryCache is allocCache's argument applied to the node summary
	// (v1.79): it walks every service *and* every alloc, and the node topic
	// asks for it once per subscriber per interval.
	nodeSummaryCache struct {
		mu     sync.Mutex
		index  uint64
		valid  bool
		counts nodeCounts
	}

	// aggCache memoizes the node view's read-time aggregates (v1.79): the sum
	// across services and the rps-weighted mean. Each costs a ring walk per
	// service plus a scan of the whole key space, and the node topic asks for
	// them per subscriber per interval.
	//
	// Keyed on the slot the range ends at, which is allocCache's store-index
	// trick applied to time: both range surfaces truncate to a raw slot, and
	// Record drops out-of-order samples, so a passed slot's answer is final and
	// invalidation is nothing but the slot rolling over. The one residual is
	// stated in §9.1: the newest slot may be partly assembled, so a sum can
	// read momentarily low and is right at the next one.
	aggCache struct {
		mu      sync.Mutex
		entries map[aggKey][]scaling.Point
	}

	// subjectCache memoizes which subjects carry a metric, keyed on the series
	// epoch rather than on time: that set changes only when a series is created
	// or dropped, which is far rarer than a slot, and the answer costs a scan
	// of the whole key space with a sort.
	subjectCache struct {
		mu       sync.Mutex
		epoch    uint64
		valid    bool
		byMetric map[string][]string
	}

	// now, started and pid feed the health payload's uptime report (v1.38).
	// started comes from the same clock now reads, so an injected clock in a
	// test sees a consistent pair.
	now     func() time.Time
	started time.Time
	pid     int
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
	if cfg.TLSGetCertificate != nil {
		if tlsConfig != nil {
			return nil, errors.New("api: a certificate pair and a managed certificate are two TLS stories; pick one")
		}
		tlsConfig = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: cfg.TLSGetCertificate,
		}
	}

	publicLimit, authLimit := DefaultPublicLimit, DefaultAuthenticatedLimit
	if cfg.PublicLimit != nil {
		publicLimit = *cfg.PublicLimit
	}
	if cfg.AuthLimit != nil {
		authLimit = *cfg.AuthLimit
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	s := &Server{
		limiter: ratelimit.New(cfg.RateLimitBuckets, cfg.Now),
		now:     now, started: now(), pid: os.Getpid(),
		publicLimit: publicLimit, authLimit: authLimit,
		listenAddr: cfg.Listen, authConfigured: cfg.AuthConfigured, tls: tlsConfig,
		listenPlaintext: cfg.ListenPlaintext,
		store:           cfg.Store, log: cfg.Logger, socket: cfg.Socket,
		version: cfg.Version, logDir: cfg.LogDir, notify: cfg.Notify,
		wsOrigins: cfg.WSOrigins, ws: newWSHub(cfg.WSMaxConns),
		secrets: cfg.Secrets, secretSync: cfg.SecretSync, pipelines: cfg.Pipelines,
		events: cfg.Events, notifyStats: cfg.NotifyStats, publish: cfg.Publish,
		notifier: cfg.Notifier, backups: cfg.Backups, settings: cfg.Settings,
		ldapServer: cfg.LDAPServer, ca: cfg.CA,
		publishPorts: cfg.PublishPorts,
		nodeVars:     cfg.NodeVars,
		auth:         cfg.Auth, audit: cfg.Audit,
		accounts: cfg.Accounts, oidc: cfg.OIDC, sessions: cfg.Sessions,
		spec:    cfg.Spec,
		metrics: cfg.Metrics, edgeMetrics: cfg.EdgeMetrics,
		invoker:   cfg.Invoker,
		usage:     cfg.Usage,
		volumeDir: cfg.VolumeDir,
		breaker:   cfg.Breaker, node: cfg.Node, exec: cfg.Exec,
		insecureCookies: cfg.InsecureCookies,
	}
	// writeError's 5xx half logs through the daemon's logger (K-34); wired
	// once here, before any request is served.
	internalErrorLog.Store(s.log.Error)
	s.streamSlots = make(chan struct{}, maxStreams)

	// Every route states what it requires next to where it is registered, and
	// the `public: true` entries are the whole exemption list (§5.2.1). Four of
	// them are "nobody has a credential yet": health, because a probe must work
	// before anyone can log in, login itself, and the two OIDC legs. The fifth,
	// the git webhook, is public in the routing sense only: it authenticates
	// itself with a per-project HMAC because the caller is a provider rather
	// than a person (docs/THREAT_MODEL.md §3.8).
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
	// The spec editor (v1.38). Render is a read with admin's blast radius
	// (it evaluates operator-supplied HCL) so it is admin-only like the audit
	// log; apply is a mutation like any other: admin, CSRF, audited.
	mux.Handle("POST "+PathSpecRender,
		s.route(policy{action: "spec.render", adminOnly: true}, s.handleSpecRender))
	mux.Handle("POST "+PathSpecApply,
		s.route(policy{action: "spec.apply", mutates: true}, s.handleSpecApply))
	mux.Handle("GET "+PathSpecSource,
		s.route(policy{action: "spec.source", adminOnly: true}, s.handleSpecSource))
	mux.Handle("DELETE "+PathServices+"/{project}/{service}",
		s.route(policy{action: "service.delete", mutates: true}, s.handleDeleteService))
	mux.Handle("POST "+PathServices+"/{project}/{service}/scale",
		s.route(policy{action: "service.scale", mutates: true}, s.handleScale))
	// A restart is a mutation like any other, and goes through the reconciler
	// like any other: it bumps a number and returns.
	mux.Handle("POST "+PathServices+"/{project}/{service}/restart",
		s.route(policy{action: "service.restart", mutates: true}, s.handleRestart))
	// Functions (v1.39): a read-only view. Deploy and edit are the spec
	// editor's routes; restart and scale are the service routes': a function
	// is a service underneath, and the mutation paths are inherited, never
	// replicated.
	mux.Handle("GET "+PathFunctions, s.route(policy{action: "functions.list"}, s.handleListFunctions))
	mux.Handle("GET "+PathVolumes, s.route(policy{action: "volumes.list"}, s.handleListVolumes))
	mux.Handle("GET "+PathProjects, s.route(policy{action: "project.list"}, s.handleListProjects))
	mux.Handle("GET "+PathProjects+"/{project}",
		s.route(policy{action: "project.get"}, s.handleGetProject))
	mux.Handle("GET "+PathStats, s.route(policy{action: "stats.read"}, s.handleStats))
	mux.Handle("GET "+PathStatsHistory,
		s.route(policy{action: "stats.history"}, s.handleStatsHistory))
	// Sending a test message reaches outside the node, so it is a mutation in the
	// sense that matters here: admin-only, and audited.
	mux.Handle("POST "+PathProjects+"/{project}/notifications/test",
		s.route(policy{action: "notify.test", mutates: true}, s.handleTestNotification))
	mux.Handle("GET "+PathAllocs, s.route(policy{action: "alloc.list"}, s.handleListAllocs))
	mux.Handle("GET "+PathMetrics, s.route(policy{action: "metrics.read"}, s.handleMetrics))
	mux.Handle("GET "+PathLogs, s.route(policy{action: "logs.read"}, s.handleLogs))
	mux.Handle("GET "+PathWS, s.route(policy{action: "ws.connect"}, s.handleWS))
	// The most privileged route here, and §14 names it: an exec is a shell
	// inside a workload, with the workload's filesystem and credentials. Marked
	// mutating so it is admin-only and audited: the entry is written whether
	// or not the session worked, because "someone tried to open a shell on
	// production" is worth keeping either way.
	mux.Handle("GET "+PathExec, s.route(policy{action: "alloc.exec", mutates: true}, s.handleExec))
	// The audit log is admin-only to read: it names who did what, and that is
	// not something a viewer needs (§13.3).
	mux.Handle("GET "+PathAudit, s.route(policy{action: "audit.list", adminOnly: true}, s.handleAudit))
	// Accounts. Admin-only throughout: minting a token is minting a credential,
	// and listing users is a list of things worth attacking (§13.3).
	mux.Handle("GET "+PathUsers, s.route(policy{action: "user.list", adminOnly: true}, s.handleListUsers))
	mux.Handle("PUT "+PathUsers+"/{name}", s.route(policy{action: "user.put", mutates: true}, s.handlePutUser))
	mux.Handle("DELETE "+PathUsers+"/{name}",
		s.route(policy{action: "user.delete", mutates: true}, s.handleDeleteUser))
	mux.Handle("DELETE "+PathUsers+"/{name}/sessions",
		s.route(policy{action: "user.sessions.revoke", mutates: true}, s.handleRevokeUserSessions))
	mux.Handle("GET "+PathTokens, s.route(policy{action: "token.list", adminOnly: true}, s.handleListTokens))
	mux.Handle("POST "+PathTokens, s.route(policy{action: "token.create", mutates: true}, s.handleCreateToken))
	mux.Handle("DELETE "+PathTokens+"/{id}",
		s.route(policy{action: "token.revoke", mutates: true}, s.handleRevokeToken))
	// List and write, never read: there is no GET for an individual secret,
	// and its absence is the enforcement (PRD §13.3).
	// Pipelines (§10). Reading runs and logs is an ordinary authenticated read;
	// asking for a build or a sync mutates, because both end in a deploy.
	mux.Handle("GET "+PathPipelines, s.route(policy{action: "pipeline.list"}, s.handleListRuns))
	mux.Handle("GET "+PathPipelines+"/{project}/{service}/{run}",
		s.route(policy{action: "pipeline.get"}, s.handleGetRun))
	mux.Handle("GET "+PathPipelines+"/{project}/{service}/{run}/logs",
		s.route(policy{action: "pipeline.logs"}, s.handleRunLogs))
	mux.Handle("POST "+PathPipelines+"/{project}/{service}/build",
		s.route(policy{action: "pipeline.build", mutates: true}, s.handleBuild))
	mux.Handle("POST "+PathProjects+"/{project}/sync",
		s.route(policy{action: "project.sync", mutates: true}, s.handleSync))
	// The third exemption, and the only one that is not "nobody has a credential
	// yet": a git push comes from a provider, not a person, so it carries a
	// per-project HMAC instead of a session. handleGitWebhook authenticates it
	// itself: see the comment there. CSRF does not apply for the same reason it
	// does not apply to a bearer token: nothing is taken from a cookie.
	//
	// Not marked `mutates`, deliberately: a public route returns before that
	// flag is read, so setting it would only suggest an automatic audit entry
	// that never fires. The handler records its own, refusals included.
	mux.Handle("POST "+PathWebhooks+"/{project}",
		s.route(policy{action: "webhook.receive", public: true}, s.handleGitWebhook))
	mux.Handle("GET "+PathEvents, s.route(policy{action: "event.list"}, s.handleEvents))
	// Backups (§15.3). Listing is an ordinary read; taking one is a mutation
	// because it writes to a bucket and costs money. Staging a restore is the
	// most destructive call this API has (it discards everything on the node
	// at the next start) and is admin-only and audited like every other.
	// The CA certificate (§7.3). A read, and not an admin one: it is presented
	// in every handshake to every client that trusts it.
	mux.Handle("GET "+PathEdgePolicy,
		s.route(policy{action: "edge.policy"}, s.handleEdgePolicy))
	// The node's shared spec variables (R30, v1.63). A read for any
	// authenticated caller: R30's contract is that variables are never
	// secrets, which is what makes this tier right.
	mux.Handle("GET "+PathVars,
		s.route(policy{action: "vars.read"}, s.handleVars))
	mux.Handle("GET "+PathCerts+"/ca",
		s.route(policy{action: "cert.ca"}, s.handleCACertificate))

	mux.Handle("GET "+PathBackups, s.route(policy{action: "backup.list"}, s.handleListBackups))
	mux.Handle("POST "+PathBackups,
		s.route(policy{action: "backup.create", mutates: true}, s.handleCreateBackup))
	mux.Handle("GET "+PathBackups+"/{id}/verify",
		// A "read" that downloads and hashes a full archive per call is not a
		// read: viewer-reachable egress/CPU churn (K-39). Admin-only.
		s.route(policy{action: "backup.verify", adminOnly: true}, s.handleVerifyBackup))
	mux.Handle("POST "+PathBackups+"/restore",
		s.route(policy{action: "backup.restore", mutates: true}, s.handleRestore))
	// Node settings (v1.46, §15.1). Reading them is admin-only: the view
	// includes the backup destination and channel config, which is more of the
	// node than a viewer's role describes. Mutations are CSRF'd and audited
	// like every other; the settings service itself validates before anything
	// commits, so a refused record costs nothing.
	mux.Handle("GET "+PathSettings,
		s.route(policy{action: "settings.read", adminOnly: true}, s.handleGetSettings))
	mux.Handle("PUT "+PathSettings+"/backup",
		s.route(policy{action: "settings.backup.put", mutates: true}, s.handlePutBackupSettings))
	mux.Handle("DELETE "+PathSettings+"/backup",
		s.route(policy{action: "settings.backup.delete", mutates: true}, s.handleResetBackupSettings))
	mux.Handle("PUT "+PathSettings+"/notifications",
		s.route(policy{action: "settings.notifications.put", mutates: true}, s.handlePutNotificationSettings))
	mux.Handle("DELETE "+PathSettings+"/notifications",
		s.route(policy{action: "settings.notifications.delete", mutates: true}, s.handleResetNotificationSettings))
	mux.Handle("POST "+PathSettings+"/notifications/test",
		s.route(policy{action: "settings.notifications.test", mutates: true}, s.handleTestNodeChannels))
	mux.Handle("GET "+PathProjects+"/{project}/notifications",
		s.route(policy{action: "project.notifications.get", adminOnly: true}, s.handleGetProjectNotifications))
	mux.Handle("PUT "+PathProjects+"/{project}/notifications",
		s.route(policy{action: "project.notifications.put", mutates: true}, s.handlePutProjectNotifications))
	// The MCP transport (§16.3). Authenticated like everything else and no more:
	// the route itself neither mutates nor requires admin, because what a tool
	// call is allowed to do is decided by the route that call lands on, one
	// level down. Marking this one `mutates` would demand admin for tools/list.
	if cfg.MCP != nil {
		for _, method := range []string{"POST", "GET", "DELETE"} {
			mux.Handle(method+" "+PathMCP,
				s.route(policy{action: "mcp.transport"}, cfg.MCP.ServeHTTP))
		}
	}
	mux.Handle("GET "+PathSecrets, s.route(policy{action: "secret.list", adminOnly: true}, s.handleListSecrets))
	mux.Handle("GET "+PathSecrets+"/providers",
		s.route(policy{action: "secret.providers", adminOnly: true}, s.handleSecretProviders))
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
		// "success" followed by a JSON decode error somewhere unrelated:
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
		mux.Handle("/", dashboard.Handler("/", cfg.WSOrigins))
		if !dashboard.Built() {
			cfg.Logger.Warn("serving the dashboard placeholder",
				"detail", "this binary was built without the UI; run `make dashboard && make build`")
		}
	}

	s.http = &http.Server{
		Handler: secureHeaders(mux),
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
// counts as a local connection: see withLocalConn.
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
	// 0600: reaching this socket is the local-root credential of §13.1. When
	// the operator has created the `kanea` group (PRD v1.48), the socket is
	// published root:kanea 0660 instead: membership is root-equivalent,
	// docker's model, and the group's absence is the default. Deny-closed:
	// root-only is set first, and any failure widening it leaves it that way.
	if err := os.Chmod(s.socket, 0o600); err != nil {
		return errors.Join(fmt.Errorf("api: chmod socket: %w", err), listener.Close())
	}
	if gid, ok := socketGroupID(user.LookupGroup, s.log); ok {
		if err := s.applySocketGroup(gid); err != nil {
			s.log.Error("could not apply the socket group; the socket stays root-only",
				"group", SocketGroup, "error", err,
				"remedy", "kanead applies the group at startup; fix the error and restart")
		} else {
			s.log.Info("socket group applied; its members may use the CLI without sudo",
				"group", SocketGroup, "socket", s.socket)
		}
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
		// A genuine bind failure (port in use, bad address, unreadable
		// certificate) is the operator's configuration not working, and
		// starting anyway would hide it.
		return errors.Join(err, listener.Close())
	default:
		s.netListener = network
	}
	return nil
}

// socketGroupID resolves the SocketGroup gid, if the operator has created the
// group. The lookup is injected so the decision is testable on a machine whose
// /etc/group this test must not depend on.
func socketGroupID(lookup func(string) (*user.Group, error), log *slog.Logger) (int, bool) {
	g, err := lookup(SocketGroup)
	if err != nil {
		var unknown user.UnknownGroupError
		if !errors.As(err, &unknown) {
			// An absent group is the default and not worth a line; a lookup
			// that failed some other way is: the operator may have created
			// the group and be waiting on a socket that never widens.
			log.Warn("could not look up the socket group", "group", SocketGroup, "error", err)
		}
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		log.Warn("the socket group's gid is not numeric", "group", SocketGroup, "gid", g.Gid)
		return 0, false
	}
	return gid, true
}

// applySocketGroup widens the socket to root:kanea 0660 (PRD v1.48).
func (s *Server) applySocketGroup(gid int) error {
	// The directory first: group members need traverse to reach the socket at
	// all. Ownership only: the mode stays what the unit created (0710 gives
	// the group traverse without listing), and the containerd socket next door
	// keeps its own root-only mode, so the group reaches exactly one thing.
	if err := os.Chown(filepath.Dir(s.socket), -1, gid); err != nil {
		return fmt.Errorf("chgrp socket dir: %w", err)
	}
	if err := os.Chown(s.socket, -1, gid); err != nil {
		return fmt.Errorf("chgrp socket: %w", err)
	}
	// #nosec G302; 0660 is the feature: a unix socket needs the group write
	// bit for connect(2), and granting the operator-created kanea group the
	// socket is exactly what PRD v1.48 specifies. Root-only was set first, so
	// failing here leaves 0600.
	return os.Chmod(s.socket, 0o660)
}

// NetworkAddr reports the network listener's address, or "" when there is none,
// because it was not configured, or because §13.1 refused it.
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
				"detail", "loopback only: put kanea-edge in front, or pass a certificate")
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
		Listen:        s.listenAddr, TLS: s.tls != nil,
		PID: s.pid, StartedAt: s.started,
		UptimeSeconds: int64(s.now().Sub(s.started) / time.Second),
	}
	// What sign-in methods exist is part of what a client needs before it can
	// authenticate, and health is the one route it can ask without a credential.
	// It names the issuer and nothing else: a provider URL is public by
	// definition; every browser sent there sees it.
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
	writeJSON(w, http.StatusOK, ServicesResponse{Services: serviceViews(services)})
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var req ApplyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	resp, status, err := s.applyServices(r, req)
	if err != nil {
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// applyServices is the apply path itself, shared by PUT /v1/services and the
// spec editor's POST /v1/spec/apply (v1.38). One implementation on purpose:
// generation carry-over, pinned-image carry-over, the R22 port check, the
// atomic batch, the wake, the events and the audit line must not exist twice.
func (s *Server) applyServices(r *http.Request, req ApplyRequest) (ApplyResponse, int, error) {
	// A request with no services is normally a mistake. It is legitimate under
	// a prune scope, which is how a spec says "this project should now be
	// empty": refusing it would make removing the last service impossible.
	if len(req.Services) == 0 && len(req.PruneProjects) == 0 {
		return ApplyResponse{}, http.StatusBadRequest, errors.New("no services in request")
	}

	muts := make([]store.Mutation, 0, len(req.Services))
	applied := make([]string, 0, len(req.Services))
	for _, svc := range req.Services {
		if svc.Project == "" || svc.Service == "" {
			return ApplyResponse{}, http.StatusBadRequest,
				errors.New("every service needs a project and a name")
		}
		key := svc.Project + "/" + svc.Service
		// The parser enforces the spec's invariants one way; a record that
		// arrives as JSON never meets it. This is the same boundary R22 is
		// checked at below: validateDesired is the rest of the rules a stored
		// record must live under, refused before any Store write.
		if err := validateDesired(svc); err != nil {
			return ApplyResponse{}, http.StatusBadRequest, err
		}
		// The restart generation belongs to the running service, not to the
		// file: it is bumped by `kanea restart`, and a spec that does not
		// mention it must not reset it. Without this, the first apply after a
		// restart would look like another spec change and roll the service a
		// second time: the same class of bug the pipeline merge below avoids.
		if current, _, err := store.GetValue[reconciler.Desired](
			r.Context(), s.store, store.KindService, key); err == nil {
			svc.Generation = current.Generation
			// The auto-update state belongs to the watcher for the same reason
			// (§6.2 R19): the digest currently pinned, what to fall back to and
			// when the registry was last asked are all facts about the running
			// service, not about the file. An apply that reset them would unpin
			// the service (redeploying it onto its bare tag) and then re-pin
			// it on the next poll, so every `kanea apply` would cost two
			// deploys of a service nobody changed.
			//
			// Two things drop the pin rather than carry it. A changed `image`
			// means the operator has said which tag to follow and the old
			// digest is not it: carrying it would leave the service running
			// 10.9 after the spec was edited to say 10.10, which is the spec
			// being ignored. And auto turned *off* hands the spec back the
			// authority: what runs should then be what the file says. Both cost
			// one rolling deploy, and both are the deploy the operator asked
			// for by editing the file.
			if svc.Update.Auto && svc.Image == current.Image {
				svc.PinnedImage = current.PinnedImage
				svc.RollbackImage = current.RollbackImage
				svc.ImageCheckedAt = current.ImageCheckedAt
				svc.ImageUpdatedAt = current.ImageUpdatedAt
			}
		}
		// R22, and this is the boundary rather than a second opinion. `kanea
		// plan` pre-checks the same policy over PathEdgePolicy so the refusal
		// lands in front of whoever typed it, but a GitOps sync reaches the
		// Store through here and never through the CLI.
		if err := s.publishPorts.Check(svc); err != nil {
			return ApplyResponse{}, http.StatusForbidden, err
		}
		// R25's boundary half, same reasoning: the parser refuses these, and a
		// record that reached the Store another way must be refused again here.
		// A runtime name resolves to a binary containerd executes as root, so
		// the set is closed; an exec probe on a wasm service is a check that
		// can never pass, which reads as a service that is permanently down.
		if svc.Runtime != "" && svc.Runtime != runtime.RuntimeWasmtime {
			return ApplyResponse{}, http.StatusBadRequest,
				fmt.Errorf("service %s names runtime %q; only %q is supported (PRD §6.2 R25)",
					key, svc.Runtime, runtime.RuntimeWasmtime)
		}
		if svc.Runtime == runtime.RuntimeWasmtime && svc.Check != nil && svc.Check.Type == reconciler.HealthExec {
			return ApplyResponse{}, http.StatusBadRequest,
				fmt.Errorf("service %s is a wasm function with an exec health check; the wasm runtime "+
					"has no exec primitive (PRD §6.2 R25): probe it over http or tcp", key)
		}
		mut, err := store.PutMutation(store.KindService, key, svc)
		if err != nil {
			return ApplyResponse{}, http.StatusInternalServerError, err
		}
		muts = append(muts, mut)
		applied = append(applied, key)
	}

	for _, pipeline := range req.Pipelines {
		if pipeline.Project == "" {
			return ApplyResponse{}, http.StatusBadRequest,
				errors.New("every pipeline config needs a project")
		}
		// Same R1 half as the services above: the project name composes into
		// DNS and paths everywhere a pipeline's services do.
		if !jobspec.IsName(pipeline.Project) {
			return ApplyResponse{}, http.StatusBadRequest,
				fmt.Errorf("pipeline project %q is not a DNS-1123 label", pipeline.Project)
		}
		// Merged rather than replaced: LastCommit and LastSyncAt belong to the
		// sync loop, and an apply that overwrote them with zero values would
		// make the next poll re-apply a commit it already applied.
		merged := pipeline
		if current, _, err := store.GetValue[gitops.Config](
			r.Context(), s.store, store.KindProject, pipeline.Project); err == nil {
			merged.LastCommit, merged.LastSyncAt = current.LastCommit, current.LastSyncAt
		}
		mut, err := store.PutMutation(store.KindProject, pipeline.Project, merged)
		if err != nil {
			return ApplyResponse{}, http.StatusInternalServerError, err
		}
		muts = append(muts, mut)
	}

	// The prune, appended to the same batch. Deletes ride with the puts so a
	// spec that renames a service never exists in a state where both or
	// neither is declared.
	removed, err := s.pruneOrphans(r.Context(), req, applied)
	if err != nil {
		return ApplyResponse{}, http.StatusInternalServerError, err
	}
	for _, key := range removed {
		muts = append(muts, store.DeleteMutation(store.KindService, key))
	}

	// One batch: a multi-service apply lands atomically, so the reconciler never
	// sees half a deploy.
	index, err := s.store.Apply(r.Context(), muts...)
	if err != nil {
		return ApplyResponse{}, http.StatusInternalServerError, err
	}
	s.wake()
	// The audit line names what was destroyed, not only what was written. A
	// destructive action whose record does not say what it removed is the one
	// outcome worth avoiding here.
	target := strings.Join(applied, ",")
	if len(removed) > 0 {
		target += " -" + strings.Join(removed, ",-")
	}
	auditTarget(r, target)
	// One event per service, not one per apply. A three-service deploy is
	// three things an operator filters and routes independently, and the
	// dispatcher coalesces them back into one message anyway.
	for _, key := range applied {
		project, service, _ := strings.Cut(key, "/")
		s.emit(notify.EventDeploySucceeded, project, service, "applied desired state")
	}
	for _, key := range removed {
		project, service, _ := strings.Cut(key, "/")
		s.emit(notify.EventServiceRemoved, project, service,
			"no longer declared by the spec that owns this project")
	}
	s.log.Info("applied services", "services", applied, "removed", removed, "index", index)
	return ApplyResponse{Applied: applied, Removed: removed, Index: index}, 0, nil
}

// pruneOrphans names the stored services a prune-scoped apply should delete:
// everything in a named project that the request does not declare.
//
// Returning the keys rather than the mutations keeps the decision testable and
// lets the caller put them in the same batch as the puts.
func (s *Server) pruneOrphans(ctx context.Context, req ApplyRequest, applied []string) ([]string, error) {
	if len(req.PruneProjects) == 0 {
		return nil, nil
	}
	scope := make(map[string]struct{}, len(req.PruneProjects))
	for _, p := range req.PruneProjects {
		scope[p] = struct{}{}
	}
	declared := make(map[string]struct{}, len(applied))
	for _, key := range applied {
		declared[key] = struct{}{}
	}

	stored, err := listAll[reconciler.Desired](ctx, s.store, store.KindService)
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, svc := range stored {
		if _, ours := scope[svc.Project]; !ours {
			continue
		}
		key := svc.Project + "/" + svc.Service
		if _, kept := declared[key]; kept {
			continue
		}
		removed = append(removed, key)
	}
	sort.Strings(removed)
	return removed, nil
}

// emit publishes a notification event, if the daemon has a dispatcher.
//
// Fire-and-forget by construction: Publish never blocks and never fails, so
// there is nothing here for an HTTP handler to do about it (AGENTS.md #8).
func (s *Server) emit(name, project, service, message string) {
	if s.publish == nil {
		return
	}
	s.publish(notify.NewEvent(name, project, service, message, time.Now()))
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
	if opts.Follow {
		// A following stream holds a goroutine and a log fd per alloc for as
		// long as the client cares to hold it (K-37): bounded, refused when
		// full, never queued.
		if !s.acquireStream(w) {
			return
		}
		defer s.releaseStream()
	}
	// One alloc keeps the stream unprefixed; several need attribution.
	prefix := len(allocs) > 1

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	tails := make([]*tailer, 0, len(allocs))
	for _, alloc := range allocs {
		path, err := logPathFor(s.logDir, alloc.ID)
		if err != nil {
			// A traversal-shaped ID in the Store means the record pre-dates
			// the apply seam's name validation; skip it rather than read
			// outside the log directory.
			s.log.Warn("refusing log path", "alloc", alloc.ID, "error", err)
			continue
		}
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
	// Defence in depth for the browser-facing listener: these responses are
	// never a document, and must never be sniffed as one.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// The header is already written, so an encoding failure cannot change the
	// response: log it rather than pretending to return an error.
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
	if status >= 500 && status != http.StatusNotImplemented {
		// A 5xx body is fixed text plus a correlation id (K-34): the verbatim
		// error can carry filesystem layout and subsystem names to any
		// authenticated caller. The real error goes to the log with the id.
		// (501 is exempt: it is the deliberate "not configured on this node"
		// answer, and its text is the point.)
		id := correlationID()
		logInternalError(msg500, "ref", id, "status", status, "error", err)
		writeJSON(w, status, Error{Error: "internal error (ref " + id + ")"})
		return
	}
	writeJSON(w, status, Error{Error: err.Error()})
}

const msg500 = "request failed"

// logInternalError is set by NewServer to the daemon's logger. A package-level
// hook rather than a parameter because writeError has ~150 call sites that
// predate it; the alternative is a signature change for a Low-severity
// finding. Stored atomically: tests run several servers in one process.
var logInternalError = func(msg string, args ...any) {
	if fn, ok := internalErrorLog.Load().(func(string, ...any)); ok {
		fn(msg, args...)
		return
	}
	slog.Default().Error(msg, args...)
}

var internalErrorLog atomic.Value // func(string, ...any)

// correlationID is a short random reference for a 5xx body, so the operator
// can find the real error in the log and the client learns nothing.
func correlationID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

// trimSocketPrefix is used by the client to render a friendlier target.
func trimSocketPrefix(path string) string {
	return strings.TrimPrefix(path, "unix://")
}

// maxStreams bounds concurrent streaming REST responses (K-37).
const maxStreams = 16

// acquireStream takes a streaming slot, answering 503 when they are all held.
// Streaming is the expensive serving mode (a goroutine and open files per
// connection); a non-follow read is short and never takes one.
func (s *Server) acquireStream(w http.ResponseWriter) bool {
	select {
	case s.streamSlots <- struct{}{}:
		return true
	default:
		writeError(w, http.StatusServiceUnavailable,
			fmt.Errorf("api: too many open streams (%d)", maxStreams))
		return false
	}
}

func (s *Server) releaseStream() { <-s.streamSlots }
