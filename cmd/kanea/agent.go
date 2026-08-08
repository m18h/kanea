package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	acmelib "github.com/kanea-dev/kanea/internal/acme"
	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/audit"
	"github.com/kanea-dev/kanea/internal/auth"
	"github.com/kanea-dev/kanea/internal/backup"
	"github.com/kanea-dev/kanea/internal/edge"
	"github.com/kanea-dev/kanea/internal/gitops"
	"github.com/kanea-dev/kanea/internal/logging"
	"github.com/kanea-dev/kanea/internal/mcp"
	"github.com/kanea-dev/kanea/internal/network"
	"github.com/kanea-dev/kanea/internal/notify"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/runtime"
	"github.com/kanea-dev/kanea/internal/scaling"
	"github.com/kanea-dev/kanea/internal/secrets"
	"github.com/kanea-dev/kanea/internal/storage"
	"github.com/kanea-dev/kanea/internal/store"
)

// Default filesystem layout. PRD §15.1 makes these configurable; M1 takes the
// defaults and the flags below.
const (
	defaultDataDir = "/var/lib/kanea"
	// stateFile is the bbolt database's name under the data directory. Named
	// because a restore has to find it without a running daemon to ask.
	stateFile     = "state.db"
	defaultLogDir = "/var/log/kanea/allocs"
	// volumeSubdir is where local volumes live under the data dir (PRD §8).
	volumeSubdir = "volumes"
	// resolvSubdir holds the generated per-project resolv.conf files.
	resolvSubdir = "resolv"
	// credentialSubdir holds transient mount credential files.
	credentialSubdir = "credentials"
	// edgeRoutesOff disables publishing the edge route table.
	edgeRoutesOff = "off"
)

// runAgent is kanead: the control plane. It owns the state file — bbolt is
// single-writer, so nothing else may open it — and therefore also serves the
// API that the CLI uses to reach that state.
func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "state directory")
	backupDir := fs.String("backup-dir", "",
		"replicate state to this directory (PRD §15.3)")
	backupS3 := fs.String("backup-s3", "",
		"replicate state to s3://bucket[/prefix]")
	backupS3Endpoint := fs.String("backup-s3-endpoint", "", "S3 endpoint URL")
	backupS3Region := fs.String("backup-s3-region", "", "S3 region")
	backupS3AccessKey := fs.String("backup-s3-access-key", "", "S3 access key id")
	backupS3Secret := fs.String("backup-s3-secret-key", "",
		"`secret:` reference to the S3 secret key (never a literal — R3)")
	backupS3PathStyle := fs.Bool("backup-s3-path-style", true,
		"address the bucket as /bucket/key rather than as a subdomain")
	backupInterval := fs.Duration("backup-interval", backup.DefaultSnapshotInterval,
		"how often to take a full state snapshot")
	backupSegmentInterval := fs.Duration("backup-segment-interval", backup.DefaultSegmentInterval,
		"how often to ship change segments (bounds the RPO)")
	backupRetention := fs.Int("backup-retention", backup.DefaultRetention,
		"how many snapshots to keep")
	autoRestore := fs.Bool("restore-if-empty", false,
		"restore the newest archive when this node has no state at all (§15.3 first-boot)")
	logDir := fs.String("log-dir", defaultLogDir, "per-alloc log directory")
	volumeDir := fs.String("volume-dir", "", "local volume root (default <data-dir>/volumes)")
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	containerdSocket := fs.String("containerd", runtime.DefaultSocket, "containerd socket")
	networkMode := fs.String("network", networkCilium,
		"network driver: cilium, or netns for development (no policy, no service LB)")
	ciliumSocket := fs.String("cilium", network.DefaultSocketPath, "cilium-agent API socket")
	cniConf := fs.String("cni-conf", network.DefaultCNIConfPath, "CNI configuration list")
	cniBin := fs.String("cni-bin", network.DefaultCNIBinDir, "CNI plugin directory")
	policyDir := fs.String("policy-dir", network.DefaultPolicyDir, "cilium --static-cnp-path directory")
	hostPaths := fs.String("allowed-host-paths", "",
		"comma-separated directories that `host` volumes may mount from (default: none)")
	lbStateFile := fs.String("lb-state-file", network.DefaultLBStateFile, "cilium --lb-state-file path")
	serviceCIDR := fs.String("service-cidr", reconciler.DefaultServiceCIDR, "pool for service frontend addresses")
	dnsListen := fs.String("dns-listen", "",
		"internal DNS listen address (default: the cilium_host address; \"off\" disables)")
	dnsUpstream := fs.String("dns-upstream", "",
		"comma-separated upstream resolvers for external names (default: the host's)")
	baseDomain := fs.String("base-domain", "",
		"domain exposed services get an FQDN under, e.g. apps.example.com (PRD §7.2)")
	edgeRoutes := fs.String("edge-routes", edge.DefaultSnapshotPath,
		"where to publish the route table for kanea-edge (\"off\" disables)")
	edgeCerts := fs.String("edge-certs", edge.DefaultBundlePath,
		"where to publish certificates for kanea-edge")
	edgeGroup := fs.String("edge-group", "",
		"group allowed to read the certificate bundle — the kanea-edge user's (default: owner only)")
	acmeEmail := fs.String("acme-email", "",
		"ACME account contact; without it no certificates are obtained")
	acmeDirectory := fs.String("acme-directory", acmelib.LetsEncryptStaging,
		"ACME directory URL (the staging CA by default: its certificates are not publicly trusted)")
	acmeCA := fs.String("acme-ca-bundle", "",
		"extra CA to trust when talking to the ACME directory (for a private or test CA)")
	acmeVerifyURL := fs.String("acme-verify-url", acmelib.DefaultVerifyURL,
		"where kanead reaches its own edge to confirm a challenge is being served")
	acmeDNSServer := fs.String("acme-dns-server", "",
		"authoritative nameserver for RFC 2136 dynamic updates, host:port (enables DNS-01 and wildcards)")
	acmeDNSZone := fs.String("acme-dns-zone", "",
		"zone the challenge records belong to (default: the challenge name's parent)")
	acmeDNSKey := fs.String("acme-dns-tsig-key", "", "TSIG key name for dynamic updates")
	acmeDNSSecret := fs.String("acme-dns-tsig-secret", "",
		"a secret: reference holding the base64 TSIG secret, e.g. secret:shared/tsig")
	acmeDNSAlgorithm := fs.String("acme-dns-tsig-algorithm", "hmac-sha256.",
		"TSIG algorithm: hmac-sha256, hmac-sha512, ...")
	serveDashboard := fs.Bool("dashboard", true, "serve the embedded dashboard on the API listener")
	wsOrigins := fs.String("dashboard-origins", "",
		"comma-separated Origins allowed to open the live-data websocket (default: same-origin only)")
	listen := fs.String("listen", "",
		"network address for the control API, e.g. "+api.DefaultListenAddr+" (default: unix socket only)")
	listenCert := fs.String("listen-cert", "", "TLS certificate for --listen (required beyond loopback)")
	listenKey := fs.String("listen-key", "", "TLS private key for --listen")
	insecureCookies := fs.Bool("insecure-cookies", false,
		"drop the Secure attribute from the session cookie (only for a daemon reached over plain HTTP)")
	auditRetention := fs.Duration("audit-retention", defaultAuditRetention,
		"how long audit entries are kept; 0 keeps them forever")
	oidcIssuer := fs.String("oidc-issuer", "",
		"identity provider base URL, e.g. https://accounts.google.com (default: password login only)")
	oidcClientID := fs.String("oidc-client-id", "", "OAuth client id registered with the provider")
	oidcClientSecret := fs.String("oidc-client-secret", "",
		"a secret: reference holding the client secret, e.g. secret:shared/oidc (omit for a public PKCE client)")
	oidcRedirect := fs.String("oidc-redirect-url", "",
		"the exact redirect URI registered with the provider, e.g. https://kanea.example.com"+api.PathOIDCCallback)
	oidcScopes := fs.String("oidc-scopes", "profile,email", "comma-separated scopes beyond openid")
	oidcRoleClaim := fs.String("oidc-role-claim", auth.DefaultRoleClaim,
		"claim consulted for authorization")
	oidcAdmins := fs.String("oidc-admin-claims", "",
		"comma-separated claim values granted the admin role")
	oidcViewers := fs.String("oidc-viewer-claims", "",
		"comma-separated claim values granted the viewer role")
	metricsInterval := fs.Duration("metrics-interval", scaling.RawInterval,
		"how often containerd and the edge are scraped for metrics")
	containerdMetrics := fs.String("containerd-metrics", scaling.DefaultContainerdMetricsURL,
		"containerd's Prometheus endpoint (\"off\" disables cgroup metrics)")
	edgeMetrics := fs.String("edge-metrics", scaling.DefaultEdgeMetricsURL,
		"kanea-edge's metrics endpoint (\"off\" disables the L7 signal)")
	hubbleMetrics := fs.String("hubble-metrics", "",
		"cilium-agent's Hubble endpoint for east-west metrics, e.g. "+
			scaling.DefaultHubbleMetricsURL+" (default: off — Hubble costs CPU per request, PRD §9.1)")
	autoscale := fs.Bool("autoscale", true, "act on the scaling policies services declare (PRD §9.2)")
	buildkit := fs.String("buildkit", gitops.DefaultBuildkitSocket,
		"rootless buildkitd address (\"off\" disables GitOps and builds, PRD §10.2)")
	buildLogDir := fs.String("build-log-dir", "",
		"where build logs are written (default <data-dir>/builds)")
	syncInterval := fs.Duration("sync-interval", DefaultSyncInterval,
		"how often projects with a git source are polled; a webhook makes a push land sooner")
	notifyAllowPrivate := fs.Bool("notify-allow-private", false,
		"allow notification targets on private/loopback addresses — for an internal chat server (PRD §11)")
	notifyAllowHTTP := fs.Bool("notify-allow-http", false,
		"allow plain-http notification targets; https is required by default")
	eventRetention := fs.Int("event-retention", notify.DefaultRetention,
		"how many notification events are kept in the store")
	insecureRegistry := fs.Bool("insecure-registry", false,
		"allow pushing built images over plain HTTP — for a node-local registry only")
	logLevel := fs.String("log-level", "info", "debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger, closer, err := logging.New(logging.Config{Level: *logLevel, Format: "text"})
	if err != nil {
		return fmt.Errorf("logging: %w", err)
	}
	defer func() {
		if err := closer.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "kanea: close log sink:", err)
		}
	}()

	// Signals first: a Ctrl-C during startup should still shut down cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	statePath := filepath.Join(*dataDir, stateFile)
	backupTarget := sinkOptions{
		dir: *backupDir, s3URL: *backupS3, endpoint: *backupS3Endpoint,
		region: *backupS3Region, accessKey: *backupS3AccessKey,
		pathStyle: *backupS3PathStyle,
	}
	if err := os.MkdirAll(*dataDir, 0o750); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	// Before the Store is opened, which is the only moment inside the daemon's
	// own lifetime when §15.3's "on a stopped node" is true of this process.
	if err := restoreAtStart(ctx, bootRestoreOptions{
		dataDir: *dataDir, statePath: statePath,
		keyPath: filepath.Join(*dataDir, secrets.KeyFileName),
		sink:    backupTarget, autoRestore: *autoRestore, log: logger,
	}); err != nil {
		return err
	}

	st, err := store.Open(store.Options{Path: statePath, Logger: logger})
	if err != nil {
		return fmt.Errorf("open state %s: %w", statePath, err)
	}
	defer func() {
		// A store that fails to close may not have flushed; say so rather than
		// exiting 0 on a possibly-corrupt shutdown.
		if err := st.Close(); err != nil {
			logger.Error("close state store", "error", err)
		}
	}()

	// Before anything reads or writes through the Store, and after it is open:
	// the one window where a copy can be taken and a migration has not started.
	if err := migrateAtStart(ctx, st, *dataDir, logger); err != nil {
		return err
	}

	driver, err := runtime.New(runtime.Config{Socket: *containerdSocket, Logger: logger})
	if err != nil {
		return fmt.Errorf("containerd: %w", err)
	}
	defer func() {
		if err := driver.Close(); err != nil {
			logger.Error("close containerd client", "error", err)
		}
	}()

	if err := os.MkdirAll(*logDir, 0o750); err != nil {
		return fmt.Errorf("log dir: %w", err)
	}
	volumes := *volumeDir
	if volumes == "" {
		volumes = filepath.Join(*dataDir, volumeSubdir)
	}
	if err := os.MkdirAll(volumes, 0o750); err != nil {
		return fmt.Errorf("volume dir: %w", err)
	}

	dns, err := buildDNS(*networkMode, *dnsListen, *dnsUpstream, logger)
	if err != nil {
		return err
	}

	// The host-volume allowlist is deliberately an operator input and empty by
	// default: until someone who owns this node names a directory, no job spec
	// can mount one (PRD §6.2 R15).
	hostPolicy, err := storage.NewHostPathPolicy(splitList(*hostPaths))
	if err != nil {
		return err
	}
	if hostPolicy.Enabled() {
		logger.Info("host volumes enabled", "allowed_paths", hostPolicy.Allowed())
	}

	// The secrets store is what lets the credentialed storage drivers actually
	// mount: until now an `auth_ref` refused with ErrCredentialsUnavailable.
	secretStore, err := secrets.Open(secrets.Config{
		Store:   st,
		KeyPath: filepath.Join(*dataDir, secrets.KeyFileName),
		Logger:  logger,
	})
	if err != nil {
		return err
	}

	mounts := storage.New(storage.Config{
		CredentialDir: filepath.Join(*dataDir, credentialSubdir),
		HostPaths:     hostPolicy,
		Secrets:       secretStore,
		Logger:        logger,
	})

	net, err := buildNetwork(ctx, *networkMode, network.Config{
		SocketPath:  *ciliumSocket,
		CNIConfPath: *cniConf,
		CNIBinDir:   *cniBin,
		PolicyDir:   *policyDir,
		LBStateFile: *lbStateFile,
		DNS:         dns,
		Logger:      logger,
	}, logger)
	if err != nil {
		return err
	}

	// The API wakes the reconciler after every apply, so a deploy converges
	// immediately rather than waiting out the interval. The certificate loop
	// wants the same signal, so the notification is fanned out below.
	notify := make(chan struct{}, 1)
	reconcileNotify := make(chan struct{}, 1)
	certNotify := make(chan struct{}, 1)

	// The route table is published for a process that may not be running yet,
	// or ever. That is deliberate: kanead does not supervise the edge and does
	// not depend on it (PRD §5.2.6).
	routesPath := *edgeRoutes
	if routesPath == edgeRoutesOff {
		routesPath = ""
		logger.Info("edge route publishing is disabled")
	}
	if routesPath != "" && *baseDomain == "" {
		logger.Warn("no --base-domain: exposed services get no automatic FQDN",
			"detail", "only services with an explicit expose.domains will be routable")
	}

	// The metrics pipeline never touches the Store (AGENTS.md #2): it is an
	// in-memory time series the scrapers write and the autoscaler reads.
	metrics := scaling.NewMetrics(scaling.MetricsConfig{})

	// One breaker, fed by the reconciler and read by the autoscaler (§4.3).
	// Two of them would each see half the node's failures and neither would
	// trip on a fault both were watching.
	notifier, feed, err := buildNotifier(ctx, notifySettings{
		store:        st,
		secrets:      secretStore,
		allowPrivate: *notifyAllowPrivate,
		allowHTTP:    *notifyAllowHTTP,
		retention:    *eventRetention,
	}, logger)
	if err != nil {
		return err
	}

	breaker := reconciler.NewBreaker(reconciler.BreakerConfig{Logger: logger})

	rec, err := reconciler.New(reconciler.Config{
		Store:         st,
		Driver:        driver,
		Network:       net,
		Logger:        logger,
		LogDir:        *logDir,
		VolumeDir:     volumes,
		ServiceCIDR:   *serviceCIDR,
		ResolvConfDir: filepath.Join(*dataDir, resolvSubdir),
		Nameserver:    nameserverOf(dns),
		Prober:        reconciler.NewProber(driver),
		Breaker:       breaker,
		Emit:          notifier.Publish,
		Mounts:        mounts,
		EdgeSnapshot:  routesPath,
		BaseDomain:    *baseDomain,
	})
	if err != nil {
		return err
	}

	// Auth and the audit trail come before the API server, because the server
	// refuses to authenticate anyone without them and every mutation it accepts
	// is written to them (PRD §13, §14 A01/A09).
	users, err := auth.NewStore(auth.StoreConfig{Store: st, Logger: logger})
	if err != nil {
		return err
	}
	trail, err := audit.Open(ctx, audit.Config{Store: st, Logger: logger})
	if err != nil {
		return err
	}
	configured, err := users.HasUsers(ctx)
	if err != nil {
		return err
	}
	if !configured {
		// §13.1: a daemon with no auth configured is usable, and says so. The
		// unix socket is the only way in until someone creates an account, which
		// is the safe end of the trade rather than a silent public listener.
		logger.Warn("no accounts are configured; the control API accepts only local socket callers",
			"detail", "create one with `kanea user add` before exposing the API to the network")
	}

	// The provider is built before the API so a bad issuer, an unreachable
	// discovery document or a missing role mapping fails at startup, in front
	// of the operator, rather than at the first login in front of a user.
	provider, err := buildOIDC(ctx, oidcSettings{
		issuer: *oidcIssuer, clientID: *oidcClientID, secretRef: *oidcClientSecret,
		redirect: *oidcRedirect, scopes: splitList(*oidcScopes), roleClaim: *oidcRoleClaim,
		admins: splitList(*oidcAdmins), viewers: splitList(*oidcViewers),
	}, secretStore, logger)
	if err != nil {
		return err
	}

	// State replication (§15.3). Built after the secrets store, because the S3
	// secret key is a `secret:` reference like every other credential (R3) and
	// there is nothing to resolve it with until now.
	backups, replicator, err := buildReplication(ctx, replicationSettings{
		sink:             backupTarget,
		secretKeyRef:     *backupS3Secret,
		dataDir:          *dataDir,
		snapshotInterval: *backupInterval,
		segmentInterval:  *backupSegmentInterval,
		retention:        *backupRetention,
		store:            st,
		emit:             notifier.Publish,
	}, secretStore, logger)
	if err != nil {
		return err
	}
	if replicator == nil {
		// Said once, at warning. A node with no backup destination is a node
		// whose entire state lives on one disk, and the operator should have
		// decided that rather than defaulted into it.
		logger.Warn("state replication is not configured",
			"detail", "this node's state exists only on its own disk; "+
				"set --backup-dir or --backup-s3 (PRD §15.3)")
	}

	pipelines, buildQueue, err := buildPipelines(pipelineSettings{
		buildkit:   *buildkit,
		logDir:     resolveBuildLogDir(*buildLogDir, *dataDir),
		interval:   *syncInterval,
		baseDomain: *baseDomain,
		insecure:   *insecureRegistry,
		store:      st,
		secrets:    secretStore,
		notify:     notify,
		emit:       notifier.Publish,
	}, logger)
	if err != nil {
		return err
	}

	// The MCP transport and the API server each need the other: the transport is
	// a route on the API, and its backend is the API's own handler. One of them
	// has to be told about the other after both exist, and a lazy reference is
	// the honest way to write that down — the alternative is a second HTTP
	// client dialling this process's own socket to reach a handler already in
	// memory.
	var apiServer *api.Server
	mcpServer, err := mcp.New(mcp.Config{
		Backend: mcp.HandlerBackend{Handler: func() http.Handler {
			if apiServer == nil {
				return nil
			}
			return apiServer.Handler()
		}},
		Logger:    logger,
		Version:   version,
		ParseSpec: parseSpecSource,
	})
	if err != nil {
		return err
	}

	server, err := api.NewServer(api.ServerConfig{
		Store: st, Logger: logger, Socket: *socket,
		Version: version, LogDir: *logDir, Notify: notify,
		WSOrigins: splitList(*wsOrigins), ServeDashboard: *serveDashboard,
		Secrets: secretStore, Pipelines: pipelines, Auth: users, Accounts: users, Audit: trail,
		Events: feed, NotifyStats: notifier.Stats, Publish: notifier.Publish,
		Notifier: notifier, MCP: mcpServer.HTTPHandler(splitList(*wsOrigins)),
		Backups: backups,
		OIDC:    provider, Sessions: users,
		Metrics: metrics, Breaker: breaker,
		Listen: *listen, TLSCert: *listenCert, TLSKey: *listenKey,
		AuthConfigured: configured, InsecureCookies: *insecureCookies,
	})
	if err != nil {
		return err
	}
	// Closes the loop opened above. Every MCP tool call from here on lands on
	// this handler, which is the same one the CLI and the dashboard reach.
	apiServer = server
	// Bind before announcing readiness: a socket collision must fail loudly at
	// startup, not silently later.
	if err := server.Listen(); err != nil {
		return err
	}

	dnsSolver, err := buildDNSSolver(ctx, dnsUpdateSettings{
		server: *acmeDNSServer, zone: *acmeDNSZone, key: *acmeDNSKey,
		secretRef: *acmeDNSSecret, algorithm: *acmeDNSAlgorithm,
	}, secretStore, logger)
	if err != nil {
		return err
	}
	certs, err := buildCertificates(*acmeEmail, *acmeDirectory, *acmeCA, *edgeCerts,
		*edgeGroup, *acmeVerifyURL, dnsSolver, st, logger)
	if err != nil {
		return err
	}

	logger.Info("kanead starting",
		"version", version, "state", statePath, "socket", *socket,
		"log_dir", *logDir, "volume_dir", volumes, "network", *networkMode)

	tasks := 2
	if dns != nil {
		tasks++
	}
	if certs != nil {
		tasks++
	}
	errs := make(chan error, tasks)
	go fanOut(ctx, notify, reconcileNotify, certNotify)
	go func() { errs <- server.Serve(ctx) }()
	go func() { errs <- rec.Run(ctx, reconcileNotify) }()
	if dns != nil {
		go func() { errs <- dns.Serve(ctx) }()
	}
	if certs != nil {
		go func() {
			errs <- runCertificates(ctx, certs.manager, certs.publisher, st, *baseDomain,
				certNotify, logger, notifier.Publish)
		}()
	}
	// The mount supervisor runs alongside, not inside, the reconcile loop: a
	// probe of a wedged mount can take seconds to abandon, and convergence must
	// not wait for it (M0 spike ③).
	go mounts.Supervise(ctx, storage.DefaultCheckInterval)
	go sweepAuthState(ctx, users, trail, *auditRetention, logger)
	// The dispatcher owns its own goroutine so a wedged channel cannot stall
	// anything that emits: Publish is non-blocking and everything slow happens
	// behind it (AGENTS.md #8).
	go notifier.Run(ctx)
	if replicator != nil {
		// Its own goroutine, and it never touches the control plane's critical
		// path: a bucket that is down means backups stop and say so, never that
		// the platform stops.
		go replicator.Run(ctx)
	}
	if pipelines != nil {
		// The queue worker and the sync loop are separate goroutines on
		// purpose: a build that takes four minutes must not stop the loop
		// noticing that another project moved.
		go buildQueue.Run(ctx)
		go runSync(ctx, pipelines, *syncInterval, logger)
	}
	startMetrics(ctx, metricsSettings{
		metrics:       metrics,
		containerdURL: *containerdMetrics,
		edgeURL:       *edgeMetrics,
		hubbleURL:     *hubbleMetrics,
		interval:      *metricsInterval,
		autoscale:     *autoscale,
		store:         st,
		notify:        notify,
		emit:          notifier.Publish,
	}, logger)

	// Wait for all of them; a context cancellation is a clean shutdown.
	var firstErr error
	for range tasks {
		if err := <-errs; err != nil && !errors.Is(err, context.Canceled) && firstErr == nil {
			firstErr = err
		}
	}
	logger.Info("kanead stopped")
	return firstErr
}

// Auth and audit housekeeping.
const (
	// defaultAuditRetention is how long audit entries are kept (§14, A09 —
	// "log retention configurable"). Long enough that an incident found late
	// still has a trail, short enough that the bucket does not grow forever.
	defaultAuditRetention = 90 * 24 * time.Hour
	// sweepInterval is how often expired state is cleared. Neither job is
	// urgent: an expired session is already refused on use, and a stale audit
	// entry is only taking space.
	sweepInterval = time.Hour
)

// sweepAuthState clears expired sessions and prunes the audit log.
//
// Sessions are also removed when a caller presents an expired one, so this is
// the path for the ones nobody comes back for — the browser tab that was closed
// and never reopened. Without it, every login leaves a record forever.
func sweepAuthState(ctx context.Context, users *auth.Store, trail *audit.Log,
	retention time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if removed, err := users.SweepSessions(ctx); err != nil {
			logger.Warn("cannot sweep expired sessions", "error", err)
		} else if removed > 0 {
			logger.Debug("swept expired sessions", "sessions", removed)
		}

		if retention <= 0 {
			continue
		}
		// A prune is a delete of state that exists to be evidence, so it says
		// what it removed rather than doing it quietly.
		if pruned, err := trail.Prune(ctx, time.Now().Add(-retention)); err != nil {
			logger.Warn("cannot prune the audit log", "error", err)
		} else if pruned > 0 {
			logger.Info("pruned audit entries past retention",
				"entries", pruned, "retention", retention)
		}
	}
}

// Network driver names for --network.
const (
	// networkCilium is the product: eBPF datapath, per-project policy, service LB.
	networkCilium = "cilium"
	// networkNetns gives each alloc a bare namespace and nothing else. It exists
	// so kanead can run on a host without Cilium — a laptop, a CI job — and is
	// not a supported deployment: no policy is enforced and no service is load
	// balanced, so allocs are unreachable by name.
	networkNetns = "netns"
)

// buildNetwork selects the network driver.
//
// An unreachable cilium-agent is a warning, not a startup failure. Refusing to
// start would take the control API down with it — and the API is exactly what
// an operator needs in order to see why the node is unhealthy. The reconciler
// already treats a failed action as retryable, so attaches resume on their own
// once the agent is back.
func buildNetwork(ctx context.Context, mode string, cfg network.Config, logger *slog.Logger) (reconciler.Network, error) {
	switch mode {
	case networkNetns:
		logger.Warn("network policy and service load balancing are disabled",
			"network", networkNetns, "detail", "development mode: allocs get a bare namespace")
		return reconciler.NetnsNetwork{}, nil

	case networkCilium:
		net, err := network.New(cfg)
		if err != nil {
			return nil, fmt.Errorf("network: %w", err)
		}
		healthCtx, cancel := context.WithTimeout(ctx, ciliumHealthTimeout)
		defer cancel()
		if err := net.Health(healthCtx); err != nil {
			logger.Warn("cilium agent is not answering; allocs cannot attach until it is",
				"socket", cfg.SocketPath, "error", err)
		}
		return net, nil

	default:
		return nil, fmt.Errorf("unknown --network %q: want %s or %s", mode, networkCilium, networkNetns)
	}
}

// ciliumHealthTimeout bounds the startup probe. It is short on purpose: this is
// a diagnostic, and kanead starts either way.
const ciliumHealthTimeout = 5 * time.Second

// DNS wiring.
const (
	// dnsOff disables the embedded resolver.
	dnsOff = "off"
	// ciliumHostInterface carries the node's address inside the cluster CIDR.
	// It is the one address reachable from every alloc's namespace *and* from
	// the host, which is exactly what a node-local resolver needs.
	ciliumHostInterface = "cilium_host"
)

// buildDNS constructs the embedded resolver, or nil when it is not wanted.
//
// The listen address defaults to the cilium_host interface rather than a
// wildcard. That is a security decision, not a convenience one: a resolver
// bound to 0.0.0.0 is reachable on the node's public interface, which makes it
// a DNS amplification source and lets anyone on the network enumerate the
// services running here. network.NewDNS refuses a wildcard outright; this
// picks a sensible specific address so nobody is tempted to pass one.
func buildDNS(mode, listen, upstreams string, logger *slog.Logger) (*network.DNS, error) {
	if listen == dnsOff {
		logger.Warn("internal DNS is disabled; services are reachable only by address")
		return nil, nil
	}
	if mode != networkCilium {
		// Without the Cilium datapath there are no service frontends to answer
		// with, so a resolver would serve an empty zone.
		return nil, nil
	}

	if listen == "" {
		addr, err := interfaceAddr(ciliumHostInterface)
		if err != nil {
			return nil, fmt.Errorf("internal DNS: %w (pass --dns-listen, or --dns-listen=off)", err)
		}
		listen = net.JoinHostPort(addr, strconv.Itoa(network.DefaultDNSPort))
	}

	resolvers, err := upstreamResolvers(upstreams)
	if err != nil {
		return nil, err
	}
	return network.NewDNS(network.DNSConfig{
		Listen:    listen,
		Upstreams: resolvers,
		Logger:    logger,
	})
}

// nameserverOf reports the address allocs should be pointed at.
func nameserverOf(dns *network.DNS) string {
	if dns == nil {
		return ""
	}
	return dns.Listen()
}

// interfaceAddr returns the first IPv4 address on a named interface.
func interfaceAddr(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("interface %s not found", name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("interface %s: %w", name, err)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if v4 := ipnet.IP.To4(); v4 != nil {
				return v4.String(), nil
			}
		}
	}
	return "", fmt.Errorf("interface %s has no IPv4 address", name)
}

// upstreamResolvers parses the forwarding targets, defaulting to the host's.
//
// Forwarding to the host's own resolvers keeps a workload's view of the
// internet identical to the node's, which is what an operator expects when they
// configure DNS once in /etc/resolv.conf.
func upstreamResolvers(configured string) ([]string, error) {
	if configured != "" {
		return splitList(configured), nil
	}
	return network.HostResolvers()
}

// splitList parses a comma-separated flag value, dropping empty entries.
func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// fanOut forwards one wake-up signal to several listeners.
//
// The sends are non-blocking because every listener's channel is a
// coalescing buffer of one: a listener that is mid-pass already has everything
// this signal would tell it, and a blocking send would let a slow consumer
// stall the API's apply path.
func fanOut(ctx context.Context, in <-chan struct{}, out ...chan<- struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-in:
			for _, ch := range out {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}
}
