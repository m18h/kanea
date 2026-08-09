package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/audit"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/autoupdate"
	"github.com/m18h/kanea/internal/backup"
	"github.com/m18h/kanea/internal/certsource"
	"github.com/m18h/kanea/internal/datapath"
	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/logging"
	"github.com/m18h/kanea/internal/mcp"
	"github.com/m18h/kanea/internal/network"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/passthrough"
	"github.com/m18h/kanea/internal/provision"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/scaling"
	"github.com/m18h/kanea/internal/secrets"
	"github.com/m18h/kanea/internal/storage"
	"github.com/m18h/kanea/internal/store"
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
	networkMode := fs.String("network", networkEBPF,
		"network driver: ebpf, or netns for development (no policy, no service LB)")
	bpfDir := fs.String("bpf-dir", dpmap.PinRoot,
		"bpffs directory the datapath pins its maps, programs and links under")
	nodeCIDR := fs.String("node-cidr", provision.DefaultNodeCIDR,
		"this node's container subnet; its .1 is the datapath host address")
	clusterCIDR := fs.String("cluster-cidr", provision.DefaultClusterCIDR,
		"what the masquerade rule treats as internal; must contain --node-cidr")
	hostPaths := fs.String("allowed-host-paths", "",
		"comma-separated directories that `host` volumes may mount from (default: none)")
	passthroughConfig := fs.String("passthrough-config", "",
		"HCL file granting host devices and sockets to named projects (default: no grants)")
	serviceCIDR := fs.String("service-cidr", reconciler.DefaultServiceCIDR, "pool for service frontend addresses")
	dnsListen := fs.String("dns-listen", "",
		"internal DNS listen address (default: the node CIDR's .1, the "+
			datapath.HostInterface+" address; \"off\" disables)")
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
	tlsDefault := fs.String("tls-default", string(certsource.ModeACME),
		"certificate source for an exposed service whose spec declares no tls block: "+
			"acme, self-signed, provided, or plaintext (PRD §6.2 R20)")
	tlsCAName := fs.String("tls-ca-name", "",
		"how this node's self-signed CA is named in a device's trust list (default: --base-domain, else the hostname)")
	tlsCertsConfig := fs.String("tls-certs-config", "",
		"HCL file granting operator-provided certificates to named projects (default: no grants)")
	publishPorts := fs.String("publish-ports", api.DefaultPublishRange,
		"node ports a spec may publish, e.g. \"1024-65535\" or \"8000-9000,25565\" (\"off\" disables)")
	acmeEmail := fs.String("acme-email", "",
		"ACME account contact; without it no certificates are obtained from a CA")
	acmeDirectory := fs.String("acme-directory", DirectoryProduction,
		"ACME directory: \"production\", \"staging\", or a URL")
	acmeCA := fs.String("acme-ca-bundle", "",
		"extra CA to trust when talking to the ACME directory (for a private or test CA)")
	acmeVerifyURL := fs.String("acme-verify-url", certsource.DefaultVerifyURL,
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

	if err := validNetworkMode(*networkMode); err != nil {
		return err
	}
	// kanead is the IPAM now (PRD v1.36): nothing downstream re-validates the
	// subnets, so a typo has to be refused here rather than presenting as a
	// datapath that hands out unroutable addresses.
	var cidrs agentCIDRs
	if *networkMode == networkEBPF {
		parsed, err := parseAgentCIDRs(*nodeCIDR, *clusterCIDR, *serviceCIDR)
		if err != nil {
			return err
		}
		cidrs = parsed
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

	dns, err := buildDNS(*networkMode, *dnsListen, *dnsUpstream, cidrs.node, logger)
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

	// Device and socket grants are the same kind of operator input and the same
	// empty default (PRD §6.2 R17–R18). A configured socket grant is logged at
	// warn: it is node-level control for whoever holds it, and the one place
	// that is unambiguously recorded should be the node's own log.
	grants, err := passthrough.Load(*passthroughConfig)
	if err != nil {
		return err
	}
	if grants.Enabled() {
		logger.Warn("device and socket passthrough is configured",
			"config", *passthroughConfig,
			"note", "a granted runtime socket is equivalent to root on this node")
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

	net, err := buildNetwork(ctx, *networkMode, datapath.Config{
		NodeCIDR:    cidrs.node,
		ClusterCIDR: cidrs.cluster,
		ServiceCIDR: cidrs.service,
		BPFDir:      *bpfDir,
		Store:       st,
		DNS:         dns,
		Logger:      logger,
	}, logger)
	if err != nil {
		return err
	}

	// The east-west metrics view, when the driver has one. Only the real
	// datapath does: netns mode has no counters, and says so in startMetrics.
	var flows scaling.FlowSource
	if dp, ok := net.(*datapath.Datapath); ok {
		if source := dp.CounterSource(); source != nil {
			flows = datapathFlows{source: source, datapath: dp}
		}
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

	// The edge's labelled families bypass that time series entirely (§9.1.1):
	// the scrape loop fills this holder and the exporter reads it, so the
	// per-code and per-method cardinality never reaches the rings the
	// autoscaler evaluates. Created here, before either side, because both take
	// it and neither may depend on the other having started.
	edgeExposition := scaling.NewEdgeExposition()

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

	breaker := reconciler.NewBreaker(reconciler.BreakerConfig{
		Logger: logger,
		// Trips survive a restart (v1.37): a daemon restart is most likely
		// during exactly the node-wide fault the breaker is open for.
		Persist: persistBreaker(context.WithoutCancel(ctx), st, logger),
	})
	restoreBreaker(ctx, st, breaker, logger)

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
		Passthrough:   grants,
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
	// Account lockouts survive the restart (v1.37) — before this, restarting
	// the daemon reset the §13.3 brute-force defence.
	if err := users.LoadLockouts(ctx); err != nil {
		logger.Warn("cannot restore login lockouts; starting without them", "error", err)
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

	// The image watcher follows the tags services declare (§6.2 R19). It is
	// inert for every service that has not asked: the sweep only looks at
	// records with update.auto set.
	updates, err := autoupdate.New(autoupdate.Config{
		Store:    st,
		Resolver: driver,
		Secrets:  secretStore,
		Logger:   logger,
		Emit:     notifier.Publish,
		Wake:     reconcileNotify,
	})
	if err != nil {
		return err
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

	dnsSolver, err := buildDNSSolver(ctx, dnsUpdateSettings{
		server: *acmeDNSServer, zone: *acmeDNSZone, key: *acmeDNSKey,
		secretRef: *acmeDNSSecret, algorithm: *acmeDNSAlgorithm,
	}, secretStore, logger)
	if err != nil {
		return err
	}
	// Parsed before the server is built, so a typo in the range is a refusal at
	// startup rather than a service that publishes nothing and says why once
	// per apply.
	portPolicy, err := api.ParsePortPolicy(*publishPorts)
	if err != nil {
		return err
	}
	if !portPolicy.Enabled() {
		logger.Info("published ports are disabled on this node", "detail", "--publish-ports off")
	}
	certs, err := buildCertificates(certConfig{
		Email:       *acmeEmail,
		Directory:   *acmeDirectory,
		CAPath:      *acmeCA,
		BundlePath:  *edgeCerts,
		Group:       *edgeGroup,
		VerifyURL:   *acmeVerifyURL,
		BaseDomain:  *baseDomain,
		Default:     *tlsDefault,
		CAName:      *tlsCAName,
		CertsConfig: *tlsCertsConfig,
		DNSSolver:   dnsSolver,
		Store:       st,
		Logger:      logger,
	})
	if err != nil {
		return err
	}

	// One reader for the API's point-in-time stats and the history recorder
	// alike: CPU percent is a delta between readings, and two readers would
	// each see only half the sample history (v1.38).
	nodeReader := scaling.NewNodeReader("")

	server, err := api.NewServer(api.ServerConfig{
		Store: st, Logger: logger, Socket: *socket,
		Version: version, LogDir: *logDir, Notify: notify,
		WSOrigins: splitList(*wsOrigins), ServeDashboard: *serveDashboard,
		Secrets: secretStore, Pipelines: pipelines, Auth: users, Accounts: users, Audit: trail,
		Events: feed, NotifyStats: notifier.Stats, Publish: notifier.Publish,
		Notifier: notifier, MCP: mcpServer.HTTPHandler(splitList(*wsOrigins)),
		Backups: backups, CA: certificateAuthority(certs),
		PublishPorts: portPolicy,
		OIDC:         provider, Sessions: users,
		Metrics: metrics, EdgeMetrics: edgeExposition,
		Breaker: breaker, Node: nodeReader,
		// The editor's renderer parses with the node's own base domain — the
		// same options the GitOps sync uses, so a spec means the same thing
		// whichever door it arrives through (v1.38).
		Spec:   specRenderer{opts: jobspec.Options{BaseDomain: *baseDomain}},
		Exec:   driver,
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
			errs <- runCertificates(ctx, certs, st, *baseDomain, *tlsDefault,
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
	// Its own goroutine for the same reason the sync loop is: a registry that
	// takes thirty seconds to answer must not hold up convergence. It writes a
	// digest and the reconciler does the rest (§6.2 R19).
	go func() {
		// Run only ever returns because the context ended, which is shutdown
		// and not news. Logged at debug so a stuck loop is still findable.
		if err := updates.Run(ctx); err != nil {
			logger.Debug("image auto-update stopped", "error", err)
		}
	}()
	startMetrics(ctx, metricsSettings{
		metrics:       metrics,
		exposition:    edgeExposition,
		containerdURL: *containerdMetrics,
		edgeURL:       *edgeMetrics,
		flows:         flows,
		node:          nodeReader,
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
	// networkEBPF is the product: Kanea's own eBPF datapath — connect-time
	// service LB, per-project policy, per-CPU counters (PRD v1.36, §5.2.5).
	networkEBPF = "ebpf"
	// networkNetns gives each alloc a bare namespace and nothing else. It exists
	// so kanead can run on a host without the datapath — a laptop, a CI job —
	// and is not a supported deployment: no policy is enforced and no service is
	// load balanced, so allocs are unreachable by name.
	networkNetns = "netns"
)

// validNetworkMode refuses anything but the two modes, up front. Before v1.36
// any value other than one recognised name silently selected the product mode,
// so a typo configured a node by accident.
func validNetworkMode(mode string) error {
	if mode != networkEBPF && mode != networkNetns {
		return fmt.Errorf("unknown --network %q: want %s or %s", mode, networkEBPF, networkNetns)
	}
	return nil
}

// agentCIDRs is the parsed subnet trio the ebpf mode runs on.
type agentCIDRs struct {
	node, cluster, service netip.Prefix
}

// parseAgentCIDRs validates the subnets against each other, mirroring the
// shape of preflight's checkSubnets: `kanea doctor` can only warn in advance,
// while this is the refusal that actually gates startup — GitOps and systemd
// reach kanead without ever passing through doctor.
func parseAgentCIDRs(node, cluster, service string) (agentCIDRs, error) {
	var out agentCIDRs
	for _, p := range []struct {
		flag  string
		value string
		into  *netip.Prefix
	}{
		{"--node-cidr", node, &out.node},
		{"--cluster-cidr", cluster, &out.cluster},
		{"--service-cidr", service, &out.service},
	} {
		prefix, err := netip.ParsePrefix(p.value)
		if err != nil {
			return out, fmt.Errorf("%s %q is not a CIDR", p.flag, p.value)
		}
		if !prefix.Addr().Is4() {
			return out, fmt.Errorf("%s %q is not an IPv4 prefix", p.flag, p.value)
		}
		*p.into = prefix.Masked()
	}
	if !out.cluster.Contains(out.node.Addr()) || out.node.Bits() < out.cluster.Bits() {
		return out, fmt.Errorf("--node-cidr %s is not within --cluster-cidr %s", node, cluster)
	}
	for _, c := range []struct {
		flag   string
		prefix netip.Prefix
	}{
		{"--node-cidr", out.node}, {"--cluster-cidr", out.cluster},
	} {
		if c.prefix.Overlaps(out.service) {
			return out, fmt.Errorf("%s %s overlaps --service-cidr %s; a service frontend would be "+
				"handed an address that is also a container address", c.flag, c.prefix, service)
		}
	}
	return out, nil
}

// buildNetwork selects the network driver.
//
// An Init failure in ebpf mode is a hard startup error, deliberately unlike
// the warn-and-continue the old external agent got: there is no separate
// process that might come up later. Loading the programs *is* the datapath —
// if that fails, nothing will ever pass traffic, there is nothing to retry
// against, and a control plane that started anyway would converge every alloc
// onto a network that silently drops everything.
func buildNetwork(ctx context.Context, mode string, cfg datapath.Config, logger *slog.Logger) (reconciler.Network, error) {
	switch mode {
	case networkNetns:
		logger.Warn("network policy and service load balancing are disabled",
			"network", networkNetns, "detail", "development mode: allocs get a bare namespace")
		return reconciler.NetnsNetwork{}, nil

	case networkEBPF:
		dp, err := datapath.New(cfg)
		if err != nil {
			return nil, fmt.Errorf("network: %w", err)
		}
		if err := dp.Init(ctx); err != nil {
			return nil, fmt.Errorf("network: %w", err)
		}
		return dp, nil

	default:
		return nil, fmt.Errorf("unknown --network %q: want %s or %s", mode, networkEBPF, networkNetns)
	}
}

// DNS wiring.
const (
	// dnsOff disables the embedded resolver.
	dnsOff = "off"
)

// buildDNS constructs the embedded resolver, or nil when it is not wanted.
//
// The listen address defaults to the node CIDR's .1 — the address Init puts on
// the datapath's host anchor (kanea0) — rather than a wildcard. That is a
// security decision, not a convenience one: a resolver bound to 0.0.0.0 is
// reachable on the node's public interface, which makes it a DNS amplification
// source and lets anyone on the network enumerate the services running here.
// network.NewDNS refuses a wildcard outright; this picks a sensible specific
// address so nobody is tempted to pass one.
//
// The address is computed from the CIDR rather than read off the interface:
// at this point Init has not run and kanea0 may not exist yet, and the CIDR
// determines the address either way. The socket itself is bound in Serve,
// which runAgent starts only after buildNetwork's Init has created the
// interface, so the address is bindable by then.
func buildDNS(mode, listen, upstreams string, nodeCIDR netip.Prefix, logger *slog.Logger) (*network.DNS, error) {
	if listen == dnsOff {
		logger.Warn("internal DNS is disabled; services are reachable only by address")
		return nil, nil
	}
	if mode == networkNetns {
		// Without the datapath there are no service frontends to answer with,
		// so a resolver would serve an empty zone.
		logger.Info("internal DNS is disabled in netns mode",
			"detail", "no service frontends exist without the datapath")
		return nil, nil
	}

	if listen == "" {
		hostAddr := nodeCIDR.Masked().Addr().Next() // the .1, datapath.HostInterface's address
		listen = net.JoinHostPort(hostAddr.String(), strconv.Itoa(network.DefaultDNSPort))
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
