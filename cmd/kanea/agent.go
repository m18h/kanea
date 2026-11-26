package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/audit"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/autoupdate"
	"github.com/m18h/kanea/internal/certsource"
	"github.com/m18h/kanea/internal/datapath"
	"github.com/m18h/kanea/internal/functions"
	"github.com/m18h/kanea/internal/imagegc"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/logging"
	"github.com/m18h/kanea/internal/mcp"
	"github.com/m18h/kanea/internal/network"
	"github.com/m18h/kanea/internal/nodeconfig"
	"github.com/m18h/kanea/internal/passthrough"
	"github.com/m18h/kanea/internal/provision"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/scaling"
	"github.com/m18h/kanea/internal/secrets"
	"github.com/m18h/kanea/internal/secretsource"
	"github.com/m18h/kanea/internal/storage"
	"github.com/m18h/kanea/internal/store"
)

// Default filesystem layout: what the node config's data_dir and
// alloc_log_dir default to (PRD §15.1).
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
	// filesSubdir holds spec-declared config files that interpolate no secret
	// (jobspec R35). Under the data directory rather than under the tmpfs root
	// beside the secret-bearing ones: that root becomes a mount point on first
	// use, and a tmpfs mounted over a directory hides what is already in it.
	filesSubdir = "files"
	// credentialSubdir holds transient mount credential files.
	credentialSubdir = "credentials"
	// edgeRoutesOff disables publishing the edge route table.
	edgeRoutesOff = "off"
)

// runAgent is kanead: the control plane. It owns the state file (bbolt is
// single-writer, so nothing else may open it) and therefore also serves the
// API that the CLI uses to reach that state.
//
// It takes no arguments (PRD §15.1, v1.115): everything it is configured
// with is /etc/kanea/kanea.hcl, read once, here, before anything else runs.
func runAgent(args []string) error {
	if len(args) > 0 {
		return daemonArgs("agent", args)
	}
	// First, before even the logger: the log level is one of its attributes.
	// A file that does not load is fatal and said on stderr, which is the
	// journal under systemd.
	nodeCfg, err := nodeconfig.Probe(nodeconfig.DefaultPath)
	if err != nil {
		return err
	}
	s := resolveAgentSettings(nodeCfg)

	// kanead is the IPAM (PRD v1.36): nothing downstream re-validates the
	// subnets, so a typo has to be refused here rather than presenting as a
	// datapath that hands out unroutable addresses.
	cidrs, err := parseAgentCIDRs(s.nodeCIDR, s.clusterCIDR, s.serviceCIDR,
		s.nodeCIDR6, s.clusterCIDR6, s.serviceCIDR6, configLabel)
	if err != nil {
		return err
	}

	logger, closer, err := logging.New(logging.Config{Level: s.logLevel, Format: "text"})
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

	statePath := filepath.Join(s.dataDir, stateFile)
	backupTarget := sinkOptions{
		dir: s.backupDir, s3URL: s.backupS3, endpoint: s.backupS3Endpoint,
		region: s.backupS3Region, accessKey: s.backupS3AccessKey,
		pathStyle: s.backupS3PathStyle,
	}
	if err := os.MkdirAll(s.dataDir, 0o750); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	// Before the Store is opened, which is the only moment inside the daemon's
	// own lifetime when §15.3's "on a stopped node" is true of this process.
	if err := restoreAtStart(ctx, bootRestoreOptions{
		dataDir: s.dataDir, statePath: statePath,
		keyPath: filepath.Join(s.dataDir, secrets.KeyFileName),
		sink:    backupTarget, autoRestore: s.autoRestore, log: logger,
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
	if err := migrateAtStart(ctx, st, s.dataDir, logger); err != nil {
		return err
	}

	driver, err := runtime.New(runtime.Config{Socket: s.containerdSocket, Logger: logger})
	if err != nil {
		return fmt.Errorf("containerd: %w", err)
	}
	defer func() {
		if err := driver.Close(); err != nil {
			logger.Error("close containerd client", "error", err)
		}
	}()

	if err := os.MkdirAll(s.logDir, 0o750); err != nil {
		return fmt.Errorf("log dir: %w", err)
	}
	volumes := s.volumeDir
	if volumes == "" {
		volumes = filepath.Join(s.dataDir, volumeSubdir)
	}
	if err := os.MkdirAll(volumes, 0o750); err != nil {
		return fmt.Errorf("volume dir: %w", err)
	}

	if nodeCfg.Path != "" {
		logger.Info("node config loaded", "config", nodeCfg.Path)
	} else {
		logger.Info("no node config; every setting is its default", "config", nodeconfig.DefaultPath)
	}
	if len(nodeCfg.Ignored) > 0 {
		logger.Warn("node config carries stanzas this version does not read",
			"config", nodeCfg.Path, "ignored", nodeCfg.Ignored)
	}

	// The node's default pull policy (R33, v1.84): if-not-present unless the
	// images stanza says otherwise, already checked at load. A service's own
	// task.pull_policy wins over it; this is the answer for a record that
	// declares none.
	pullPolicy := or(nodeCfg.ImagePullPolicy, runtime.PullIfNotPresent)

	// The internal resolver: the dns stanza's upstreams, or the host's
	// resolv.conf when it names none (v1.66).
	dns, err := buildDNS(s.dnsListen, s.dnsUpstream, cidrs.node, logger)
	if err != nil {
		return err
	}

	// The API/dashboard listener (§15.1 bind, v1.61). The stanza is atomic:
	// the address and its TLS story are one declaration.
	apiL := apiListenFromConfig(nodeCfg)
	if apiL.addr != "" {
		logger.Info("api/dashboard listener", "listen", apiL.addr, "tls", apiL.mode)
	}
	apiInsecureCookies := s.insecureCookies
	if apiL.mode == nodeconfig.TLSPlaintext {
		if public, err := api.IsPublicAddr(apiL.addr); err == nil && public {
			// Typed, so allowed, and said loudly, once, where the decision
			// lives. The Secure cookie attribute is dropped with it: a Secure
			// cookie over plain HTTP is a login that silently fails (v1.61).
			apiInsecureCookies = true
			logger.Warn("the API/dashboard listener serves plain HTTP beyond loopback (bind.api_tls = \"plaintext\")",
				"listen", apiL.addr,
				"detail", "credentials cross this network unencrypted; session cookies drop the Secure attribute")
		}
	}

	// The host-volume allowlist is deliberately an operator input and empty by
	// default: until someone who owns this node names a directory, no job spec
	// can mount one (PRD §6.2 R15).
	hostPolicy, err := storage.NewHostPathPolicy(nodeCfg.AllowedHostPaths)
	if err != nil {
		return err
	}
	if hostPolicy.Enabled() {
		logger.Info("host volumes enabled", "allowed_paths", hostPolicy.Allowed())
	}

	// Device and socket grants are the same kind of operator input and the same
	// empty default (PRD §6.2 R17-R18), decoded from the bytes already read:
	// one read of the file, one trust check. A configured socket grant is
	// logged at warn: it is node-level control for whoever holds it, and the
	// one place that is unambiguously recorded should be the node's own log.
	grants, err := passthrough.Parse(nodeCfg.Path, nodeCfg.Source)
	if err != nil {
		return err
	}
	if grants.Enabled() {
		logger.Warn("device and socket passthrough is configured",
			"config", nodeCfg.Path,
			"note", "a granted runtime socket is equivalent to root on this node")
	}

	// The secrets store is what lets the credentialed storage drivers actually
	// mount: until now an `auth_ref` refused with ErrCredentialsUnavailable.
	secretStore, err := secrets.Open(secrets.Config{
		Store:   st,
		KeyPath: filepath.Join(s.dataDir, secrets.KeyFileName),
		Logger:  logger,
	})
	if err != nil {
		return err
	}

	// External secret providers (PRD §5.2.13): a sync loop pulls mapped
	// values into the store above, so everything downstream (including every
	// consumer wired in this function) reads them with no idea where they
	// came from. The reconciler never waits for a pass; the store serves
	// whatever the last one wrote.
	if s.secretsSyncInterval < secretSyncMinInterval {
		return fmt.Errorf("%s %s is below the %s floor: "+
			"a poll is a request against a provider's rate limit",
			configLabel("secrets.sync_interval"), s.secretsSyncInterval, secretSyncMinInterval)
	}
	// The provider blocks, from the same bytes: a malformed block is fatal
	// here like any other part of the file (the load-once family), while the
	// credential files they point at stay in the reload family.
	secretProviders, err := secretsource.NewProviders(nodeCfg.Path, nodeCfg.Source,
		secretsource.DefaultHTTPClient(), logger)
	if err != nil {
		return err
	}
	secretSyncer := secretsource.NewSyncer(secretsource.SyncerConfig{
		Providers: secretProviders, Target: secretStore, Logger: logger,
	})
	if secretProviders.Configured() {
		logger.Info("external secret providers configured", "config", nodeCfg.Path)
	}

	buildUID := buildEgressUID(logger)
	subStart, subCount := buildSubUIDRange(buildUID, logger)
	net, err := buildNetwork(ctx, datapath.Config{
		NodeCIDR:     cidrs.node,
		ClusterCIDR:  cidrs.cluster,
		ServiceCIDR:  cidrs.service,
		NodeCIDR6:    cidrs.node6,
		ClusterCIDR6: cidrs.cluster6,
		ServiceCIDR6: cidrs.service6,
		BPFDir:       s.bpfDir,
		Store:        st,
		DNS:          dns,
		// The build-egress drop (v1.75) keys on the build daemon's uid. A
		// node without the account (no install, no pipelines) gets no rule:
		// there is no build traffic to filter, and a rule keyed on a uid
		// nobody owns would match nothing anyway.
		BuildEgressUID: buildUID,
		// And on its subordinate range (v1.105): a Dockerfile USER step runs
		// as a subuid, which the uid rule never matches.
		BuildSubUIDStart: subStart,
		BuildSubUIDCount: subCount,
		Logger:           logger,
	})
	if err != nil {
		return err
	}

	// The east-west metrics view. Nil where the platform seams carry no
	// counters (every non-linux build); startMetrics says so.
	var flows scaling.FlowSource
	if source := net.CounterSource(); source != nil {
		flows = datapathFlows{source: source, datapath: net}
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
	routesPath := s.edgeRoutes
	if routesPath == edgeRoutesOff {
		routesPath = ""
		logger.Info("edge route publishing is disabled")
	}
	if routesPath != "" && s.baseDomain == "" {
		logger.Warn("no base_domain: exposed services get no automatic FQDN",
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
	notifyCfg := notifySettings{
		store:        st,
		secrets:      secretStore,
		allowPrivate: s.notifyAllowPrivate,
		allowHTTP:    s.notifyAllowHTTP,
		retention:    s.eventRetention,
	}
	notifier, feed, tee, err := buildNotifier(ctx, notifyCfg, logger)
	if err != nil {
		return err
	}

	// The mount manager is built here rather than earlier because it needs the
	// notifier: a volume that will not mount, and one the supervisor recovered,
	// are both things an operator should hear about (v1.69), and before that
	// existed the entire story lived in the daemon log.
	mounts := storage.New(storage.Config{
		CredentialDir: filepath.Join(s.dataDir, credentialSubdir),
		HostPaths:     hostPolicy,
		Secrets:       secretStore,
		Logger:        logger,
		Emit:          notifier.Publish,
	})

	// The volume usage sampler (R31). It measures on its own slow schedule and
	// is told what exists by the reconciler each pass; nothing it holds touches
	// the Store (constraint #2).
	volumeUsage := storage.NewUsageSampler(storage.UsageConfig{
		Emit:   notifier.Publish,
		Logger: logger,
	})
	go volumeUsage.Run(ctx)

	// The function invoker (v1.39, §11): event triggers tee off the
	// dispatcher's feed, cron triggers run on its own schedule, and both POST
	// to VIPs the Store derived, never a URL a spec could hold (R26).
	// Attached to the tee before notifier.Run starts; woken by the same
	// store-change signal the reconciler gets, so `kanea apply` wires a new
	// trigger with no restart.
	invoker, err := functions.New(functions.Config{
		Source: functionTargets{store: st},
		Logger: logger,
		// The signing secret is resolved per delivery, never stored on the
		// target list (R26, v1.40).
		Resolver: secretStore,
		Publish:  notifier.Publish,
	})
	if err != nil {
		return err
	}
	tee.secondary = invoker

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
		LogDir:        s.logDir,
		VolumeDir:     volumes,
		ServiceCIDR:   s.serviceCIDR,
		ServiceCIDR6:  s.serviceCIDR6,
		ResolvConfDir: filepath.Join(s.dataDir, resolvSubdir),
		PlainFilesDir: filepath.Join(s.dataDir, filesSubdir),
		Nameserver:    nameserverOf(dns),
		Prober:        reconciler.NewProber(driver),
		Breaker:       breaker,
		Emit:          notifier.Publish,
		Mounts:        mounts,
		VolumeUsage:   volumeUsage,
		Passthrough:   grants,
		// Without this the reconciler holds a nil resolver, and every service
		// that names a `secret:` env ref, a registry credential or route auth
		// fails its alloc on a node whose secrets store is perfectly healthy.
		// Every reconciler test supplies its own, which is why nothing caught
		// the daemon never supplying one.
		Secrets:      secretStore,
		EdgeSnapshot: routesPath,
		BaseDomain:   s.baseDomain,
		// R33's node default. Without it every record that declares no policy
		// would fall to the driver's zero value, which happens to be the same
		// behaviour today - so a missing wire here is invisible until someone
		// sets `images { pull_policy = "never" }` and the node keeps pulling.
		DefaultPullPolicy: pullPolicy,
	})
	if err != nil {
		return err
	}

	// The directory verifier is built before the auth store so it wires at
	// construction (no mutation window) and like OIDC it fails on bad
	// config at startup, in front of the operator; only *reachability* is a
	// warning (§3.20: an unreachable directory is weather).
	directory, err := buildLDAP(ctx, ldapSettings{
		url: s.ldapURL, bindDN: s.ldapBindDN, bindRef: s.ldapBindPassword,
		userBaseDN: s.ldapUserBaseDN, userFilter: s.ldapUserFilter,
		groupBaseDN: s.ldapGroupBaseDN, groupFilter: s.ldapGroupFilter,
		adminGroups: s.ldapAdmins, viewerGroups: s.ldapViewers,
		caFile: s.ldapCA,
	}, secretStore, logger)
	if err != nil {
		return err
	}

	// Auth and the audit trail come before the API server, because the server
	// refuses to authenticate anyone without them and every mutation it accepts
	// is written to them (PRD §13, §14 A01/A09).
	users, err := auth.NewStore(auth.StoreConfig{
		Store: st, Logger: logger, Verifier: ldapVerifier(directory),
	})
	if err != nil {
		return err
	}
	// Account lockouts survive the restart (v1.37); before this, restarting
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
		issuer: s.oidcIssuer, clientID: s.oidcClientID, secretRef: s.oidcClientSecret,
		redirect: s.oidcRedirect, scopes: s.oidcScopes, roleClaim: s.oidcRoleClaim,
		admins: s.oidcAdmins, viewers: s.oidcViewers,
	}, secretStore, logger)
	if err != nil {
		return err
	}

	// State replication (§15.3). Built after the secrets store, because the S3
	// secret key is a `secret:` reference like every other credential (R3) and
	// there is nothing to resolve it with until now. The backup stanza is the
	// seed; a settings/backup record in the Store, once written, wins (v1.46).
	fileRepl := replicationSettings{
		sink:             backupTarget,
		secretKeyRef:     s.backupS3Secret,
		dataDir:          s.dataDir,
		snapshotInterval: s.backupInterval,
		segmentInterval:  s.backupSegmentInterval,
		retention:        s.backupRetention,
		store:            st,
		emit:             notifier.Publish,
	}
	backups, err := buildBackups(ctx, fileRepl, secretStore, logger)
	if err != nil {
		return err
	}
	if !backups.configured() {
		// Said once, at warning. A node with no backup destination is a node
		// whose entire state lives on one disk, and the operator should have
		// decided that rather than defaulted into it.
		logger.Warn("state replication is not configured",
			"detail", "this node's state exists only on its own disk; "+
				"set backup.dir or backup.s3 in "+nodeconfig.DefaultPath+
				", or use the dashboard's Settings page")
	}

	// The settings service (v1.46): the API's window onto what this block just
	// decided, and the runtime path for changing it. routesNotify wakes the
	// notification reloader: pulsed by the fan-out below and directly by
	// settings mutations.
	routesNotify := make(chan struct{}, 1)
	settingsSvc := &settingsService{
		st: st, notifyCfg: notifyCfg, manager: backups, fileRepl: fileRepl,
		resolver: secretStore, wake: routesNotify, log: logger,
		node: api.NodeConfigView{
			Listen: apiL.addr, TLS: apiL.tlsEnabled(),
			BaseDomain: s.baseDomain,
			NodeCIDR:   s.nodeCIDR, ClusterCIDR: s.clusterCIDR, ServiceCIDR: s.serviceCIDR,
			NodeCIDR6: s.nodeCIDR6, ClusterCIDR6: s.clusterCIDR6, ServiceCIDR6: s.serviceCIDR6,
			DNSListen: s.dnsListen, DataDir: s.dataDir, LogDir: s.logDir,
			PublishPorts: s.publishPorts, TLSDefault: s.tlsDefault,
		},
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

	// The image GC (§5.2.4, v1.111): the disk-hygiene half of the watcher
	// above. Always constructed, because the images API's read half works on
	// any node; whether the sweep may run is the collector's own refusal,
	// which the loop below and POST /v1/images/gc both consult. On unless
	// the gc block says otherwise: the one default in this family whose
	// absence is not off, because a disk that fills silently is exactly the
	// surprise §5.2.4 forbids.
	gcDisabled := nodeCfg.ImageGC != nil && nodeCfg.ImageGC.Disabled
	if gcDisabled {
		logger.Info("image gc disabled by node config", "config", nodeCfg.Path)
	}
	imageGC, err := imagegc.New(imagegc.Config{
		Store:          st,
		Images:         driver,
		Logger:         logger,
		NodePullPolicy: pullPolicy,
		Disabled:       gcDisabled,
		Interval:       nodeCfg.ImageGC.SweepInterval(),
		MinAge:         nodeCfg.ImageGC.SweepMinAge(),
		Keep:           nodeCfg.ImageGC.SweepKeep(),
	})
	if err != nil {
		return err
	}

	// The internal registry precedes the pipeline stack because the stack
	// needs its bound address: the defaulted build target names the port that
	// answers (§5.2.14).
	reg, pipelineRegistry, err := buildRegistry(s.registryAddr, s.buildkit, s.dataDir, st, logger)
	if err != nil {
		return err
	}

	pipelines, buildQueue, err := buildPipelines(pipelineSettings{
		buildkit:   s.buildkit,
		logDir:     resolveBuildLogDir(s.buildLogDir, s.dataDir),
		interval:   s.syncInterval,
		baseDomain: s.baseDomain,
		nodeVars:   nodeCfg.Variables,
		insecure:   s.insecureRegistry,
		registry:   pipelineRegistry,
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
	// the honest way to write that down: the alternative is a second HTTP
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
		ParseSpec: specParser(nodeCfg.Variables),
	})
	if err != nil {
		return err
	}

	dnsSolver, err := buildDNSSolver(ctx, dnsUpdateSettings{
		server: s.acmeDNSServer, zone: s.acmeDNSZone, key: s.acmeDNSKey,
		secretRef: s.acmeDNSSecret, algorithm: s.acmeDNSAlgorithm,
	}, secretStore, logger)
	if err != nil {
		return err
	}
	// Parsed before the server is built, so a typo in the range is a refusal at
	// startup rather than a service that publishes nothing and says why once
	// per apply.
	portPolicy, err := api.ParsePortPolicy(s.publishPorts)
	if err != nil {
		return err
	}
	if !portPolicy.Enabled() {
		logger.Info("published ports are disabled on this node", "detail", "edge.publish.ports = \"off\"")
	}
	certs, err := buildCertificates(certConfig{
		Email:        s.acmeEmail,
		Directory:    s.acmeDirectory,
		CAPath:       s.acmeCA,
		BundlePath:   s.edgeCerts,
		Group:        s.edgeGroup,
		VerifyURL:    s.acmeVerifyURL,
		BaseDomain:   s.baseDomain,
		Default:      s.tlsDefault,
		CAName:       s.tlsCAName,
		ConfigPath:   nodeCfg.Path,
		ConfigSource: nodeCfg.Source,
		DNSSolver:    dnsSolver,
		Store:        st,
		Logger:       logger,
	})
	if err != nil {
		return err
	}
	// The R27 verifier material rides the same restricted bundle the
	// publisher writes certificates into (v1.40). Wired here rather than in
	// the reconciler's Config because the publisher is built after it, and
	// before rec.Run so no pass runs without the sink.
	rec.SetAuthSink(certs.publisher)

	// A managed listener certificate (bind.api_tls acme/self-signed, v1.61)
	// rides the §7.3 pass: the request is registered here, and the pass
	// delivers each issuance (and each renewal) through the holder the
	// listener's handshakes read.
	var apiGetCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	switch apiL.mode {
	case nodeconfig.TLSAcme:
		if !certs.hasACME {
			return fmt.Errorf("bind.api_tls %q needs an ACME account: set acme.email in %s",
				apiL.mode, nodeconfig.DefaultPath)
		}
		certs.listener = &listenerCertificate{
			mode: certsource.ModeACME, domains: []string{apiL.domain},
		}
		apiGetCert = certs.listener.GetCertificate
	case nodeconfig.TLSSelfSigned:
		certs.listener = &listenerCertificate{
			mode: certsource.ModeSelfSigned, domains: []string{apiL.domain},
		}
		apiGetCert = certs.listener.GetCertificate
	}

	// One reader for the API's point-in-time stats and the history recorder
	// alike: CPU percent is a delta between readings, and two readers would
	// each see only half the sample history (v1.38).
	nodeReader := scaling.NewNodeReader("")

	server, err := api.NewServer(api.ServerConfig{
		Store: st, Logger: logger, Socket: s.socket,
		Version: version, LogDir: s.logDir, Notify: notify,
		WSOrigins: s.wsOrigins, ServeDashboard: s.serveDashboard,
		Secrets: secretStore, SecretSync: secretSyncStatus(secretSyncer, secretProviders),
		Pipelines: pipelines, Auth: users, Accounts: users, Audit: trail,
		Events: feed, NotifyStats: notifier.Stats, Publish: notifier.Publish,
		Notifier: notifier, MCP: mcpServer.HTTPHandler(s.wsOrigins),
		Backups: backups, Settings: settingsSvc, LDAPServer: ldapServerName(directory),
		// The dashboard's upgrade (PRD v1.107) is the CLI's fetch half run by
		// the daemon on itself; the restart half is the signal context's own
		// stop, so an upgrade exit and a SIGTERM are the same clean shutdown.
		Upgrader: newDaemonUpgrader(logger, stop, s.upgradeRepo, s.upgradeRequireSignature),
		// The updates view (PRD v1.108): local reads only, never an install.
		HostInspector: newHostInspector(logger),
		// The images view and the manual sweep (PRD v1.111, §5.2.4).
		ImageGC:      imageGC,
		CA:           certificateAuthority(certs),
		PublishPorts: portPolicy,
		NodeVars:     nodeCfg.Variables,
		OIDC:         provider, Sessions: users,
		Metrics: metrics, EdgeMetrics: edgeExposition,
		Invoker: invoker,
		Usage:   volumeUsage, VolumeDir: volumes,
		Breaker: breaker, Node: nodeReader,
		// The editor's renderer parses with the node's own base domain and
		// variables; the same options the GitOps sync uses, so a spec means
		// the same thing whichever door it arrives through (v1.38, v1.63).
		Spec: specRenderer{opts: jobspec.Options{BaseDomain: s.baseDomain, NodeVars: nodeCfg.Variables}},
		// The apply path resolves a changed tag itself, so a release is one
		// rolling deploy rather than one onto the bare tag and a second onto
		// the digest a tick later (v1.114). The watcher's own resolve, behind
		// the same credential: one function, two callers.
		Pinner: imagePinner{resolver: driver, secrets: secretStore},
		Exec:   driver,
		Listen: apiL.addr, TLSCert: apiL.cert, TLSKey: apiL.key,
		TLSGetCertificate: apiGetCert,
		ListenPlaintext:   apiL.mode == nodeconfig.TLSPlaintext,
		AuthConfigured:    configured, InsecureCookies: apiInsecureCookies,
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
		"version", version, "state", statePath, "socket", s.socket,
		"log_dir", s.logDir, "volume_dir", volumes)

	tasks := 2
	if dns != nil {
		tasks++
	}
	if reg != nil {
		tasks++
	}
	if certs != nil {
		tasks++
	}
	if secretProviders.Configured() {
		tasks++
	}
	errs := make(chan error, tasks)
	invokerNotify := make(chan struct{}, 1)
	go fanOut(ctx, notify, reconcileNotify, certNotify, invokerNotify, routesNotify)
	// The notification reloader (v1.46): rebuilds the dispatcher's routes when
	// channel config changes, through whichever door; HCL apply, GitOps sync,
	// or the settings routes, which also pulse routesNotify directly.
	go runNotifyReload(ctx, routesNotify, notifyCfg, notifyCfg.egress(), notifier, logger)
	go invokerWaker(ctx, invokerNotify, invoker)
	go func() { errs <- server.Serve(ctx) }()
	go func() { errs <- rec.Run(ctx, reconcileNotify) }()
	if dns != nil {
		go func() { errs <- dns.Serve(ctx) }()
	}
	if reg != nil {
		go func() { errs <- reg.Serve(ctx) }()
	}
	if certs != nil {
		go func() {
			errs <- runCertificates(ctx, certs, st, s.baseDomain, s.tlsDefault,
				certNotify, logger, notifier.Publish)
		}()
	}
	if secretProviders.Configured() {
		go func() {
			errs <- runSecretSync(ctx, secretSyncer, secretProviders,
				s.secretsSyncInterval, logger, notifier.Publish)
		}()
	}
	// The mount supervisor runs alongside, not inside, the reconcile loop: a
	// probe of a wedged mount can take seconds to abandon, and convergence must
	// not wait for it (spike ③).
	go mounts.Supervise(ctx, storage.DefaultCheckInterval)
	go sweepAuthState(ctx, users, trail, s.auditRetention, logger)
	// The dispatcher owns its own goroutine so a wedged channel cannot stall
	// anything that emits: Publish is non-blocking and everything slow happens
	// behind it (AGENTS.md #8).
	go notifier.Run(ctx)
	// The invoker's own goroutine, for the reason the dispatcher has one: a
	// slow function must never stall anything that emits (constraint #8).
	go func() { _ = invoker.Run(ctx) }() //nolint:errcheck // Run only returns the context's error at shutdown
	// The manager launches whatever destination is adopted and owns every
	// later swap. Its own goroutine, and it never touches the control plane's
	// critical path: a bucket that is down means backups stop and say so,
	// never that the platform stops.
	go backups.run(ctx)
	if pipelines != nil {
		// The queue worker and the sync loop are separate goroutines on
		// purpose: a build that takes four minutes must not stop the loop
		// noticing that another project moved.
		go buildQueue.Run(ctx)
		go runSync(ctx, pipelines, s.syncInterval, logger)
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
	// The image GC sweep (§5.2.4, v1.111), best-effort like the watcher
	// above. A refused collector still serves the images API's read half;
	// the reason is logged once here so a node that never collects says why.
	if reason := imageGC.Refusal(); reason != "" {
		logger.Info("image gc will not sweep", "reason", reason)
	} else {
		logger.Info("image gc sweeping", "interval", imageGC.Interval())
		go func() {
			if err := imageGC.Run(ctx); err != nil {
				logger.Debug("image gc stopped", "error", err)
			}
		}()
	}
	startMetrics(ctx, metricsSettings{
		metrics:       metrics,
		exposition:    edgeExposition,
		containerdURL: s.containerdMetrics,
		edgeURL:       s.edgeMetrics,
		flows:         flows,
		node:          nodeReader,
		interval:      s.metricsInterval,
		autoscale:     s.autoscale,
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
	// defaultAuditRetention is how long audit entries are kept (§14, A09:
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
// the path for the ones nobody comes back for: the browser tab that was closed
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

// A setting has two spellings: the node config attribute kanead reads, and the
// flag `kanea init` takes for the same thing. The checks below serve both, so
// each caller says which spelling its operator typed: an error naming a flag
// kanead does not have is one nobody can act on.

// configLabel names a node config attribute as the file spells it.
func configLabel(attr string) string { return attr }

// flagLabel names the command-line flag for a node config attribute:
// network.node_cidr6 is --node-cidr6.
func flagLabel(attr string) string {
	_, name, found := strings.Cut(attr, ".")
	if !found {
		name = attr
	}
	return "--" + strings.ReplaceAll(name, "_", "-")
}

// agentCIDRs is the parsed subnet trio the ebpf mode runs on: six with
// dual-stack (PRD v1.41); the *6 prefixes are invalid when v6 is off.
type agentCIDRs struct {
	node, cluster, service    netip.Prefix
	node6, cluster6, service6 netip.Prefix
}

// parseAgentCIDRs validates the subnets against each other, mirroring the
// shape of preflight's checkSubnets: `kanea doctor` can only warn in advance,
// while this is the refusal that actually gates startup; GitOps and systemd
// reach kanead without ever passing through doctor.
//
// The v6 trio is all-or-nothing, refused by name: a v6 alloc address without
// a v6 VIP pool is a half-configured stack whose failures are silent.
func parseAgentCIDRs(node, cluster, service, node6, cluster6, service6 string,
	label func(string) string,
) (agentCIDRs, error) {
	var out agentCIDRs
	var (
		nodeAttr, clusterAttr, serviceAttr    = label("network.node_cidr"), label("network.cluster_cidr"), label("network.service_cidr")
		node6Attr, cluster6Attr, service6Attr = label("network.node_cidr6"), label("network.cluster_cidr6"), label("network.service_cidr6")
	)
	for _, p := range []struct {
		flag  string
		value string
		into  *netip.Prefix
	}{
		{nodeAttr, node, &out.node},
		{clusterAttr, cluster, &out.cluster},
		{serviceAttr, service, &out.service},
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
		return out, fmt.Errorf("%s %s is not within %s %s", nodeAttr, node, clusterAttr, cluster)
	}
	for _, c := range []struct {
		flag   string
		prefix netip.Prefix
	}{
		{nodeAttr, out.node}, {clusterAttr, out.cluster},
	} {
		if c.prefix.Overlaps(out.service) {
			return out, fmt.Errorf("%s %s overlaps %s %s; a service frontend would be "+
				"handed an address that is also a container address", c.flag, c.prefix, serviceAttr, service)
		}
	}

	set := 0
	for _, v := range []string{node6, cluster6, service6} {
		if v != "" {
			set++
		}
	}
	if set == 0 {
		return out, nil
	}
	if set != 3 {
		return out, fmt.Errorf("%s, %s and %s come as a trio: all three or none",
			node6Attr, cluster6Attr, service6Attr)
	}
	for _, p := range []struct {
		flag  string
		value string
		into  *netip.Prefix
	}{
		{node6Attr, node6, &out.node6},
		{cluster6Attr, cluster6, &out.cluster6},
		{service6Attr, service6, &out.service6},
	} {
		prefix, err := netip.ParsePrefix(p.value)
		if err != nil {
			return out, fmt.Errorf("%s %q is not a CIDR", p.flag, p.value)
		}
		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return out, fmt.Errorf("%s %q is not an IPv6 prefix", p.flag, p.value)
		}
		*p.into = prefix.Masked()
	}
	if !out.cluster6.Contains(out.node6.Addr()) || out.node6.Bits() < out.cluster6.Bits() {
		return out, fmt.Errorf("%s %s is not within %s %s", node6Attr, node6, cluster6Attr, cluster6)
	}
	for _, c := range []struct {
		flag   string
		prefix netip.Prefix
	}{
		{node6Attr, out.node6}, {cluster6Attr, out.cluster6},
	} {
		if c.prefix.Overlaps(out.service6) {
			return out, fmt.Errorf("%s %s overlaps %s %s; a service frontend would be "+
				"handed an address that is also a container address", c.flag, c.prefix, service6Attr, service6)
		}
	}
	return out, nil
}

// buildNetwork loads the datapath, the only network a node has (PRD v1.115).
//
// An Init failure is a hard startup error, deliberately unlike the
// warn-and-continue the old external agent got: there is no separate process
// that might come up later. Loading the programs *is* the datapath: if that
// fails, nothing will ever pass traffic, there is nothing to retry against,
// and a control plane that started anyway would converge every alloc onto a
// network that silently drops everything.
func buildNetwork(ctx context.Context, cfg datapath.Config) (*datapath.Datapath, error) {
	dp, err := datapath.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("network: %w", err)
	}
	if err := dp.Init(ctx); err != nil {
		return nil, fmt.Errorf("network: %w", err)
	}
	return dp, nil
}

// buildEgressUID resolves the build daemon's account to the uid the
// build-egress nftables rule matches on (v1.75). 0 - no rule - when the
// account does not exist: a node with no build daemon has no build traffic
// to filter, and init creates the account before the daemon first runs.
func buildEgressUID(logger *slog.Logger) int {
	u, err := user.Lookup(provision.BuildkitUser)
	if err != nil {
		logger.Debug("no build daemon account; the build-egress rule is off",
			"user", provision.BuildkitUser, "error", err)
		return 0
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		logger.Warn("the build daemon account has a non-numeric uid; the build-egress rule is off",
			"user", provision.BuildkitUser, "uid", u.Uid)
		return 0
	}
	return uid
}

// buildSubUIDRange resolves the build account's subordinate uid range, which
// keys the subuid half of the build-egress rule (v1.105): a Dockerfile USER
// step runs as a subuid, which the uid rule never matches. 0/0 - no rule -
// when the account is off (uid 0) or holds no range; a range without the
// account would be somebody else's allocation and gets no rule either way.
func buildSubUIDRange(buildUID int, logger *slog.Logger) (start, count int) {
	if buildUID == 0 {
		return 0, 0
	}
	start, count, err := provision.SubIDRange(provision.SubUIDFile, provision.BuildkitUser)
	if err != nil {
		logger.Warn("cannot read the build daemon's subordinate uid range; the subuid build-egress rule is off",
			"user", provision.BuildkitUser, "error", err)
		return 0, 0
	}
	if start == 0 || count == 0 {
		logger.Debug("the build daemon has no subordinate uid range; the subuid build-egress rule is off",
			"user", provision.BuildkitUser)
		return 0, 0
	}
	return start, count
}

// DNS wiring.
const (
	// dnsOff disables the embedded resolver.
	dnsOff = "off"
)

// buildDNS constructs the embedded resolver, or nil when it is not wanted.
//
// The listen address defaults to the node CIDR's .1 (the address Init puts on
// the datapath's host anchor (kanea0)) rather than a wildcard. That is a
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
func buildDNS(listen string, upstreams []string, nodeCIDR netip.Prefix, logger *slog.Logger) (*network.DNS, error) {
	if listen == dnsOff {
		logger.Warn("internal DNS is disabled; services are reachable only by address")
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

// upstreamResolvers resolves the forwarding targets: the node config's dns
// stanza (v1.66), or the host's own resolvers when it names none.
//
// Forwarding to the host's own resolvers by default keeps a workload's view
// of the internet identical to the node's, which is what an operator expects
// when they configure DNS once in /etc/resolv.conf. The stanza exists for the
// node where that stopped being what they wanted: resolv.conf is read once
// at startup and held, so pinning belongs in config, not in whatever DHCP
// last wrote.
func upstreamResolvers(fromFile []string) ([]string, error) {
	if len(fromFile) > 0 {
		return fromFile, nil
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
