package main

import (
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/backup"
	"github.com/m18h/kanea/internal/certsource"
	"github.com/m18h/kanea/internal/datapath/dpmap"
	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/nodeconfig"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/provision"
	"github.com/m18h/kanea/internal/ratelimit"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/registry"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/scaling"
)

// The daemons' settings (PRD §15.1, v1.115): what /etc/kanea/kanea.hcl says,
// with every default applied.
//
// The defaults live here and not in internal/nodeconfig on purpose. Each one
// is a constant owned by the subsystem it configures, and a leaf package that
// imported them all would stop being a leaf: internal/edge imports
// nodeconfig. nodeconfig says what was written (zero means unset); this file
// says what that means for a running daemon.
//
// Each field is named for the flag variable it replaced, and each default is
// that flag's default expression, moved here verbatim: an upgrade with no
// file changes nothing, which TestSettingsDefaultsAreTheFormerFlagDefaults
// pins.

// agentSettings is kanead's resolved configuration.
type agentSettings struct {
	dataDir   string
	logDir    string
	logLevel  string
	volumeDir string // "" means <dataDir>/volumes, resolved where it is used

	socket           string
	containerdSocket string

	bpfDir       string
	nodeCIDR     string
	clusterCIDR  string
	serviceCIDR  string
	nodeCIDR6    string
	clusterCIDR6 string
	serviceCIDR6 string

	dnsListen   string
	dnsUpstream []string

	baseDomain   string
	edgeRoutes   string
	edgeCerts    string
	edgeGroup    string
	publishPorts string

	tlsDefault string
	tlsCAName  string

	acmeEmail        string
	acmeDirectory    string
	acmeCA           string
	acmeVerifyURL    string
	acmeDNSServer    string
	acmeDNSZone      string
	acmeDNSKey       string
	acmeDNSSecret    string
	acmeDNSAlgorithm string

	serveDashboard  bool
	wsOrigins       []string
	insecureCookies bool
	auditRetention  time.Duration

	oidcIssuer       string
	oidcClientID     string
	oidcClientSecret string
	oidcRedirect     string
	oidcScopes       []string
	oidcRoleClaim    string
	oidcAdmins       []string
	oidcViewers      []string

	ldapURL          string
	ldapBindDN       string
	ldapBindPassword string
	ldapUserBaseDN   string
	ldapUserFilter   string
	ldapGroupBaseDN  string
	ldapGroupFilter  string
	ldapAdmins       []string
	ldapViewers      []string
	ldapCA           string

	metricsInterval   time.Duration
	containerdMetrics string
	edgeMetrics       string
	autoscale         bool

	buildkit         string
	buildLogDir      string // "" means <dataDir>/builds, resolved where it is used
	registryAddr     string
	insecureRegistry bool
	syncInterval     time.Duration

	secretsSyncInterval time.Duration

	notifyAllowPrivate bool
	notifyAllowHTTP    bool
	eventRetention     int

	backupDir             string
	backupS3              string
	backupS3Endpoint      string
	backupS3Region        string
	backupS3AccessKey     string
	backupS3Secret        string
	backupS3PathStyle     bool
	backupInterval        time.Duration
	backupSegmentInterval time.Duration
	backupRetention       int
	autoRestore           bool

	// The two former daemon environment variables (KANEA_REPO,
	// KANEA_REQUIRE_SIGNATURE).
	upgradeRepo             string
	upgradeRequireSignature bool
}

// or returns v, or def when v is the zero value: the one rule every attribute
// follows, since nodeconfig's zero means "not written".
func or[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// orPtr is or for the attributes whose zero is a legal value (a bool, a
// count, a duration): nil is what means "not written" there.
func orPtr[T any](v *T, def T) T {
	if v == nil {
		return def
	}
	return *v
}

// resolveAgentSettings applies kanead's defaults to the node config.
func resolveAgentSettings(cfg *nodeconfig.Config) agentSettings {
	bind := cfg.Bind
	if bind == nil {
		bind = &nodeconfig.BindConfig{}
	}
	s := agentSettings{
		dataDir:   or(cfg.DataDir, defaultDataDir),
		logDir:    or(cfg.AllocLogDir, defaultLogDir),
		logLevel:  or(cfg.LogLevel, "info"),
		volumeDir: cfg.VolumeDir,

		socket:           or(bind.APISocket, api.DefaultSocket),
		containerdSocket: or(cfg.Containerd.Socket, runtime.DefaultSocket),

		bpfDir:       or(cfg.Network.BPFDir, dpmap.PinRoot),
		nodeCIDR:     or(cfg.Network.NodeCIDR, provision.DefaultNodeCIDR),
		clusterCIDR:  or(cfg.Network.ClusterCIDR, provision.DefaultClusterCIDR),
		serviceCIDR:  or(cfg.Network.ServiceCIDR, reconciler.DefaultServiceCIDR),
		nodeCIDR6:    cfg.Network.NodeCIDR6,
		clusterCIDR6: cfg.Network.ClusterCIDR6,
		serviceCIDR6: cfg.Network.ServiceCIDR6,

		dnsListen:   cfg.DNSListen,
		dnsUpstream: cfg.DNSUpstreams,

		baseDomain:   cfg.BaseDomain,
		edgeRoutes:   or(cfg.Edge.RoutesFile, edge.DefaultSnapshotPath),
		edgeCerts:    or(cfg.Edge.CertsFile, edge.DefaultBundlePath),
		edgeGroup:    cfg.Edge.CertsGroup,
		publishPorts: or(cfg.Edge.Publish.Ports, api.DefaultPublishRange),

		tlsDefault: or(cfg.TLS.DefaultMode, string(certsource.ModeACME)),
		tlsCAName:  cfg.TLS.CAName,

		acmeEmail:        cfg.ACME.Email,
		acmeDirectory:    or(cfg.ACME.Directory, DirectoryProduction),
		acmeCA:           cfg.ACME.CABundleFile,
		acmeVerifyURL:    or(cfg.ACME.VerifyURL, certsource.DefaultVerifyURL),
		acmeDNSServer:    cfg.ACME.DNS01.Server,
		acmeDNSZone:      cfg.ACME.DNS01.Zone,
		acmeDNSKey:       cfg.ACME.DNS01.TSIGKey,
		acmeDNSSecret:    cfg.ACME.DNS01.TSIGSecret,
		acmeDNSAlgorithm: or(cfg.ACME.DNS01.TSIGAlgorithm, "hmac-sha256."),

		serveDashboard:  orPtr(cfg.Dashboard.Enabled, true),
		wsOrigins:       cfg.Dashboard.Origins,
		insecureCookies: orPtr(cfg.Auth.InsecureCookies, false),
		auditRetention:  orPtr(cfg.Audit.Retention, defaultAuditRetention),

		oidcIssuer:       cfg.Auth.OIDC.Issuer,
		oidcClientID:     cfg.Auth.OIDC.ClientID,
		oidcClientSecret: cfg.Auth.OIDC.ClientSecret,
		oidcRedirect:     cfg.Auth.OIDC.RedirectURL,
		oidcScopes:       orPtr(cfg.Auth.OIDC.Scopes, []string{"profile", "email"}),
		oidcRoleClaim:    or(cfg.Auth.OIDC.RoleClaim, auth.DefaultRoleClaim),
		oidcAdmins:       cfg.Auth.OIDC.AdminClaims,
		oidcViewers:      cfg.Auth.OIDC.ViewerClaims,

		ldapURL:          cfg.Auth.LDAP.URL,
		ldapBindDN:       cfg.Auth.LDAP.BindDN,
		ldapBindPassword: cfg.Auth.LDAP.BindPassword,
		ldapUserBaseDN:   cfg.Auth.LDAP.UserBaseDN,
		ldapUserFilter:   or(cfg.Auth.LDAP.UserFilter, "(uid=%s)"),
		ldapGroupBaseDN:  cfg.Auth.LDAP.GroupBaseDN,
		ldapGroupFilter:  cfg.Auth.LDAP.GroupFilter,
		ldapAdmins:       cfg.Auth.LDAP.AdminGroups,
		ldapViewers:      cfg.Auth.LDAP.ViewerGroups,
		ldapCA:           cfg.Auth.LDAP.CAFile,

		metricsInterval:   orPtr(cfg.Metrics.Interval, scaling.RawInterval),
		containerdMetrics: or(cfg.Metrics.ContainerdURL, scaling.DefaultContainerdMetricsURL),
		edgeMetrics:       or(cfg.Metrics.EdgeURL, scaling.DefaultEdgeMetricsURL),
		autoscale:         orPtr(cfg.Scaling.Enabled, true),

		buildkit:         or(cfg.Builds.BuildkitAddr, gitops.DefaultBuildkitSocket),
		buildLogDir:      cfg.Builds.LogDir,
		registryAddr:     or(cfg.Builds.RegistryAddr, registry.DefaultAddr),
		insecureRegistry: orPtr(cfg.Builds.InsecureRegistry, false),
		syncInterval:     orPtr(cfg.GitOps.SyncInterval, DefaultSyncInterval),

		secretsSyncInterval: orPtr(cfg.Secrets.SyncInterval, secretSyncDefaultInterval),

		notifyAllowPrivate: orPtr(cfg.Notifications.AllowPrivate, false),
		notifyAllowHTTP:    orPtr(cfg.Notifications.AllowHTTP, false),
		eventRetention:     orPtr(cfg.Notifications.EventRetention, notify.DefaultRetention),

		backupDir:             cfg.Backup.Dir,
		backupS3:              cfg.Backup.S3.URL,
		backupS3Endpoint:      cfg.Backup.S3.Endpoint,
		backupS3Region:        cfg.Backup.S3.Region,
		backupS3AccessKey:     cfg.Backup.S3.AccessKey,
		backupS3Secret:        cfg.Backup.S3.SecretKey,
		backupS3PathStyle:     orPtr(cfg.Backup.S3.PathStyle, true),
		backupInterval:        orPtr(cfg.Backup.SnapshotInterval, backup.DefaultSnapshotInterval),
		backupSegmentInterval: orPtr(cfg.Backup.SegmentInterval, backup.DefaultSegmentInterval),
		backupRetention:       orPtr(cfg.Backup.Retention, backup.DefaultRetention),
		autoRestore:           orPtr(cfg.Backup.RestoreIfEmpty, false),

		upgradeRepo:             or(cfg.Upgrade.Repo, defaultRepo),
		upgradeRequireSignature: orPtr(cfg.Upgrade.RequireSignature, false),
	}
	return s
}

// edgeSettings is kanea-edge's resolved configuration.
type edgeSettings struct {
	snapshot          string
	httpAddr          string
	httpsAddr         string
	certs             string
	statusAddr        string
	poll              time.Duration
	drain             time.Duration
	publishDrain      time.Duration
	maxPublishedConns int
	functionsPort     int
	bodyTimeout       time.Duration
	upstreamTimeout   time.Duration
	securityHeaders   bool
	limiterCap        int
	memLimit          string
	logLevel          string
}

// resolveEdgeSettings applies the edge's defaults to its slice of the node
// config. The two projection paths are the same attributes kanead publishes
// to, so the processes cannot come to disagree about where the files live.
func resolveEdgeSettings(f *nodeconfig.EdgeFile) edgeSettings {
	e := f.Edge
	return edgeSettings{
		snapshot:          or(e.RoutesFile, edge.DefaultSnapshotPath),
		httpAddr:          or(f.HTTPAddr, edge.DefaultHTTPAddr),
		httpsAddr:         or(f.HTTPSAddr, edge.DefaultHTTPSAddr),
		certs:             or(e.CertsFile, edge.DefaultBundlePath),
		statusAddr:        or(e.StatusAddr, edge.DefaultStatusAddr),
		poll:              orPtr(e.PollInterval, edge.DefaultPollInterval),
		drain:             orPtr(e.DrainTimeout, edge.DefaultDrainTimeout),
		publishDrain:      orPtr(e.Publish.DrainTimeout, 0),
		maxPublishedConns: orPtr(e.Publish.MaxConns, edge.DefaultMaxPublishedConns),
		functionsPort:     orPtr(e.FunctionsPort, 0),
		bodyTimeout:       orPtr(e.BodyTimeout, edge.DefaultBodyTimeout),
		upstreamTimeout:   orPtr(e.UpstreamTimeout, edge.DefaultResponseHeaderTimeout),
		securityHeaders:   orPtr(e.SecurityHeaders, true),
		limiterCap:        orPtr(e.RateLimitBuckets, ratelimit.DefaultCapacity),
		memLimit:          e.MemoryLimit,
		logLevel:          or(e.LogLevel, "info"),
	}
}
