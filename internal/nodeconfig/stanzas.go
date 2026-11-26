package nodeconfig

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// The stanzas PRD v1.115 added: one per group of former daemon flags.
//
// A stanza whose attributes are all strings, lists, bools or numbers is
// decoded straight into its exported struct. A stanza with a duration or a
// nested block has an unexported hcl twin: durations arrive as strings (the
// images.gc precedent) and are parsed in decodeStanzas, where the diagnostic
// carries the file name and the attribute's dotted path; nested blocks are
// pointers in the twin (gohcl's spelling of "optional") and plain structs in
// Config, so a caller reads cfg.Auth.OIDC.Issuer with no nil check.
//
// No struct here has a remain body: an unknown attribute inside a read stanza
// is an error.

// AuthConfig is the auth stanza.
type AuthConfig struct {
	InsecureCookies *bool
	OIDC            OIDCConfig
	LDAP            LDAPConfig
}

// OIDCConfig is auth.oidc. ClientSecret is a secret: reference.
type OIDCConfig struct {
	Issuer       string `hcl:"issuer,optional"`
	ClientID     string `hcl:"client_id,optional"`
	ClientSecret string `hcl:"client_secret,optional"`
	RedirectURL  string `hcl:"redirect_url,optional"`
	// Scopes is nil when the attribute is absent (the daemon's default
	// scopes) and empty when it was written as []: no scope beyond openid.
	Scopes       *[]string `hcl:"scopes,optional"`
	RoleClaim    string    `hcl:"role_claim,optional"`
	AdminClaims  []string  `hcl:"admin_claims,optional"`
	ViewerClaims []string  `hcl:"viewer_claims,optional"`
}

// LDAPConfig is auth.ldap. BindPassword is a secret: reference.
type LDAPConfig struct {
	URL          string   `hcl:"url,optional"`
	BindDN       string   `hcl:"bind_dn,optional"`
	BindPassword string   `hcl:"bind_password,optional"`
	UserBaseDN   string   `hcl:"user_base_dn,optional"`
	UserFilter   string   `hcl:"user_filter,optional"`
	GroupBaseDN  string   `hcl:"group_base_dn,optional"`
	GroupFilter  string   `hcl:"group_filter,optional"`
	AdminGroups  []string `hcl:"admin_groups,optional"`
	ViewerGroups []string `hcl:"viewer_groups,optional"`
	CAFile       string   `hcl:"ca_file,optional"`
}

type hclAuth struct {
	InsecureCookies *bool       `hcl:"insecure_cookies,optional"`
	OIDC            *OIDCConfig `hcl:"oidc,block"`
	LDAP            *LDAPConfig `hcl:"ldap,block"`
}

// AuditConfig is the audit stanza. A zero Retention keeps entries forever,
// which is why it is a pointer.
type AuditConfig struct {
	Retention *time.Duration
}

type hclAudit struct {
	Retention string `hcl:"retention,optional"`
}

// DashboardConfig is the dashboard stanza.
type DashboardConfig struct {
	Enabled *bool    `hcl:"enabled,optional"`
	Origins []string `hcl:"origins,optional"`
}

// NetworkConfig is the network stanza.
type NetworkConfig struct {
	NodeCIDR     string `hcl:"node_cidr,optional"`
	ClusterCIDR  string `hcl:"cluster_cidr,optional"`
	ServiceCIDR  string `hcl:"service_cidr,optional"`
	NodeCIDR6    string `hcl:"node_cidr6,optional"`
	ClusterCIDR6 string `hcl:"cluster_cidr6,optional"`
	ServiceCIDR6 string `hcl:"service_cidr6,optional"`
	BPFDir       string `hcl:"bpf_dir,optional"`
}

// ContainerdConfig is the containerd stanza.
type ContainerdConfig struct {
	Socket string `hcl:"socket,optional"`
}

// MetricsConfig is the metrics stanza. Each URL takes "off".
type MetricsConfig struct {
	Interval      *time.Duration
	ContainerdURL string
	EdgeURL       string
}

type hclMetrics struct {
	Interval      string `hcl:"interval,optional"`
	ContainerdURL string `hcl:"containerd_url,optional"`
	EdgeURL       string `hcl:"edge_url,optional"`
}

// ScalingConfig is the scaling stanza.
type ScalingConfig struct {
	Enabled *bool `hcl:"enabled,optional"`
}

// BuildsConfig is the builds stanza. BuildkitAddr and RegistryAddr take
// "off".
type BuildsConfig struct {
	BuildkitAddr     string `hcl:"buildkit_addr,optional"`
	LogDir           string `hcl:"log_dir,optional"`
	RegistryAddr     string `hcl:"registry_addr,optional"`
	InsecureRegistry *bool  `hcl:"insecure_registry,optional"`
}

// GitOpsConfig is the gitops stanza.
type GitOpsConfig struct {
	SyncInterval *time.Duration
}

// SecretsConfig is the secrets stanza: the schedule of the provider blocks,
// which internal/secretsource decodes from the same file.
type SecretsConfig struct {
	SyncInterval *time.Duration
}

// hclSyncInterval is the shape gitops and secrets share: one duration.
type hclSyncInterval struct {
	SyncInterval string `hcl:"sync_interval,optional"`
}

// TLSConfig is the tls stanza: the node default an exposed service gets when
// its spec declares no tls block, and the self-signed CA's name.
type TLSConfig struct {
	DefaultMode string `hcl:"default_mode,optional"`
	CAName      string `hcl:"ca_name,optional"`
}

// ACMEConfig is the acme stanza.
type ACMEConfig struct {
	Email        string
	Directory    string
	CABundleFile string
	VerifyURL    string
	DNS01        ACMEDNS01Config
}

// ACMEDNS01Config is acme.dns01: RFC 2136 dynamic updates. TSIGSecret is a
// secret: reference.
type ACMEDNS01Config struct {
	Server        string `hcl:"server,optional"`
	Zone          string `hcl:"zone,optional"`
	TSIGKey       string `hcl:"tsig_key,optional"`
	TSIGSecret    string `hcl:"tsig_secret,optional"`
	TSIGAlgorithm string `hcl:"tsig_algorithm,optional"`
}

type hclACME struct {
	Email        string           `hcl:"email,optional"`
	Directory    string           `hcl:"directory,optional"`
	CABundleFile string           `hcl:"ca_bundle_file,optional"`
	VerifyURL    string           `hcl:"verify_url,optional"`
	DNS01        *ACMEDNS01Config `hcl:"dns01,block"`
}

// EdgeConfig is the edge stanza. kanead reads the two projection paths, the
// group and publish.ports; kanea-edge reads everything but the group.
// RoutesFile and StatusAddr take "off".
type EdgeConfig struct {
	RoutesFile       string
	CertsFile        string
	CertsGroup       string
	StatusAddr       string
	PollInterval     *time.Duration
	DrainTimeout     *time.Duration
	BodyTimeout      *time.Duration
	UpstreamTimeout  *time.Duration
	FunctionsPort    *int
	SecurityHeaders  *bool
	RateLimitBuckets *int
	MemoryLimit      string
	LogLevel         string
	Publish          EdgePublishConfig
}

// EdgePublishConfig is edge.publish. Ports takes "off".
type EdgePublishConfig struct {
	Ports        string
	MaxConns     *int
	DrainTimeout *time.Duration
}

type hclEdge struct {
	RoutesFile       string          `hcl:"routes_file,optional"`
	CertsFile        string          `hcl:"certs_file,optional"`
	CertsGroup       string          `hcl:"certs_group,optional"`
	StatusAddr       string          `hcl:"status_addr,optional"`
	PollInterval     string          `hcl:"poll_interval,optional"`
	DrainTimeout     string          `hcl:"drain_timeout,optional"`
	BodyTimeout      string          `hcl:"body_timeout,optional"`
	UpstreamTimeout  string          `hcl:"upstream_timeout,optional"`
	FunctionsPort    *int            `hcl:"functions_port,optional"`
	SecurityHeaders  *bool           `hcl:"security_headers,optional"`
	RateLimitBuckets *int            `hcl:"rate_limit_buckets,optional"`
	MemoryLimit      string          `hcl:"memory_limit,optional"`
	LogLevel         string          `hcl:"log_level,optional"`
	Publish          *hclEdgePublish `hcl:"publish,block"`
}

type hclEdgePublish struct {
	Ports        string `hcl:"ports,optional"`
	MaxConns     *int   `hcl:"max_conns,optional"`
	DrainTimeout string `hcl:"drain_timeout,optional"`
}

// NotificationsConfig is the notifications stanza.
type NotificationsConfig struct {
	AllowPrivate   *bool `hcl:"allow_private,optional"`
	AllowHTTP      *bool `hcl:"allow_http,optional"`
	EventRetention *int  `hcl:"event_retention,optional"`
}

// BackupConfig is the backup stanza: the fallback replication destination. A
// destination saved through the API wins over it.
type BackupConfig struct {
	Dir              string
	SnapshotInterval *time.Duration
	SegmentInterval  *time.Duration
	Retention        *int
	RestoreIfEmpty   *bool
	S3               BackupS3Config
}

// BackupS3Config is backup.s3. URL keeps the s3://bucket[/prefix] form;
// SecretKey is a secret: reference.
type BackupS3Config struct {
	URL       string `hcl:"url,optional"`
	Endpoint  string `hcl:"endpoint,optional"`
	Region    string `hcl:"region,optional"`
	AccessKey string `hcl:"access_key,optional"`
	SecretKey string `hcl:"secret_key,optional"`
	PathStyle *bool  `hcl:"path_style,optional"`
}

type hclBackup struct {
	Dir              string          `hcl:"dir,optional"`
	SnapshotInterval string          `hcl:"snapshot_interval,optional"`
	SegmentInterval  string          `hcl:"segment_interval,optional"`
	Retention        *int            `hcl:"retention,optional"`
	RestoreIfEmpty   *bool           `hcl:"restore_if_empty,optional"`
	S3               *BackupS3Config `hcl:"s3,block"`
}

// UpgradeConfig is the upgrade stanza: where releases come from, and whether
// an unverifiable signature is fatal.
type UpgradeConfig struct {
	Repo             string `hcl:"repo,optional"`
	RequireSignature *bool  `hcl:"require_signature,optional"`
}

// durations parses the file's duration strings, keeping the first failure.
// One collector rather than an error check per attribute: a stanza with four
// durations would otherwise be mostly error plumbing.
type durations struct {
	filename string
	err      error
}

// parse returns nil for an unset attribute. attr is the dotted path the
// operator wrote, which is what the diagnostic names.
func (d *durations) parse(attr, raw string) *time.Duration {
	if raw == "" || d.err != nil {
		return nil
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		d.err = fmt.Errorf("nodeconfig: %s: %s %q: %w", d.filename, attr, raw, err)
		return nil
	}
	return &v
}

// decodeStanzas copies the v1.115 stanzas from the decoded root into cfg.
// Shape only: what a value means is checked where it is used, by the code
// that already produced those errors when the value arrived as a flag.
func decodeStanzas(filename string, root *hclRoot, cfg *Config) error {
	d := &durations{filename: filename}

	if a := root.Auth; a != nil {
		cfg.Auth.InsecureCookies = a.InsecureCookies
		if a.OIDC != nil {
			cfg.Auth.OIDC = *a.OIDC
		}
		if a.LDAP != nil {
			cfg.Auth.LDAP = *a.LDAP
		}
	}
	if root.Audit != nil {
		cfg.Audit.Retention = d.parse("audit.retention", root.Audit.Retention)
	}
	if root.Dashboard != nil {
		cfg.Dashboard = *root.Dashboard
	}
	if root.Network != nil {
		cfg.Network = *root.Network
	}
	if root.Containerd != nil {
		cfg.Containerd = *root.Containerd
	}
	if m := root.Metrics; m != nil {
		cfg.Metrics = MetricsConfig{
			Interval:      d.parse("metrics.interval", m.Interval),
			ContainerdURL: m.ContainerdURL,
			EdgeURL:       m.EdgeURL,
		}
	}
	if root.Scaling != nil {
		cfg.Scaling = *root.Scaling
	}
	if root.Builds != nil {
		cfg.Builds = *root.Builds
	}
	if root.GitOps != nil {
		cfg.GitOps.SyncInterval = d.parse("gitops.sync_interval", root.GitOps.SyncInterval)
	}
	if root.Secrets != nil {
		cfg.Secrets.SyncInterval = d.parse("secrets.sync_interval", root.Secrets.SyncInterval)
	}
	if root.TLS != nil {
		cfg.TLS = *root.TLS
	}
	if a := root.ACME; a != nil {
		cfg.ACME = ACMEConfig{
			Email: a.Email, Directory: a.Directory,
			CABundleFile: a.CABundleFile, VerifyURL: a.VerifyURL,
		}
		if a.DNS01 != nil {
			cfg.ACME.DNS01 = *a.DNS01
		}
	}
	if root.Edge != nil {
		cfg.Edge = decodeEdge(d, root.Edge)
	}
	if root.Notifications != nil {
		cfg.Notifications = *root.Notifications
	}
	if b := root.Backup; b != nil {
		cfg.Backup = BackupConfig{
			Dir:              b.Dir,
			SnapshotInterval: d.parse("backup.snapshot_interval", b.SnapshotInterval),
			SegmentInterval:  d.parse("backup.segment_interval", b.SegmentInterval),
			Retention:        b.Retention,
			RestoreIfEmpty:   b.RestoreIfEmpty,
		}
		if b.S3 != nil {
			cfg.Backup.S3 = *b.S3
		}
	}
	if root.Upgrade != nil {
		cfg.Upgrade = *root.Upgrade
	}
	return d.err
}

// decodeEdge is shared by Parse and ParseEdge, so the two processes that read
// the stanza cannot come to read it differently.
func decodeEdge(d *durations, e *hclEdge) EdgeConfig {
	out := EdgeConfig{
		RoutesFile: e.RoutesFile, CertsFile: e.CertsFile,
		CertsGroup: e.CertsGroup, StatusAddr: e.StatusAddr,
		PollInterval:     d.parse("edge.poll_interval", e.PollInterval),
		DrainTimeout:     d.parse("edge.drain_timeout", e.DrainTimeout),
		BodyTimeout:      d.parse("edge.body_timeout", e.BodyTimeout),
		UpstreamTimeout:  d.parse("edge.upstream_timeout", e.UpstreamTimeout),
		FunctionsPort:    e.FunctionsPort,
		SecurityHeaders:  e.SecurityHeaders,
		RateLimitBuckets: e.RateLimitBuckets,
		MemoryLimit:      e.MemoryLimit, LogLevel: e.LogLevel,
	}
	if p := e.Publish; p != nil {
		out.Publish = EdgePublishConfig{
			Ports:        p.Ports,
			MaxConns:     p.MaxConns,
			DrainTimeout: d.parse("edge.publish.drain_timeout", p.DrainTimeout),
		}
	}
	return out
}

// EdgeFile is what kanea-edge takes from the node config: its two public
// listeners (the bind stanza's edge half) and the edge stanza. Nothing else
// in the file is decoded for it.
type EdgeFile struct {
	// Path is the file that was read; "" when there was none.
	Path      string
	HTTPAddr  string
	HTTPSAddr string
	Edge      EdgeConfig
}

// hclEdgeRoot decodes the two stanzas the edge reads and leaves the rest of
// the file to remain, undecoded.
type hclEdgeRoot struct {
	Bind   *hclBind `hcl:"bind,block"`
	Edge   *hclEdge `hcl:"edge,block"`
	Remain hcl.Body `hcl:",remain"`
}

// LoadEdge reads the node config for the edge process. A missing file is
// every default. The file is trust-checked and must parse, but only the bind
// and edge stanzas are decoded: a mistake in a stanza only kanead reads must
// not stop ingress (PRD §5.2.6: the edge never depends on the control
// plane's health, and that includes the health of its configuration).
func LoadEdge(path string) (*EdgeFile, error) {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &EdgeFile{}, nil
		}
		return nil, fmt.Errorf("nodeconfig: stat %s: %w", path, err)
	}
	if err := CheckTrusted(path); err != nil {
		return nil, err
	}
	src, err := os.ReadFile(path) // #nosec G304; the fixed node config path
	if err != nil {
		return nil, fmt.Errorf("nodeconfig: read %s: %w", path, err)
	}
	file, err := ParseEdge(path, src)
	if err != nil {
		return nil, err
	}
	file.Path = path
	return file, nil
}

// ParseEdge builds an EdgeFile from source. Exported for tests; LoadEdge is
// the trust-checked door.
func ParseEdge(filename string, src []byte) (*EdgeFile, error) {
	parser := hclparse.NewParser()
	parsed, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("nodeconfig: %s", diags.Error())
	}
	var root hclEdgeRoot
	if diags := gohcl.DecodeBody(parsed.Body, nil, &root); diags.HasErrors() {
		return nil, fmt.Errorf("nodeconfig: %s", diags.Error())
	}
	out := &EdgeFile{}
	if root.Bind != nil {
		// The API half is kanead's to validate; the edge takes its two
		// addresses and nothing else from this stanza.
		out.HTTPAddr, out.HTTPSAddr = root.Bind.EdgeHTTP, root.Bind.EdgeHTTPS
	}
	if root.Edge != nil {
		d := &durations{filename: filename}
		out.Edge = decodeEdge(d, root.Edge)
		if d.err != nil {
			return nil, d.err
		}
	}
	return out, nil
}
