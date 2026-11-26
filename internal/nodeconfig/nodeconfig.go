// Package nodeconfig reads the node config, /etc/kanea/kanea.hcl (PRD §15.1):
// the one file kanead and kanea-edge are configured from (v1.115).
//
// The file is the §14 A05 boundary in file form: what it grants, no API, MCP
// tool or job spec can grant. That shapes every decision here. It is read
// once, at startup; a probe is one stat, never a poll, and there is no
// reload: a grant is a decision. Only the files a block points at
// (certificate pairs, provider credentials) are re-read, by their own
// packages. Absent means every default; present-but-malformed is fatal; and
// because the path is well-known, the file is trust-checked before parsing
// (CheckTrusted) so a policy nobody but the node's owner could have written
// stays true.
//
// Four decoders share the bytes, each owning its blocks: this package,
// internal/passthrough (device, socket), internal/secretsource (provider) and
// internal/certsource (certificate). A top-level stanza none of them reads is
// collected into Config.Ignored for a startup warning naming it: not silently
// swallowed (a typo that vanishes is the trap), not refused. An unknown
// attribute inside a read stanza is an error.
//
// Zero means unset throughout Config: "" for strings, nil for lists, and a
// nil pointer for every bool, number and duration. Defaults are the daemon's
// (cmd/kanea/settings.go), never this package's: it validates shape, not
// meaning, and imports none of the subsystems it configures.
package nodeconfig

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/m18h/kanea/internal/runtime"
)

// DefaultPath is the only path the daemons read. The value is
// provision.DefaultConfDir's; a test pins agreement.
const DefaultPath = "/etc/kanea/kanea.hcl"

// readBlocks are the top-level block types some decoder consumes: device and
// socket by internal/passthrough, provider by internal/secretsource,
// certificate by internal/certsource, the rest here.
var readBlocks = map[string]bool{
	"storage": true, "device": true, "socket": true, "bind": true, "variables": true,
	"dns": true, "images": true, "auth": true, "audit": true, "dashboard": true,
	"network": true, "containerd": true, "metrics": true, "scaling": true,
	"builds": true, "gitops": true, "secrets": true, "provider": true, "tls": true,
	"certificate": true, "acme": true, "edge": true, "notifications": true,
	"backup": true, "upgrade": true,
}

// readAttrs are the top-level attributes this package reads.
var readAttrs = map[string]bool{
	"data_dir": true, "alloc_log_dir": true, "log_level": true, "base_domain": true,
}

// Config is the node config as written: every attribute of PRD §15.1.
type Config struct {
	// The four top-level attributes.
	DataDir     string
	AllocLogDir string
	LogLevel    string
	BaseDomain  string

	// AllowedHostPaths is storage.allowed_host_paths (R15).
	// nil when the file or the stanza is absent.
	AllowedHostPaths []string
	// VolumeDir is storage.volume_dir.
	VolumeDir string
	// Bind is the bind stanza: every listener the node opens.
	// nil when the file or the stanza is absent.
	Bind *BindConfig
	// Variables is the variables stanza (R30, v1.63): node-wide spec-variable
	// defaults, the lowest-precedence R2 source. Values are primitives carried
	// as strings, never secrets: the map is served to any authenticated
	// caller over GET /v1/vars. nil when the file or the stanza is absent.
	Variables map[string]string
	// DNSUpstreams is the dns stanza's upstream list (v1.66): the resolvers
	// the internal DNS forwards external queries to. nil when the file, the
	// stanza or the attribute is absent, which means the host's own
	// resolv.conf.
	DNSUpstreams []string
	// DNSListen is dns.listen: the internal resolver's address, or "off".
	DNSListen string
	// ImagePullPolicy is the images stanza's pull_policy (R33, v1.84): the
	// node's default for a service that declares none. "" when the file or
	// the stanza is absent, which means runtime.PullIfNotPresent.
	ImagePullPolicy string
	// ImageGC is the images stanza's gc block (§5.2.4, v1.111). nil when the
	// file or the block is absent, which means the collector's own defaults:
	// the GC is on by default, so absence here is not off.
	ImageGC *ImageGCConfig

	Auth          AuthConfig
	Audit         AuditConfig
	Dashboard     DashboardConfig
	Network       NetworkConfig
	Containerd    ContainerdConfig
	Metrics       MetricsConfig
	Scaling       ScalingConfig
	Builds        BuildsConfig
	GitOps        GitOpsConfig
	Secrets       SecretsConfig
	TLS           TLSConfig
	ACME          ACMEConfig
	Edge          EdgeConfig
	Notifications NotificationsConfig
	Backup        BackupConfig
	Upgrade       UpgradeConfig

	// Ignored names the top-level blocks and attributes the file carries
	// and no decoder reads, for the startup warning.
	Ignored []string
	// Path is the file that was read; "" when nothing was.
	Path string
	// Source is the bytes Load read, for the decoders that share the file
	// (passthrough, secretsource, certsource) and for `kanea init`'s editor.
	// nil when no file was read.
	Source []byte
}

// The api_tls modes (PRD §15.1, v1.61): R20's vocabulary applied to the
// node's own listener. An empty mode resolves at the daemon: a declared pair
// means provided, a loopback address means plaintext, anything else refuses.
const (
	TLSAcme       = "acme"
	TLSSelfSigned = "self-signed"
	TLSProvided   = "provided"
	TLSPlaintext  = "plaintext"
)

// BindConfig is the bind stanza: kanead's API socket and API/dashboard
// listener, and the edge's two public listeners. The API listener half is
// atomic: an address travels with its TLS story. Parse refuses every
// contradiction it can see (a cert without a key, plaintext beside a pair,
// acme without a domain) but whether an *unset* mode on a non-loopback
// address may stand is deliberately not decided here: that refusal lives at
// the daemon's listener construction.
type BindConfig struct {
	// APISocket is the control API's unix socket.
	APISocket string
	APIAddr   string
	// APITLS is one of the mode constants above, or "" for the default
	// resolution.
	APITLS string
	// APIDomain names the certificate for the acme and self-signed modes.
	// Required for acme, and for self-signed when APIAddr binds every
	// interface: a certificate needs a name, and "every interface" is not
	// one.
	APIDomain string
	APICert   string
	APIKey    string
	// EdgeHTTP and EdgeHTTPS are kanea-edge's public listeners; EdgeHTTPS
	// takes "off" for a plaintext-only edge.
	EdgeHTTP  string
	EdgeHTTPS string
}

type hclRoot struct {
	DataDir     string `hcl:"data_dir,optional"`
	AllocLogDir string `hcl:"alloc_log_dir,optional"`
	LogLevel    string `hcl:"log_level,optional"`
	BaseDomain  string `hcl:"base_domain,optional"`

	Storage       *hclStorage          `hcl:"storage,block"`
	Bind          *hclBind             `hcl:"bind,block"`
	Variables     *hclVariables        `hcl:"variables,block"`
	DNS           *hclDNS              `hcl:"dns,block"`
	Images        *hclImages           `hcl:"images,block"`
	Auth          *hclAuth             `hcl:"auth,block"`
	Audit         *hclAudit            `hcl:"audit,block"`
	Dashboard     *DashboardConfig     `hcl:"dashboard,block"`
	Network       *NetworkConfig       `hcl:"network,block"`
	Containerd    *ContainerdConfig    `hcl:"containerd,block"`
	Metrics       *hclMetrics          `hcl:"metrics,block"`
	Scaling       *ScalingConfig       `hcl:"scaling,block"`
	Builds        *BuildsConfig        `hcl:"builds,block"`
	GitOps        *hclSyncInterval     `hcl:"gitops,block"`
	Secrets       *hclSyncInterval     `hcl:"secrets,block"`
	TLS           *TLSConfig           `hcl:"tls,block"`
	ACME          *hclACME             `hcl:"acme,block"`
	Edge          *hclEdge             `hcl:"edge,block"`
	Notifications *NotificationsConfig `hcl:"notifications,block"`
	Backup        *hclBackup           `hcl:"backup,block"`
	Upgrade       *UpgradeConfig       `hcl:"upgrade,block"`
	Remain        hcl.Body             `hcl:",remain"`
}

// hclDNS reads the dns stanza (v1.66). No remain body: an unknown attribute
// inside a read stanza is an error, like storage's and bind's.
type hclDNS struct {
	Listen    string   `hcl:"listen,optional"`
	Upstreams []string `hcl:"upstreams,optional"`
}

// hclImages reads the images stanza (v1.84, §6.2 R33): the node's default for
// where a service's images may come from, and (v1.111) its gc block. No
// remain body, like the rest.
type hclImages struct {
	PullPolicy string      `hcl:"pull_policy,optional"`
	GC         *hclImageGC `hcl:"gc,block"`
}

// hclImageGC reads the images stanza's gc block (§5.2.4, v1.111). Durations
// arrive as strings - the file's first - and are parsed and floor-checked in
// Parse, where the diagnostic carries the file name.
type hclImageGC struct {
	Enabled  *bool  `hcl:"enabled,optional"`
	Interval string `hcl:"interval,optional"`
	MinAge   string `hcl:"min_age,optional"`
	Keep     *int   `hcl:"keep,optional"`
}

// ImageGCConfig is the parsed gc block. Zero values mean "the collector's
// default", never zero itself: Keep stays a pointer because zero is a legal
// value there ("no data is never zero").
type ImageGCConfig struct {
	// Disabled is enabled = false: written positively here so the zero
	// value of the struct means the default posture, which is on.
	Disabled bool
	Interval time.Duration
	MinAge   time.Duration
	Keep     *int
}

// The floors Parse refuses below (§15.1, v1.111). An interval tighter than
// ten minutes is a busy-loop over containerd's image service for no plausible
// need, and a min_age under an hour races the deploys it exists to protect.
const (
	MinGCInterval = 10 * time.Minute
	MinGCMinAge   = time.Hour
)

// The Sweep accessors are nil-safe on purpose: an absent gc block means the
// collector's own defaults, and the caller should not need to know which.
// Zero here is "unset" - Parse's floors make a genuine zero unrepresentable
// for the durations, and Keep carries its legal zero through the pointer.

// SweepInterval is the block's interval, or zero for the default.
func (c *ImageGCConfig) SweepInterval() time.Duration {
	if c == nil {
		return 0
	}
	return c.Interval
}

// SweepMinAge is the block's min_age, or zero for the default.
func (c *ImageGCConfig) SweepMinAge() time.Duration {
	if c == nil {
		return 0
	}
	return c.MinAge
}

// SweepKeep is the block's keep, or nil for the default.
func (c *ImageGCConfig) SweepKeep() *int {
	if c == nil {
		return nil
	}
	return c.Keep
}

// hclVariables carries the variables stanza's body raw: its attribute names
// are the operator's to choose, so there is no fixed schema to decode against.
// Every attribute is read (decodeVariables), which is what keeps the
// no-remain rule's spirit: nothing inside the stanza can be silently ignored.
type hclVariables struct {
	Body hcl.Body `hcl:",remain"`
}

// validateDNSUpstreams applies the daemon's own rule (network.DNS's
// normalizeUpstream) at parse time, where the diagnostic carries a file name:
// an entry is an address, or a host:port pair. An empty list is refused by
// name: it configures nothing, and a stanza that meant "no upstreams" would
// silently turn external resolution into SERVFAIL.
// parseImageGC validates the gc block (§5.2.4, v1.111). Malformed or
// below-floor values are fatal like everything else in this file: a GC
// running on a misread cadence is worse than a daemon that says so and stops.
func parseImageGC(raw *hclImageGC) (*ImageGCConfig, error) {
	gc := &ImageGCConfig{}
	if raw.Enabled != nil {
		gc.Disabled = !*raw.Enabled
	}
	if s := strings.TrimSpace(raw.Interval); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("images: gc interval %q is not a duration: %w", s, err)
		}
		if d < MinGCInterval {
			return nil, fmt.Errorf("images: gc interval %s is below the %s floor: "+
				"a tighter loop polls containerd for nothing", d, MinGCInterval)
		}
		gc.Interval = d
	}
	if s := strings.TrimSpace(raw.MinAge); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("images: gc min_age %q is not a duration: %w", s, err)
		}
		if d < MinGCMinAge {
			return nil, fmt.Errorf("images: gc min_age %s is below the %s floor: "+
				"an image can be pulled before the record that references it exists, "+
				"and min_age is what makes that race harmless", d, MinGCMinAge)
		}
		gc.MinAge = d
	}
	if raw.Keep != nil {
		if *raw.Keep < 0 {
			return nil, fmt.Errorf("images: gc keep %d is negative; it counts images", *raw.Keep)
		}
		gc.Keep = raw.Keep
	}
	return gc, nil
}

func validateDNSUpstreams(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(entry); err == nil {
			out = append(out, entry)
			continue
		}
		if _, err := netip.ParseAddr(entry); err != nil {
			return nil, fmt.Errorf("dns: upstream %q is not an address or host:port pair", entry)
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil, errors.New("dns: an empty upstreams list configures nothing; " +
			"name at least one resolver, or remove the stanza to use the host's resolv.conf")
	}
	return out, nil
}

// hclStorage has no remain body on purpose: an unknown attribute inside a
// stanza this version reads is an error, not a warning; the operator is
// configuring the real feature, and a typo there must not half-apply.
type hclStorage struct {
	VolumeDir        string   `hcl:"volume_dir,optional"`
	AllowedHostPaths []string `hcl:"allowed_host_paths,optional"`
}

// hclBind reads the bind stanza: kanead's listeners (api_*) and the edge's
// (edge_*). An unknown attribute inside the block is an error (no remain
// body).
type hclBind struct {
	APISocket string `hcl:"api_socket,optional"`
	APIAddr   string `hcl:"api_addr,optional"`
	APITLS    string `hcl:"api_tls,optional"`
	APIDomain string `hcl:"api_domain,optional"`
	APICert   string `hcl:"api_cert,optional"`
	APIKey    string `hcl:"api_key,optional"`
	EdgeHTTP  string `hcl:"edge_http,optional"`
	EdgeHTTPS string `hcl:"edge_https,optional"`
}

// Probe loads path if it exists. A missing file is the feature being off:
// an empty Config and no error. Any other stat failure is an error: an
// unreadable policy file is ambiguity, and ambiguity on a grant surface
// resolves loud.
func Probe(path string) (*Config, error) {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("nodeconfig: stat %s: %w", path, err)
	}
	return Load(path)
}

// Load reads the node config at path. The file must exist, pass
// CheckTrusted, and parse; each failure is an error (deny-closed).
func Load(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("nodeconfig: no path given")
	}
	if err := CheckTrusted(path); err != nil {
		return nil, err
	}
	src, err := os.ReadFile(path) // #nosec G304; operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("nodeconfig: read %s: %w", path, err)
	}
	cfg, err := Parse(path, src)
	if err != nil {
		return nil, err
	}
	cfg.Path = path
	cfg.Source = src
	return cfg, nil
}

// Parse builds a Config from source. filename appears in diagnostics.
// Exported for tests; Load is the trust-checked door.
func Parse(filename string, src []byte) (*Config, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("nodeconfig: %s", diags.Error())
	}

	var root hclRoot
	if diags := gohcl.DecodeBody(file.Body, nil, &root); diags.HasErrors() {
		return nil, fmt.Errorf("nodeconfig: %s", diags.Error())
	}

	cfg := &Config{
		DataDir: root.DataDir, AllocLogDir: root.AllocLogDir,
		LogLevel: root.LogLevel, BaseDomain: root.BaseDomain,
		Ignored: walkTopLevel(file.Body),
	}
	if root.Storage != nil {
		cfg.VolumeDir = root.Storage.VolumeDir
		// nil stays nil: an absent attribute and an explicit empty list are
		// both "no host volumes", and only the second is something written.
		if root.Storage.AllowedHostPaths != nil {
			paths := make([]string, 0, len(root.Storage.AllowedHostPaths))
			for _, p := range root.Storage.AllowedHostPaths {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				paths = append(paths, p)
			}
			cfg.AllowedHostPaths = paths
		}
	}
	if root.Images != nil {
		// The same closed set jobspec enforces on a spec, checked here so the
		// node's own default cannot be a word nothing understands. "always" is
		// refused: it lowers to per-service auto-update (R19), which is a
		// decision about one service's tag, and a node-wide default that
		// turned auto-update on for every service would be a policy nobody
		// asked for.
		policy := strings.TrimSpace(root.Images.PullPolicy)
		switch policy {
		case "", runtime.PullIfNotPresent, runtime.PullNever:
			cfg.ImagePullPolicy = policy
		case runtime.PullAlways:
			return nil, fmt.Errorf("images: pull_policy %q is not a node default: it turns on "+
				"image auto-update for one service, which is a per-service "+
				"decision. Declare it on the service's task instead", policy)
		default:
			return nil, fmt.Errorf("images: pull_policy %q is not a policy; it must be %q or %q",
				policy, runtime.PullIfNotPresent, runtime.PullNever)
		}
		if root.Images.GC != nil {
			gc, err := parseImageGC(root.Images.GC)
			if err != nil {
				return nil, fmt.Errorf("nodeconfig: %s: %w", filename, err)
			}
			cfg.ImageGC = gc
		}
	}
	if root.DNS != nil {
		cfg.DNSListen = root.DNS.Listen
		// An absent upstreams attribute means the host's resolvers; an
		// explicit empty list is refused by name (validateDNSUpstreams).
		if root.DNS.Upstreams != nil {
			upstreams, err := validateDNSUpstreams(root.DNS.Upstreams)
			if err != nil {
				return nil, fmt.Errorf("nodeconfig: %s: %w", filename, err)
			}
			cfg.DNSUpstreams = upstreams
		}
	}
	if root.Bind != nil {
		bind := &BindConfig{
			APISocket: strings.TrimSpace(root.Bind.APISocket),
			APIAddr:   strings.TrimSpace(root.Bind.APIAddr),
			APITLS:    strings.TrimSpace(root.Bind.APITLS),
			APIDomain: strings.TrimSpace(root.Bind.APIDomain),
			APICert:   strings.TrimSpace(root.Bind.APICert),
			APIKey:    strings.TrimSpace(root.Bind.APIKey),
			EdgeHTTP:  strings.TrimSpace(root.Bind.EdgeHTTP),
			EdgeHTTPS: strings.TrimSpace(root.Bind.EdgeHTTPS),
		}
		if err := validateBind(bind); err != nil {
			return nil, fmt.Errorf("nodeconfig: %s: %w", filename, err)
		}
		cfg.Bind = bind
	}
	if root.Variables != nil {
		vars, err := decodeVariables(root.Variables.Body)
		if err != nil {
			return nil, fmt.Errorf("nodeconfig: %s: %w", filename, err)
		}
		cfg.Variables = vars
	}
	if err := decodeStanzas(filename, &root, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// reservedVarNames may not be declared as variables (R30): the R2 built-ins,
// whose values belong to the pipeline, and `service`, the spec's
// service-reference namespace. Deliberately duplicated from internal/jobspec
// (the ownershipRefusedBy precedent): a dependency between the node's config
// reader and the spec parser would point no right way, and the list is five
// entries.
var reservedVarNames = map[string]bool{
	"GIT_SHA": true, "GIT_SHA_SHORT": true, "GIT_BRANCH": true,
	"KANEA_PROJECT": true, "service": true,
}

// decodeVariables reads the variables stanza. Values are literals: a node
// default has no context to reference, so an expression that needs one is the
// unknown-variable error HCL already gives it. Primitives only, carried as
// strings; a list or object is refused by name, like a reserved name
// (present-but-malformed is fatal, the v1.51 rule).
func decodeVariables(body hcl.Body) (map[string]string, error) {
	attrs, diags := body.JustAttributes()
	if diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	vars := make(map[string]string, len(attrs))
	for name, attr := range attrs {
		if reservedVarNames[name] {
			return nil, fmt.Errorf("variables: %q is a reserved name", name)
		}
		v, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			return nil, fmt.Errorf("variables: %s", diags.Error())
		}
		if v.IsNull() {
			return nil, fmt.Errorf("variables: %q is null", name)
		}
		if !v.Type().IsPrimitiveType() {
			return nil, fmt.Errorf("variables: %q is a %s; a variable is a string, number or bool",
				name, v.Type().FriendlyName())
		}
		s, err := convert.Convert(v, cty.String)
		if err != nil {
			return nil, fmt.Errorf("variables: %q: %w", name, err)
		}
		vars[name] = s.AsString()
	}
	return vars, nil
}

// validateBind refuses every bind contradiction parse can see (PRD §15.1,
// v1.61). What it deliberately does not decide: whether an unset mode on a
// non-loopback address may stand; that resolution needs the daemon's
// context and lives at its listener construction.
func validateBind(b *BindConfig) error {
	hasPair := b.APICert != "" || b.APIKey != ""
	if (b.APICert == "") != (b.APIKey == "") {
		return errors.New("bind.api_cert and bind.api_key go together")
	}
	if hasPair && b.APIAddr == "" {
		return errors.New("bind declares a TLS pair with no api_addr to serve it on")
	}
	if (b.APITLS != "" || b.APIDomain != "") && b.APIAddr == "" {
		return errors.New("bind declares TLS with no api_addr to serve it on")
	}

	switch b.APITLS {
	case "":
		// Resolved at the daemon: a pair means provided, loopback means
		// plaintext, anything else refuses there.
	case TLSProvided:
		if !hasPair {
			return errors.New("bind.api_tls \"provided\" needs bind.api_cert and bind.api_key")
		}
	case TLSPlaintext:
		if hasPair {
			// A pair beside plaintext is a control that cannot act, carried;
			// R21's rule: refused, never silently dropped.
			return errors.New("bind.api_tls \"plaintext\" beside a TLS pair drops the pair; remove one")
		}
	case TLSAcme:
		if hasPair {
			return errors.New("bind.api_tls \"acme\" issues its own certificate; remove the api_cert/api_key pair")
		}
		if b.APIDomain == "" {
			return errors.New("bind.api_tls \"acme\" needs bind.api_domain; an IP cannot hold an ACME certificate")
		}
	case TLSSelfSigned:
		if hasPair {
			return errors.New("bind.api_tls \"self-signed\" issues its own certificate; remove the api_cert/api_key pair")
		}
		if b.APIDomain == "" && unspecifiedHost(b.APIAddr) {
			return fmt.Errorf("bind.api_addr %q binds every interface; set bind.api_domain so the certificate has a name", b.APIAddr)
		}
	default:
		return fmt.Errorf("bind.api_tls %q: use one of %s, %s, %s, %s",
			b.APITLS, TLSAcme, TLSSelfSigned, TLSProvided, TLSPlaintext)
	}
	return nil
}

// unspecifiedHost reports whether addr binds every interface: an empty host
// (":8600") or the unspecified address of either family. An address that does
// not even split is not this function's finding: the daemon's listener will
// name that problem.
func unspecifiedHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsUnspecified()
}

// walkTopLevel collects the top-level blocks and attributes no decoder
// reads. Duplicate storage blocks are gohcl's error, not an entry here.
func walkTopLevel(body hcl.Body) []string {
	syn, ok := body.(*hclsyntax.Body)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for _, block := range syn.Blocks {
		if !readBlocks[block.Type] {
			seen[block.Type] = true
		}
	}
	for name := range syn.Attributes {
		if !readAttrs[name] {
			seen[name] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// CheckTrusted refuses a policy file someone other than the node's owner
// could have written: it must be a regular file (not a symlink; this check
// cannot vouch for a target it did not stat), owned by root or the daemon's
// own uid, and neither group- nor world-writable. World-readable is fine;
// this is policy, not a secret.
func CheckTrusted(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("nodeconfig: stat %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("nodeconfig: %s: cannot read file ownership on this platform", path)
	}
	if err := checkTrustedInfo(info.Mode(), stat.Uid, os.Geteuid()); err != nil {
		return fmt.Errorf("nodeconfig: %s: %w", path, err)
	}
	return nil
}

func checkTrustedInfo(mode os.FileMode, uid uint32, euid int) error {
	if !mode.IsRegular() {
		return fmt.Errorf("not a regular file (mode %s); a policy file this check cannot vouch for is refused", mode)
	}
	if perm := mode.Perm(); perm&0o022 != 0 {
		return fmt.Errorf(
			"mode %04o is group- or world-writable; a policy anyone can edit is not a policy (chmod 0644)", perm)
	}
	if uid != 0 && int(uid) != euid {
		return fmt.Errorf(
			"owned by uid %d; a policy file must be owned by root or the daemon's own user (uid %d)", uid, euid)
	}
	return nil
}
