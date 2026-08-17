package secretsource

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"

	"github.com/m18h/kanea/internal/secrets"
)

// The node config file (PRD §5.2.13, §15.1), named by
// --secrets-providers-config. Its semantics are certsource.Provided's, not
// passthrough's load-once: re-read via a content fingerprint over the config
// and every credential file it names, parse failure keeps the last good set
// and warns once, and a fingerprint change rebuilds the providers, which is
// also what drops Azure's and GCP's cached tokens when a credential rotates.

// dns1123Label is the shape an allow entry must have. Held here rather than
// imported, the reason passthrough and certsource each hold their own copy: a
// scope the config accepts and no spec can reference is a grant nobody can
// use.
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type hclRoot struct {
	Providers []hclProvider `hcl:"provider,block"`
	Remain    hcl.Body      `hcl:",remain"`
}

type hclProvider struct {
	Kind  string    `hcl:"kind,label"`
	Name  string    `hcl:"name,label"`
	Allow []string  `hcl:"allow"`
	Syncs []hclSync `hcl:"sync,block"`

	// Shared credential file (doppler, vault).
	TokenFile string `hcl:"token_file,optional"`

	// doppler
	Project    string `hcl:"project,optional"`
	ConfigName string `hcl:"config,optional"`
	BaseURL    string `hcl:"base_url,optional"` // default https://api.doppler.com

	// vault
	Address string `hcl:"address,optional"`
	Mount   string `hcl:"mount,optional"`
	CAFile  string `hcl:"ca_file,optional"`

	// aws-sm
	Region        string `hcl:"region,optional"`
	AccessKey     string `hcl:"access_key,optional"`
	SecretKeyFile string `hcl:"secret_key_file,optional"`
	Endpoint      string `hcl:"endpoint,optional"` // default derived from region

	// azure-kv
	VaultURI         string `hcl:"vault_uri,optional"`
	TenantID         string `hcl:"tenant_id,optional"`
	ClientID         string `hcl:"client_id,optional"`
	ClientSecretFile string `hcl:"client_secret_file,optional"`
	LoginURL         string `hcl:"login_url,optional"` // default https://login.microsoftonline.com

	// gcp-sm
	CredentialsFile string `hcl:"credentials_file,optional"`
	// Project doubles for gcp-sm (defaults to the key's project_id) and
	// doppler; the kinds never share a block, so the field can be shared.

	DefRange hcl.Range `hcl:",def_range"`
}

type hclSync struct {
	To string `hcl:"to"`

	Name         string `hcl:"name,optional"`          // doppler, azure-kv, gcp-sm
	Path         string `hcl:"path,optional"`          // vault
	Field        string `hcl:"field,optional"`         // vault
	ID           string `hcl:"id,optional"`            // aws-sm
	JSONKey      string `hcl:"json_key,optional"`      // aws-sm
	Version      string `hcl:"version,optional"`       // azure-kv (optional), gcp-sm (default "latest")
	VersionStage string `hcl:"version_stage,optional"` // aws-sm (default AWSCURRENT)

	DefRange hcl.Range `hcl:",def_range"`
}

// syncMapping is one validated mapping, with per-kind defaults applied.
type syncMapping struct {
	To           string
	Name         string
	Path, Field  string
	ID, JSONKey  string
	Version      string
	VersionStage string
}

// providerConfig is one validated provider block.
type providerConfig struct {
	kind Kind
	name string
	hcl  hclProvider
	maps []syncMapping
}

// credentialFiles lists every file the block names, for the fingerprint.
func (c providerConfig) credentialFiles() []string {
	var out []string
	for _, f := range []string{
		c.hcl.TokenFile, c.hcl.SecretKeyFile, c.hcl.ClientSecretFile,
		c.hcl.CredentialsFile, c.hcl.CAFile,
	} {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// Providers loads the config file and hands out the current provider set.
type Providers struct {
	path   string
	client *http.Client
	log    *slog.Logger

	mu sync.Mutex
	// providers is the last set that built. A parse failure keeps it, the way
	// certsource.Provided keeps its last good policy: a half-saved file must
	// not stop a working sync.
	providers []Provider
	built     bool
	builtHash [sha256.Size]byte
	warned    bool
	// pollHash is Changed's own cursor, separate from builtHash so the loop
	// asking "did anything move" does not stop Current from noticing.
	polled   bool
	pollHash [sha256.Size]byte
}

// NewProviders builds the loader. An empty path turns the feature off.
func NewProviders(path string, client *http.Client, logger *slog.Logger) *Providers {
	if client == nil {
		client = DefaultHTTPClient()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Providers{path: strings.TrimSpace(path), client: client, log: logger}
}

// Configured reports whether an operator pointed this node at a config file.
func (p *Providers) Configured() bool { return p.path != "" }

// Path is the config file, for logs.
func (p *Providers) Path() string { return p.path }

// Changed reports whether the config or any credential file it names has
// moved since the last call, so the loop can wake an immediate pass.
//
// Content-hashed, never stat-ed, and a poll rather than fsnotify; the
// certsource.Provided reasoning verbatim: rotation tools write then rename,
// which lies to mtime and replaces the inode a watch would be registered on.
func (p *Providers) Changed() bool {
	if p.path == "" {
		return false
	}
	sum := p.fingerprint()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.polled && sum == p.pollHash {
		return false
	}
	p.pollHash = sum
	p.polled = true
	return true
}

// Current returns the provider set, rebuilding only when the fingerprint
// moved. Keeping instances stable across unchanged passes is what lets Azure
// and GCP hold their cached tokens between passes: rebuilding every pass
// would re-authenticate against two identity providers per poll for nothing.
func (p *Providers) Current() []Provider {
	if p.path == "" {
		return nil
	}
	sum := p.fingerprint()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.built && sum == p.builtHash {
		return p.providers
	}

	src, err := os.ReadFile(p.path) // #nosec G304: operator-supplied config path
	if err == nil {
		var configs []providerConfig
		if configs, err = parseConfig(p.path, src); err == nil {
			built := make([]Provider, 0, len(configs))
			for _, cfg := range configs {
				prov, buildErr := p.build(cfg)
				if buildErr != nil {
					// A provider that cannot be built (unloadable CA file) is
					// a config problem; treat the whole file as unusable so
					// the operator meets one coherent complaint.
					err = buildErr
					break
				}
				built = append(built, prov)
			}
			if err == nil {
				p.providers, p.built, p.builtHash, p.warned = built, true, sum, false
				return p.providers
			}
		}
	}
	// Logged once per bad state (certsource's rule): a config nobody fixes
	// for a week must not be a log line every minute.
	if !p.warned {
		p.warned = true
		p.log.Error("secret provider config unusable; keeping the last one that built",
			"path", p.path, "error", err, "providers", len(p.providers))
	}
	// The hash is recorded even on failure so a *fix* is what rebuilds, not
	// every pass retrying a file that has not moved.
	p.built, p.builtHash = true, sum
	return p.providers
}

// build constructs one provider from its validated config.
func (p *Providers) build(cfg providerConfig) (Provider, error) {
	// Plaintext endpoints are legal (Vault on RFC1918 is the reason the egress
	// guard does not apply here) and warned about, on every build (K-50):
	// http carries the provider's own credential, and a rebuild is a config
	// change, which is when the operator is listening.
	for _, ep := range []struct{ name, v string }{
		{"base_url", cfg.hcl.BaseURL}, {"address", cfg.hcl.Address},
		{"endpoint", cfg.hcl.Endpoint}, {"vault_uri", cfg.hcl.VaultURI},
		{"login_url", cfg.hcl.LoginURL},
	} {
		if strings.HasPrefix(ep.v, "http://") {
			p.log.Warn("secrets provider endpoint is plain HTTP",
				"provider", cfg.name, ep.name, ep.v,
				"detail", "the provider's credential travels unencrypted; fine on a trusted "+
					"link, never across one you do not own")
		}
	}
	switch cfg.kind {
	case KindDoppler:
		return newDoppler(cfg, p.client, p.log), nil
	case KindVault:
		return newVault(cfg, p.client, p.log)
	case KindAWS:
		return newAWSSM(cfg, p.client, p.log), nil
	case KindAzure:
		return newAzureKV(cfg, p.client, p.log), nil
	case KindGCP:
		return newGCPSM(cfg, p.client, p.log), nil
	default:
		// parseConfig already refused unknown kinds; reaching this is a bug.
		return nil, fmt.Errorf("secretsource: unhandled kind %q", cfg.kind)
	}
}

// fingerprint hashes the config and every credential file it names. An
// unreadable file contributes its error text, so a token that disappears and
// comes back is two changes rather than none.
func (p *Providers) fingerprint() [sha256.Size]byte {
	h := sha256.New()
	// hash.Hash.Write never returns an error, so nothing in here can fail.
	write := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		h.Write([]byte(line))
	}

	src, err := os.ReadFile(p.path) // #nosec G304: operator-supplied config path
	if err != nil {
		write("config-error:%v\n", err)
		return sum256(h)
	}
	h.Write(src)

	configs, perr := parseConfig(p.path, src)
	if perr != nil {
		return sum256(h)
	}
	for _, cfg := range configs {
		for _, f := range cfg.credentialFiles() {
			body, err := os.ReadFile(f) // #nosec G304: operator-supplied path
			if err != nil {
				write("%s:error:%v\n", f, err)
				continue
			}
			write("%s:", f)
			h.Write(body)
		}
	}
	return sum256(h)
}

func sum256(h interface{ Sum([]byte) []byte }) [sha256.Size]byte {
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// parseConfig reads and validates the whole file. Every refusal names what is
// wrong and where; a config error is met by an operator, and "invalid" is not
// an answer they can act on.
func parseConfig(filename string, src []byte) ([]providerConfig, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("secretsource: %s", diags.Error())
	}
	var root hclRoot
	if diags := gohcl.DecodeBody(file.Body, nil, &root); diags.HasErrors() {
		return nil, fmt.Errorf("secretsource: %s", diags.Error())
	}

	seenNames := make(map[string]struct{}, len(root.Providers))
	// Two writers on one local path is a fight, not a merge: refused across
	// the whole file, whichever providers they belong to.
	targets := make(map[string]string)

	out := make([]providerConfig, 0, len(root.Providers))
	for _, block := range root.Providers {
		kind := Kind(block.Kind)
		label := fmt.Sprintf("provider %q %q", block.Kind, block.Name)

		if !kind.Valid() {
			return nil, fmt.Errorf("secretsource: %s: unknown kind %q; known kinds are %s",
				label, block.Kind, joinKinds())
		}
		if !dns1123Label.MatchString(block.Name) {
			return nil, fmt.Errorf("secretsource: %s: the name is not a DNS-1123 label", label)
		}
		if _, dup := seenNames[block.Name]; dup {
			return nil, fmt.Errorf("secretsource: provider %q is defined twice", block.Name)
		}
		seenNames[block.Name] = struct{}{}

		// An empty allow is a typo, not a permissive default: the certsource
		// and passthrough rule, on the write side this time.
		if len(block.Allow) == 0 {
			return nil, fmt.Errorf(
				"secretsource: %s lists no scopes in `allow`; a provider that may write "+
					"nowhere is not a permissive default", label)
		}
		allow := make(map[string]struct{}, len(block.Allow))
		for _, scope := range block.Allow {
			if scope != secrets.SharedScope && !dns1123Label.MatchString(scope) {
				return nil, fmt.Errorf(
					"secretsource: %s allows %q, which is not a project name or %q",
					label, scope, secrets.SharedScope)
			}
			allow[scope] = struct{}{}
		}

		if err := checkProviderFields(kind, label, block); err != nil {
			return nil, err
		}

		if len(block.Syncs) == 0 {
			return nil, fmt.Errorf("secretsource: %s declares no sync blocks; "+
				"a provider syncing nothing is not configuration", label)
		}
		maps := make([]syncMapping, 0, len(block.Syncs))
		for _, s := range block.Syncs {
			clean, err := secrets.CleanPath(s.To)
			if err != nil {
				return nil, fmt.Errorf("secretsource: %s: sync `to` %q: %w", label, s.To, err)
			}
			scope, err := secrets.Scope(clean)
			if err != nil {
				return nil, fmt.Errorf("secretsource: %s: sync `to` %q: %w", label, s.To, err)
			}
			if _, ok := allow[scope]; !ok {
				return nil, fmt.Errorf(
					"secretsource: %s: sync `to` %q writes into scope %q, which `allow` does not list",
					label, clean, scope)
			}
			if owner, dup := targets[clean]; dup {
				return nil, fmt.Errorf(
					"secretsource: two sync blocks target %q (%s and %s); one local path has one writer",
					clean, owner, label)
			}
			targets[clean] = label

			m, err := checkSyncFields(kind, label, s)
			if err != nil {
				return nil, err
			}
			m.To = clean
			maps = append(maps, m)
		}

		out = append(out, providerConfig{kind: kind, name: block.Name, hcl: block, maps: maps})
	}
	return out, nil
}

func joinKinds() string {
	names := make([]string, 0, len(Kinds()))
	for _, k := range Kinds() {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}

// checkProviderFields enforces each kind's required fields and refuses fields
// that belong to another kind: a field silently ignored is R21's dropped
// control wearing a config file's clothes.
func checkProviderFields(kind Kind, label string, b hclProvider) error {
	type field struct {
		name  string
		value string
	}
	all := []field{
		{"token_file", b.TokenFile},
		{"project", b.Project}, {"config", b.ConfigName}, {"base_url", b.BaseURL},
		{"address", b.Address}, {"mount", b.Mount}, {"ca_file", b.CAFile},
		{"region", b.Region}, {"access_key", b.AccessKey},
		{"secret_key_file", b.SecretKeyFile}, {"endpoint", b.Endpoint},
		{"vault_uri", b.VaultURI}, {"tenant_id", b.TenantID},
		{"client_id", b.ClientID}, {"client_secret_file", b.ClientSecretFile},
		{"login_url", b.LoginURL},
		{"credentials_file", b.CredentialsFile},
	}
	belongs := map[Kind]map[string]bool{
		KindDoppler: {"token_file": true, "project": true, "config": true, "base_url": true},
		KindVault:   {"token_file": true, "address": true, "mount": true, "ca_file": true},
		KindAWS:     {"region": true, "access_key": true, "secret_key_file": true, "endpoint": true},
		KindAzure: {"vault_uri": true, "tenant_id": true, "client_id": true,
			"client_secret_file": true, "login_url": true},
		KindGCP: {"credentials_file": true, "project": true, "endpoint": true},
	}
	required := map[Kind][]string{
		KindDoppler: {"token_file", "project", "config"},
		KindVault:   {"token_file", "address", "mount"},
		KindAWS:     {"region", "access_key", "secret_key_file"},
		KindAzure:   {"vault_uri", "tenant_id", "client_id", "client_secret_file"},
		KindGCP:     {"credentials_file"},
	}

	set := make(map[string]string, len(all))
	for _, f := range all {
		if f.value != "" {
			set[f.name] = f.value
		}
	}
	for name := range set {
		if !belongs[kind][name] {
			return fmt.Errorf("secretsource: %s: %q is not a %s field", label, name, kind)
		}
	}
	for _, name := range required[kind] {
		if set[name] == "" {
			return fmt.Errorf("secretsource: %s is missing %q", label, name)
		}
	}

	// Credential files are absolute: the daemon's working directory is not
	// something a config should depend on (certsource's rule).
	for _, name := range []string{"token_file", "secret_key_file", "client_secret_file",
		"credentials_file", "ca_file"} {
		if v, ok := set[name]; ok && !strings.HasPrefix(v, "/") {
			return fmt.Errorf("secretsource: %s: %s %q is a relative path", label, name, v)
		}
	}
	// Endpoints must be URLs someone meant to type.
	for _, name := range []string{"base_url", "address", "endpoint", "vault_uri", "login_url"} {
		v, ok := set[name]
		if !ok {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("secretsource: %s: %s %q is not an http(s) URL", label, name, v)
		}
	}
	return nil
}

// checkSyncFields enforces each kind's sync-block shape and applies defaults.
func checkSyncFields(kind Kind, label string, s hclSync) (syncMapping, error) {
	type field struct {
		name  string
		value string
	}
	all := []field{
		{"name", s.Name}, {"path", s.Path}, {"field", s.Field},
		{"id", s.ID}, {"json_key", s.JSONKey},
		{"version", s.Version}, {"version_stage", s.VersionStage},
	}
	belongs := map[Kind]map[string]bool{
		KindDoppler: {"name": true},
		KindVault:   {"path": true, "field": true},
		KindAWS:     {"id": true, "json_key": true, "version_stage": true},
		KindAzure:   {"name": true, "version": true},
		KindGCP:     {"name": true, "version": true},
	}
	required := map[Kind][]string{
		KindDoppler: {"name"},
		KindVault:   {"path", "field"},
		KindAWS:     {"id"},
		KindAzure:   {"name"},
		KindGCP:     {"name"},
	}

	set := make(map[string]string, len(all))
	for _, f := range all {
		if f.value != "" {
			set[f.name] = f.value
		}
	}
	for name := range set {
		if !belongs[kind][name] {
			return syncMapping{}, fmt.Errorf(
				"secretsource: %s: sync for %q: %q is not a %s sync field", label, s.To, name, kind)
		}
	}
	for _, name := range required[kind] {
		if set[name] == "" {
			return syncMapping{}, fmt.Errorf(
				"secretsource: %s: sync for %q is missing %q", label, s.To, name)
		}
	}

	m := syncMapping{
		Name: s.Name, Path: s.Path, Field: s.Field,
		ID: s.ID, JSONKey: s.JSONKey,
		Version: s.Version, VersionStage: s.VersionStage,
	}
	if kind == KindAWS && m.VersionStage == "" {
		m.VersionStage = "AWSCURRENT"
	}
	if kind == KindGCP && m.Version == "" {
		m.Version = "latest"
	}
	return m, nil
}
