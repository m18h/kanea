// Package nodeconfig reads the node's server config, /etc/kanea/kanea.hcl
// (PRD §15.1, real since v1.51).
//
// The file is the §14 A05 boundary in file form: what it grants, no API, MCP
// tool or job spec can grant. That shapes every decision here. It is read
// once, at startup — a probe is one stat, never a poll, and there is no
// reload: a grant is a decision, so the keep-last-good discipline of the
// reload-family configs (certsource, secretsource) deliberately does not
// apply. Absent means off; present-but-malformed is fatal; and because the
// path is well-known, the file is trust-checked before parsing (CheckTrusted)
// so a policy nobody but the node's owner could have written stays true.
//
// This version reads only the storage stanza. The device/socket grant blocks
// in the same file are decoded by internal/passthrough over the same bytes —
// two decoders, each owning its blocks. Stanzas neither reads are collected
// into Config.Ignored for a startup warning naming them: not silently
// swallowed (a typo that vanishes is the trap), not refused (PRD §15.1
// sketches them, and an operator writing ahead of the implementation is not
// typoing). An unknown attribute inside a read stanza is an error.
package nodeconfig

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// DefaultPath is where the server config is probed when --config does not
// name one. The value is provision.DefaultConfDir's; a test pins agreement.
const DefaultPath = "/etc/kanea/kanea.hcl"

// readBlocks are the top-level block types some decoder consumes: storage
// here, device/socket by internal/passthrough over the same file.
var readBlocks = map[string]bool{"storage": true, "device": true, "socket": true}

// Config is the subset of PRD §15.1 this version reads.
type Config struct {
	// AllowedHostPaths is storage.allowed_host_paths (R15).
	// nil when the file or the stanza is absent.
	AllowedHostPaths []string
	// Ignored names the top-level blocks and attributes the file carries
	// and no decoder reads, for the startup warning.
	Ignored []string
	// HasGrants reports whether the file carries device or socket blocks —
	// internal/passthrough owns their parsing; this only lets the caller say
	// when an explicit --passthrough-config is overriding them.
	HasGrants bool
	// Path is the file that was read; "" when nothing was.
	Path string
}

type hclRoot struct {
	Storage *hclStorage `hcl:"storage,block"`
	Remain  hcl.Body    `hcl:",remain"`
}

// hclStorage has no remain body on purpose: an unknown attribute inside a
// stanza this version reads is an error, not a warning — the operator is
// configuring the real feature, and a typo there must not half-apply.
type hclStorage struct {
	AllowedHostPaths []string `hcl:"allowed_host_paths,optional"`
}

// Probe loads path if it exists. A missing file is the feature being off —
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

// Load reads an explicitly named server config. The file must exist, pass
// CheckTrusted, and parse; each failure is an error (deny-closed).
func Load(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("nodeconfig: no path given")
	}
	if err := CheckTrusted(path); err != nil {
		return nil, err
	}
	src, err := os.ReadFile(path) // #nosec G304 — operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("nodeconfig: read %s: %w", path, err)
	}
	cfg, err := Parse(path, src)
	if err != nil {
		return nil, err
	}
	cfg.Path = path
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

	cfg := &Config{}
	cfg.Ignored, cfg.HasGrants = walkTopLevel(file.Body)
	if root.Storage != nil {
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
	return cfg, nil
}

// walkTopLevel collects the top-level blocks and attributes no decoder
// reads, and whether grant blocks are present. Duplicate storage blocks are
// gohcl's error, not an entry here.
func walkTopLevel(body hcl.Body) (ignored []string, hasGrants bool) {
	syn, ok := body.(*hclsyntax.Body)
	if !ok {
		return nil, false
	}
	seen := map[string]bool{}
	for _, block := range syn.Blocks {
		if block.Type == "device" || block.Type == "socket" {
			hasGrants = true
		}
		if !readBlocks[block.Type] {
			seen[block.Type] = true
		}
	}
	for name := range syn.Attributes {
		seen[name] = true
	}
	if len(seen) == 0 {
		return nil, hasGrants
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, hasGrants
}

// CheckTrusted refuses a policy file someone other than the node's owner
// could have written: it must be a regular file (not a symlink — this check
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
