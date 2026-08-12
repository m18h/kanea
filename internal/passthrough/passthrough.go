// Package passthrough decides which host devices and unix sockets a job spec
// may be given (PRD §6.2 R17–R18).
//
// The model is R15's, with one addition. R15 splits *shape* from *permission*:
// a job spec says what it wants, the server config says what is allowed, and
// the default allows nothing. This package is the permission half for devices
// and sockets — but unlike `storage.allowed_host_paths`, a spec here never
// names a path at all. It names a *grant*, an operator defines that grant on
// the node, and the node resolves the name locally. No host path reaches the
// Store, the API or a git repository (§18 rule 5).
//
// Grants are project-scoped, which the host-path allowlist is not. A prefix
// allowlist is proportionate for a shared data directory; it is not
// proportionate for the container runtime's socket, which is node-level control
// for whoever holds it (R18). So each grant names the projects that may claim
// it, and a grant naming none is refused as a config error rather than read as
// a permissive default.
//
// The zero value permits nothing, and so does a nil *Policy: the feature does
// not exist until an operator writes a file.
package passthrough

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// ErrNotAllowed marks a passthrough a spec asked for and the node does not
// permit. It is deliberately one error for "no such grant", "not your project"
// and "that is not a device any more": all three mean the alloc does not start,
// and distinguishing them for the caller would only invite a fallback.
var ErrNotAllowed = errors.New("passthrough: not allowed")

// dns1123Label is the same shape a job spec validates a grant reference as
// (R1). Held here as well rather than imported: a grant name the config accepts
// and no spec can reference is a grant nobody can use, and the two rules
// agreeing is the point.
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// devicePerms is the cgroup permission string a device grant may carry.
var devicePerms = regexp.MustCompile(`^[rwm]+$`)

// DefaultDeviceMode is what a device grant gets when it does not say.
//
// Read and write, never mknod: `m` lets the container create *other* device
// nodes of the same major, which is a different and much larger grant than the
// one an operator writing `nodes = ["/dev/dri/renderD128"]` believes they are
// making. An operator who wants it writes it.
const DefaultDeviceMode = "rw"

// Device is one resolved device node, ready to be put in an OCI spec.
//
// Major, minor and file mode are deliberately absent: the runtime reads those
// from the node itself at spec-build time, and a second copy here would be a
// copy that can disagree with the device.
type Device struct {
	// Path is the resolved host path. It is also where the device appears
	// inside the container — v1 does not remap.
	Path string
	// Perms is the cgroup device permission string ("rw", "rwm").
	Perms string
}

// Policy is the set of grants an operator has defined on this node.
type Policy struct {
	devices map[string]deviceGrant
	sockets map[string]socketGrant
}

type deviceGrant struct {
	nodes []string
	allow map[string]struct{}
	mode  string
}

type socketGrant struct {
	path  string
	allow map[string]struct{}
}

// ---- config file ---------------------------------------------------------

type hclRoot struct {
	Devices []hclDevice `hcl:"device,block"`
	Sockets []hclSocket `hcl:"socket,block"`
	Remain  hcl.Body    `hcl:",remain"`
}

type hclDevice struct {
	Name     string    `hcl:"name,label"`
	Nodes    []string  `hcl:"nodes"`
	Allow    []string  `hcl:"allow"`
	Mode     string    `hcl:"mode,optional"`
	DefRange hcl.Range `hcl:",def_range"`
}

type hclSocket struct {
	Name     string    `hcl:"name,label"`
	Path     string    `hcl:"path"`
	Allow    []string  `hcl:"allow"`
	DefRange hcl.Range `hcl:",def_range"`
}

// Load reads a passthrough config from disk.
//
// An empty path is not an error and yields a policy that permits nothing —
// that is the default, and the daemon runs without the file.
func Load(path string) (*Policy, error) {
	if strings.TrimSpace(path) == "" {
		return &Policy{}, nil
	}
	src, err := os.ReadFile(path) // #nosec G304 — operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("passthrough: read %s: %w", path, err)
	}
	return Parse(path, src)
}

// Parse builds a policy from config source. filename appears in diagnostics.
func Parse(filename string, src []byte) (*Policy, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("passthrough: %s", diags.Error())
	}

	var root hclRoot
	if diags := gohcl.DecodeBody(file.Body, nil, &root); diags.HasErrors() {
		return nil, fmt.Errorf("passthrough: %s", diags.Error())
	}

	policy := &Policy{
		devices: make(map[string]deviceGrant, len(root.Devices)),
		sockets: make(map[string]socketGrant, len(root.Sockets)),
	}

	for _, d := range root.Devices {
		if err := checkGrantName("device", d.Name); err != nil {
			return nil, err
		}
		if _, dup := policy.devices[d.Name]; dup {
			return nil, fmt.Errorf("passthrough: device grant %q is defined twice", d.Name)
		}
		if len(d.Nodes) == 0 {
			return nil, fmt.Errorf("passthrough: device grant %q lists no nodes", d.Name)
		}
		nodes := make([]string, 0, len(d.Nodes))
		for _, node := range d.Nodes {
			if err := checkGrantPath("device", d.Name, node); err != nil {
				return nil, err
			}
			nodes = append(nodes, filepath.Clean(node))
		}
		mode := strings.TrimSpace(d.Mode)
		if mode == "" {
			mode = DefaultDeviceMode
		}
		if !devicePerms.MatchString(mode) {
			return nil, fmt.Errorf(
				"passthrough: device grant %q has mode %q; it must be some combination of r, w and m",
				d.Name, d.Mode)
		}
		allow, err := checkAllow("device", d.Name, d.Allow)
		if err != nil {
			return nil, err
		}
		policy.devices[d.Name] = deviceGrant{nodes: nodes, allow: allow, mode: mode}
	}

	for _, s := range root.Sockets {
		if err := checkGrantName("socket", s.Name); err != nil {
			return nil, err
		}
		if _, dup := policy.sockets[s.Name]; dup {
			return nil, fmt.Errorf("passthrough: socket grant %q is defined twice", s.Name)
		}
		if err := checkGrantPath("socket", s.Name, s.Path); err != nil {
			return nil, err
		}
		allow, err := checkAllow("socket", s.Name, s.Allow)
		if err != nil {
			return nil, err
		}
		policy.sockets[s.Name] = socketGrant{path: filepath.Clean(s.Path), allow: allow}
	}

	return policy, nil
}

func checkGrantName(kind, name string) error {
	if !dns1123Label.MatchString(name) {
		return fmt.Errorf(
			"passthrough: %s grant %q is not a DNS-1123 label, so no job spec could reference it",
			kind, name)
	}
	return nil
}

// checkGrantPath validates the shape of a configured path.
//
// Shape only, and at load time only. Whether the path is a device or a socket
// is checked when it is *used* rather than here: a node that answers "yes" at
// daemon start and is a regular file by the time an alloc gets it is exactly
// the swap worth catching, and a USB device that is unplugged at boot must not
// stop the daemon from starting.
func checkGrantPath(kind, name, path string) error {
	reject := func(detail string) error {
		return fmt.Errorf("passthrough: %s grant %q: %s", kind, name, detail)
	}
	switch {
	case strings.TrimSpace(path) == "":
		return reject("a path is required")
	case !filepath.IsAbs(path):
		return reject(fmt.Sprintf("path %q must be absolute", path))
	case strings.Contains(path, ".."):
		return reject(fmt.Sprintf("path %q must not contain \"..\"", path))
	case filepath.Clean(path) == "/":
		return reject("the root filesystem is not a device or a socket")
	}
	return nil
}

// checkAllow requires a grant to name the projects that may claim it.
//
// An empty list is refused rather than read as "everyone". A grant is at
// minimum a hole in the §14 A05 defaults and at maximum root on the node, and
// the difference between "I have not filled this in yet" and "anyone may have
// this" is not one to resolve in the permissive direction.
func checkAllow(kind, name string, projects []string) (map[string]struct{}, error) {
	if len(projects) == 0 {
		return nil, fmt.Errorf(
			"passthrough: %s grant %q names no projects in `allow`; "+
				"list the projects that may use it", kind, name)
	}
	allow := make(map[string]struct{}, len(projects))
	for _, project := range projects {
		if !dns1123Label.MatchString(project) {
			return nil, fmt.Errorf(
				"passthrough: %s grant %q allows %q, which is not a project name",
				kind, name, project)
		}
		allow[project] = struct{}{}
	}
	return allow, nil
}

// ---- resolution ----------------------------------------------------------

// Enabled reports whether any grant is defined.
func (p *Policy) Enabled() bool {
	if p == nil {
		return false
	}
	return len(p.devices) > 0 || len(p.sockets) > 0
}

// ResolveDevice returns the device nodes a project may have under a grant.
func (p *Policy) ResolveDevice(project, grant string) ([]Device, error) {
	if p == nil || len(p.devices) == 0 {
		return nil, notConfigured("device", grant)
	}
	g, ok := p.devices[grant]
	if !ok {
		return nil, fmt.Errorf("%w: no device grant named %q on this node (have: %s)",
			ErrNotAllowed, grant, grantNames(p.devices))
	}
	if _, ok := g.allow[project]; !ok {
		return nil, fmt.Errorf("%w: device grant %q is not allowed to project %q",
			ErrNotAllowed, grant, project)
	}

	devices := make([]Device, 0, len(g.nodes))
	for _, node := range g.nodes {
		resolved, info, err := resolve(node)
		if err != nil {
			return nil, fmt.Errorf("%w: device grant %q: %w", ErrNotAllowed, grant, err)
		}
		if info.Mode()&os.ModeDevice == 0 {
			return nil, fmt.Errorf("%w: device grant %q: %q is not a device",
				ErrNotAllowed, grant, node)
		}
		devices = append(devices, Device{Path: resolved, Perms: g.mode})
	}
	return devices, nil
}

// ResolveSocket returns the host socket a project may have under a grant.
func (p *Policy) ResolveSocket(project, grant string) (string, error) {
	if p == nil || len(p.sockets) == 0 {
		return "", notConfigured("socket", grant)
	}
	g, ok := p.sockets[grant]
	if !ok {
		return "", fmt.Errorf("%w: no socket grant named %q on this node (have: %s)",
			ErrNotAllowed, grant, grantNames(p.sockets))
	}
	if _, ok := g.allow[project]; !ok {
		return "", fmt.Errorf("%w: socket grant %q is not allowed to project %q",
			ErrNotAllowed, grant, project)
	}

	resolved, info, err := resolve(g.path)
	if err != nil {
		return "", fmt.Errorf("%w: socket grant %q: %w", ErrNotAllowed, grant, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return "", fmt.Errorf("%w: socket grant %q: %q is not a socket",
			ErrNotAllowed, grant, g.path)
	}
	return resolved, nil
}

// resolve evaluates symlinks and stats the result.
//
// Both happen per alloc rather than once at load: the file behind a configured
// path can change type or vanish while the daemon runs, and the check that
// matters is the one taken at the moment the path is handed to a container.
func resolve(path string) (string, os.FileInfo, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, fmt.Errorf("%q does not exist on this node", path)
		}
		return "", nil, fmt.Errorf("%q: %w", path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", nil, fmt.Errorf("%q: %w", path, err)
	}
	return resolved, info, nil
}

func notConfigured(kind, grant string) error {
	return fmt.Errorf("%w: this node has no %s grants, so %q cannot be given "+
		"(add %s blocks to /etc/kanea/kanea.hcl, or set --passthrough-config)",
		ErrNotAllowed, kind, grant, kind)
}

// grantNames lists what is defined, so a typo reports what was meant.
func grantNames[T any](grants map[string]T) string {
	if len(grants) == 0 {
		return "none"
	}
	names := make([]string, 0, len(grants))
	for name := range grants {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
