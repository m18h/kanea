// Package provision installs and pins the host components Kanea runs on:
// containerd, runc and rootless buildkitd (PRD §5.2.12).
//
// The shape that matters is the one seam in this package: nothing below
// [Installer] fetches anything. An installer is handed a [Source] and asks it
// for bytes, and every byte is checked against a hash compiled into this
// binary. That is what makes the air-gapped path the same code as the online
// one rather than a second implementation nobody exercises, and it is why the
// verification lives here, on the near side of the seam, where a Source cannot
// opt out of it.
package provision

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

//go:embed components.json
var manifestJSON []byte

// Kind is how a component's bytes arrive.
type Kind string

const (
	// KindArchive is a tar.gz whose members are extracted.
	KindArchive Kind = "archive"
	// KindBinary is a single executable, downloaded as-is.
	KindBinary Kind = "binary"
	// KindImage is an OCI image, pulled by digest and never by tag, because a
	// tag is a mutable pointer to a root filesystem.
	KindImage Kind = "image"
)

// File is one payload member and where it lands under the install prefix.
type File struct {
	// From is the path inside the archive or image rootfs. Empty means the
	// payload itself, which is what KindBinary always uses.
	From string `json:"from"`
	// Alt is a second place to look. Upstream images move binaries between
	// releases, and failing an install over a path that shifted is worse than
	// trying both.
	Alt string `json:"alt"`
	// To is the destination, relative to the install prefix.
	To string `json:"to"`
	// Mode is the destination mode, as an octal string ("0755").
	Mode string `json:"mode"`
	// Exclude names members a directory capture must not take. Upstream
	// archives carry a LICENSE and a README next to the binaries, and a bin
	// directory where two of the entries are documents installed 0755 invites
	// exactly one question from every operator who looks.
	Exclude []string `json:"exclude"`
}

// excluded reports whether a captured member should be dropped.
func (f File) excluded(base string) bool {
	for _, e := range f.Exclude {
		if e == base {
			return true
		}
	}
	return false
}

// Component is one thing Kanea installs.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    Kind   `json:"kind"`
	Summary string `json:"summary"`

	// URL is a template over {{.Version}} and {{.Arch}} (archive and binary).
	URL string `json:"url"`
	// Hashes maps GOARCH to the artefact's SHA-256 (archive and binary).
	Hashes map[string]string `json:"hashes"`

	// Image, Tag and Digest describe an OCI image. Digest is the authority;
	// Tag is carried only so a human reading a log sees a version rather than
	// sixty-four hex characters.
	Image  string `json:"image"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`

	Files []File `json:"files"`
}

// Manifest is the full component set, and the §15.4 version matrix. There is
// deliberately no second copy of these versions anywhere: a matrix kept apart
// from the thing that installs is a matrix that describes a node nobody has.
type Manifest struct {
	Kind       string      `json:"kind"`
	Schema     int         `json:"schema"`
	Components []Component `json:"components"`
}

// schemaVersion is the manifest layout this build understands.
const schemaVersion = 1

// Arches are the architectures Kanea publishes for. Every component must carry
// every one of them; a manifest that covers amd64 alone produces an install
// that fails on arm64 at the first download rather than at build time.
var Arches = []string{"amd64", "arm64"}

// Load parses the embedded manifest.
//
// It validates on the way through, so a malformed manifest is a test failure
// rather than a half-installed node: everything here is known at compile time,
// and the only reason it is data rather than Go is that the CI job which
// re-verifies the hashes upstream has to read it too.
func Load() (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil, fmt.Errorf("parse the embedded component manifest: %w", err)
	}
	if m.Schema != schemaVersion {
		return nil, fmt.Errorf("component manifest schema %d, want %d", m.Schema, schemaVersion)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// MustLoad is Load for callers that cannot do anything useful with a failure.
// The manifest is embedded, so a failure here is a broken build.
func MustLoad() *Manifest {
	m, err := Load()
	if err != nil {
		panic(err)
	}
	return m
}

var (
	nameRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	sha256RE = regexp.MustCompile(`^[a-f0-9]{64}$`)
	digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

func (m *Manifest) validate() error {
	if len(m.Components) == 0 {
		return fmt.Errorf("the component manifest is empty")
	}
	seen := make(map[string]bool, len(m.Components))
	for _, c := range m.Components {
		if !nameRE.MatchString(c.Name) {
			return fmt.Errorf("component name %q is not a DNS-1123 label", c.Name)
		}
		if seen[c.Name] {
			return fmt.Errorf("component %q appears twice", c.Name)
		}
		seen[c.Name] = true
		if c.Version == "" {
			return fmt.Errorf("component %q has no version", c.Name)
		}
		if len(c.Files) == 0 {
			return fmt.Errorf("component %q installs no files", c.Name)
		}
		for _, f := range c.Files {
			if f.To == "" {
				return fmt.Errorf("component %q has a file with no destination", c.Name)
			}
			if _, err := f.FileMode(); err != nil {
				return fmt.Errorf("component %q file %q: %w", c.Name, f.To, err)
			}
		}
		if err := c.validateSource(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Component) validateSource() error {
	switch c.Kind {
	case KindArchive, KindBinary:
		// HTTPS is checked rather than assumed. A plaintext URL would still be
		// hash-checked, so this is not the control that stops a tampered
		// artefact: it is the one that stops the *request* being readable.
		if !strings.HasPrefix(c.URL, "https://") {
			return fmt.Errorf("component %q: url must be https, got %q", c.Name, c.URL)
		}
		for _, arch := range Arches {
			if expanded := c.expand(c.URL, arch); strings.Contains(expanded, "{{") {
				return fmt.Errorf("component %q: url %q holds a template variable expand does not know", c.Name, expanded)
			}
		}
		if c.Digest != "" {
			return fmt.Errorf("component %q is kind %s but carries an image digest", c.Name, c.Kind)
		}
		for _, arch := range Arches {
			h, ok := c.Hashes[arch]
			if !ok {
				return fmt.Errorf("component %q has no %s hash", c.Name, arch)
			}
			if !sha256RE.MatchString(h) {
				return fmt.Errorf("component %q %s hash is not a lowercase sha-256: %q", c.Name, arch, h)
			}
		}
	case KindImage:
		if c.Image == "" {
			return fmt.Errorf("component %q is kind image but names no image", c.Name)
		}
		if !digestRE.MatchString(c.Digest) {
			return fmt.Errorf("component %q digest is not a sha-256 digest: %q", c.Name, c.Digest)
		}
		if len(c.Hashes) != 0 {
			return fmt.Errorf("component %q is kind image but carries artefact hashes", c.Name)
		}
	default:
		return fmt.Errorf("component %q has unknown kind %q", c.Name, c.Kind)
	}
	return nil
}

// Get returns a component by name.
func (m *Manifest) Get(name string) (*Component, error) {
	for i := range m.Components {
		if m.Components[i].Name == name {
			return &m.Components[i], nil
		}
	}
	return nil, fmt.Errorf("no component named %q (have %s)", name, strings.Join(m.Names(), ", "))
}

// Names lists every component, in manifest order, which is install order
// (§5.2.12). Do not sort this.
func (m *Manifest) Names() []string {
	names := make([]string, len(m.Components))
	for i, c := range m.Components {
		names[i] = c.Name
	}
	return names
}

// Select returns the named components in *manifest* order regardless of the
// order asked for, because install order is load-bearing: containerd has to be
// running before the buildkit image can be pulled through it, and
// `--only buildkit,containerd` must not mean what it says.
func (m *Manifest) Select(names []string) ([]*Component, error) {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, err := m.Get(n); err != nil {
			return nil, err
		}
		want[n] = true
	}
	var out []*Component
	for i := range m.Components {
		if want[m.Components[i].Name] {
			out = append(out, &m.Components[i])
		}
	}
	return out, nil
}

// All returns every component, in install order.
func (m *Manifest) All() []*Component {
	out := make([]*Component, len(m.Components))
	for i := range m.Components {
		out[i] = &m.Components[i]
	}
	return out
}

// FileMode parses the octal mode.
func (f File) FileMode() (uint32, error) {
	mode := f.Mode
	if mode == "" {
		mode = "0644"
	}
	var parsed uint32
	if _, err := fmt.Sscanf(mode, "%o", &parsed); err != nil {
		return 0, fmt.Errorf("mode %q is not octal: %w", mode, err)
	}
	if parsed > 0o7777 {
		return 0, fmt.Errorf("mode %q is out of range", mode)
	}
	return parsed, nil
}

// unameArch maps GOARCH to the `uname -m` spelling upstream release artefacts
// use. runwasi names its tarballs x86_64/aarch64 where Go says amd64/arm64;
// both spellings exist in the manifest because both exist upstream.
var unameArch = map[string]string{
	"amd64": "x86_64",
	"arm64": "aarch64",
}

// expand fills {{.Version}}, {{.Arch}} and {{.UnameArch}}.
//
// Hand-rolled rather than text/template: the substitution set is three keys and
// the inputs are a file in this repository, so a template engine would add a
// parse error path to something that cannot have one. A variable the replacer
// does not know is left in place and caught by validate: an unknown template
// variable must be a manifest error, not a URL with braces in it.
func (c *Component) expand(s, arch string) string {
	r := strings.NewReplacer(
		"{{.Version}}", c.Version,
		"{{.Arch}}", arch,
		"{{.UnameArch}}", unameArch[arch],
	)
	return r.Replace(s)
}

// ArtefactURL is where this component's bytes live upstream.
func (c *Component) ArtefactURL(arch string) string { return c.expand(c.URL, arch) }

// Hash is the expected SHA-256 for an arch, lowercase hex.
func (c *Component) Hash(arch string) (string, error) {
	h, ok := c.Hashes[arch]
	if !ok {
		return "", fmt.Errorf("component %q has no hash for %s", c.Name, arch)
	}
	return h, nil
}

// Ref is the pull reference: image@digest, never image:tag.
func (c *Component) Ref() string { return c.Image + "@" + c.Digest }

// Display is what a log line or a `kanea install` row calls this component.
func (c *Component) Display() string {
	if c.Kind == KindImage && c.Tag != "" {
		return c.Name + " " + c.expand(c.Tag, HostArch())
	}
	return c.Name + " " + c.Version
}

// ResolveFiles fills templates in the file paths.
func (c *Component) ResolveFiles(arch string) []File {
	out := make([]File, len(c.Files))
	for i, f := range c.Files {
		f.From = c.expand(f.From, arch)
		f.Alt = c.expand(f.Alt, arch)
		f.To = c.expand(f.To, arch)
		out[i] = f
	}
	return out
}

// HostArch is this machine's GOARCH.
func HostArch() string { return runtime.GOARCH }

// SupportedArch reports whether Kanea publishes components for an arch.
func SupportedArch(arch string) bool {
	for _, a := range Arches {
		if a == arch {
			return true
		}
	}
	return false
}

// SortedArches is Arches in a stable order, for messages.
func SortedArches() []string {
	out := append([]string(nil), Arches...)
	sort.Strings(out)
	return out
}
