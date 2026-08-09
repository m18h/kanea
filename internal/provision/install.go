package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
)

// Layout is where a Kanea install puts things (PRD §5.2.12).
//
// Everything is under a Kanea-owned path. Nothing here is a location a
// distribution's package manager also writes: a node that ran Docker yesterday
// runs it tomorrow, and an install that breaks other software is not a property
// a single-binary platform gets to have.
type Layout struct {
	// Prefix holds binaries: <Prefix>/bin. Manifest file destinations are
	// relative to it.
	Prefix string
	// ConfDir holds containerd's config.
	ConfDir string
	// DataDir holds containerd's content store.
	DataDir string
	// RunDir holds the sockets.
	RunDir string
	// UnitDir is where systemd units are written.
	UnitDir string
	// ContainerdSocket overrides SocketPath when an existing containerd was
	// adopted (`--containerd external`). Empty means Kanea's own.
	ContainerdSocket string
	// NodeCIDR and ClusterCIDR are the container subnet (PRD §5.2.5). Empty
	// means the compiled default.
	//
	// They live here because `kanea install` and `kanea doctor` validate them
	// before they reach the eBPF datapath: the datapath is compiled into the
	// binary and configured through kanead's argv (cmd/kanea/units.go renders
	// the subnet into the kanead unit), so a bad CIDR is caught here rather than
	// surfacing as a datapath that hands out unroutable addresses.
	NodeCIDR    string
	ClusterCIDR string
}

// Default CIDRs. Both are RFC 1918 space chosen not to collide with the
// defaults of the things Kanea sits next to (Docker's 172.17/16, and the
// 10.42/16 k3s uses).
const (
	DefaultNodeCIDR    = "10.244.0.0/24"
	DefaultClusterCIDR = "10.244.0.0/16"
)

// ValidateNetworking checks the CIDRs before they configure the datapath.
//
// A typo otherwise surfaces on a live node rather than here: the containment
// rule is that the cluster CIDR must cover the node CIDR — the range the
// datapath masquerades as internal has to contain the range it allocates alloc
// addresses from — so a node CIDR outside its cluster CIDR is a configuration
// that cannot route.
func (l Layout) ValidateNetworking() error {
	node, cluster := l.Networking()

	parsed := map[string]netip.Prefix{}
	for _, c := range []struct{ flag, value string }{
		{"--node-cidr", node}, {"--cluster-cidr", cluster},
	} {
		prefix, err := netip.ParsePrefix(c.value)
		if err != nil {
			return fmt.Errorf("%s %q: not a CIDR", c.flag, c.value)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("%s %q: v1 allocates IPv4 only", c.flag, c.value)
		}
		if prefix.Masked() != prefix {
			return fmt.Errorf("%s %q: has host bits set; write %s", c.flag, c.value, prefix.Masked())
		}
		parsed[c.flag] = prefix
	}
	if !parsed["--cluster-cidr"].Overlaps(parsed["--node-cidr"]) ||
		parsed["--cluster-cidr"].Bits() > parsed["--node-cidr"].Bits() {
		return fmt.Errorf("--node-cidr %s is not inside --cluster-cidr %s; "+
			"the native routing CIDR has to cover the range it allocates from",
			node, cluster)
	}
	return nil
}

// Networking returns the CIDRs with defaults applied.
func (l Layout) Networking() (node, cluster string) {
	node, cluster = l.NodeCIDR, l.ClusterCIDR
	if node == "" {
		node = DefaultNodeCIDR
	}
	if cluster == "" {
		cluster = DefaultClusterCIDR
	}
	return node, cluster
}

// Default paths. They mirror the ones already in internal/runtime and
// internal/network, but under /run/kanea rather than the distribution's.
const (
	DefaultPrefix  = "/usr/local/lib/kanea"
	DefaultConfDir = "/etc/kanea"
	DefaultDataDir = "/var/lib/kanea"
	DefaultRunDir  = "/run/kanea"
	DefaultUnitDir = "/etc/systemd/system"
)

// DefaultLayout is the standard install.
func DefaultLayout() Layout {
	return Layout{
		Prefix:  DefaultPrefix,
		ConfDir: DefaultConfDir,
		DataDir: DefaultDataDir,
		RunDir:  DefaultRunDir,
		UnitDir: DefaultUnitDir,
	}
}

// BinDir is where component executables land.
func (l Layout) BinDir() string { return filepath.Join(l.Prefix, "bin") }

// receiptDir records what is installed. Kept inside the prefix so removing the
// prefix removes the record with it: a receipt that outlives its binaries
// would make `kanea doctor` confidently wrong.
func (l Layout) receiptDir() string { return filepath.Join(l.Prefix, ".receipts") }

// Images pulls and unpacks OCI image components.
//
// An interface because it needs a running containerd, which does not exist
// until the archive components are installed and started — the install
// bootstraps itself in one direction (§5.2.12), and this is where that shows
// up in the types.
type Images interface {
	// Fetch makes the image available locally, by digest.
	Fetch(ctx context.Context, ref string) error
	// Unpack copies files out of the image's rootfs into dest.
	Unpack(ctx context.Context, ref string, files []File, dest string) error
}

// Action is what an install did to a component.
type Action string

const (
	// ActionInstalled means bytes were written.
	ActionInstalled Action = "installed"
	// ActionCurrent means the pinned version was already there.
	ActionCurrent Action = "up-to-date"
	// ActionPlanned is what --dry-run reports instead of installing.
	ActionPlanned Action = "would install"
	// ActionSkipped means a prerequisite was missing — an image component with
	// no containerd to pull it through, say.
	ActionSkipped Action = "skipped"
)

// Result is one component's outcome.
type Result struct {
	Component *Component
	Action    Action
	// Reason explains a skip. Empty otherwise.
	Reason string
	Err    error
}

// Installer places host components.
//
// It never fetches anything itself: it asks its [Source], and every byte is
// checked against the manifest compiled into this binary before it is written
// anywhere it could be executed. That is what lets the air-gapped path be the
// same code as the online one.
type Installer struct {
	Source Source
	Layout Layout
	Images Images
	Log    *slog.Logger

	// Arch is the target architecture. Set for bundle authoring; otherwise
	// this machine's.
	Arch string
	// DryRun resolves and verifies without writing.
	DryRun bool
	// Force reinstalls a component already at the pinned version.
	Force bool
}

// Install places the given components, in the order it is given them — which
// [Manifest.Select] guarantees is manifest order, because containerd has to be
// running before an image can be pulled through it.
//
// It returns a result per component and stops at the first failure. Stopping
// is deliberate: the components depend on each other in one direction, so
// carrying on past a failed containerd install produces a longer list of
// failures that all say the same thing.
func (i *Installer) Install(ctx context.Context, components []*Component) ([]Result, error) {
	arch := i.Arch
	if arch == "" {
		arch = HostArch()
	}
	if !SupportedArch(arch) {
		return nil, fmt.Errorf("unsupported architecture %q (Kanea publishes %v)", arch, SortedArches())
	}

	results := make([]Result, 0, len(components))
	for _, c := range components {
		res := i.installOne(ctx, c, arch)
		results = append(results, res)
		if res.Err != nil {
			return results, fmt.Errorf("install %s: %w", c.Name, res.Err)
		}
	}
	return results, nil
}

func (i *Installer) installOne(ctx context.Context, c *Component, arch string) Result {
	log := i.logger().With("component", c.Name, "version", c.Version)

	current, err := i.isCurrent(c, arch)
	if err != nil {
		return Result{Component: c, Err: err}
	}
	if current && !i.Force {
		log.Debug("already at the pinned version")
		return Result{Component: c, Action: ActionCurrent}
	}

	if i.DryRun {
		// Still verified: the point of --dry-run is to find out whether this
		// install would work, and "the artefact is reachable and matches its
		// pin" is most of that question.
		if err := i.verifyOnly(ctx, c, arch); err != nil {
			return Result{Component: c, Err: err}
		}
		return Result{Component: c, Action: ActionPlanned}
	}

	if c.Kind == KindImage {
		if i.Images == nil {
			return Result{
				Component: c, Action: ActionSkipped,
				Reason: "no containerd to pull it through yet",
			}
		}
		if err := i.installImage(ctx, c, arch); err != nil {
			return Result{Component: c, Err: err}
		}
	} else if err := i.installArtefact(ctx, c, arch); err != nil {
		return Result{Component: c, Err: err}
	}

	if err := i.writeReceipt(c, arch); err != nil {
		return Result{Component: c, Err: err}
	}
	log.Info("installed", "prefix", i.Layout.Prefix)
	return Result{Component: c, Action: ActionInstalled}
}

// installArtefact handles the archive and binary kinds.
func (i *Installer) installArtefact(ctx context.Context, c *Component, arch string) error {
	// #nosec G301 — see writeFileAtomic: the prefix holds executables the
	// unprivileged buildkit user must traverse.
	if err := os.MkdirAll(i.Layout.Prefix, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", i.Layout.Prefix, err)
	}
	staged, err := Stage(ctx, i.Source, c, arch, i.Layout.Prefix)
	if err != nil {
		return err
	}
	defer func() {
		_ = staged.Close()           //nolint:errcheck // cleanup path
		_ = os.Remove(staged.Name()) //nolint:errcheck // cleanup path
	}()

	files := c.ResolveFiles(arch)
	switch c.Kind {
	case KindBinary:
		// One file, and the payload is it — there is nothing to extract.
		if len(files) != 1 {
			return fmt.Errorf("component %q is a bare binary but names %d files", c.Name, len(files))
		}
		mode, err := files[0].FileMode()
		if err != nil {
			return err
		}
		dest, err := resolveUnder(i.Layout.Prefix, files[0].To)
		if err != nil {
			return err
		}
		return writeFileAtomic(dest, staged, os.FileMode(mode))
	case KindArchive:
		return extractTarGz(staged, extractOptions{
			files: files, dest: i.Layout.Prefix, defaultMode: 0o755,
		})
	default:
		return fmt.Errorf("component %q has kind %q, which is not an artefact", c.Name, c.Kind)
	}
}

// installImage pulls by digest and unpacks the named files.
func (i *Installer) installImage(ctx context.Context, c *Component, arch string) error {
	ref := c.Ref()
	if err := i.Images.Fetch(ctx, ref); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	files := c.ResolveFiles(arch)
	if len(files) == 0 {
		// Nothing to place on the host: the image itself is the deliverable, and
		// having it locally is the install.
		return nil
	}
	// #nosec G301 — see writeFileAtomic.
	if err := os.MkdirAll(i.Layout.Prefix, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", i.Layout.Prefix, err)
	}
	return i.Images.Unpack(ctx, ref, files, i.Layout.Prefix)
}

// verifyOnly resolves and hashes an artefact without installing it.
func (i *Installer) verifyOnly(ctx context.Context, c *Component, arch string) error {
	if c.Kind == KindImage {
		// A registry round trip to confirm the digest resolves would need
		// containerd, which a dry run on a laptop does not have. The digest is
		// pinned, so there is nothing to check that is not already checked.
		return nil
	}
	dir, err := os.MkdirTemp("", "kanea-dryrun-")
	if err != nil {
		return fmt.Errorf("temporary directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }() //nolint:errcheck // cleanup path
	staged, err := Stage(ctx, i.Source, c, arch, dir)
	if err != nil {
		return err
	}
	return staged.Close()
}

// receipt records what was installed, so a re-run is a no-op and `kanea
// doctor` can tell a Kanea-installed component from one that happened to be
// there.
type receipt struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    Kind   `json:"kind"`
	Arch    string `json:"arch"`
	// Pin is the hash or digest this was installed against. Comparing it
	// rather than the version means a manifest that re-pins the same version
	// at a different hash — an upstream re-tagging a release — reinstalls.
	Pin string `json:"pin"`
}

func (i *Installer) pinFor(c *Component, arch string) (string, error) {
	if c.Kind == KindImage {
		return c.Digest, nil
	}
	return c.Hash(arch)
}

func (i *Installer) receiptPath(name string) string {
	return filepath.Join(i.Layout.receiptDir(), name+".json")
}

// isCurrent reports whether the pinned version is already installed.
func (i *Installer) isCurrent(c *Component, arch string) (bool, error) {
	raw, err := os.ReadFile(i.receiptPath(c.Name)) // #nosec G304 — a path this package composed
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read the receipt for %s: %w", c.Name, err)
	}
	var r receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		// A corrupt receipt means "reinstall", not "fail". The receipt is a
		// cache of a fact the filesystem already holds.
		return false, nil
	}
	pin, err := i.pinFor(c, arch)
	if err != nil {
		return false, err
	}
	if r.Version != c.Version || r.Pin != pin || r.Arch != arch {
		return false, nil
	}
	// The receipt says so; the filesystem is asked too. A prefix wiped by an
	// operator with a receipt left behind is exactly the state that makes an
	// installer skip the work it exists to do.
	for _, f := range c.ResolveFiles(arch) {
		if f.To == "" || f.From == "." {
			continue
		}
		if _, err := os.Stat(filepath.Join(i.Layout.Prefix, f.To)); err != nil {
			return false, nil
		}
	}
	return true, nil
}

func (i *Installer) writeReceipt(c *Component, arch string) error {
	pin, err := i.pinFor(c, arch)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(receipt{
		Name: c.Name, Version: c.Version, Kind: c.Kind, Arch: arch, Pin: pin,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the receipt for %s: %w", c.Name, err)
	}
	// #nosec G301 — receipts record installed versions and carry nothing
	// secret; `kanea doctor` reads them, and it is not always run as root.
	if err := os.MkdirAll(i.Layout.receiptDir(), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", i.Layout.receiptDir(), err)
	}
	return writeFileAtomic(i.receiptPath(c.Name), bytes.NewReader(body), 0o644)
}

// Installed reads the receipt for a component, if there is one. `kanea doctor`
// uses it to enforce the version matrix.
func (i *Installer) Installed(name string) (version, pin string, ok bool) {
	raw, err := os.ReadFile(i.receiptPath(name)) // #nosec G304 — a path this package composed
	if err != nil {
		return "", "", false
	}
	var r receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", "", false
	}
	return r.Version, r.Pin, true
}

func (i *Installer) logger() *slog.Logger {
	if i.Log != nil {
		return i.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
