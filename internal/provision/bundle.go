package provision

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Offline bundles (PRD §5.2.12).
//
// A bundle is a [Source] backed by a directory an operator carried in on a
// disk. That is the whole mechanism: because the installer is *handed* bytes
// rather than fetching them, the air-gapped path is the same code as the
// online one — verified by the same hashes, extracted by the same extractor,
// covered by the same tests. There is no second install implementation to rot.
//
// A bundle is not trusted more than the network. Its contents are checked
// against the hashes compiled into this binary and never against the metadata
// inside it: a bundle that supplied its own hashes would be a bundle that
// authenticates itself.

// bundleMeta describes a bundle, for humans and for refusals.
//
// Nothing here is used to verify anything. It exists so that pointing `kanea
// install` at the wrong bundle produces "this bundle is for arm64" instead of
// six hash mismatches.
type bundleMeta struct {
	Kind string `json:"kind"`
	// KaneaVersion is the binary that authored it.
	KaneaVersion string `json:"kaneaVersion"`
	Arch         string `json:"arch"`
	Components   []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Kind    Kind   `json:"kind"`
	} `json:"components"`
}

const (
	bundleKind     = "kanea-bundle"
	bundleMetaName = "bundle.json"
	bundleArtefact = "artefacts"
	bundleImages   = "images"
)

// BundleSource reads artefacts out of a bundle.
type BundleSource struct {
	dir  string
	from string
	meta bundleMeta
	// tmp is set when a tarball was unpacked, and removed by Close.
	tmp string
}

// OpenBundle opens a bundle directory or tarball.
//
// Both are accepted because they are the same thing at different points in a
// journey: a tarball is what crosses an air gap, and a directory is what it
// becomes on a machine with room to unpack it once and install from it many
// times.
func OpenBundle(path string) (*BundleSource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("open the bundle at %s: %w", path, err)
	}

	b := &BundleSource{from: path}
	if info.IsDir() {
		b.dir = path
	} else {
		tmp, err := os.MkdirTemp("", "kanea-bundle-")
		if err != nil {
			return nil, fmt.Errorf("unpack the bundle: %w", err)
		}
		f, err := os.Open(path) // #nosec G304 — an operator-supplied path, which is the point
		if err != nil {
			_ = os.RemoveAll(tmp) //nolint:errcheck // cleanup path
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		defer func() { _ = f.Close() }() //nolint:errcheck // cleanup path

		// The same traversal-safe extractor the components use. A bundle is an
		// archive from outside this machine like any other.
		if err := extractTarGz(f, extractOptions{dest: tmp, defaultMode: 0o644}); err != nil {
			_ = os.RemoveAll(tmp) //nolint:errcheck // cleanup path
			return nil, fmt.Errorf("unpack %s: %w", path, err)
		}
		b.dir, b.tmp = tmp, tmp
	}

	if err := b.readMeta(); err != nil {
		_ = b.Close() //nolint:errcheck // cleanup path
		return nil, err
	}
	return b, nil
}

func (b *BundleSource) readMeta() error {
	raw, err := os.ReadFile(filepath.Join(b.dir, bundleMetaName)) // #nosec G304 — inside the opened bundle
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s has no %s — it is not a Kanea bundle", b.from, bundleMetaName)
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", bundleMetaName, err)
	}
	if err := json.Unmarshal(raw, &b.meta); err != nil {
		return fmt.Errorf("parse %s: %w", bundleMetaName, err)
	}
	if b.meta.Kind != bundleKind {
		return fmt.Errorf("%s is not a Kanea bundle (kind %q)", b.from, b.meta.Kind)
	}
	return nil
}

// Arch is the architecture this bundle was built for.
func (b *BundleSource) Arch() string { return b.meta.Arch }

// KaneaVersion is the binary that authored it.
func (b *BundleSource) KaneaVersion() string { return b.meta.KaneaVersion }

// Describe names the bundle, so a failure says which one.
func (b *BundleSource) Describe() string {
	desc := "the bundle at " + b.from
	if b.meta.Arch != "" {
		desc += " (" + b.meta.Arch + ")"
	}
	return desc
}

// Offline is always true, and it is why selecting a bundle disables network
// fetching rather than making it a fallback.
func (b *BundleSource) Offline() bool { return true }

// Open returns a component's artefact from the bundle.
func (b *BundleSource) Open(_ context.Context, c *Component, arch string) (io.ReadCloser, error) {
	if b.meta.Arch != "" && arch != b.meta.Arch {
		return nil, fmt.Errorf("this bundle is for %s, not %s — build one with `kanea bundle create --arch %s`",
			b.meta.Arch, arch, arch)
	}
	path := filepath.Join(b.dir, bundleArtefact, c.Name)
	f, err := os.Open(path) // #nosec G304 — a path composed from a validated component name
	if errors.Is(err, fs.ErrNotExist) {
		// Named rather than left as "no such file": the usual cause is a
		// bundle authored by a different Kanea version, whose manifest did not
		// have this component in it.
		return nil, fmt.Errorf("%s is not in %s (authored by kanea %s)",
			c.Display(), b.Describe(), orUnknown(b.meta.KaneaVersion))
	}
	if err != nil {
		return nil, fmt.Errorf("read %s from the bundle: %w", c.Name, err)
	}
	return f, nil
}

// ImageArchive is the path to a component's OCI archive inside the bundle, and
// whether there is one.
func (b *BundleSource) ImageArchive(c *Component) (string, bool) {
	path := filepath.Join(b.dir, bundleImages, c.Name+".oci.tar")
	if _, err := os.Stat(path); err != nil {
		return "", false
	}
	return path, true
}

// Close removes anything unpacked.
func (b *BundleSource) Close() error {
	if b.tmp == "" {
		return nil
	}
	return os.RemoveAll(b.tmp)
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown version"
	}
	return s
}

// ImageExporter writes a digest-pinned image to an OCI archive, for bundling.
//
// Separate from [Images] because authoring a bundle and installing from one
// happen on different machines: the authoring machine needs a containerd to
// pull through, the installing one needs it to import into.
type ImageExporter interface {
	Export(ctx context.Context, ref, arch, destPath string) error
}

// BundleOptions configures authoring.
type BundleOptions struct {
	// Arch is what the bundle is for. A bundle is per-architecture: carrying
	// both doubles ~280 MB for a node that can only use one.
	Arch string
	// Dest is the directory to write. The caller tars it if it wants a file.
	Dest string
	// KaneaVersion is stamped into the metadata.
	KaneaVersion string
	// Images exports the image components. Nil omits them, which is only
	// useful for a bundle destined for a `--network none` node.
	Images ImageExporter
}

// CreateBundle downloads every component and writes a bundle directory.
//
// Every artefact is verified on the way in, so a bundle cannot be authored
// from a tampered download — which matters more here than usual, because the
// bundle is the thing that then crosses an air gap and gets trusted by a human
// rather than by a network.
func CreateBundle(ctx context.Context, m *Manifest, src Source, opts BundleOptions) error {
	if !SupportedArch(opts.Arch) {
		return fmt.Errorf("unsupported architecture %q (Kanea publishes %v)", opts.Arch, SortedArches())
	}
	artefactDir := filepath.Join(opts.Dest, bundleArtefact)
	// #nosec G301 — a bundle holds published upstream binaries and nothing
	// else. It is built to be copied to a USB stick and read on another
	// machine, quite possibly by a different user than the one that made it.
	if err := os.MkdirAll(artefactDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", artefactDir, err)
	}

	meta := bundleMeta{Kind: bundleKind, KaneaVersion: opts.KaneaVersion, Arch: opts.Arch}

	for _, c := range m.All() {
		entry := struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Kind    Kind   `json:"kind"`
		}{c.Name, c.Version, c.Kind}

		if c.Kind == KindImage {
			if opts.Images == nil {
				continue
			}
			imageDir := filepath.Join(opts.Dest, bundleImages)
			// #nosec G301 — see above: public artefacts, meant to be carried.
			if err := os.MkdirAll(imageDir, 0o755); err != nil {
				return fmt.Errorf("create %s: %w", imageDir, err)
			}
			dest := filepath.Join(imageDir, c.Name+".oci.tar")
			if err := opts.Images.Export(ctx, c.Ref(), opts.Arch, dest); err != nil {
				return fmt.Errorf("export %s: %w", c.Display(), err)
			}
			meta.Components = append(meta.Components, entry)
			continue
		}

		staged, err := Stage(ctx, src, c, opts.Arch, artefactDir)
		if err != nil {
			return err
		}
		err = writeFileAtomic(filepath.Join(artefactDir, c.Name), staged, 0o644)
		closeErr := staged.Close()
		_ = os.Remove(staged.Name()) //nolint:errcheck // cleanup path
		if err != nil {
			return err
		}
		if closeErr != nil {
			return fmt.Errorf("close the staged %s: %w", c.Name, closeErr)
		}
		meta.Components = append(meta.Components, entry)
	}

	body, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", bundleMetaName, err)
	}
	return writeFileAtomic(filepath.Join(opts.Dest, bundleMetaName), strings.NewReader(string(body)), 0o644)
}
