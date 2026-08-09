package provision

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/archive"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// OCI image components (PRD §5.2.12): cilium and buildkit.
//
// The asymmetry between them is deliberate and worth stating where someone
// will read it. BuildKit's binaries are self-contained, so `buildkitd`,
// `buildctl` and `rootlesskit` are extracted onto the host and run there —
// §23.2 specified it that way. cilium-agent is not: it needs its bundled
// helpers, its iptables and its BPF templates, and unpacking that image onto a
// host is unsupported upstream and a large surface to get quietly wrong. So the
// agent stays inside the image and runs as a containerd task (M0 spike ①
// validated that form 25/25); only `cilium-cni` and `cilium-dbg` come out,
// because containerd execs the CNI plugin and it therefore has to be a host
// file.
//
// Files are pulled out by reading the image's layers rather than by mounting a
// snapshot. That buys three things: no mount syscall and no root requirement
// beyond writing the prefix, no dependency on the snapshotter having unpacked,
// and — the one that matters — the identical code path serves an OCI archive
// carried in on a disk, which is what makes image components work air-gapped.

// SystemNamespace holds the platform's own images, apart from the per-project
// namespaces workloads use (§5.2.4). A workload namespace is a project's;
// cilium is not any project's.
const SystemNamespace = "kanea-system"

// ImageClient pulls and unpacks image components through containerd.
type ImageClient struct {
	client *containerd.Client
	log    *slog.Logger
}

// NewImageClient connects to containerd.
func NewImageClient(socket string, log *slog.Logger) (*ImageClient, error) {
	client, err := containerd.New(socket, containerd.WithDefaultNamespace(SystemNamespace))
	if err != nil {
		return nil, fmt.Errorf("dial containerd at %s: %w", socket, err)
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &ImageClient{client: client, log: log}, nil
}

// Close releases the connection.
func (c *ImageClient) Close() error { return c.client.Close() }

func (c *ImageClient) scope(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, SystemNamespace)
}

// Fetch pulls an image by digest and unpacks it into the snapshotter.
//
// Unpacked because cilium-agent is *run* from this image, not merely read.
// Fetching without unpacking would leave the task creation to discover the
// missing snapshot much later, when the dataplane is supposed to come up.
func (c *ImageClient) Fetch(ctx context.Context, ref string) error {
	ctx = c.scope(ctx)
	if !strings.Contains(ref, "@sha256:") {
		// Belt and braces: the manifest validator already refuses a tag-only
		// image, and this is the last place before a pull where that could
		// still be wrong.
		return fmt.Errorf("refusing to pull %q: images are pinned by digest, never by tag", ref)
	}
	if _, err := c.client.GetImage(ctx, ref); err == nil {
		c.log.Debug("image already present", "ref", ref)
		return nil
	}
	c.log.Info("pulling", "ref", ref)
	if _, err := c.client.Pull(ctx, ref, containerd.WithPullUnpack); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	return nil
}

// Unpack copies the named files out of an image's layers into dest.
func (c *ImageClient) Unpack(ctx context.Context, ref string, files []File, dest string) error {
	ctx = c.scope(ctx)
	img, err := c.client.GetImage(ctx, ref)
	if err != nil {
		return fmt.Errorf("look up %s: %w", ref, err)
	}
	manifest, err := images.Manifest(ctx, c.client.ContentStore(), img.Target(), platforms.Default())
	if err != nil {
		return fmt.Errorf("read the manifest for %s: %w", ref, err)
	}
	return extractFromLayers(ctx, layerReaderFunc(func(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
		ra, err := c.client.ContentStore().ReaderAt(ctx, desc)
		if err != nil {
			return nil, err
		}
		return &readerAtCloser{
			Reader: io.NewSectionReader(ra, 0, ra.Size()),
			closer: ra,
		}, nil
	}), manifest.Layers, files, dest)
}

// Export writes an image to an OCI archive, for a bundle.
//
// One architecture, matching the bundle's. A bundle is already per-arch
// because the artefacts are, and carrying both platforms of two images to a
// node that can use one would add roughly the size of everything else in it.
// Authoring a bundle for an architecture other than the authoring machine's is
// ordinary — a pull is not run, it is fetched.
func (c *ImageClient) Export(ctx context.Context, ref, arch, destPath string) error {
	ctx = c.scope(ctx)
	platform := platforms.Only(ocispec.Platform{OS: "linux", Architecture: arch})

	if _, err := c.client.Pull(ctx, ref, containerd.WithPlatformMatcher(platform)); err != nil {
		return fmt.Errorf("pull %s for %s: %w", ref, arch, err)
	}

	f, err := os.Create(destPath) // #nosec G304 — an operator-chosen bundle path
	if err != nil {
		return fmt.Errorf("create %s: %w", destPath, err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // cleanup path
	if err := c.client.Export(ctx, f,
		archive.WithImage(c.client.ImageService(), ref),
		archive.WithPlatform(platform),
	); err != nil {
		return fmt.Errorf("export %s: %w", ref, err)
	}
	return f.Sync()
}

// Import loads an OCI archive from a bundle into containerd.
//
// The digest is still the authority: an archive whose content does not produce
// the pinned digest fails at [Fetch], because the image it imported is not the
// one the manifest names. A bundle is not trusted more than a registry.
func (c *ImageClient) Import(ctx context.Context, archivePath string) error {
	ctx = c.scope(ctx)
	f, err := os.Open(archivePath) // #nosec G304 — a path inside the opened bundle
	if err != nil {
		return fmt.Errorf("open %s: %w", archivePath, err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // cleanup path
	if _, err := c.client.Import(ctx, f, containerd.WithAllPlatforms(true)); err != nil {
		return fmt.Errorf("import %s: %w", archivePath, err)
	}
	return nil
}

// layerReader opens one layer's blob.
type layerReader interface {
	Open(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error)
}

type layerReaderFunc func(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error)

func (f layerReaderFunc) Open(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	return f(ctx, desc)
}

type readerAtCloser struct {
	io.Reader
	closer io.Closer
}

func (r *readerAtCloser) Close() error { return r.closer.Close() }

// extractFromLayers walks layers newest-first and pulls out the wanted files.
//
// Newest-first with an early exit, rather than oldest-first applying every
// layer: the first occurrence found scanning downwards is the one that would
// win anyway, and stopping as soon as everything is found means a 600 MiB
// image is usually read for a fraction of its size. Whiteouts are honoured for
// the same reason — a file deleted by a later layer is not present, and taking
// the copy from an earlier one would install something the image does not have.
func extractFromLayers(ctx context.Context, layers layerReader, descs []ocispec.Descriptor, files []File, dest string) error {
	wanted := make(map[string]File, len(files))
	for _, f := range files {
		if f.From != "" {
			wanted[path.Clean(f.From)] = f
		}
		if f.Alt != "" {
			wanted[path.Clean(f.Alt)] = f
		}
	}
	found := make(map[string]bool, len(files)) // by destination
	deleted := make(map[string]bool, len(files))

	remaining := func() int {
		n := 0
		for _, f := range files {
			if !found[f.To] {
				n++
			}
		}
		return n
	}

	for i := len(descs) - 1; i >= 0 && remaining() > 0; i-- {
		if err := scanLayer(ctx, layers, descs[i], wanted, found, deleted, dest); err != nil {
			return err
		}
	}

	for _, f := range files {
		if found[f.To] {
			continue
		}
		where := f.From
		if f.Alt != "" {
			where += " or " + f.Alt
		}
		return fmt.Errorf("%s (%s) is not in the image", path.Base(f.To), where)
	}
	return nil
}

func scanLayer(ctx context.Context, layers layerReader, desc ocispec.Descriptor,
	wanted map[string]File, found, deleted map[string]bool, dest string) error {

	blob, err := layers.Open(ctx, desc)
	if err != nil {
		return fmt.Errorf("read layer %s: %w", desc.Digest, err)
	}
	defer func() { _ = blob.Close() }() //nolint:errcheck // cleanup path

	// DecompressStream handles gzip and zstd, and passes an uncompressed layer
	// through — the media type is not consulted because a mismatched one is a
	// thing that happens.
	dec, err := compression.DecompressStream(blob)
	if err != nil {
		return fmt.Errorf("decompress layer %s: %w", desc.Digest, err)
	}
	defer func() { _ = dec.Close() }() //nolint:errcheck // cleanup path
	tr := tar.NewReader(dec)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read layer %s: %w", desc.Digest, err)
		}
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if !safeArchivePath(name) {
			// A layer that names a path outside the rootfs is not a layer to
			// take a binary from, whatever else it contains.
			return fmt.Errorf("%w: layer %s member %q", ErrUnsafePath, desc.Digest, hdr.Name)
		}

		// A whiteout marks the file as absent from here down.
		if base := path.Base(name); strings.HasPrefix(base, ".wh.") {
			deleted[path.Join(path.Dir(name), strings.TrimPrefix(base, ".wh."))] = true
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		f, ok := wanted[name]
		if !ok || found[f.To] || deleted[name] {
			continue
		}

		mode, err := f.FileMode()
		if err != nil {
			return err
		}
		target, err := resolveUnder(dest, f.To)
		if err != nil {
			return err
		}
		if hdr.Size > maxFileSize {
			return fmt.Errorf("image member %q is %d bytes, over the %d-byte cap", hdr.Name, hdr.Size, maxFileSize)
		}
		if err := writeFileAtomic(target, io.LimitReader(tr, maxFileSize), os.FileMode(mode)); err != nil {
			return err
		}
		found[f.To] = true
	}
}

// CiliumArgs is the agent's command line (PRD §5.2.5, M0 spike ①).
//
// Every one of these is load-bearing and the set is not a starting point to
// tune. --enable-k8s=false is the whole premise; --kube-proxy-replacement is
// required for kanea-edge to reach a service VIP; --lb-state-file and
// --static-cnp-path are the file interfaces that replaced the writable REST
// APIs removed in 1.18; --policy-default-local-cluster=false stops every
// policy selector matching nothing.
// The layout is taken but unused: the agent writes its socket and its two
// file control surfaces to Cilium's own paths, not Kanea's, and internal/network
// reads them there. It stays in the signature because every other component's
// paths do come from the layout, and a lone exception invites someone to
// "fix" it by pointing these at the prefix — where the network driver would
// never look.
func CiliumArgs(_ Layout, nodeCIDR, clusterCIDR string) []string {
	return []string{
		"cilium-agent",
		"--enable-k8s=false",
		"--kvstore=etcd",
		"--kvstore-opt=etcd.address=" + EtcdEndpoint,
		"--identity-allocation-mode=kvstore",
		"--ipam=cluster-pool",
		"--ipv4-range=" + nodeCIDR,
		"--enable-ipv4=true",
		"--enable-ipv6=false",
		"--routing-mode=native",
		"--ipv4-native-routing-cidr=" + clusterCIDR,
		"--enable-ipv4-masquerade=true",
		"--kube-proxy-replacement=true",
		"--policy-default-local-cluster=false",
		"--lb-state-file=" + filepath.Join(CiliumRunDir, "lb-state.json"),
		"--static-cnp-path=" + filepath.Join(CiliumRunDir, "policies"),
		"--cgroup-root=/run/cilium/cgroupv2",
		"--bpf-root=/sys/fs/bpf",
	}
}

// CiliumRunDir is where the agent's socket and its two file control surfaces
// live. It is Cilium's own path, not Kanea's: the agent writes the socket, and
// internal/network already reads it there.
const CiliumRunDir = "/var/run/cilium"
