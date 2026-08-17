package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/m18h/kanea/internal/provision"
)

// `kanea bundle create`: author an offline bundle (PRD §5.2.12).
//
// The bundle exists so an air-gapped node is a supported installation rather
// than a documented workaround. It is built here, on a machine with a network,
// and carried across; `kanea install --bundle` consumes it with no egress at
// all.
//
// Note what is *not* here: a hash file. The bundle's contents are verified on
// the installing node against the hashes compiled into that node's kanea
// binary. A bundle that carried its own hashes would be a bundle that
// authenticates itself.

func runBundle(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kanea bundle create [flags]")
	}
	switch args[0] {
	case "create":
		return runBundleCreate(args[1:])
	default:
		return fmt.Errorf("unknown bundle command %q (have: create)", args[0])
	}
}

func runBundleCreate(args []string) error {
	fs := flag.NewFlagSet("bundle create", flag.ContinueOnError)
	arch := fs.String("arch", provision.HostArch(), "target architecture: amd64 or arm64")
	outPath := fs.String("o", "", "output path (default kanea_<version>_linux_<arch>_bundle.tar.gz)")
	dirOnly := fs.Bool("dir", false, "write a directory instead of a tarball")
	socket := fs.String("containerd", provision.DefaultRunDir+"/containerd.sock",
		"containerd socket, for exporting the image components")
	noImages := fs.Bool("no-images", false,
		"omit buildkit (only useful for a --network netns node with no in-cluster builds)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !provision.SupportedArch(*arch) {
		return fmt.Errorf("unsupported architecture %q (Kanea publishes %v)", *arch, provision.SortedArches())
	}
	manifest, err := provision.Load()
	if err != nil {
		return err
	}

	dest := *outPath
	if dest == "" {
		dest = fmt.Sprintf("kanea_%s_linux_%s_bundle.tar.gz", strings.TrimPrefix(version, "v"), *arch)
		if *dirOnly {
			dest = strings.TrimSuffix(dest, ".tar.gz")
		}
	}

	o := newOut()
	o.printf("kanea bundle create: %s (%s)\n\n", version, *arch)

	// Image components need a containerd to export from. Said plainly up
	// front, because the alternative is discovering it after ~200 MB of
	// artefact downloads.
	var images provision.ImageExporter
	if !*noImages {
		client, err := provision.NewImageClient(*socket, nil)
		if err != nil {
			return fmt.Errorf("%w\n\nExporting buildkit needs a containerd to pull "+
				"through. Run this on a node where `kanea install` has run, or pass --no-images "+
				"for a bundle destined for a `--network netns` node", err)
		}
		defer func() { _ = client.Close() }() //nolint:errcheck // cleanup path
		images = client
	} else {
		o.println("--no-images: buildkit is omitted.")
	}

	// A staging directory, tarred at the end. Building into the final path
	// would leave a half-written bundle looking like a whole one if this is
	// interrupted, and the whole point of a bundle is that somebody carries
	// it somewhere and trusts it.
	staging := dest
	if !*dirOnly {
		staging, err = os.MkdirTemp("", "kanea-bundle-")
		if err != nil {
			return fmt.Errorf("staging directory: %w", err)
		}
		defer func() { _ = os.RemoveAll(staging) }() //nolint:errcheck // cleanup path
	}

	o.println("Downloading and verifying every component…")
	if err := provision.CreateBundle(context.Background(), manifest,
		provision.NewHTTPSource(), provision.BundleOptions{
			Arch:         *arch,
			Dest:         staging,
			KaneaVersion: version,
			Images:       images,
		}); err != nil {
		return err
	}

	if *dirOnly {
		o.printf("\nWrote %s\n", dest)
	} else {
		if err := tarGzDir(staging, dest); err != nil {
			return err
		}
		size, err := fileSize(dest)
		if err != nil {
			return err
		}
		o.printf("\nWrote %s (%s)\n", dest, humanBytes(size))
	}

	o.println()
	o.println("On the air-gapped node:")
	o.printf("  sudo kanea install --bundle %s\n", filepath.Base(dest))
	o.println()
	o.println("Its contents are verified against the hashes compiled into that node's kanea")
	o.println("binary, so the bundle needs no signature of its own, but it does need the")
	o.printf("same version: this one was built by kanea %s.\n", version)
	return o.Err()
}

// tarGzDir packs a directory.
//
// Members are opened through an [os.Root] scoped to srcDir rather than by
// absolute path. Walking a tree and then opening what you found is a
// time-of-check/time-of-use gap: a symlink swapped in between the two would
// have this read a file outside the staging directory and pack it into a
// bundle somebody then carries to another machine. The staging directory is
// ours and short-lived, so the window is small, but "small window" is the
// description of every TOCTOU bug, and the root-scoped API closes it outright.
func tarGzDir(srcDir, dest string) error {
	root, err := os.OpenRoot(srcDir)
	if err != nil {
		return fmt.Errorf("open %s: %w", srcDir, err)
	}
	defer func() { _ = root.Close() }() //nolint:errcheck // cleanup path
	f, err := os.Create(dest)           // #nosec G304; an operator-chosen output path
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // cleanup path
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)

	err = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		src, err := root.Open(rel)
		if err != nil {
			return err
		}
		defer func() { _ = src.Close() }() //nolint:errcheck // cleanup path
		_, err = io.Copy(tw, src)
		return err
	})
	if err != nil {
		return errors.Join(fmt.Errorf("pack %s: %w", dest, err), tw.Close(), zw.Close())
	}
	if err := tw.Close(); err != nil {
		return errors.Join(err, zw.Close())
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return f.Sync()
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for size := n / unit; size >= unit; size /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
