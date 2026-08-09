package provision

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Archive extraction.
//
// Every path here comes from a tarball built by somebody else and is used to
// write files that run as root. That is the same shape as GO-2026-5597, the
// go-billy path traversal AGENTS.md pins a security floor for: repository-
// controlled paths written to disk through a chroot filesystem that did not
// hold. The lesson taken here is that the check has to be on the *resolved*
// path and has to include the link target, because "does the name start with
// ../" is not the property anyone actually wants.

// ErrUnsafePath is returned for an archive member that would write outside the
// destination.
var ErrUnsafePath = errors.New("archive member escapes the destination")

// maxFileSize caps a single extracted member at 1 GiB.
//
// A decompression bomb is a real archive with a real hash, so the manifest's
// pin does not protect against one — it only means the bomb had to be shipped
// by the upstream project. containerd's largest binary is ~50 MiB and the cap
// is twenty times that, so it can only ever fire on something already wrong.
const maxFileSize = 1 << 30

// extractOptions says what to pull out of an archive.
type extractOptions struct {
	// files selects members and their destinations. Empty means everything.
	files []File
	// dest is the install prefix. Every destination is relative to it.
	dest string
	// defaultMode applies when a selected file names none.
	defaultMode os.FileMode
}

// extractTarGz pulls the wanted members out of a gzipped tar.
func extractTarGz(r io.Reader, opts extractOptions) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	defer func() { _ = zr.Close() }() //nolint:errcheck // cleanup path
	return extractTar(zr, opts)
}

// extractTar pulls the wanted members out of a tar stream.
func extractTar(r io.Reader, opts extractOptions) error {
	// wanted maps a cleaned archive path to its destination. A nil map means
	// "everything", which the CNI plugin set uses.
	wanted, dirs := planExtraction(opts.files)
	// Keyed by destination, not by archive path: a file with an Alt has two
	// entries in `wanted` pointing at one File, and either satisfies it.
	found := make(map[string]bool, len(wanted))

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read the archive: %w", err)
		}
		// Regular files only. A tarball of binaries has no business carrying a
		// device node, a symlink or a hard link, and honouring one is how an
		// extractor writes through a path it already checked. Refusing them
		// outright is simpler to reason about than resolving them safely.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if !safeArchivePath(name) {
			return fmt.Errorf("%w: %q", ErrUnsafePath, hdr.Name)
		}

		rel, mode, ok := destinationFor(name, wanted, dirs, opts)
		if !ok {
			continue
		}
		// An archive that carries both the primary and the Alt location would
		// otherwise have the second overwrite the first. First wins.
		if found[rel] {
			continue
		}

		target, err := resolveUnder(opts.dest, rel)
		if err != nil {
			return err
		}
		if hdr.Size > maxFileSize {
			return fmt.Errorf("archive member %q is %d bytes, over the %d-byte cap",
				hdr.Name, hdr.Size, maxFileSize)
		}
		// LimitReader as well as the header check: the header is a claim, and
		// the number of bytes that follow it is the thing that fills a disk.
		if err := writeFileAtomic(target, io.LimitReader(tr, maxFileSize), mode); err != nil {
			return err
		}
		found[rel] = true
	}

	for _, f := range opts.files {
		if f.From == "" || f.From == "." || found[f.To] {
			continue
		}
		// Named after the destination as well as the source: "usr/bin/buildctl
		// not found" is a puzzle, "buildctl (usr/bin/buildctl) not found in
		// the archive" says which of the two is wrong.
		where := f.From
		if f.Alt != "" {
			where += " or " + f.Alt
		}
		return fmt.Errorf("%s (%s) not found in the archive", path.Base(f.To), where)
	}
	return nil
}

// planExtraction splits the wanted files into exact matches and directory
// captures ("." or a trailing-slash prefix meaning "everything under here").
func planExtraction(files []File) (exact map[string]File, dirs []File) {
	if len(files) == 0 {
		return nil, nil
	}
	exact = make(map[string]File, len(files))
	for _, f := range files {
		switch f.From {
		case "", ".":
			dirs = append(dirs, f)
		default:
			exact[path.Clean(f.From)] = f
			if f.Alt != "" {
				exact[path.Clean(f.Alt)] = f
			}
		}
	}
	if len(exact) == 0 {
		exact = nil
	}
	return exact, dirs
}

// destinationFor decides where an archive member goes, if anywhere.
func destinationFor(name string, wanted map[string]File, dirs []File, opts extractOptions) (string, os.FileMode, bool) {
	if f, ok := wanted[name]; ok {
		mode, err := f.FileMode()
		if err != nil {
			return "", 0, false
		}
		return f.To, os.FileMode(mode), true
	}
	for _, f := range dirs {
		mode, err := f.FileMode()
		if err != nil {
			continue
		}
		base := path.Base(name)
		if f.excluded(base) {
			return "", 0, false
		}
		// A directory capture keeps the member's base name only. Archives
		// disagree about whether they carry a top-level directory, and
		// flattening means the manifest does not have to know.
		return path.Join(f.To, base), os.FileMode(mode), true
	}
	if wanted == nil && dirs == nil {
		return path.Join(".", name), opts.defaultMode, true
	}
	return "", 0, false
}

// safeArchivePath rejects a member name that could escape.
func safeArchivePath(name string) bool {
	if name == "" || name == "." {
		return false
	}
	// Absolute, or a Windows-style volume — neither belongs in an archive of
	// Linux binaries, and both are a way to leave the destination.
	if path.IsAbs(name) || strings.HasPrefix(name, "/") || filepath.IsAbs(name) {
		return false
	}
	if name == ".." || strings.HasPrefix(name, "../") {
		return false
	}
	// Checked after Clean, so this catches a name that only becomes traversal
	// once separators are normalised.
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// resolveUnder joins rel onto dest and proves the result is still inside it.
//
// The destination is resolved through symlinks first, because the check has to
// be about where the write actually lands. A `dest` that is itself a symlink is
// ordinary — /usr/local is one on some distributions — so resolving it is not a
// concession, it is the only way the comparison means anything.
func resolveUnder(dest, rel string) (string, error) {
	if !safeArchivePath(path.Clean(rel)) {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, rel)
	}
	root, err := filepath.Abs(dest)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", dest, err)
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("resolve %s: %w", dest, err)
	}

	target := filepath.Join(root, filepath.FromSlash(rel))
	// filepath.Rel is the comparison rather than strings.HasPrefix: the latter
	// says /var/lib/kanea-evil is inside /var/lib/kanea.
	relToRoot, err := filepath.Rel(root, target)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, rel)
	}
	if relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q resolves outside %s", ErrUnsafePath, rel, root)
	}

	// The parent must not be a symlink either: an attacker who can create one
	// inside dest between two installs could otherwise redirect a write that
	// passed every check above.
	parent := filepath.Dir(target)
	if info, err := os.Lstat(parent); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: %s is a symlink", ErrUnsafePath, parent)
	}
	return target, nil
}
