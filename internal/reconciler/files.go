package reconciler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/m18h/kanea/internal/atomicfile"
	"github.com/m18h/kanea/internal/runtime"
	secretstore "github.com/m18h/kanea/internal/secrets"
)

// Spec-declared files (PRD §6.2 R35).
//
// A `file` block's bytes live in the record with secret placeholders in them;
// this is where the placeholders become values and the bytes become a file the
// container can read. It is R3's shape applied to content rather than to an env
// var: the record keeps references, resolution happens at alloc create, and a
// rotation therefore lands at the next replacement.
//
// Two trees, decided by whether a file carries a reference at all - a property
// of the record (FileMount.HasSecrets), never a scan over the bytes.

// DefaultFilesDir is where files carrying a secret are materialised.
//
// Deliberately not the secrets tmpfs. That one is 4 MiB shared by *every alloc
// on the node*, and its size was chosen for credentials, which are small; a
// config file filling it would surface as secrets_failed on a service that
// declares no files at all, in another project. Separate trees means a config
// mistake cannot take out credential delivery.
const DefaultFilesDir = "/run/kanea/files"

// Rendered ceilings, checked on the node before the first write.
//
// The plan-time byte budgets bound the *record*, and substitution grows it: a
// placeholder is tens of bytes and the secret it names may be 64 KiB, so eight
// references turn a compliant record into half a megabyte of tmpfs. Without
// these the plan-time bounds would be decorative with respect to what actually
// gets written.
const (
	MaxRenderedFileBytes  = 256 << 10
	MaxRenderedAllocBytes = 1 << 20
)

// allocFiles is one alloc's materialised files: the mounts to add to its spec.
type allocFiles struct {
	Mounts []runtime.Mount
}

// ensureFiles materialises a service's files for one alloc.
//
// Plain files are shared by every alloc of the service - the content derives
// from Desired alone and nothing in it is per-alloc, so this is one inode
// instead of N, which is the argument WriteResolvConf already makes for one
// file per project. Secret-bearing files are per alloc, because they are
// chowned to the reading container.
func (r *Reconciler) ensureFiles(ctx context.Context, d Desired, allocID string) (allocFiles, error) {
	var out allocFiles
	if len(d.Files) == 0 {
		return out, nil
	}
	if r.plainFilesDir == "" {
		return out, fmt.Errorf("service declares files but no config-file directory is configured")
	}

	secretDir := filepath.Join(r.filesDir, allocID)
	// Rebuilt from empty, ensureSecrets' pattern and its safety argument: no
	// container of the alloc is running when this happens, because container
	// ids are unique so a replacement is removed before it is created.
	if err := os.RemoveAll(secretDir); err != nil {
		return out, fmt.Errorf("clear %s: %w", secretDir, err)
	}

	rendered := 0
	for i := range d.Files {
		f := d.Files[i]
		body, err := r.renderFile(ctx, f)
		if err != nil {
			return allocFiles{}, err
		}
		if len(body) > MaxRenderedFileBytes {
			return allocFiles{}, fmt.Errorf(
				"file %q renders to %d bytes; the limit is %d (PRD §21)",
				f.Name, len(body), MaxRenderedFileBytes)
		}
		rendered += len(body)
		if rendered > MaxRenderedAllocBytes {
			return allocFiles{}, fmt.Errorf(
				"this alloc's files render to more than %d bytes (PRD §21)", MaxRenderedAllocBytes)
		}

		source, err := r.writeFile(d, f, body, secretDir)
		if err != nil {
			return allocFiles{}, err
		}
		out.Mounts = append(out.Mounts, runtime.Mount{
			Source:      source,
			Destination: f.Path,
			ReadOnly:    true,
			// A file block delivers configuration, never a program, which is
			// what lets these be unconditional rather than mode-dependent.
			Options: []string{"nosuid", "noexec", "nodev"},
		})
	}
	return out, nil
}

// renderFile substitutes a file's placeholders.
//
// Errors name the file and the reference and never the value, the surrounding
// bytes, or an offset into content: an error string is a place a credential
// escapes to a log, and materializeSecrets sets the shape.
func (r *Reconciler) renderFile(ctx context.Context, f FileMount) ([]byte, error) {
	if !f.HasSecrets() {
		return f.Content, nil
	}
	if r.secrets == nil {
		return nil, fmt.Errorf("file %q interpolates %s but no secret store is configured",
			f.Name, f.SecretRefs[0])
	}
	body := string(f.Content)
	for i, ref := range f.SecretRefs {
		value, err := r.secrets.Resolve(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("file %q: resolve %s: %w", f.Name, ref, err)
		}
		body = strings.ReplaceAll(body, secretstore.PlaceholderText(f.Nonce, i), string(value))
	}
	return []byte(body), nil
}

// writeFile puts one rendered file on disk and returns its host path.
func (r *Reconciler) writeFile(d Desired, f FileMount, body []byte, secretDir string) (string, error) {
	mode, err := fileMode(f)
	if err != nil {
		return "", err
	}

	if !f.HasSecrets() {
		// Shared, world-readable, on disk: resolv.conf's reasoning, which is
		// that the file is bind-mounted into a container that may run as any
		// uid and holds nothing secret. Written atomically and only when the
		// bytes changed, so steady state writes nothing - and rename(2) gives
		// rolling-update correctness for free, since a running alloc's bind
		// pins the old inode while a new alloc binds the new one.
		dir := filepath.Join(r.plainFilesDir, d.Project, d.Service)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", fmt.Errorf("file %q: %w", f.Name, err)
		}
		path := filepath.Join(dir, f.Name)
		if _, err := atomicfile.WriteIfChanged(path, body, mode); err != nil {
			return "", fmt.Errorf("file %q: %w", f.Name, err)
		}
		return path, nil
	}

	// Secret-bearing: the secrets tree's rules. 0700 on the directory rather
	// than the secrets tree's 0711, because only the leaf file is bound and no
	// container uid ever traverses this one - kanead resolves the source as
	// root at mount time.
	fellBack, err := ensureFilesTmpfs(r.filesDir)
	if err != nil {
		return "", err
	}
	if fellBack {
		r.warnFilesTmpfsFallback(r.filesDir)
	}
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		return "", fmt.Errorf("file %q: %w", f.Name, err)
	}
	path := filepath.Join(secretDir, f.Name)
	if err := os.WriteFile(path, body, mode); err != nil {
		return "", fmt.Errorf("file %q: %w", f.Name, err)
	}
	// Owned by its reader, materializeSecrets' rule: a file 0400 owned by
	// somebody else reads as a missing credential rather than as a permission
	// problem. Written 0400 root-owned first, so it is unreadable in between.
	uid, gid := 0, 0
	if d.User != nil {
		uid, gid = int(d.User.UID), int(d.User.GID)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return "", fmt.Errorf("file %q: %w", f.Name, err)
	}
	return path, nil
}

// fileMode resolves a file's permission bits, defaulting by kind.
func fileMode(f FileMount) (os.FileMode, error) {
	spelled := f.Mode
	if spelled == "" {
		spelled = "0644"
		if f.HasSecrets() {
			spelled = "0400"
		}
	}
	mode, err := strconv.ParseUint(spelled, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("file %q: mode %q is not octal", f.Name, f.Mode)
	}
	return os.FileMode(mode), nil
}

// discardFiles removes an alloc's secret-bearing files at teardown.
//
// The plain tree is deliberately untouched: it is shared by every alloc of the
// service, so a sibling still binds it. It goes when the service does.
func (r *Reconciler) discardFiles(allocID string) {
	dir := filepath.Join(r.filesDir, allocID)
	if err := os.RemoveAll(dir); err != nil {
		r.log.Warn("cannot remove alloc files", "alloc", allocID, "error", err)
	}
}
