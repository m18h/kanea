package reconciler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/m18h/kanea/internal/runtime"
	secretstore "github.com/m18h/kanea/internal/secrets"
)

// Env-secret injection (PRD §6.2 R3, v1.76).
//
// A `secret:` env value never reaches a container as text. At create, the
// reconciler resolves it into a per-alloc tmpfs file under
// /run/kanea/secrets/<alloc>/<scope>/<name> - 0400, owned by the alloc's
// effective user, presented read-only at the same path inside the container -
// and the env var carries the file's path. The `secret-env:` form inlines the
// value into the variable instead: the documented weaker option R3 names
// (visible in /proc/<pid>/environ, inherited by children), for software that
// only reads env values.
//
// Resolution happens here and only here. Nothing is written into the Store
// (the record keeps the reference, which is also why nothing re-hashes), the
// API stays write-only, and `kanea describe` shows the reference. A rotation
// lands the way it does everywhere else in v1: on the alloc's next
// replacement.

// DefaultSecretsDir is where per-alloc secret files live (R3). It is a tmpfs
// the reconciler ensures on first use, so the guarantee is structural rather
// than "systemd happens to mount /run as one".
const DefaultSecretsDir = "/run/kanea/secrets" // #nosec G101: a directory path, not a credential

// envSecretRef is one parsed env reference.
type envSecretRef struct {
	key    string
	ref    string // canonical secret:<scope>/<name> form
	scope  string
	name   string
	inline bool
}

// scanEnvRefs finds the secret references in a service's environment.
func scanEnvRefs(env map[string]string) []envSecretRef {
	var refs []envSecretRef
	for key, value := range env {
		ref, inline, ok := secretstore.ParseEnvRef(value)
		if !ok {
			continue
		}
		scope, name, _ := strings.Cut(strings.TrimPrefix(ref, "secret:"), "/")
		refs = append(refs, envSecretRef{key: key, ref: ref, scope: scope, name: name, inline: inline})
	}
	return refs
}

// ensureSecrets resolves one alloc's env references and returns the effective
// environment and the mount that presents the files, or (nil, nil, nil) for a
// service with none. The alloc id is the caller's, so the directory this
// builds and the spec's agree.
//
// The directory is rebuilt from empty: a create runs only when no live
// container holds the old bind (container ids are unique, so a replacement is
// removed before it is created), which makes "rewrite" and "replace" the same
// operation.
func (r *Reconciler) ensureSecrets(
	ctx context.Context, d Desired, allocID string,
) (map[string]string, *runtime.Mount, error) {
	refs := scanEnvRefs(d.Env)
	if len(refs) == 0 {
		return nil, nil, nil
	}
	if r.secrets == nil {
		return nil, nil, fmt.Errorf("env references %s but no secrets store is configured", refs[0].ref)
	}

	dir := filepath.Join(r.secretsDir, allocID)
	if err := os.RemoveAll(dir); err != nil {
		return nil, nil, fmt.Errorf("clear %s: %w", dir, err)
	}
	// The tmpfs is ensured lazily: a node whose services reference no secrets
	// never mounts one. And the directory itself is traversable (0711): the
	// 0400 files inside it are the boundary, not the path to them.
	if err := ensureSecretsTmpfs(r.secretsDir); err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o711); err != nil { // #nosec G301: o+x on parents is the point - a non-root alloc uid must traverse to its 0400 files
		return nil, nil, err
	}

	// The effective uid/gid owns the files: the workload's own user is the one
	// that must read them, and 0400 keeps every other uid in the container out.
	uid, gid := 0, 0
	if d.User != nil {
		uid, gid = int(d.User.UID), int(d.User.GID)
	}

	env := make(map[string]string, len(d.Env))
	for k, v := range d.Env {
		env[k] = v
	}
	for _, ref := range refs {
		value, err := r.secrets.Resolve(ctx, ref.ref)
		if err != nil {
			return nil, nil, fmt.Errorf("env %s: resolve %s: %w", ref.key, ref.ref, err)
		}
		if ref.inline {
			env[ref.key] = string(value)
			continue
		}
		rel := filepath.Join(ref.scope, ref.name)
		target := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o711); err != nil { // #nosec G301: traversal, as above
			return nil, nil, fmt.Errorf("env %s: %w", ref.key, err)
		}
		if err := os.WriteFile(target, value, 0o400); err != nil {
			return nil, nil, fmt.Errorf("env %s: %w", ref.key, err)
		}
		if err := os.Chown(target, uid, gid); err != nil {
			return nil, nil, fmt.Errorf("env %s: %w", ref.key, err)
		}
		env[ref.key] = filepath.Join(DefaultSecretsDir, allocID, rel)
	}

	// The bind presents the directory read-only at the identical path, so the
	// paths the env vars carry mean the same thing inside and out.
	mount := &runtime.Mount{
		Source:      dir,
		Destination: filepath.Join(DefaultSecretsDir, allocID),
		ReadOnly:    true,
	}
	return env, mount, nil
}

// discardSecrets removes an alloc's directory. Files under it are 0400 and
// read by no one else, so teardown is the only lifetime they get; kanead
// crashing between create and teardown leaves a directory, and the next
// create of the same alloc rebuilds from empty anyway.
func (r *Reconciler) discardSecrets(allocID string) {
	if r.secretsDir == "" {
		return
	}
	if err := os.RemoveAll(filepath.Join(r.secretsDir, allocID)); err != nil {
		r.log.Warn("cannot remove alloc secrets", "alloc", allocID, "error", err)
	}
}
