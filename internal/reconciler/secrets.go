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

// allocSecrets is one alloc's resolved secret material: the task's effective
// environment, each init container's, and the single mount that presents the
// files to all of them.
//
// One tree and one mount for the whole alloc, because the alloc is what owns
// the tmpfs and its lifetime (R32: every step shares it, like the netns and
// the volumes).
type allocSecrets struct {
	// Env is the task's effective environment, or nil when it had no refs.
	Env map[string]string
	// InitEnv is each init container's, keyed by step name; an entry is absent
	// when that step referenced no secrets.
	InitEnv map[string]map[string]string
	// Mount presents the tree read-only at the same path it has on the host.
	Mount *runtime.Mount
}

// ensureSecrets resolves an alloc's env references - the task's and every init
// container's - and returns the effective environments and the mount that
// presents the files. A service that references none gets a zero result.
//
// Layout. The task's files keep the path R3 documents,
// /run/kanea/secrets/<alloc>/<scope>/<name>, byte for byte; a step's live one
// level in, under init/<step>/. They are separated rather than shared because
// each file is 0400 owned by *its reader's* uid, and the whole point of an
// init container is that it runs as a different user than its task: one shared
// file could be read by exactly one of them.
//
// The tree is rebuilt from empty on every call, which is safe because no
// container of the alloc is running when it happens. For a task create that is
// because container ids are unique, so a replacement is removed before it is
// created; for an init step it is because the planner starts step k+1 only
// after step k has stopped, and never re-runs this while one is running (the
// adopt path does no container work at all).
func (r *Reconciler) ensureSecrets(
	ctx context.Context, d Desired, allocID string,
) (allocSecrets, error) {
	var out allocSecrets

	taskRefs := scanEnvRefs(d.Env)
	initRefs := make(map[string][]envSecretRef, len(d.Init))
	total := len(taskRefs)
	for _, init := range d.Init {
		if refs := scanEnvRefs(init.Env); len(refs) > 0 {
			initRefs[init.Name] = refs
			total += len(refs)
		}
	}
	if total == 0 {
		return out, nil
	}
	if r.secrets == nil {
		first := ""
		if len(taskRefs) > 0 {
			first = taskRefs[0].ref
		} else {
			for _, refs := range initRefs {
				first = refs[0].ref
				break
			}
		}
		return out, fmt.Errorf("env references %s but no secrets store is configured", first)
	}

	dir := filepath.Join(r.secretsDir, allocID)
	if err := os.RemoveAll(dir); err != nil {
		return out, fmt.Errorf("clear %s: %w", dir, err)
	}
	// The tmpfs is ensured lazily: a node whose services reference no secrets
	// never mounts one. And the directory itself is traversable (0711): the
	// 0400 files inside it are the boundary, not the path to them.
	fellBack, err := ensureSecretsTmpfs(r.secretsDir)
	if err != nil {
		return out, err
	}
	if fellBack {
		r.warnSecretsTmpfsFallback(r.secretsDir)
	}
	if err := os.MkdirAll(dir, 0o711); err != nil { // #nosec G301: o+x on parents is the point - a non-root alloc uid must traverse to its 0400 files
		return out, err
	}

	if len(taskRefs) > 0 {
		env, err := r.materializeSecrets(ctx, dir, allocID, "", d.Env, taskRefs, d.User)
		if err != nil {
			return allocSecrets{}, err
		}
		out.Env = env
	}
	for _, init := range d.Init {
		refs, ok := initRefs[init.Name]
		if !ok {
			continue
		}
		env, err := r.materializeSecrets(
			ctx, dir, allocID, filepath.Join("init", init.Name), init.Env, refs, init.User)
		if err != nil {
			return allocSecrets{}, err
		}
		if out.InitEnv == nil {
			out.InitEnv = map[string]map[string]string{}
		}
		out.InitEnv[init.Name] = env
	}

	// The bind presents the directory read-only at the identical path, so the
	// paths the env vars carry mean the same thing inside and out.
	out.Mount = &runtime.Mount{
		Source:      dir,
		Destination: filepath.Join(DefaultSecretsDir, allocID),
		ReadOnly:    true,
	}
	return out, nil
}

// materializeSecrets writes one container's referenced secrets under subdir of
// the alloc's tree and returns its effective environment.
//
// user is that container's own, because the files it writes are 0400 owned by
// whoever has to read them: a probe or a step running as a different uid than
// the task would otherwise get a file it cannot open, which reads as a missing
// credential rather than as a permission problem.
func (r *Reconciler) materializeSecrets(
	ctx context.Context, dir, allocID, subdir string,
	declared map[string]string, refs []envSecretRef, user *runtime.User,
) (map[string]string, error) {
	uid, gid := 0, 0
	if user != nil {
		uid, gid = int(user.UID), int(user.GID)
	}

	env := make(map[string]string, len(declared))
	for k, v := range declared {
		env[k] = v
	}
	for _, ref := range refs {
		value, err := r.secrets.Resolve(ctx, ref.ref)
		if err != nil {
			return nil, fmt.Errorf("env %s: resolve %s: %w", ref.key, ref.ref, err)
		}
		if ref.inline {
			env[ref.key] = string(value)
			continue
		}
		rel := filepath.Join(subdir, ref.scope, ref.name)
		target := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o711); err != nil { // #nosec G301: traversal, as above
			return nil, fmt.Errorf("env %s: %w", ref.key, err)
		}
		if err := os.WriteFile(target, value, 0o400); err != nil {
			return nil, fmt.Errorf("env %s: %w", ref.key, err)
		}
		if err := os.Chown(target, uid, gid); err != nil {
			return nil, fmt.Errorf("env %s: %w", ref.key, err)
		}
		env[ref.key] = filepath.Join(DefaultSecretsDir, allocID, rel)
	}
	return env, nil
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
