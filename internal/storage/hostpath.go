package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrHostPathNotAllowed marks a host volume the operator has not permitted.
var ErrHostPathNotAllowed = errors.New("storage: host path is not allowed")

// HostPathPolicy decides which host directories a job spec may mount (R15).
//
// The allowlist comes from the *server* configuration, never from a job spec.
// That split is the whole security argument for the driver existing: an
// unrestricted host mount is `privileged` under another name (`/`, `/etc`, the
// containerd socket) and would make the §14 A05 hardening defaults irrelevant.
// So the boundary is set by whoever owns the node, and a spec author can only
// reference a directory inside it.
//
// The zero value permits nothing, which is the intended default: the driver
// does nothing at all until an operator opts in.
type HostPathPolicy struct {
	// allowed holds cleaned, symlink-resolved absolute prefixes.
	allowed []string
}

// NewHostPathPolicy builds a policy from the configured prefixes.
//
// Each prefix is resolved through symlinks at construction, so the comparison
// later is between two real paths rather than between two spellings of one.
func NewHostPathPolicy(prefixes []string) (HostPathPolicy, error) {
	var policy HostPathPolicy
	for _, raw := range prefixes {
		prefix := strings.TrimSpace(raw)
		if prefix == "" {
			continue
		}
		if !filepath.IsAbs(prefix) {
			return HostPathPolicy{}, fmt.Errorf("storage: allowed host path %q must be absolute", prefix)
		}
		if filepath.Clean(prefix) == "/" {
			// Allowing "/" would permit every path on the node and make the
			// allowlist a formality. Refuse it rather than let an operator
			// disable the control by filling it in.
			return HostPathPolicy{}, fmt.Errorf(
				"storage: %q allows the entire filesystem; list the directories you actually intend to share", prefix)
		}

		resolved, err := filepath.EvalSymlinks(filepath.Clean(prefix))
		if err != nil {
			return HostPathPolicy{}, fmt.Errorf("storage: allowed host path %q: %w", prefix, err)
		}
		policy.allowed = append(policy.allowed, resolved)
	}
	return policy, nil
}

// Enabled reports whether any host path is permitted.
func (p HostPathPolicy) Enabled() bool { return len(p.allowed) > 0 }

// Allowed returns the configured prefixes, for diagnostics.
func (p HostPathPolicy) Allowed() []string { return p.allowed }

// Resolve checks a host path against the allowlist and returns the real
// directory to mount.
//
// Three things have to hold, and each of them is a way this goes wrong:
//
//   - the directory must already exist. Creating it on demand turns a typo into
//     a volume that is silently empty, which is the failure PRD §8 spends most
//     of its words on.
//   - it must be a directory, not a file or a socket. Bind-mounting
//     /run/containerd/containerd.sock into a container is a full node takeover.
//   - the *resolved* path must be inside an allowed prefix. Checking the
//     spelling instead would let `/srv/data/link → /etc` walk straight out.
func (p HostPathPolicy) Resolve(path string) (string, error) {
	if !p.Enabled() {
		return "", fmt.Errorf("%w: no host paths are configured on this node "+
			"(set storage.allowed_host_paths in /etc/kanea/kanea.hcl, or --allowed-host-paths)",
			ErrHostPathNotAllowed)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: %q is not absolute", ErrHostPathNotAllowed, path)
	}

	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: %q does not exist; a host volume must be "+
				"a directory the operator has already created", ErrHostPathNotAllowed, path)
		}
		return "", fmt.Errorf("%w: %q: %w", ErrHostPathNotAllowed, path, err)
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrHostPathNotAllowed, path, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: %q is not a directory", ErrHostPathNotAllowed, path)
	}

	if p.anyPrefixAllows(resolved) {
		return resolved, nil
	}
	return "", fmt.Errorf("%w: %q (resolved to %q) is not under any of %s",
		ErrHostPathNotAllowed, path, resolved, strings.Join(p.allowed, ", "))
}

// ResolveOrCreate is Resolve, plus permission to create the directory when the
// spec asked for it (R15, PRD v1.69).
//
// With create false it *is* Resolve, so the default behaviour has exactly one
// implementation and cannot drift from it.
//
// The ordering is the entire security argument, and it is forced by a detail:
// a path that does not exist cannot be symlink-resolved, so the allowlist
// cannot be checked against it directly. Instead the nearest **existing**
// ancestor is resolved and checked first (meaning a create outside a permitted
// prefix refuses before anything is written to disk) and then the ordinary
// Resolve runs on the result, so the decision about whether a directory may be
// mounted is still made in one place, against a real resolved path.
//
// Creating a directory is not the same as owning it: the mode is 0750 and no
// chown happens, because R24 refuses ownership on host volumes and creating one
// does not change whose directory it is.
func (p HostPathPolicy) ResolveOrCreate(path string, create bool) (string, error) {
	if !create {
		return p.Resolve(path)
	}
	if !p.Enabled() {
		return "", fmt.Errorf("%w: no host paths are configured on this node "+
			"(set storage.allowed_host_paths in /etc/kanea/kanea.hcl, or --allowed-host-paths)",
			ErrHostPathNotAllowed)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: %q is not absolute", ErrHostPathNotAllowed, path)
	}

	clean := filepath.Clean(path)
	if _, err := os.Stat(clean); err == nil {
		// Already there: nothing to create, and Resolve is the whole check.
		return p.Resolve(path)
	}

	// Find the deepest ancestor that exists, and judge *that*. Everything below
	// it is what we would be creating.
	ancestor, err := existingAncestor(clean)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrHostPathNotAllowed, path, err)
	}
	resolved, err := filepath.EvalSymlinks(ancestor)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrHostPathNotAllowed, path, err)
	}
	if !p.anyPrefixAllows(resolved) {
		return "", fmt.Errorf("%w: %q cannot be created: its nearest existing parent %q "+
			"(resolved to %q) is not under any of %s",
			ErrHostPathNotAllowed, path, ancestor, resolved, strings.Join(p.allowed, ", "))
	}

	if err := os.MkdirAll(clean, 0o750); err != nil {
		return "", fmt.Errorf("create host volume %q: %w", path, err)
	}
	// Re-check from scratch. Not paranoia about our own MkdirAll: it is what
	// keeps a single function answering "may this be mounted", so a future
	// change to Resolve's rules applies here too without anyone remembering to.
	return p.Resolve(path)
}

// existingAncestor walks up from path to the first component that exists.
//
// It stops at the root, which always exists, so it terminates. A path whose
// ancestor is a *file* rather than a directory is returned as-is and refused by
// the caller's prefix check or by MkdirAll: either way it does not become a
// mount.
func existingAncestor(path string) (string, error) {
	for {
		parent := filepath.Dir(path)
		if parent == path {
			return parent, nil // reached the root
		}
		if _, err := os.Stat(parent); err == nil {
			return parent, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		path = parent
	}
}

// anyPrefixAllows reports whether a resolved path sits under an allowed prefix.
func (p HostPathPolicy) anyPrefixAllows(resolved string) bool {
	for _, prefix := range p.allowed {
		if withinPrefix(resolved, prefix) {
			return true
		}
	}
	return false
}

// withinPrefix reports whether path is prefix or sits inside it.
//
// The separator is not optional: a plain string prefix test would let
// "/srv/database" pass an allowlist entry of "/srv/data".
func withinPrefix(path, prefix string) bool {
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")+string(filepath.Separator))
}
