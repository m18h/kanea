package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// mountCommand builds the command that establishes one mount.
//
// Everything is an argument array. A mount command assembled as a shell string
// with a bucket name or a server address interpolated into it would be a command
// injection reachable from a job spec (PRD §14, A03).
func (m *Manager) mountCommand(ctx context.Context, req Request) (name string, args []string, cleanup func(), err error) {
	switch req.Resource.Type {
	case TypeNFS:
		name, args = nfsCommand(req)
	case TypeSMB:
		name, args, cleanup, err = m.smbCommand(ctx, req)
	case TypeS3:
		name, args, cleanup, err = m.s3Command(ctx, req)
	default:
		return "", nil, nil, fmt.Errorf("%w: %q", ErrUnsupported, req.Resource.Type)
	}
	if cleanup == nil {
		cleanup = func() {}
	}
	return name, args, cleanup, err
}

// nfsCommand mounts an NFS export with the kernel client.
func nfsCommand(req Request) (string, []string) {
	source := req.Resource.Server + ":" + req.Resource.Export
	return "mount", []string{"-t", "nfs", "-o", mountOptions(req), source, req.Target}
}

// mountOptions renders the option list shared by the kernel mounts.
//
// Three of these are load-bearing rather than tuning:
//
//   - soft: a hard mount blocks a workload's syscalls forever when the server
//     goes away. Kanea bounds everything else it touches; a volume that can
//     wedge a process indefinitely would make that pointless.
//   - retry=0: mount.nfs otherwise keeps retrying in the *background* for two
//     minutes, so a mount against a dead server costs the caller its full
//     timeout rather than failing when the server is plainly unreachable.
//   - timeo/retrans: bound one RPC attempt rather than inheriting a default
//     measured in minutes.
func mountOptions(req Request) string {
	opts := []string{"soft", "retry=0", "timeo=100", "retrans=2"}
	if req.ReadOnly {
		opts = append(opts, "ro")
	}
	if req.Resource.Options != "" {
		opts = append(opts, req.Resource.Options)
	}
	return strings.Join(opts, ",")
}

// smbCommand mounts a CIFS share.
//
// Credentials go in a 0600 file rather than on the command line: anything in
// argv is readable by every process on the host via /proc/<pid>/cmdline.
func (m *Manager) smbCommand(ctx context.Context, req Request) (string, []string, func(), error) {
	credPath, cleanup, err := m.writeCredentials(ctx, req, smbCredentialFile)
	if err != nil {
		return "", nil, nil, err
	}
	source := "//" + req.Resource.Server + "/" + req.Resource.Share

	opts := []string{"credentials=" + credPath, "vers=3.0"}
	if req.ReadOnly {
		opts = append(opts, "ro")
	}
	if req.Resource.Options != "" {
		opts = append(opts, req.Resource.Options)
	}
	return "mount", []string{"-t", "cifs", "-o", strings.Join(opts, ","), source, req.Target}, cleanup, nil
}

// s3Command mounts a bucket with the driver the mode selects (M0 spike ③).
//
// mountpoint-s3 is the default and is read-mostly: it refuses append,
// write-at-offset, chmod and symlink. s3fs is the opt-in read-write driver and
// carries its own caveat — it *silently* ignores truncate, returning success
// while leaving the file unchanged.
func (m *Manager) s3Command(ctx context.Context, req Request) (string, []string, func(), error) {
	credPath, cleanup, err := m.writeCredentials(ctx, req, awsCredentialFile)
	if err != nil {
		return "", nil, nil, err
	}

	if req.Resource.Mode == ModeReadWrite {
		opts := []string{
			"passwd_file=" + credPath,
			"use_path_request_style",
			// Explicit timeouts and a bounded retry budget, rather than the
			// driver's defaults: a mount that retries forever is how a workload
			// ends up blocked in the kernel (spike ③).
			"connect_timeout=10",
			"readwrite_timeout=30",
			"retries=3",
		}
		if req.Resource.Endpoint != "" {
			opts = append(opts, "url="+req.Resource.Endpoint)
		}
		if req.ReadOnly {
			opts = append(opts, "ro")
		}
		if req.Resource.Options != "" {
			opts = append(opts, req.Resource.Options)
		}
		// allow_other is required because the mount is established by an
		// unprivileged helper and traversed by root-run containerd. It needs
		// user_allow_other in /etc/fuse.conf, which `kanea init` sets up.
		opts = append(opts, "allow_other")
		return "s3fs", []string{req.Resource.Bucket, req.Target, "-o", strings.Join(opts, ",")}, cleanup, nil
	}

	args := []string{
		req.Resource.Bucket, req.Target,
		"--profile", awsProfile,
		"--allow-other",
		"--read-only",
	}
	if req.Resource.Endpoint != "" {
		args = append(args, "--endpoint-url", req.Resource.Endpoint, "--force-path-style")
	}
	return "mount-s3", args, cleanup, nil
}

// Credential file names and the profile mountpoint-s3 reads.
const (
	awsCredentialFile = "aws"
	smbCredentialFile = "smb"
	awsProfile        = "kanea"
)

// writeCredentials materialises a resource's credentials into a 0600 file and
// returns its path plus a cleanup that removes it.
//
// Credentials never reach a command line. Everything in argv is world-readable
// through /proc/<pid>/cmdline, so a bucket secret passed as a flag is a secret
// published to every process on the node.
func (m *Manager) writeCredentials(ctx context.Context, req Request, kind string) (string, func(), error) {
	if req.Resource.AuthRef == "" {
		// Anonymous access is legitimate for a public bucket or an
		// unauthenticated export, so this is not an error.
		return "", func() {}, nil
	}
	if m.secrets == nil {
		return "", nil, fmt.Errorf("%w: %s references %s but the secrets store is not available",
			ErrCredentialsUnavailable, req.Resource.Name, req.Resource.AuthRef)
	}

	value, err := m.secrets.Resolve(ctx, req.Resource.AuthRef)
	if err != nil {
		return "", nil, fmt.Errorf("resolve %s for storage %s: %w",
			req.Resource.AuthRef, req.Resource.Name, err)
	}

	body, err := renderCredentials(kind, value)
	if err != nil {
		return "", nil, fmt.Errorf("storage %s: %w", req.Resource.Name, err)
	}

	if err := os.MkdirAll(m.credentialDir, 0o700); err != nil {
		return "", nil, fmt.Errorf("credential dir: %w", err)
	}
	path := filepath.Join(m.credentialDir, req.Resource.Name+"."+kind)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", nil, fmt.Errorf("write credentials for %s: %w", req.Resource.Name, err)
	}

	return path, func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			m.log.Warn("cannot remove credential file", "path", path, "error", err)
		}
	}, nil
}

// renderCredentials converts a stored secret into the file format the driver
// expects. The secret itself is "<access-key>:<secret-key>" for both.
func renderCredentials(kind string, value []byte) ([]byte, error) {
	user, pass, ok := strings.Cut(strings.TrimSpace(string(value)), ":")
	if !ok || user == "" {
		return nil, fmt.Errorf("credential must be \"<user>:<secret>\"")
	}
	switch kind {
	case awsCredentialFile:
		return fmt.Appendf(nil,
			"[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\n",
			awsProfile, user, pass), nil
	case smbCredentialFile:
		return fmt.Appendf(nil, "username=%s\npassword=%s\n", user, pass), nil
	default:
		return nil, fmt.Errorf("unknown credential format %q", kind)
	}
}
