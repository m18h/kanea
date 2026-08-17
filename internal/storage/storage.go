// Package storage establishes and supervises the volume mounts services
// declare (PRD §8).
//
// The design is shaped almost entirely by one M0 spike ③ finding: a FUSE mount
// whose backing store has gone away does not fail; it *blocks*, for 40 s to
// over 2 minutes, uninterruptibly. A syscall in that state cannot be cancelled
// by a context, because the goroutine is stuck in the kernel. Every function
// here that touches a mount path therefore runs the touch on a goroutine it is
// willing to abandon, and answers on a timer instead of waiting.
//
// The second finding is why the supervisor exists at all: after an object-store
// outage, s3fs keeps serving ENOENT for objects that are verifiably still in
// the bucket, and it never recovers on its own. Only a remount fixes it. So
// "mount it and hope" is not an option: supervision and remount are part of
// the driver, not an optional extra.
package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/notify"
)

// Storage types (PRD §8).
const (
	TypeLocal = "local"
	TypeS3    = "s3"
	TypeNFS   = "nfs"
	TypeSMB   = "smb"
	// TypeHost mounts a directory the operator already owns, gated by the
	// server-config allowlist (R15).
	TypeHost = "host"
)

// S3 access modes. The driver differs by mode because the two are not
// interchangeable (M0 spike ③): mountpoint-s3 refuses append, write-at-offset,
// chmod and symlink, which is fine for media and fatal for anything that
// rewrites files in place.
const (
	ModeReadOnly  = "ro"
	ModeReadWrite = "rw"
)

// Errors callers branch on.
var (
	// ErrUnsupported marks a storage type this build cannot mount.
	ErrUnsupported = errors.New("storage: unsupported type")
	// ErrCredentialsUnavailable means the resource needs credentials that
	// cannot be resolved yet.
	ErrCredentialsUnavailable = errors.New("storage: credentials unavailable")
	// ErrTimeout means an operation on a mount did not return in time; almost
	// always a wedged FUSE mount rather than a slow one.
	ErrTimeout = errors.New("storage: timed out")
)

// Resource is a named storage resource from the job spec (PRD §8).
type Resource struct {
	Name string
	Type string
	// S3.
	Bucket   string
	Endpoint string
	AuthRef  string
	Mode     string
	// NFS and SMB.
	Server  string
	Export  string
	Share   string
	Options string
	// Host: the directory to mount, as written in the spec.
	Path string
	// Create permits Kanea to create a missing host directory (R15, v1.69).
	// False keeps the original behaviour, where a missing path is a mistake to
	// report rather than a directory to invent.
	Create bool `json:"create,omitempty"`
}

// NeedsMount reports whether this resource requires a mount command.
//
// Local and host volumes do not: both are already directories on this node, so
// the alloc's own bind mount is the whole mechanism. They differ only in who
// chose the directory: Kanea derives a local one, an operator owns a host one.
func (r Resource) NeedsMount() bool {
	switch r.Type {
	case "", TypeLocal, TypeHost:
		return false
	default:
		return true
	}
}

// IsHost reports whether this resource is an operator-provided directory.
func (r Resource) IsHost() bool { return r.Type == TypeHost }

// Request is one mount to establish.
type Request struct {
	Resource Resource
	// Target is the host directory the volume appears at.
	Target string
	// ReadOnly mounts it read-only.
	ReadOnly bool
	// UID, GID and Mode are the ownership the mount presents (PRD §6.2 R24),
	// nil for none. They live on the Request rather than on the Resource
	// because ownership is the *volume's* decision: two services mounting one
	// storage resource already get distinct targets, so they may legitimately
	// see it owned differently.
	//
	// Note Resource.Mode is a different thing entirely: it selects the S3
	// driver, ro or rw. Do not conflate them.
	UID  *uint32
	GID  *uint32
	Mode *uint32
}

// ownershipRefusedBy names the drivers that cannot carry ownership (R24).
//
// jobspec refuses these at `plan`, which is where an operator should meet them.
// This copy is the backstop for a record that reached the Store another way,
// and it is small and static enough that the duplication is cheaper than a
// dependency from storage to jobspec, which would point the wrong way.
var ownershipRefusedBy = map[string]string{
	TypeHost: "a host volume is the operator's own directory, which Kanea neither creates " +
		"nor changes (R15)",
	TypeNFS: "the kernel NFS client has no uid= or gid= mount option; ownership is the " +
		"server's to decide",
}

// owned reports whether this request carries any ownership.
func (r Request) owned() bool { return r.UID != nil || r.GID != nil || r.Mode != nil }

// idOptions renders the uid= and gid= options the kernel mounts share.
func (r Request) idOptions() []string {
	var opts []string
	if r.UID != nil {
		opts = append(opts, fmt.Sprintf("uid=%d", *r.UID))
	}
	if r.GID != nil {
		opts = append(opts, fmt.Sprintf("gid=%d", *r.GID))
	}
	return opts
}

// Timeouts. Every one of these exists because the alternative is a control
// plane that blocks on a dead network filesystem.
const (
	// DefaultMountTimeout bounds a mount command. NFS and SMB negotiate; s3fs
	// and mountpoint-s3 make a bucket round trip.
	DefaultMountTimeout = 30 * time.Second
	// DefaultUnmountTimeout bounds an unmount. A lazy unmount follows if this
	// expires, so it does not need to be generous.
	DefaultUnmountTimeout = 10 * time.Second
	// DefaultCheckTimeout bounds one health probe of a mount. It is short by
	// design: the question is "is this mount answering", and a mount that takes
	// five seconds to stat a directory has already failed for a workload.
	DefaultCheckTimeout = 5 * time.Second
	// DefaultCheckInterval is how often each mount is probed.
	DefaultCheckInterval = 30 * time.Second
)

// Runner executes a command. It exists so the mount commands can be asserted in
// a unit test without root, a network, or a real filesystem.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// execRunner runs commands for real.
type execRunner struct{}

// waitDelay bounds how long Wait will keep waiting for a command's output pipes
// after the context has already killed it.
//
// This is not a nicety. `mount` forks `mount.nfs`, which inherits stdout and
// stderr; when the context expires, CommandContext kills `mount` but the
// grandchild survives and holds those pipes open, and CombinedOutput waits for
// *every* writer to close them. Without WaitDelay the mount timeout kills the
// process and the call still blocks indefinitely, which is precisely the
// failure this package exists to prevent. Observed against an unreachable NFS
// server: the reconcile pass stopped for minutes with a 30 s timeout set.
const waitDelay = 2 * time.Second

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Arguments are always an array, never a shell string (PRD §14, A03).
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204: fixed argv, no shell
	cmd.WaitDelay = waitDelay
	out, err := cmd.CombinedOutput()
	return out, err
}

// SecretResolver resolves a `secret:<path>` reference to its value.
//
// Storage credentials are referenced, never inlined (PRD §6.2 R3/R5). The
// secrets store itself is M5, so a nil resolver here is expected for now and
// produces a clear refusal rather than an attempt to mount without credentials.
type SecretResolver interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

// Config configures the Manager.
type Config struct {
	// Runner executes mount commands. Nil uses the real one.
	Runner Runner
	// Secrets resolves credential references. Nil means credentialed drivers
	// refuse to mount.
	Secrets SecretResolver
	// CredentialDir holds per-mount credential files. They are written 0600 and
	// removed as soon as the mount command has read them.
	CredentialDir string
	// Logger receives mount lifecycle events.
	Logger *slogLogger

	MountTimeout   time.Duration
	UnmountTimeout time.Duration
	CheckTimeout   time.Duration
	// Now is injectable for tests.
	Now func() time.Time
	// MountTable reports whether a path is currently mounted. Nil reads
	// /proc/mounts; tests substitute their own.
	MountTable func(string) (bool, error)
	// HostPaths is the operator's allowlist for `host` volumes (R15). The zero
	// value permits none, which is the intended default.
	HostPaths HostPathPolicy
	// Emit publishes volume.* events (§11, PRD v1.69). Nil disables them.
	//
	// Before this existed the supervisor could remount a failed volume three
	// times in an afternoon and tell nobody: the whole recovery story was in
	// the daemon log. Constraint #8 governs the call (Publish never blocks and
	// never returns an error) which is what makes it safe to emit from inside
	// a mount's own lock.
	Emit func(notify.Event)
}

// mountPath is the host path of a mount, used as its identity.
type mountPath = string

// isMountPoint reports whether path appears in the kernel's mount table.
//
// It reads /proc/mounts rather than stat-ing the path, and that is deliberate:
// stat on a wedged FUSE mount blocks in the kernel, while /proc/mounts is
// served from memory and always answers. Asking "is something mounted here"
// must never be the thing that hangs.
func isMountPoint(path string) (bool, error) {
	raw, err := os.ReadFile(procMounts)
	if errors.Is(err, os.ErrNotExist) {
		// No mount table means nothing can be mounted: the case on a
		// non-Linux host, where this package does no real work anyway.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", procMounts, err)
	}
	for line := range strings.Lines(string(raw)) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// The mount point is field 2, with octal escapes for spaces and tabs.
		if unescapeMountPath(fields[1]) == path {
			return true, nil
		}
	}
	return false, nil
}

const procMounts = "/proc/mounts"

// unescapeMountPath decodes the octal escapes the kernel uses in /proc/mounts
// for space (\040), tab (\011), newline (\012) and backslash (\134).
func unescapeMountPath(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var v int
			// Three octal digits cannot exceed 0o777, and the kernel only emits
			// escapes below 0o200; anything larger is not an escape we wrote.
			// #nosec G115: bounded to a byte on the line above.
			if _, err := fmt.Sscanf(s[i+1:i+4], "%3o", &v); err == nil && v >= 0 && v <= 0xFF {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
