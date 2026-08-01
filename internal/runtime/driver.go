// Package runtime is the containerd driver: it turns an alloc specification
// into a running container and reports what happened to it.
//
// Everything here is per-alloc and stateless — the reconciler owns desired
// state, the Store owns durable state, and this package owns only the
// conversation with containerd (PRD §5.2.4).
//
// Three properties are not negotiable, and the spec builder enforces them
// rather than trusting callers:
//
//   - Hardening defaults (PRD §14, A05): every alloc drops ALL capabilities,
//     sets no-new-privileges, and gets its own PID, IPC, UTS, mount and cgroup
//     namespaces. A service may request capabilities back (PRD §6.2 R13), but
//     only from a permitted set that jobspec enforces — there is no `privileged`
//     escape hatch in the v1 spec, and the allowlist must not become one.
//   - Resource limits (PRD §6.2 R11, §5.2.11): no container ever runs
//     unlimited. Missing limits are a programming error, not a default.
//   - Network namespace ordering (M0 spike ②): the netns is created and wired
//     up *before* the task starts, and torn down *after* the task dies, so a
//     workload never runs without its network and CNI DEL always has a netns
//     to clean up.
package runtime

import (
	"context"
	"errors"
	"time"
)

// Errors callers branch on.
var (
	// ErrNotFound means no such alloc is known to containerd.
	ErrNotFound = errors.New("runtime: alloc not found")
	// ErrAlreadyExists means the alloc id is already in use.
	ErrAlreadyExists = errors.New("runtime: alloc already exists")
	// ErrInvalidSpec marks a spec this driver refuses to run.
	ErrInvalidSpec = errors.New("runtime: invalid alloc spec")
)

// AllocSpec is everything needed to run one alloc. The reconciler derives it
// from a validated job spec; the driver does not consult the Store or the job
// spec itself.
type AllocSpec struct {
	// ID is the alloc identifier and the containerd container id. It must be
	// at least 5 characters: the Cilium CNI plugin derives an interface name
	// from the first 5 characters of "<id>:<ifname>", and a shorter id leaks
	// the separator into an interface name (M0 spike ①).
	ID string
	// Project scopes the containerd namespace (one namespace per project,
	// PRD §5.2.4) and is part of the alloc's labels.
	Project string
	// Service is the service this alloc belongs to.
	Service string
	// Image is a pullable reference, ideally digest-pinned.
	Image string
	// Command overrides the image entrypoint when non-empty. Argument array,
	// never a shell string (PRD §6.2 R12).
	Command []string
	// Capabilities is the explicit allowlist on top of the drop-ALL default
	// (PRD §6.2 R13). The caller is responsible for having validated it: this
	// package grants exactly what it is given.
	Capabilities []string
	// Env is the resolved environment. Secret values are already materialised
	// by the caller; this package never resolves secret: references.
	Env map[string]string
	// Resources are mandatory limits (R11).
	Resources Resources
	// CgroupPath places the alloc under the workload parent, e.g.
	// "/kanea-workloads.slice/kanea-shop-web-1" (PRD §5.2.11).
	CgroupPath string
	// NetnsPath is a pre-created persistent netns the task joins. Empty means
	// the task gets its own fresh (unconfigured) network namespace, which is
	// only appropriate for tasks that must not reach the network at all.
	NetnsPath string
	// Mounts are volume mounts, already resolved to host paths.
	Mounts []Mount
	// ReadOnlyRootfs is the optional read-only root filesystem (PRD §14, A05).
	ReadOnlyRootfs bool
	// LogPath receives the task's stdout and stderr.
	LogPath string
}

// Resources are the per-alloc limits. Every field must be positive: PRD §6.2
// R11 fills defaults at spec-validation time, so a zero here means the caller
// skipped that step.
type Resources struct {
	// CPUMillis is the CPU quota in millicores (1000 = one core).
	CPUMillis int
	// MemoryBytes is the hard memory ceiling; a breach OOM-kills the alloc.
	MemoryBytes int64
	// PidsLimit caps process count, containing fork bombs.
	PidsLimit int64
}

// Mount is one bind mount into the alloc.
type Mount struct {
	Source      string
	Destination string
	ReadOnly    bool
}

// State is an alloc's lifecycle state as containerd reports it.
type State string

// Alloc states.
const (
	StateCreated State = "created"
	StateRunning State = "running"
	StateStopped State = "stopped"
	StatePaused  State = "paused"
	StateUnknown State = "unknown"
)

// Status is a point-in-time view of one alloc.
type Status struct {
	ID       string
	State    State
	PID      uint32
	ExitCode uint32
	ExitedAt time.Time
	// Image is the reference the alloc was created from.
	Image string
}

// Exit reports a task that has stopped. The reconciler's crash signal.
type Exit struct {
	ID       string
	ExitCode uint32
	ExitedAt time.Time
	// Err is set when the exit was observed through a failure rather than a
	// clean status (for example the event stream dropped).
	Err error
}

// Driver is the runtime surface the reconciler depends on. It is deliberately
// small: create, start, observe, stop, remove.
type Driver interface {
	// EnsureImage pulls the image unless it is already present, and returns
	// the resolved digest so a deploy can pin it (PRD §10.2).
	EnsureImage(ctx context.Context, project, ref string) (string, error)
	// Create builds the container and its task without starting it. The netns
	// referenced by the spec must already exist and be wired up.
	Create(ctx context.Context, spec AllocSpec) error
	// Start runs a created alloc.
	Start(ctx context.Context, project, id string) error
	// Status reports one alloc, or ErrNotFound.
	Status(ctx context.Context, project, id string) (Status, error)
	// List reports every alloc in a project's namespace.
	List(ctx context.Context, project string) ([]Status, error)
	// Stop sends SIGTERM, then SIGKILL after the grace period.
	Stop(ctx context.Context, project, id string, grace time.Duration) error
	// Remove deletes the task, container and snapshot. Idempotent.
	Remove(ctx context.Context, project, id string) error
	// Exec runs a command inside a running alloc and returns its exit code.
	// It backs the `exec` health check (R7): argument array, never a shell.
	Exec(ctx context.Context, project, id string, cmd []string, timeout time.Duration) (uint32, error)
	// Wait blocks until the alloc exits or the context is cancelled.
	Wait(ctx context.Context, project, id string) (Exit, error)
	// Exits streams task exits for a project — the reconciler's crash signal,
	// so it never has to poll. The channel closes when ctx is done.
	Exits(ctx context.Context, project string) (<-chan Exit, error)
	// Close releases the containerd connection.
	Close() error
}
