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
	"io"
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
	// ErrNoExec means the alloc's runtime has no exec primitive. The wasmtime
	// shim is one: a wasm sandbox holds exactly one instance, so `kanea exec`
	// against a function fails here with the reason rather than surfacing a
	// shim error nobody can act on (PRD §6.2 R25).
	ErrNoExec = errors.New("runtime: this alloc's runtime does not support exec")
)

// RuntimeWasmtime is the containerd runtime name for the wasmtime runwasi shim
// (PRD v1.39, §6.2 R25). containerd resolves it to a binary named
// containerd-shim-wasmtime-v1 on its own PATH — which is why the generated
// containerd unit sets Environment=PATH (internal/provision/units.go).
const RuntimeWasmtime = "io.containerd.wasmtime.v1"

// AllocSpec is everything needed to run one alloc. The reconciler derives it
// from a validated job spec; the driver does not consult the Store or the job
// spec itself.
type AllocSpec struct {
	// ID is the alloc identifier and the containerd container id. It must be
	// at least MinAllocIDLength characters: the datapath derives a host veth
	// name from a hash of the id (internal/datapath), and the floor keeps ids
	// long enough to stay collision-safe and legible.
	ID string
	// Project scopes the containerd namespace (one namespace per project,
	// PRD §5.2.4) and is part of the alloc's labels.
	Project string
	// Service is the service this alloc belongs to.
	Service string
	// Image is a pullable reference, ideally digest-pinned.
	Image string
	// Runtime selects the containerd runtime. Empty means containerd's
	// default (the runc shim) — the meaning every alloc had before v1.39, so
	// empty must never be spelled out. The only other accepted value is
	// RuntimeWasmtime: the set is closed here, not passed through, because a
	// runtime name is a binary containerd will execute as root.
	Runtime string
	// Command overrides the image entrypoint when non-empty. Argument array,
	// never a shell string (PRD §6.2 R12).
	Command []string
	// Capabilities is the *effective* set, already projected by the caller
	// (PRD §6.2 R13): the reconciler resolves the baseline, the union with a
	// service's declared grants, and the "none" opt-out before anything
	// reaches this package. This package grants exactly what it is given and
	// defaults nothing — every entry must be a real CAP_* name (Validate).
	Capabilities []string
	// Env is the resolved environment. Secret values are already materialised
	// by the caller; this package never resolves secret: references.
	Env map[string]string
	// User is the numeric identity the workload runs as (PRD §6.2 R23). Nil
	// leaves the image's own USER directive in force, which is what every spec
	// written before R23 means — so a nil here must never be read as root.
	User *User
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
	// Devices are host devices the operator granted this service (PRD §6.2
	// R17), already resolved. This package neither knows nor asks which grant
	// they came from: by the time a device reaches here the decision has been
	// made, and making it again with less context could only make it wrong.
	Devices []Device
	// ReadOnlyRootfs is the optional read-only root filesystem (PRD §14, A05).
	ReadOnlyRootfs bool
	// LogPath receives the task's stdout and stderr.
	LogPath string
}

// User is the uid/gid an alloc's process runs as (PRD §6.2 R23).
//
// Numeric, and resolved by the caller. This package will not look a name up:
// doing so means reading /etc/passwd out of the container's rootfs, which lets
// a container-controlled file decide which uid the control plane runs a process
// as. It is also why oci.WithUser and oci.WithUserID are not used to apply this
// — both consult the rootfs even when handed a number.
type User struct {
	UID uint32
	GID uint32
	// AdditionalGIDs are supplementary groups, for a workload that has to reach
	// a volume owned by a group it is not the primary member of.
	AdditionalGIDs []uint32
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
	// Options are extra mount options on top of the rbind and rw/ro this
	// package always sets. A volume needs none; a bind of something that is not
	// a directory of the workload's own data generally wants nosuid, noexec and
	// nodev, and the caller that knows which is which passes them.
	Options []string
}

// Device is one host device node to expose to the alloc.
//
// Major, minor and file mode are read from the node itself when the spec is
// built rather than carried here: a second copy of a device's identity is a
// copy that can disagree with the device.
type Device struct {
	// Path is the host device node, and where it appears in the container.
	Path string
	// Perms is the cgroup device permission string ("rw", "rwm"). Without a
	// matching cgroup rule the node is visible and cannot be opened, because
	// containerd's default spec denies every device and this package only ever
	// adds to that list.
	Perms string
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
	// OOMKilled reports that the kernel OOM-killed a process in this alloc's
	// cgroup (PRD v1.68, §17). Read from `memory.events`, never inferred from
	// exit 137 — `kanea stop` produces 137 too, and calling that a memory
	// problem would be worse than saying nothing.
	//
	// False is not "not OOM-killed": it is also what an unreadable or
	// already-reaped cgroup gives, which is why OOMKnown exists.
	OOMKilled bool
	// OOMKnown reports that the cgroup was readable, so OOMKilled means
	// something. §9.2's "no data is never zero", applied to a cause.
	OOMKnown bool
	// MemoryLimit is the alloc's own `memory.max` in bytes, or 0 when it
	// declared none (unbounded, R11 v1.58). It is what separates "exceeded its
	// own limit" from "hit the node's collective ceiling" (§5.2.11).
	MemoryLimit uint64
}

// ExecOptions describes an attached exec.
//
// Separate from the health check's signature because the two differ in every
// respect that matters: one discards output and has a deadline, the other
// carries a person's terminal and lasts as long as they keep typing.
type ExecOptions struct {
	// Command is an argument array, executed directly. Never a shell string —
	// that is the same command-injection rule the health check follows (§14
	// A03), and it matters more here, where the input reaches a real shell only
	// because the operator asked for one by name.
	Command []string
	// TTY allocates a pseudo-terminal, which merges stdout and stderr and lets
	// the remote process behave interactively.
	TTY bool
	// Stdin is closed by the caller to signal EOF. Nil means no stdin.
	Stdin io.Reader
	// Stdout and Stderr receive output. With TTY set, everything arrives on
	// Stdout, because that is what a pseudo-terminal does.
	Stdout io.Writer
	Stderr io.Writer
	// Resize delivers terminal size changes. Nil means the size never changes,
	// which is what a non-interactive exec wants.
	Resize <-chan TerminalSize
	// User overrides the container's own user. Empty keeps it.
	User string
}

// TerminalSize is a pseudo-terminal's dimensions.
type TerminalSize struct {
	Width  uint16
	Height uint16
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
	EnsureImage(ctx context.Context, img ImageRef) (string, error)
	// ResolveRemote reports what a reference points at in its registry right
	// now, without pulling. EnsureImage cannot answer this: once an image is
	// local it returns the local digest, which is the one already running
	// (PRD §6.2 R19).
	ResolveRemote(ctx context.Context, img ImageRef) (string, error)
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
	// ExecStream runs a command with its streams attached — the debug shell of
	// PRD §16.2, as opposed to the health check above, which discards output.
	ExecStream(ctx context.Context, project, id string, opts ExecOptions) (uint32, error)
	// Wait blocks until the alloc exits or the context is cancelled.
	Wait(ctx context.Context, project, id string) (Exit, error)
	// Exits streams task exits for a project — the reconciler's crash signal,
	// so it never has to poll. The channel closes when ctx is done.
	Exits(ctx context.Context, project string) (<-chan Exit, error)
	// Close releases the containerd connection.
	Close() error
}
