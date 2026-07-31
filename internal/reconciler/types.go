// Package reconciler continuously converges actual state to desired state.
//
// It is a control loop, not a one-shot placer (PRD §4.3): every pass compares
// what the Store says should exist against what containerd reports does exist,
// and emits the actions that close the gap. That shape is what makes crash
// recovery, drift correction and scaling the same code path — a crashed alloc
// and a hand-deleted container are both just "desired but absent".
//
// The planner is a pure function (plan.go). Everything that talks to the world
// lives in the loop (reconcile.go), so the decision logic is testable without
// a daemon.
package reconciler

import (
	"strconv"
	"time"

	"github.com/kanea-dev/kanea/internal/runtime"
)

// Desired is one service's target state, derived from the job spec.
type Desired struct {
	Project string
	Service string
	// Count is how many allocs should be running.
	Count int
	// Image is the resolved (ideally digest-pinned) image reference.
	Image string
	// Command overrides the image entrypoint when non-empty.
	Command []string
	// Capabilities is the validated capability allowlist (jobspec R13).
	Capabilities []string
	// Env is the fully resolved environment for each alloc.
	Env map[string]string
	// Resources are the mandatory per-alloc limits.
	Resources runtime.Resources
	// Volumes are the service's declared volumes. Host paths are resolved
	// per-alloc at spec-build time, not here: the same declaration produces a
	// different directory for each alloc index.
	Volumes []Volume
	// Ports are the named container ports the service listens on (jobspec
	// `network { port "http" { container = 8080 } }`). A service with no ports
	// gets no frontend: there is nothing to load balance.
	Ports []Port
	// ResolvConfPath is the host file bind-mounted at /etc/resolv.conf. It is
	// filled in by the reconciler rather than the spec: which resolver an alloc
	// talks to is a property of the node, not of the job.
	ResolvConfPath string `json:"-"`
	// ReadOnlyRootfs opts into a read-only root filesystem.
	ReadOnlyRootfs bool
	// Restart is the crash-restart policy.
	Restart RestartPolicy
}

// Port is a named container port. The service frontend listens on the same
// number, so `port "http" { container = 8080 }` is reachable at <vip>:8080 —
// one number to reason about instead of two.
type Port struct {
	Name      string
	Container int
}

// RestartPolicy bounds how often a crashed alloc is restarted (PRD §6.1
// `restart` block). Backoff is a schedule, not a single delay: a service that
// crashes on startup should not be restarted in a tight loop.
type RestartPolicy struct {
	// Attempts is the maximum number of restarts before the alloc is left
	// stopped and marked failed. Zero means the default.
	Attempts int
	// Backoff is the delay schedule; the last entry repeats. Empty means the
	// default schedule.
	Backoff []time.Duration
}

// Restart policy defaults (PRD §6.1 shows attempts = 5, backoff 10s,30s,1m,5m).
var (
	// DefaultRestartAttempts bounds restart storms.
	DefaultRestartAttempts = 5
	// DefaultRestartBackoff is the escalating delay schedule.
	DefaultRestartBackoff = []time.Duration{
		10 * time.Second, 30 * time.Second, time.Minute, 5 * time.Minute,
	}
)

// attempts returns the effective attempt limit.
func (p RestartPolicy) attempts() int {
	if p.Attempts <= 0 {
		return DefaultRestartAttempts
	}
	return p.Attempts
}

// delayFor returns the backoff before restart number n (1-based). The last
// entry repeats, so a chronically failing alloc settles at the longest delay
// rather than falling off the end of the schedule.
func (p RestartPolicy) delayFor(n int) time.Duration {
	schedule := p.Backoff
	if len(schedule) == 0 {
		schedule = DefaultRestartBackoff
	}
	if n < 1 {
		n = 1
	}
	if n > len(schedule) {
		n = len(schedule)
	}
	return schedule[n-1]
}

// Volume is one local volume mounted into every alloc of a service.
//
// M1 implements local storage only, and gives each alloc its own directory.
// Sharing one directory between allocs is what PRD §8 calls the "shared" mode;
// it needs a spec field to opt into, and per-alloc is the safe default — two
// database allocs writing the same data directory would corrupt it.
type Volume struct {
	// Name is the volume's name within the service.
	Name string
	// Storage is the storage resource it comes from.
	Storage string
	// MountPath is where it appears inside the container.
	MountPath string
	// ReadOnly mounts it read-only.
	ReadOnly bool
}

// AllocState is the reconciler's own view of an alloc, independent of what
// containerd currently reports.
type AllocState string

// Alloc states.
const (
	// AllocPending means the alloc should run but has not been created yet.
	AllocPending AllocState = "pending"
	// AllocRunning means the alloc should be running.
	AllocRunning AllocState = "running"
	// AllocBackoff means the alloc crashed and is waiting out its restart delay.
	AllocBackoff AllocState = "backoff"
	// AllocFailed means the alloc exhausted its restart attempts. The
	// reconciler stops trying; a human or a new deploy has to intervene.
	AllocFailed AllocState = "failed"
	// AllocStopped means the alloc was intentionally stopped.
	AllocStopped AllocState = "stopped"
)

// AllocRecord is the durable per-alloc state, stored under store.KindAlloc.
// It outlives kanead: restart bookkeeping must survive a control-plane restart,
// or "attempts = 5" would reset every time kanead was upgraded.
type AllocRecord struct {
	ID      string     `json:"id"`
	Project string     `json:"project"`
	Service string     `json:"service"`
	Index   int        `json:"index"`
	Image   string     `json:"image"`
	State   AllocState `json:"state"`
	// Restarts counts crash-restarts so far.
	Restarts int `json:"restarts"`
	// LastExitCode and LastExitAt describe the most recent exit.
	LastExitCode uint32    `json:"last_exit_code,omitempty"`
	LastExitAt   time.Time `json:"last_exit_at,omitzero"`
	// NextRestartAt is when the alloc may be restarted; zero means immediately.
	NextRestartAt time.Time `json:"next_restart_at,omitzero"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Key is the alloc's Store key: project/service/index, which sorts naturally
// and lets a service's allocs be listed by prefix.
func (a AllocRecord) Key() string {
	return AllocKey(a.Project, a.Service, a.Index)
}

// ActionKind is what the planner decided to do about one alloc.
type ActionKind string

// Actions the planner can emit.
const (
	// ActionCreate creates and starts a missing alloc.
	ActionCreate ActionKind = "create"
	// ActionStart starts an alloc that exists but is not running.
	ActionStart ActionKind = "start"
	// ActionRestart replaces a crashed alloc: remove, then create and start.
	ActionRestart ActionKind = "restart"
	// ActionRemove tears an alloc down completely.
	ActionRemove ActionKind = "remove"
)

// Action is one unit of convergence work.
type Action struct {
	Kind    ActionKind
	AllocID string
	Project string
	Service string
	Index   int
	// Reason explains why the planner emitted this action. It goes into events
	// and logs; "why did my container restart" must always be answerable.
	Reason string
}

// AllocKey builds the Store key for an alloc.
func AllocKey(project, service string, index int) string {
	return project + "/" + service + "/" + strconv.Itoa(index)
}

// AllocID builds the containerd container id and netns name for an alloc.
// Project and service are DNS-1123 labels (jobspec R1), so the result is safe
// for both — and always longer than the CNI plugin's 5-character floor.
func AllocID(project, service string, index int) string {
	return project + "-" + service + "-" + strconv.Itoa(index)
}

// ServicePrefix is the Store key prefix for one service's allocs.
func ServicePrefix(project, service string) string {
	return project + "/" + service + "/"
}
