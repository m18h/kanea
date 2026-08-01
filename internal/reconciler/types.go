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
	"github.com/kanea-dev/kanea/internal/storage"
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
	// AllowFrom names the peers permitted to reach this service on top of the
	// project default (jobspec R14). It only ever adds reachability.
	AllowFrom []PeerRef
	// Expose is the north-south route this service publishes, or nil for a
	// service that is only reachable east-west (PRD §7.2).
	Expose *Expose
	// DependsOn names the services that must be healthy before this one starts
	// (jobspec R10). It already includes the implicit edges from ${service.*}
	// references, and is same-project in v1.
	DependsOn []string
	// Check is the service's health probe, if it declared one.
	Check *HealthCheck
	// ResolvConfPath is the host file bind-mounted at /etc/resolv.conf. It is
	// filled in by the reconciler rather than the spec: which resolver an alloc
	// talks to is a property of the node, not of the job.
	ResolvConfPath string `json:"-"`
	// ReadOnlyRootfs opts into a read-only root filesystem.
	ReadOnlyRootfs bool
	// Restart is the crash-restart policy.
	Restart RestartPolicy
}

// PeerRef names another service, as "<project>/<service>".
type PeerRef struct {
	Project string
	Service string
}

// Expose is a service's public ingress (PRD §7.2). It is what the agent turns
// into an edge route.
type Expose struct {
	// Domains are the hostnames declared in the spec. Empty means "generate
	// one": the auto-FQDN needs the server's base_domain, which is node
	// configuration a job spec does not have and should not carry.
	Domains []string
	// Port is the container port the edge sends requests to, picked by the R16
	// rule (named "http", or the only one declared).
	Port int
	// LetsEncrypt requests a certificate for the domains (PRD §7.3).
	LetsEncrypt bool
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
	// Resource is the resolved storage resource. A local volume leaves it
	// zero-valued; anything else has to be mounted before the alloc starts.
	Resource storage.Resource
	// MountPath is where it appears inside the container.
	MountPath string
	// ReadOnly mounts it read-only.
	ReadOnly bool
	// resolvedHostPath is the allowlist-checked directory for a host volume,
	// filled in by the reconciler just before the alloc is created. It is
	// unexported and untagged on purpose: it is a node-local fact, so it must
	// not travel through the Store or the API alongside the spec.
	resolvedHostPath string
}

// HostPath returns the resolved directory for a host volume, if one has been
// checked against the allowlist.
func (v Volume) HostPath() string { return v.resolvedHostPath }

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
	// Healthy reports the last health-check verdict. A service with no check
	// declared is healthy as soon as it runs, so this stays true.
	Healthy bool `json:"healthy"`
	// HealthFailures counts consecutive failed probes. It resets on a pass, so
	// a service that flaps below the threshold is never marked unhealthy.
	HealthFailures int `json:"health_failures,omitempty"`
	// LastProbeAt is when the check last ran, so the declared interval is
	// honoured rather than the reconcile interval.
	LastProbeAt time.Time `json:"last_probe_at,omitzero"`
	// HealthMessage explains the most recent failure, for `kanea ps`.
	HealthMessage string    `json:"health_message,omitempty"`
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
	// ActionWait records that an alloc cannot be created yet because a
	// dependency is not healthy. It has no side effect — it exists so that
	// waiting is visible in `kanea plan` and in the log, rather than an alloc
	// silently never appearing.
	ActionWait ActionKind = "wait"
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
