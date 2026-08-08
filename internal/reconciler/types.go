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

	"github.com/kanea-dev/kanea/internal/edge"
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
	// Scaling is the autoscaling policy, or nil for a service whose count is
	// whatever was declared (PRD §9.2).
	//
	// It lives on the desired state rather than in a table of its own because
	// it is part of what the operator declared, and because the evaluator has
	// to read it beside the count it is deciding about.
	Scaling *ScalingPolicy
	// ResolvConfPath is the host file bind-mounted at /etc/resolv.conf. It is
	// filled in by the reconciler rather than the spec: which resolver an alloc
	// talks to is a property of the node, not of the job.
	ResolvConfPath string `json:"-"`
	// ReadOnlyRootfs opts into a read-only root filesystem.
	ReadOnlyRootfs bool
	// Restart is the crash-restart policy.
	Restart RestartPolicy
	// Update governs how running allocs are replaced when this spec changes.
	Update UpdatePolicy
	// Generation is bumped to force a rolling restart of a service whose spec
	// has not otherwise changed (`kanea restart`, the MCP restart_service tool).
	//
	// It is part of the spec hash, which means a restart is not a second code
	// path: it is a spec change, it rolls through the same update policy, and it
	// converges the same way. The alternative — a route that reaches in and
	// kills containers — would be a second scheduler, which is the thing §9.2
	// says the autoscaler must not be either.
	//
	// It belongs to the running service rather than to the declared spec, so an
	// apply that does not mention it keeps whatever it was; see the API's apply
	// handler. Otherwise every `kanea run` after a restart would be a second
	// restart.
	Generation int `json:"generation,omitempty"`
}

// UpdatePolicy is the rolling-deploy policy (PRD §4.3, §6.1 `update` block).
//
// It answers a question the restart policy does not: a crashed alloc is
// replaced with an identical one, but an alloc whose *spec* changed has to be
// replaced with a different one, and doing that to every replica at once is an
// outage. The policy is what keeps a deploy from being a restart storm.
type UpdatePolicy struct {
	// Strategy is StrategyRolling (the default) or StrategyReplace.
	Strategy string
	// MaxParallel is how many of a service's allocs may be disrupted at once.
	// Zero means the default. Ignored by StrategyReplace, which means "all".
	MaxParallel int
	// MinHealthy is how long a replacement must have been up before the next
	// one is disturbed. Zero means the default.
	MinHealthy time.Duration
}

// Update strategies (PRD §4.3). Canary is v1.1+ and deliberately absent: there
// is no half-implemented third value for a spec to select.
const (
	// StrategyRolling replaces allocs a few at a time, health-gated.
	StrategyRolling = "rolling"
	// StrategyReplace takes them all down and brings them all back. It exists
	// for workloads that cannot run two versions at once — a singleton holding
	// an exclusive lock, a schema migration — and it is an outage by design.
	StrategyReplace = "replace"
)

// Update policy defaults (PRD §6.1 shows max_parallel = 1, min_healthy = 30s;
// the shown values are an example, these are what an omitted block means).
const (
	// DefaultMaxParallel is one at a time: the safe answer, and the only one
	// that is safe for every service without knowing anything about it.
	DefaultMaxParallel = 1
	// DefaultMinHealthy is how long a new alloc must have been running before
	// the next replacement starts. A container that is going to fail on startup
	// almost always does so in the first few seconds; rolling straight past it
	// would take a service down one replica at a time while every pass reported
	// progress.
	DefaultMinHealthy = 10 * time.Second
)

// maxParallel is how many allocs may be disrupted at once for a service of this
// size.
func (u UpdatePolicy) maxParallel(count int) int {
	if u.Strategy == StrategyReplace {
		return count
	}
	if u.MaxParallel <= 0 {
		return DefaultMaxParallel
	}
	if u.MaxParallel > count {
		return count
	}
	return u.MaxParallel
}

// minHealthy is the settling time before the next replacement.
func (u UpdatePolicy) minHealthy() time.Duration {
	if u.Strategy == StrategyReplace {
		// Nothing to settle between: they all went at once, on purpose.
		return 0
	}
	if u.MinHealthy <= 0 {
		return DefaultMinHealthy
	}
	return u.MinHealthy
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
	// IPRestriction, RateLimit and Headers are the edge middleware chain
	// (PRD §7.2.1), carried verbatim from the spec. They are validated at plan
	// time (R16) and again when the edge compiles them, so nothing here needs
	// to be interpreted on the way through.
	IPRestriction *edge.IPRestriction
	RateLimit     *edge.RateLimit
	Headers       *edge.Headers
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

// ScalingPolicy is a service's autoscaling configuration, as §6.1 declares it.
//
// A copy of the shape rather than internal/scaling's own type: this struct is
// serialised into the Store, so its JSON is a storage format that has to stay
// stable independently of what the evaluator finds convenient.
type ScalingPolicy struct {
	Min int `json:"min"`
	Max int `json:"max"`
	// Metrics are the targets to drive toward. An empty list means no
	// autoscaling, whatever min and max say.
	Metrics []ScalingMetric `json:"metrics,omitempty"`
	// Cooldown is the minimum time between changes, as a duration string.
	Cooldown string `json:"cooldown,omitempty"`
}

// ScalingMetric is one metric target.
type ScalingMetric struct {
	Name   string  `json:"name"`
	Target float64 `json:"target"`
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
	// SpecHash fingerprints the desired state this alloc was created from
	// (SpecHash). It is what makes a deploy visible to the planner: a container
	// carries the spec it was built with for as long as it lives, and comparing
	// that against what is declared now is the only way to tell a running alloc
	// that is current from one that is stale.
	//
	// Empty means "written before this field existed". It is adopted rather
	// than treated as a mismatch — an upgrade of kanead must not roll every
	// alloc on the node (Observe).
	SpecHash string `json:"spec_hash,omitempty"`
	// Restarts counts crash-restarts so far.
	Restarts int `json:"restarts"`
	// LastExitCode and LastExitAt describe the most recent exit.
	LastExitCode uint32    `json:"last_exit_code,omitempty"`
	LastExitAt   time.Time `json:"last_exit_at,omitzero"`
	// NextRestartAt is when the alloc may be restarted; zero means immediately.
	NextRestartAt time.Time `json:"next_restart_at,omitzero"`
	// Healthy reports the last health-check verdict.
	//
	// It is only ever written by a probe, so an alloc of a service that declares
	// no check has it false for its whole life. That is not "unhealthy" — it is
	// "nobody asked". Read it through Probed(), or with the same
	// `Check.configured()` guard the planner uses; testing the field on its own
	// reports every check-free service as broken.
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

// Probed reports whether a health check has ever run against this alloc, which
// is what makes Healthy meaningful.
func (a AllocRecord) Probed() bool { return !a.LastProbeAt.IsZero() }

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
	// ActionReplace rolls a healthy alloc onto a changed spec: the same remove,
	// create and start, for a different reason.
	//
	// A separate kind rather than a restart with a different Reason, because the
	// two differ in what they do to the alloc's history. A crash-restart spends
	// the restart budget — that budget exists to stop a crash loop. A deploy
	// does not: the operator changed something, and the new spec deserves its
	// own five attempts rather than inheriting the exhausted budget of the image
	// it replaced. Folding them together would mean a service that crash-looped
	// yesterday cannot be fixed by deploying the fix.
	ActionReplace ActionKind = "replace"
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
