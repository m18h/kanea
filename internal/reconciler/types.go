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

	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/storage"
)

// Desired is one service's target state, derived from the job spec.
type Desired struct {
	Project string
	Service string
	// Count is how many allocs should be running.
	Count int
	// Image is the resolved (ideally digest-pinned) image reference.
	Image string
	// PinnedImage is what actually runs when auto-update is following Image's
	// tag (R19) — a complete digest-pinned reference, not a bare digest, so
	// nothing downstream has to reassemble one. It sits beside Image rather
	// than replacing it because the tag is what the next poll re-resolves:
	// pinning over it would destroy the thing the feature reads. Empty means
	// "run Image as written", which is every service that has not turned
	// auto-update on.
	//
	// It is server-owned, like Generation: an apply must carry it over, or
	// every `kanea apply` would unpin the service and redeploy it.
	PinnedImage string `json:"pinned_image,omitempty"`
	// RollbackImage is what was running before the current auto-update, kept so
	// a bad image can be reverted to something known good. It is cleared once
	// the update converges.
	RollbackImage string `json:"rollback_image,omitempty"`
	// ImageCheckedAt is when the registry was last polled, so the declared
	// interval survives a daemon restart rather than resetting to "now" and
	// hammering someone else's registry after a crash loop.
	ImageCheckedAt time.Time `json:"image_checked_at,omitzero"`
	// ImageUpdatedAt is when the current digest was pinned. It is the clock the
	// revert deadline runs against.
	ImageUpdatedAt time.Time `json:"image_updated_at,omitzero"`
	// RegistryAuthRef is a `secret:` reference to a docker config.json used to
	// pull the image. It is a reference, never a value: a resolved credential
	// in the Store would be a secret at rest in the one place §15.3 ships off
	// the node.
	RegistryAuthRef string `json:"registry_auth_ref,omitempty"`
	// Command overrides the image entrypoint when non-empty.
	Command []string
	// Capabilities is the validated *declared* list (jobspec R13) — grants on
	// top of the baseline, or CapabilityNone to start from nothing. The
	// baseline itself is never written here: it is applied at projection time
	// (effectiveCapabilities), because this field is SpecHash material and a
	// default that entered the record would re-hash — and roll — every
	// capability-less service at upgrade (the R23 lesson).
	Capabilities []string
	// Env is the fully resolved environment for each alloc.
	Env map[string]string
	// User is the numeric identity the workload runs as (jobspec R23). Nil
	// means the image's own USER stands — the pre-R23 meaning of every record
	// already in a Store, which is why it is a pointer and why SpecHash omits
	// it when unset.
	User *runtime.User `json:"user,omitempty"`
	// Resources are the mandatory per-alloc limits.
	Resources runtime.Resources
	// Volumes are the service's declared volumes. Host paths are resolved
	// per-alloc at spec-build time, not here: the same declaration produces a
	// different directory for each alloc index.
	Volumes []Volume
	// Devices and Sockets are the passthrough grants the service asked for
	// (jobspec R17, R18). They carry the *grant name* and never a host path:
	// the node resolves the name locally at spec-build time, so nothing here
	// travels through the Store or the API as a path (§18 rule 5).
	Devices []DeviceRequest
	Sockets []SocketRequest
	// Ports are the named container ports the service listens on (jobspec
	// `network { port "http" { container = 8080 } }`). A service with no ports
	// gets no frontend: there is nothing to load balance.
	Ports []Port
	// AllowFrom names the peers permitted to reach this service on top of the
	// project default (jobspec R14). It only ever adds reachability.
	AllowFrom []PeerRef
	// Expose is the north-south route this service publishes, or nil for a
	// service that is only reachable east-west (PRD §7.2). It is the FIRST
	// route: a service may publish several (v1.50), and this field staying the
	// first is what keeps every pre-v1.50 record and reader meaning what it
	// meant.
	Expose *Expose
	// ExtraExposes are the routes after the first (PRD v1.50), additive beside
	// Expose rather than a list replacing it: a single-route record must
	// serialize byte-identically (the R23 lesson). Read through AllExposes,
	// never directly. NOT SpecHash material, like Expose.
	ExtraExposes []Expose `json:"extra_exposes,omitempty"`
	// Publish are the node ports the edge binds for this service (PRD §7.2.2,
	// R21). A service can be published and not exposed: Jellyfin on :8096 with
	// no domain and no certificate is the case the feature exists for.
	//
	// Deliberately *not* in SpecHash's material, like Expose. Nothing about a
	// node port is baked into a container at creation — the container ports
	// already are — so hashing it would roll every alloc of a service to fix a
	// typo in a CIDR.
	Publish []PublishedPort
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
	// Runtime selects the containerd runtime (PRD v1.39, §6.2 R25). Empty
	// means the runc default — the meaning of every record already in a
	// Store, which is why it is omitempty here AND in the SpecHash material:
	// a field that serialised for existing services would change every hash
	// on the node, and upgrading kanead would roll every container on it
	// (the R23 lesson).
	Runtime string `json:"runtime,omitempty"`
	// Function marks a desired record lowered from a `function` block and
	// carries its triggers (R25/R26). Nil for every ordinary service — it is
	// the marker `GET /v1/functions` filters on and the Services list filters
	// out.
	//
	// Deliberately NOT in the SpecHash material: nothing about a trigger is
	// baked into a container at creation (the invokers read it live, like
	// Publish's listeners), so hashing it would roll an alloc to change a
	// cron schedule.
	Function *FunctionMeta `json:"function,omitempty"`
}

// FunctionMeta is what makes a lowered function more than a service: its
// triggers, read live by the invokers (internal/functions), and the http flag
// the API uses to describe the route without re-deriving it from Expose.
type FunctionMeta struct {
	// HTTP records that a `trigger "http"` was declared; the detail lives on
	// Expose, exactly as it does for a service.
	HTTP bool `json:"http,omitempty"`
	// Events are the event triggers, patterns already validated against the
	// notification vocabulary (R26).
	Events []EventTrigger `json:"events,omitempty"`
	// Crons are the cron triggers, schedules already validated (R26).
	Crons []CronTrigger `json:"crons,omitempty"`
	// SigningRef names the secret the invoker MACs event/cron POSTs with
	// (R26, v1.40). A reference, never a value; the invoker resolves it per
	// delivery and a reference that stops resolving fails the invocation
	// rather than sending unsigned.
	SigningRef string `json:"signing_ref,omitempty"`
}

// AuthPolicy is R27's auth block as stored desired state: references and
// claim requirements, never material.
type AuthPolicy struct {
	BasicRef  string         `json:"basic_ref,omitempty"`
	BearerRef string         `json:"bearer_ref,omitempty"`
	JWT       *JWTAuthPolicy `json:"jwt,omitempty"`
}

// JWTAuthPolicy mirrors the spec's jwt block.
type JWTAuthPolicy struct {
	Algorithm    string `json:"algorithm"`
	SecretRef    string `json:"secret_ref,omitempty"`
	PublicKeyRef string `json:"public_key_ref,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	Audience     string `json:"audience,omitempty"`
}

// EventTrigger fires a POST to the function when a matching event occurs.
type EventTrigger struct {
	// On are glob patterns over the notification vocabulary (R26). Never
	// matches function.* — refused at parse and skipped at match time.
	On []string `json:"on"`
	// Path is the request path, normalized absolute; empty means "/".
	Path string `json:"path,omitempty"`
}

// CronTrigger fires a POST to the function on a schedule.
type CronTrigger struct {
	// Schedule is a five-field cron expression, evaluated in UTC (R26).
	Schedule string `json:"schedule"`
	// Path is the request path, normalized absolute; empty means "/".
	Path string `json:"path,omitempty"`
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
	// Auto turns on image auto-update (R19). Off by default: following a
	// moving tag is the one thing §14 A08 otherwise refuses, so it is a
	// decision a service makes explicitly.
	Auto bool `json:"auto,omitempty"`
	// Interval is how often the registry is polled. Zero means the default.
	Interval time.Duration `json:"interval,omitempty"`
	// Deadline is how long a new digest has to converge before it is reverted.
	// Zero means the default.
	Deadline time.Duration `json:"deadline,omitempty"`
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
	// DefaultUpdateInterval is how often an auto-updating service re-resolves
	// its tag (R19). Six hours because a poll is a request to somebody else's
	// registry, and nobody deploying by tag needs the answer sooner.
	DefaultUpdateInterval = 6 * time.Hour
	// MinUpdateInterval is the floor. A tighter loop is a rate-limit problem
	// for the registry and a rounding error for the operator.
	MinUpdateInterval = 5 * time.Minute
	// DefaultUpdateDeadline is how long a new digest has to converge before it
	// is reverted.
	DefaultUpdateDeadline = 10 * time.Minute
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

// PollInterval is how often this service's tag is re-resolved (R19).
func (u UpdatePolicy) PollInterval() time.Duration {
	if u.Interval <= 0 {
		return DefaultUpdateInterval
	}
	return u.Interval
}

// RevertDeadline is how long a newly pinned digest has to converge.
func (u UpdatePolicy) RevertDeadline() time.Duration {
	if u.Deadline <= 0 {
		return DefaultUpdateDeadline
	}
	return u.Deadline
}

// RunImage is the reference an alloc is actually created from.
//
// The declared image for everything that has not turned auto-update on; the
// pinned digest for everything that has. Reading Image directly would start a
// service on whatever its tag points at *now* instead of the digest the
// updater chose, which would make a deploy non-atomic across allocs.
func (d Desired) RunImage() string {
	if d.PinnedImage != "" {
		return d.PinnedImage
	}
	return d.Image
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
	// TLSMode is the certificate source this service asked for (PRD §6.2 R20),
	// or "" for "whatever this node defaults to".
	//
	// Resolved on the node by TLSMode, not here and not in the CLI: toDesired
	// runs wherever the spec was written, so baking a node's --tls-default into
	// a stored record would make one spec mean different things on two machines.
	TLSMode string
	// TLSName selects one of the certificates the operator configured on this
	// node. Meaningful only when TLSMode is "provided" (R20).
	TLSName string
	// LetsEncrypt is the pre-v1.33 spelling, read but never written.
	//
	// It is kept so records written by an older CLI keep meaning what they
	// meant — an empty TLSMode with this set resolves to "acme" — which is why
	// this change needs no schema migration (§15.4).
	//
	// Deprecated: use TLSMode.
	LetsEncrypt bool
	// Auth is R27's request authentication (v1.40), carried as the references
	// the spec declared. The reconciler's projection resolves them into the
	// verifier material the edge is handed; nothing here is a credential.
	// Deliberately NOT in the SpecHash material, like the middleware: nothing
	// about it is baked into a container.
	Auth *AuthPolicy `json:"auth,omitempty"`
	// IPRestriction, RateLimit and Headers are the edge middleware chain
	// (PRD §7.2.1), carried verbatim from the spec. They are validated at plan
	// time (R16) and again when the edge compiles them, so nothing here needs
	// to be interpreted on the way through.
	IPRestriction *edge.IPRestriction
	RateLimit     *edge.RateLimit
	Headers       *edge.Headers
	// Protocol is R28's upstream-transport marker (v1.41): "" for HTTP/1.1,
	// "grpc" for h2c. Like everything else on Expose it is NOT SpecHash
	// material — nothing about the upstream dial is baked into a container,
	// so changing it republishes routes and never rolls an alloc.
	Protocol string `json:"protocol,omitempty"`
}

// AllExposes returns every route of the service in order, the first block
// first — nil for an unexposed service. The one way to read routes (v1.50):
// reading Expose alone silently drops the extras.
func (d *Desired) AllExposes() []*Expose {
	if d.Expose == nil {
		return nil
	}
	out := make([]*Expose, 0, 1+len(d.ExtraExposes))
	out = append(out, d.Expose)
	for i := range d.ExtraExposes {
		out = append(out, &d.ExtraExposes[i])
	}
	return out
}

// Port is a named container port. The service frontend listens on the same
// number, so `port "http" { container = 8080 }` is reachable at <vip>:8080 —
// one number to reason about instead of two.
type Port struct {
	Name      string
	Container int
	// Protocol is "" (TCP, the default) or "udp" (v1.42). A declared "tcp"
	// normalizes to "" before it is stored. The tag's omitempty is
	// load-bearing exactly as Desired.User's is: Ports are SpecHash material,
	// and every pre-v1.42 record must hash with the field absent — a hash
	// that moved on upgrade would roll every service on the node. Flipping a
	// port's protocol *does* roll the alloc, which is right: what the process
	// binds inside the container is baked into it.
	Protocol string `json:"Protocol,omitempty"`
}

// PortProtocolUDP marks a datagram port (v1.42). A udp port never enters the
// VIP's port set — it is reachable only through a published udp listener.
const PortProtocolUDP = "udp"

// IsUDP reports whether this is a datagram port.
func (p Port) IsUDP() bool { return p.Protocol == PortProtocolUDP }

// PublishedPort is one node port bound on this service's behalf (R21).
//
// Port names a declared container port rather than giving a number, so a
// published port can never reach somewhere the service did not say it listens.
type PublishedPort struct {
	// Port is the name of the `network { port }` this forwards to.
	Port string
	// Host is the node port to bind.
	Host int
	// Mode is "http" or "tcp"; empty means http.
	Mode string
	// MaxConns bounds live connections. TCP only.
	MaxConns int

	IPRestriction *edge.IPRestriction
	// RateLimit and Headers are http only — a tcp listener refuses what it
	// cannot enforce rather than dropping it.
	RateLimit *edge.RateLimit
	Headers   *edge.Headers
}

// portNumber resolves a declared port name to its container port, or 0.
func (d Desired) portNumber(name string) int {
	for _, p := range d.Ports {
		if p.Name == name {
			return p.Container
		}
	}
	return 0
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
	// UID, GID and Mode are the volume's ownership (jobspec R24), already
	// resolved against the task's user. All nil means "leave it alone", which
	// is every volume of every spec written before R24.
	//
	// The json tags matter and the pointers matter. Volume is hashed whole by
	// SpecHash, the fields above it carry no tags and marshal under their Go
	// names, and these three are omitted entirely when nil — so a record that
	// predates this feature hashes exactly as it did before, and upgrading
	// kanead does not roll every alloc on the node.
	UID  *uint32 `json:"uid,omitempty"`
	GID  *uint32 `json:"gid,omitempty"`
	Mode *uint32 `json:"mode,omitempty"`
	// resolvedHostPath is the allowlist-checked directory for a host volume,
	// filled in by the reconciler just before the alloc is created. It is
	// unexported and untagged on purpose: it is a node-local fact, so it must
	// not travel through the Store or the API alongside the spec.
	resolvedHostPath string
}

// HostPath returns the resolved directory for a host volume, if one has been
// checked against the allowlist.
func (v Volume) HostPath() string { return v.resolvedHostPath }

// Owned reports whether ownership is to be applied to this volume.
func (v Volume) Owned() bool { return v.UID != nil || v.GID != nil || v.Mode != nil }

// DeviceRequest asks for a host device by grant name (jobspec R17).
//
// The resolved nodes follow the Volume.resolvedHostPath precedent: unexported
// and untagged, because which device a grant means is a node-local fact. Two
// nodes can define the same grant over different hardware, and the spec that
// names it is the same spec on both.
type DeviceRequest struct {
	// Name is the block's label in the spec, for diagnostics.
	Name string
	// Grant names an entry in the node's passthrough config.
	Grant string
	// resolved is filled in by the reconciler just before the alloc is created.
	resolved []runtime.Device
}

// Devices returns the resolved device nodes, if the grant has been checked.
func (d DeviceRequest) Devices() []runtime.Device { return d.resolved }

// SocketRequest asks for a host unix socket by grant name (jobspec R18).
//
// MountPath is part of the spec because the tools this serves expect a
// particular path inside the container; the socket behind it is the node's.
type SocketRequest struct {
	Name      string
	Grant     string
	MountPath string
	ReadOnly  bool
	// resolvedHostPath is the node's socket, filled in by the reconciler. See
	// Volume.resolvedHostPath for why it does not travel with the spec.
	resolvedHostPath string
}

// HostPath returns the resolved socket, if the grant has been checked.
func (s SocketRequest) HostPath() string { return s.resolvedHostPath }

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
