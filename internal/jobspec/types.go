// Package jobspec parses and validates Kanea job specifications (HCL v2).
//
// The schema and its rules R1–R11 are PRD §6. Two properties drive the design:
//
//   - Every rejection carries file/line/column diagnostics (R1). A spec error is
//     a user error, and "invalid spec" without a position is useless.
//   - Validation runs against the whole applied set, not one file: service
//     references and dependencies are resolved across files, so declaration
//     order never matters (R9).
//
// Parsing is deliberately two-pass. The first pass reads structure only —
// service names, ports — because the second pass needs them to evaluate
// ${service.<name>.host} references into real DNS names. Expressions are
// collected before evaluation so the reference graph survives (R9, R10).
package jobspec

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// Spec is one parsed, validated applied set: everything `kanea apply` was given.
type Spec struct {
	// SpecVersion gates future schema revisions (R6, PRD §15.4).
	SpecVersion int
	Projects    []*Project
	Services    []*Service
	// Storages are the named storage resources services mount (PRD §8).
	Storages []*Storage
	// BaseDomain is the server's `base_domain`, carried from Options so that
	// validation can generate the auto-FQDNs of §7.2 and check them for
	// collisions (R16). Empty when the spec was parsed without server config.
	BaseDomain string
}

// Storage is a named storage resource (PRD §8). Services reference it by name
// from their volume blocks; credentials always come from the secret store.
type Storage struct {
	Name string
	// Type is local | s3 | nfs | smb.
	Type string
	// Local has no fields: the path is derived under data_dir/volumes.
	//
	// S3:
	Bucket   string
	Endpoint string
	AuthRef  string
	// Mode selects the S3 driver: "ro" (mountpoint-s3, the default) or "rw"
	// (s3fs) — M0 spike ③.
	Mode string
	// NFS and SMB:
	Server  string
	Export  string
	Share   string
	Options string
	// Host: the absolute directory to mount. Whether it *may* be mounted is a
	// server-config decision, not a job-spec one (R15).
	Path string
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// Storage driver types (PRD §8).
const (
	StorageLocal = "local"
	StorageS3    = "s3"
	StorageNFS   = "nfs"
	StorageSMB   = "smb"
	// StorageHost mounts a directory the operator already owns. It does nothing
	// unless an operator has allowlisted its parent (R15, §15.1).
	StorageHost = "host"
)

// StorageByName returns the named storage resource, or nil.
func (s *Spec) StorageByName(name string) *Storage {
	for _, st := range s.Storages {
		if st.Name == name {
			return st
		}
	}
	return nil
}

// Project groups services; it is the isolation, discovery and notification
// boundary (PRD §4.1).
type Project struct {
	Name          string
	Description   string
	Git           *Git
	Notifications *Notifications
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// Git is the optional GitOps source for a project (PRD §10.1).
type Git struct {
	URL    string
	Branch string
	Path   string
	// AuthRef is a `secret:` reference to a deploy key or token for cloning.
	AuthRef string
	// WebhookSecretRef is the shared secret push webhooks are authenticated
	// with. It is deliberately separate from AuthRef: one lets Kanea read the
	// repository, the other lets the repository tell Kanea something. Reusing
	// a deploy key as a webhook secret would put a credential that can read
	// source into a header on every push.
	WebhookSecretRef string
	// PollInterval overrides the default sync cadence, as a duration string.
	PollInterval string
	// RequireApproval holds a synced change instead of applying it (§10.1).
	RequireApproval bool
}

// Notifications configures per-project channels and the events they fire on.
type Notifications struct {
	Telegram *TelegramChannel
	Webhook  *WebhookChannel
	Slack    *SlackChannel
	Ntfy     *NtfyChannel
	SMTP     *SMTPChannel
	// On is the event filter (§11): glob patterns like "deploy.*".
	On []string
	// Severity is a floor beneath which nothing is sent, whatever On says.
	Severity string
	DefRange hcl.Range
}

// TelegramChannel targets a chat; the bot token comes from the secret store.
type TelegramChannel struct {
	ChatID   string
	TokenRef string
}

// WebhookChannel posts a signed JSON payload to a URL.
type WebhookChannel struct {
	URL string
	// SecretRef signs the payload with HMAC-SHA256.
	SecretRef string
}

// SlackChannel posts to a Slack or Discord incoming webhook.
//
// The URL is a reference, not a literal, and there is no field to inline one
// into: an incoming-webhook URL is a credential in path form (R3).
type SlackChannel struct {
	URLRef string
}

// NtfyChannel publishes to an ntfy topic.
type NtfyChannel struct {
	URL      string
	TokenRef string
}

// SMTPChannel sends email.
type SMTPChannel struct {
	Host        string
	Port        string
	From        string
	To          []string
	Username    string
	PasswordRef string
}

// Service is one deployable unit: N identical allocs of a task.
type Service struct {
	Name        string
	Project     string
	Description string
	// Count is the desired alloc count. Defaults to 1.
	Count int
	Build *Build
	Task  *Task
	// Network declares the container ports other services and the edge address.
	Network *Network
	// Expose turns on north-south ingress through kanea-edge (PRD §7.2).
	Expose       *Expose
	HealthChecks []*HealthCheck
	Volumes      []*Volume
	Scaling      *Scaling
	Update       *Update
	Restart      *Restart
	// DependsOn declares explicit start ordering (R10). Implicit edges from
	// ${service.*} references are merged into Dependencies during validation.
	DependsOn []string
	// Dependencies is the resolved edge set: DependsOn plus every service
	// referenced from env (R9). Populated by validation, sorted, deduplicated.
	Dependencies []string
	// Refs records every ${service.*} reference found in this service, for
	// diagnostics and for the reconciler's dependency-ordered starts.
	Refs []ServiceRef
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// Build produces the service's image from source (PRD §10.2).
type Build struct {
	Context string
	// Dockerfile overrides recipe detection. Empty means auto-detect:
	// Containerfile first, then Dockerfile (M0 spike ④).
	Dockerfile string
	Target     string
	Tag        string
	CacheRepo  string
	// RegistryAuthRef names the secret holding a docker config.json used to
	// push the built image. It is scoped by R5 like every other reference, and
	// it is materialised as a file for the duration of the build — never put in
	// the build context, and never a --build-arg (build args survive in image
	// history, §10.2).
	RegistryAuthRef string
	DefRange        hcl.Range
}

// Task is the container that runs. v1 allows exactly one per service.
type Task struct {
	Name  string
	Image string
	// Command overrides the image entrypoint (R12). Argument array, never a
	// shell string.
	Command []string
	// Capabilities is the explicit allowlist on top of the drop-ALL default
	// (R13). Only PermittedCapabilities may be requested.
	Capabilities []string
	Env          map[string]string
	// User is the numeric identity the workload runs as (R23). Nil means the
	// image's own USER directive stands, which is what every spec written
	// before R23 meant — so adding the field changes no running service.
	User *User
	// Resources are always enforced; an omitted block yields defaults (R11).
	Resources Resources
	// ResourcesDeclared records whether the spec declared the block, so
	// `kanea plan` can show defaults as defaults.
	ResourcesDeclared bool
	// RegistryAuthRef names the secret holding a docker config.json used to
	// pull the image (R19). Project-scoped like every other reference (R5).
	RegistryAuthRef string
	// Devices are host devices the task requests by grant name (R17).
	Devices []*Device
	// Sockets are host unix sockets the task requests by grant name (R18).
	Sockets []*Socket
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// Device requests a host device the operator has granted (R17).
//
// It carries a grant name and no path. The node holds the mapping from grant to
// device nodes, so a spec cannot ask for `/dev/mem` — there is nowhere to write
// it — and no host path travels through the Store or a git repository.
type Device struct {
	// Name is local to the task: it makes duplicates detectable and reads in a
	// diagnostic. It has no meaning outside the spec.
	Name string
	// Grant names an entry in the node's passthrough config (§15.1).
	Grant string
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// Socket requests a host unix socket the operator has granted (R18).
//
// Unlike a device, it says where the socket appears inside the container:
// the tools this exists for expect a specific path (`/var/run/docker.sock`),
// and that path is the spec's business while the socket behind it is not.
type Socket struct {
	Name  string
	Grant string
	// MountPath is where the socket appears inside the container.
	MountPath string
	// ReadOnly is available and rarely meaningful: a socket is bidirectional
	// once connected, so this restricts the filesystem entry, not the protocol.
	ReadOnly bool
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// User is the uid/gid a task runs as (R23).
//
// Numeric only, and there is no field here for a username: see hclUser for why
// resolving one is a thing this deliberately does not do. Setting a user is not
// a substitute for R13 — capabilities are still dropped to nothing — but it is
// what makes most capability grants unnecessary, because the CHOWN/SETUID/SETGID
// trio exists so an image can do at startup what this states up front.
// The fields are `int` rather than `uint32` so that validateUser sees the value
// as it was written and can say so. Narrowing happens at the toDesired boundary,
// where Resources is narrowed too — after validation has refused the values that
// would not survive it.
type User struct {
	UID int
	GID int
	// Groups are supplementary GIDs.
	Groups []int
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// MaxID is the largest uid or gid a spec may name. 2^32-1 is (uid_t)-1, which
// the kernel reserves to mean "unchanged" in chown(2) — a workload asking to
// run as it is asking for something that is not a user.
const MaxID = 1<<32 - 2

// MaxGroups bounds the supplementary group list. NGROUPS_MAX is 65536 on Linux,
// but a spec naming thousands of groups is a mistake being expressed at length,
// and every one of them is copied into every alloc's OCI spec.
const MaxGroups = 64

// Resources are the per-alloc limits. Never unlimited (R11, PRD §5.2.11).
type Resources struct {
	// CPU in MHz.
	CPU int
	// Memory in MiB.
	Memory int
}

// Defaults applied when `resources` is omitted (R11).
const (
	DefaultCPU    = 100
	DefaultMemory = 256
	DefaultCount  = 1
)

// Network declares container ports by name, the node ports the edge publishes
// on this service's behalf, and the service's ingress policy.
type Network struct {
	Ports   []*Port
	Publish []*Publish
	Policy  *NetworkPolicy
}

// PublishMode names what a published listener speaks (R21).
const (
	// PublishHTTP is an alternate-port HTTP listener. It keeps the whole
	// §7.2.1 middleware chain, because the edge is still reading requests.
	PublishHTTP = "http"
	// PublishTCP relays bytes. Only ip_restriction survives, because there is
	// nothing else in a byte stream to apply a rule to.
	PublishTCP = "tcp"
)

// Publish is one node port the edge binds and forwards to this service (R21).
//
// It is a sibling of expose, not a field inside it, and that is deliberate.
// An expose block generates an auto-FQDN, requests a certificate *for those
// domains* and requires one unambiguous upstream port; a service on three node
// ports has no such thing. Nesting would make every expose field conditionally
// meaningful — the same reason R17's device grants are a separate kind rather
// than a relaxation of the host volume driver.
type Publish struct {
	// Port names the `network { port }` this listener forwards to. There is no
	// field for a container port number: a published port cannot name a port
	// the service did not declare.
	Port string
	// Host is the node port the edge binds. Whether it is *allowed* to is the
	// node's decision, not this spec's (R22).
	Host int
	// Mode is PublishHTTP (the default) or PublishTCP.
	Mode string
	// MaxConns bounds live connections on this listener. TCP only: an HTTP
	// listener is bounded by the edge's own server limits.
	MaxConns int

	IPRestriction *IPRestriction
	RateLimit     *RateLimit
	Headers       *Headers

	DefRange hcl.Range
}

// ResolvedMode is the mode with the default applied.
func (p *Publish) ResolvedMode() string {
	if p == nil || p.Mode == "" {
		return PublishHTTP
	}
	return p.Mode
}

// NetworkPolicy is the per-service ingress allowlist (R14).
//
// It only ever *adds* reachability. Cilium ingress rules union, so an entry
// here cannot weaken the project's default-deny boundary — which is what makes
// it safe to let a job spec influence policy at all.
type NetworkPolicy struct {
	// AllowFrom names the peers permitted to reach this service, each a
	// fully-qualified "<project>/<service>" exactly as written in the file.
	// Validation guarantees every entry parses; use Peers to read them.
	AllowFrom []string
	// DefRange is where the block was declared, for diagnostics.
	DefRange hcl.Range
}

// Peers returns the parsed allowlist. It assumes validation has run — a spec
// that reached the reconciler has already had every entry checked.
func (p *NetworkPolicy) Peers() []PeerRef {
	if p == nil {
		return nil
	}
	out := make([]PeerRef, 0, len(p.AllowFrom))
	for _, raw := range p.AllowFrom {
		if ref, err := ParsePeerRef(raw); err == nil {
			out = append(out, ref)
		}
	}
	return out
}

// PeerRef is a fully-qualified reference to another service.
type PeerRef struct {
	Project string
	Service string
}

// String renders the canonical "project/service" form.
func (p PeerRef) String() string { return p.Project + "/" + p.Service }

// ParsePeerRef reads a "<project>/<service>" reference.
//
// Both halves are required. A bare service name would have to mean "in my own
// project", which reads fine in a same-project spec and silently means the
// wrong thing the moment the block is copied into another project — so the
// fully-qualified form is the only one accepted (R14).
func ParsePeerRef(s string) (PeerRef, error) {
	project, service, ok := strings.Cut(s, "/")
	if !ok {
		return PeerRef{}, fmt.Errorf("%q must be written as \"<project>/<service>\"", s)
	}
	if strings.Contains(service, "/") {
		return PeerRef{}, fmt.Errorf("%q has more than one %q separator", s, "/")
	}
	// A wildcard would open an entire project at once. Naming the peer is the
	// point of the field, so this is refused rather than quietly expanded.
	if project == "*" || service == "*" {
		return PeerRef{}, fmt.Errorf("%q uses a wildcard; name the peer service explicitly", s)
	}
	if !dns1123Label.MatchString(project) || len(project) > MaxNameLength {
		return PeerRef{}, fmt.Errorf("project %q in %q is not a DNS-1123 label", project, s)
	}
	if !dns1123Label.MatchString(service) || len(service) > MaxNameLength {
		return PeerRef{}, fmt.Errorf("service %q in %q is not a DNS-1123 label", service, s)
	}
	return PeerRef{Project: project, Service: service}, nil
}

// Port is a named container port; the name is what ${service.x.port.<name>}
// resolves against (R9).
type Port struct {
	Name      string
	Container int
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// Expose configures north-south ingress and its middleware chain (PRD §7.2).
type Expose struct {
	// Domains defaults to <service>.<project>.<base_domain> when empty.
	Domains       []string
	TLS           *TLS
	IPRestriction *IPRestriction
	RateLimit     *RateLimit
	Headers       *Headers
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// TLS names where this service's certificate comes from (R20).
//
// Mode names a source, never a path: "acme", "self-signed", "provided" or
// "plaintext". Name narrows "provided" to one of the grants in the node's
// --tls-certs-config — the same rule R17 draws for devices, for the same
// reason. A spec is deployed by GitOps, so anything it can name, anyone who
// can push to a synced repository can name.
//
// An empty Mode means the node decides (--tls-default). That is what lets a
// homelabber annotate nothing and still get a certificate.
type TLS struct {
	Mode string
	Name string
	// LetsEncrypt is the pre-v1.33 spelling. nil means the field was absent.
	//
	// Deprecated: write Mode instead.
	LetsEncrypt *bool
	DefRange    hcl.Range
}

// IPRestriction is the first middleware in the chain; deny wins over allow.
type IPRestriction struct {
	Allow    []string
	Deny     []string
	DefRange hcl.Range
}

// RateLimit is a token bucket applied per the Per key.
type RateLimit struct {
	Requests int
	Window   string
	Per      string
	Burst    int
	DefRange hcl.Range
}

// Headers rewrites request and response headers at the edge.
type Headers struct {
	RequestSet     map[string]string
	RequestRemove  []string
	ResponseSet    map[string]string
	ResponseRemove []string
	DefRange       hcl.Range
}

// HealthCheck gates readiness and drives restarts (R7).
type HealthCheck struct {
	Name     string
	Type     string
	Path     string
	Port     string
	Command  []string
	Interval string
	Timeout  string
	Failures int
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// Health check types (R7). `exec` takes an argument array — never a shell
// string, which would be an injection vector (PRD §14, A03).
const (
	HealthHTTP = "http"
	HealthTCP  = "tcp"
	HealthExec = "exec"
)

// Volume mounts a named storage resource into the task (PRD §8).
type Volume struct {
	Name      string
	Storage   string
	MountPath string
	ReadOnly  bool
	// UID, GID and Mode are the volume's ownership (R24), filled in by
	// conversion: an undeclared uid/gid inherits task.user, and a volume that
	// ends up owned takes DefaultVolumeMode if it declared no mode.
	//
	// All three stay nil for a task with no user block and no explicit fields,
	// and nil means "leave it exactly as it is" — which is what every spec
	// written before R24 means, and is why they are pointers rather than a
	// zero value that would read as "chown to root".
	//
	// Mode stays the string it was written as, for the same reason User holds
	// ints: a value that does not parse has to reach the validator intact.
	UID  *int
	GID  *int
	Mode *string
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// Owned reports whether ownership is to be applied to this volume.
func (v Volume) Owned() bool { return v.UID != nil || v.GID != nil || v.Mode != nil }

// ParseMode reads a volume's `mode` as octal.
//
// Octal always, with or without the leading zero, and never decimal: "700"
// means 0o700 here because that is what every operator writing it means, and
// silently reading it as decimal 700 would yield 0o1274.
func ParseMode(s string) (uint32, error) {
	if s == "" {
		return 0, errors.New("mode is empty")
	}
	if len(s) > 4 {
		return 0, fmt.Errorf("mode %q is longer than four octal digits", s)
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("mode %q is not octal", s)
	}
	if uint32(v) > MaxMode {
		return 0, fmt.Errorf("mode %q sets a bit above 0777", s)
	}
	return uint32(v), nil
}

// DefaultVolumeMode is the mode an owned volume takes when it declares none.
//
// 0700 rather than the 0750 an unowned volume is created with: once a volume
// has an owner it is that workload's own data, and the group and other bits
// grant reach to nothing that exists. It is also the only mode postgres will
// start on, which is a useful reminder that this is the common case.
const DefaultVolumeMode uint32 = 0o700

// MaxMode is the largest permission bit set a volume may declare. Deliberately
// no setuid, setgid or sticky bit: those are not permissions on a data
// directory, and a spec that could set them could set them on a bind mount.
const MaxMode uint32 = 0o777

// Scaling configures the autoscaler (PRD §9).
type Scaling struct {
	Min      int
	Max      int
	Metrics  []*ScalingMetric
	Cooldown string
}

// ScalingMetric is one target the autoscaler drives toward.
type ScalingMetric struct {
	Name   string
	Target int
}

// Update is the rolling-deploy policy.
type Update struct {
	Strategy    string
	MaxParallel int
	MinHealthy  string
	// Auto turns on image auto-update (R19): the tag task.image declares is
	// re-resolved on a schedule and the digest behind it is pinned when it
	// moves. Off by default — following a moving tag is the one thing §14 A08
	// otherwise refuses, so it is stated explicitly or not at all.
	Auto bool
	// Interval is how often the registry is polled. Empty means the default.
	Interval string
	// Deadline is how long a new digest has to converge before it is reverted
	// to the one that was running. Empty means the default.
	Deadline string
}

// Restart is the crash-restart policy.
type Restart struct {
	Attempts int
	Backoff  string
}

// ServiceRef is one ${service.<name>.host} or ${service.<name>.port.<port>}
// reference, with the position that produced it for diagnostics.
type ServiceRef struct {
	// From is the referencing service's name.
	From string
	// Service is the referenced service's name.
	Service string
	// Port is set for port references, empty for host references.
	Port string
	// EnvKey is the environment variable the reference appeared in.
	EnvKey string
}

// ProjectByName returns the named project, or nil.
func (s *Spec) ProjectByName(name string) *Project {
	for _, p := range s.Projects {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// ServiceByName returns the named service within a project, or nil. Names are
// unique per project, not globally (PRD §4.1).
func (s *Spec) ServiceByName(project, name string) *Service {
	for _, svc := range s.Services {
		if svc.Project == project && svc.Name == name {
			return svc
		}
	}
	return nil
}

// ServicesInProject returns every service belonging to a project, in spec order.
func (s *Spec) ServicesInProject(project string) []*Service {
	var out []*Service
	for _, svc := range s.Services {
		if svc.Project == project {
			out = append(out, svc)
		}
	}
	return out
}
