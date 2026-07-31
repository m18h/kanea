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

import "github.com/hashicorp/hcl/v2"

// Spec is one parsed, validated applied set: everything `kanea apply` was given.
type Spec struct {
	// SpecVersion gates future schema revisions (R6, PRD §15.4).
	SpecVersion int
	Projects    []*Project
	Services    []*Service
	// Storages are the named storage resources services mount (PRD §8).
	Storages []*Storage
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
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

// Storage driver types (PRD §8).
const (
	StorageLocal = "local"
	StorageS3    = "s3"
	StorageNFS   = "nfs"
	StorageSMB   = "smb"
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

// Git is the optional GitOps source for a project (PRD §10).
type Git struct {
	URL     string
	Branch  string
	Path    string
	AuthRef string
}

// Notifications configures per-project channels and the events they fire on.
type Notifications struct {
	Telegram *TelegramChannel
	Webhook  *WebhookChannel
	On       []string
}

// TelegramChannel targets a chat; the bot token comes from the secret store.
type TelegramChannel struct {
	ChatID string
}

// WebhookChannel posts events to a URL.
type WebhookChannel struct {
	URL string
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
	// Resources are always enforced; an omitted block yields defaults (R11).
	Resources Resources
	// ResourcesDeclared records whether the spec declared the block, so
	// `kanea plan` can show defaults as defaults.
	ResourcesDeclared bool
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

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

// Network declares container ports by name.
type Network struct {
	Ports []*Port
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
}

// TLS controls certificate provisioning for the exposed domains.
type TLS struct {
	LetsEncrypt bool
}

// IPRestriction is the first middleware in the chain; deny wins over allow.
type IPRestriction struct {
	Allow []string
	Deny  []string
}

// RateLimit is a token bucket applied per the Per key.
type RateLimit struct {
	Requests int
	Window   string
	Per      string
	Burst    int
}

// Headers rewrites request and response headers at the edge.
type Headers struct {
	RequestSet     map[string]string
	RequestRemove  []string
	ResponseSet    map[string]string
	ResponseRemove []string
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
	// DefRange is where this block was declared, for diagnostics.
	DefRange hcl.Range
}

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
