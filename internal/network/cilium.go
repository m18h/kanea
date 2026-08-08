package network

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/m18h/kanea/internal/runtime"
)

// Config configures the Cilium network driver.
type Config struct {
	// SocketPath is the cilium-agent API socket. Empty means the default.
	SocketPath string
	// CNIConfPath is the deployed conflist. Empty means the default.
	CNIConfPath string
	// CNIBinDir holds the CNI plugin binaries. Empty means the default.
	CNIBinDir string
	// PolicyDir is the agent's --static-cnp-path. Empty means the default.
	PolicyDir string
	// LBStateFile is the agent's --lb-state-file. Empty means the default.
	LBStateFile string
	// DNS, when set, has its zone republished on every service sync.
	DNS *DNS
	// Logger receives attach/detach events.
	Logger *slog.Logger
	// IdentityTimeout bounds the wait for an endpoint to reach a real security
	// identity. Empty means DefaultIdentityTimeout.
	IdentityTimeout time.Duration
	// RequestTimeout bounds a single agent API call.
	RequestTimeout time.Duration
}

// DefaultIdentityTimeout bounds the post-attach identity wait. Identity
// allocation is a kvstore round trip plus an endpoint regeneration; spike ①
// measured attaches at 123 ms–1.15 s, so this is generous by design — the cost
// of waiting is a slow alloc, the cost of giving up early is a workload that
// starts with its traffic denied.
const DefaultIdentityTimeout = 30 * time.Second

// identityPollInterval paces the readiness poll.
const identityPollInterval = 200 * time.Millisecond

// Cilium attaches allocs to the standalone Cilium datapath.
//
// The order of operations is the contract, and it is load-bearing:
//
//	netns → CNI ADD → PATCH identity labels → (task start, by the caller)
//
// Between CNI ADD and the label PATCH the endpoint holds `reserved:init`, and
// init endpoints are policy-enforced deny in *both* directions. A workload
// started in that window does not come up degraded — it comes up with no
// network at all, usually failing in whatever way its client library fails when
// DNS is unreachable. That is why Attach returns only once the endpoint has a
// real identity, and why the reconciler calls it before Create (M0 spike ①).
//
// Teardown runs in reverse: CNI DEL while the namespace still exists, then the
// namespace.
type Cilium struct {
	client *client
	cni    cniPlugin
	netns  netnsOps
	log    *slog.Logger

	policyDir       string
	lbStateFile     string
	dns             *DNS
	identityTimeout time.Duration
	labelRetry      backoff
}

// cniPlugin is the CNI surface Attach and Detach use. It exists so the attach
// *ordering* — the one property of this package that is genuinely load-bearing
// — can be asserted in a unit test instead of only on a live node.
type cniPlugin interface {
	add(ctx context.Context, allocID, netnsPath string) (string, error)
	del(ctx context.Context, allocID, netnsPath string) error
}

// netnsOps is the namespace surface, injectable for the same reason. Creating a
// persistent netns needs root and iproute2, neither of which a unit test has.
type netnsOps struct {
	create func(allocID string) (string, error)
	path   func(allocID string) string
	delete func(allocID string) error
	exists func(allocID string) bool
}

func hostNetns() netnsOps {
	return netnsOps{
		create: runtime.CreateNetns,
		path:   runtime.NetnsPath,
		delete: runtime.DeleteNetns,
		exists: runtime.NetnsExists,
	}
}

// New builds a Cilium driver. It performs no I/O — call Health to check that
// the agent is actually up.
func New(cfg Config) (*Cilium, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.IdentityTimeout <= 0 {
		cfg.IdentityTimeout = DefaultIdentityTimeout
	}
	if cfg.PolicyDir == "" {
		cfg.PolicyDir = DefaultPolicyDir
	}
	if cfg.LBStateFile == "" {
		cfg.LBStateFile = DefaultLBStateFile
	}
	return &Cilium{
		client:          newClient(cfg.SocketPath, cfg.RequestTimeout),
		cni:             newCNIInvoker(cfg.CNIConfPath, cfg.CNIBinDir),
		netns:           hostNetns(),
		log:             cfg.Logger,
		policyDir:       cfg.PolicyDir,
		lbStateFile:     cfg.LBStateFile,
		dns:             cfg.DNS,
		identityTimeout: cfg.IdentityTimeout,
		labelRetry:      defaultBackoff,
	}, nil
}

// Health reports whether cilium-agent is reachable and answering.
func (c *Cilium) Health(ctx context.Context) error { return c.client.health(ctx) }

// Attachment is one endpoint as Kanea sees it.
type Attachment struct {
	// AllocID is the alloc the endpoint belongs to.
	AllocID string
	// EndpointID is Cilium's own endpoint id.
	EndpointID int64
	// IPv4 is the address the datapath assigned.
	IPv4 string
	// Service is the project/service the endpoint's identity says it serves.
	Service ServiceRef
	// Ready reports a resolved, non-init security identity.
	Ready bool
}

// Attach wires an alloc into the datapath and returns once its endpoint carries
// a real security identity.
//
// It is idempotent, because the reconciler retries. An alloc whose endpoint is
// already attached and ready returns immediately; an alloc whose CNI ADD
// succeeded but whose labels never landed skips the ADD and resumes at the
// PATCH. Re-running CNI ADD on an attached container would create a second
// endpoint and leak the first, so the existence check is not an optimisation.
func (c *Cilium) Attach(ctx context.Context, spec runtime.AllocSpec) error {
	if err := validateAttach(spec); err != nil {
		return err
	}
	labels := IdentityLabels(spec.Project, spec.Service)

	existing, err := c.lookup(ctx, spec.ID)
	if err != nil {
		return err
	}
	if existing != nil && existing.ready() {
		if ref, ok := serviceRefFrom(existing.Status.Identity.Labels); ok &&
			ref.Project == spec.Project && ref.Service == spec.Service {
			return nil // already attached to the right service
		}
		// Same alloc id, different service: the id is derived from
		// project/service/index, so this means a stale endpoint survived a
		// teardown. Re-labelling it is correct and cheaper than a full cycle.
		c.log.Warn("re-labelling endpoint with unexpected identity",
			"alloc", spec.ID, "labels", existing.Status.Identity.Labels)
	}

	netnsPath, err := c.netns.create(spec.ID)
	if err != nil {
		return fmt.Errorf("netns: %w", err)
	}

	if existing == nil {
		ip, err := c.cni.add(ctx, spec.ID, netnsPath)
		if err != nil {
			return err
		}
		if !validIP(ip) {
			return fmt.Errorf("cni add %s returned invalid address %q", spec.ID, ip)
		}
		c.log.Debug("cni add", "alloc", spec.ID, "ip", ip, "netns", netnsPath)
	}

	if err := c.client.setIdentityLabels(ctx, spec.ID, labels, c.labelRetry); err != nil {
		return fmt.Errorf("identity labels: %w", err)
	}

	ep, err := c.waitReady(ctx, spec.ID)
	if err != nil {
		return err
	}
	c.log.Info("alloc attached",
		"alloc", spec.ID, "project", spec.Project, "service", spec.Service,
		"ip", ep.ipv4(), "endpoint", ep.ID, "identity", ep.Status.Identity.ID)
	return nil
}

// Detach removes the alloc from the datapath. Missing is success: teardown runs
// on paths where part of it may already have happened.
func (c *Cilium) Detach(ctx context.Context, spec runtime.AllocSpec) error {
	if spec.ID == "" {
		return nil
	}
	netnsPath := c.netns.path(spec.ID)
	hadNetns := c.netns.exists(spec.ID)

	if err := c.cni.del(ctx, spec.ID, netnsPath); err != nil {
		// With the namespace already gone the plugin has nothing to enter, and
		// this is the tail of a teardown that mostly succeeded. Failing here
		// would wedge the alloc in a state no retry can leave. Failing while the
		// namespace *does* exist is a real cleanup failure: report it, so the
		// endpoint and its IP allocation do not leak silently.
		if hadNetns {
			return err
		}
		c.log.Warn("cni del failed after netns was already gone", "alloc", spec.ID, "error", err)
	}
	if err := c.netns.delete(spec.ID); err != nil {
		return fmt.Errorf("netns: %w", err)
	}
	c.log.Debug("alloc detached", "alloc", spec.ID)
	return nil
}

// Attachments lists every Kanea-managed endpoint the agent knows about, keyed
// by alloc id.
//
// This is the authoritative source of alloc IPs, and it is deliberately a live
// query rather than something the Store remembers. Addresses are derived state
// (constraint #9): they are reassigned when the agent restarts with a fresh
// kvstore, so a persisted copy would be a stale answer that outlives the truth.
func (c *Cilium) Attachments(ctx context.Context) (map[string]Attachment, error) {
	eps, err := c.client.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Attachment, len(eps))
	for i := range eps {
		ep := &eps[i]
		ref, ok := serviceRefFrom(ep.Status.Identity.Labels)
		if !ok {
			continue // not ours: reserved:host, health, or another tool's endpoint
		}
		allocID := ep.Status.ExternalIdentifiers.ContainerID
		if allocID == "" {
			continue
		}
		out[allocID] = Attachment{
			AllocID:    allocID,
			EndpointID: ep.ID,
			IPv4:       ep.ipv4(),
			Service:    ref,
			Ready:      ep.ready(),
		}
	}
	return out, nil
}

// Attached lists the allocs currently holding a Kanea endpoint, so the
// reconciler can reclaim ones that belong to nothing (reconciler.NetworkReaper).
//
// The list is filtered by the `kanea=true` identity label, and that filter is
// the safety property: reaping deletes, and the reserved:host endpoint or one
// belonging to another tool must never appear in a set the caller is about to
// tear down.
func (c *Cilium) Attached(ctx context.Context) ([]string, error) {
	attachments, err := c.Attachments(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(attachments))
	for id := range attachments {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// lookup returns the alloc's endpoint, or nil when there is none.
func (c *Cilium) lookup(ctx context.Context, allocID string) (*endpoint, error) {
	ep, err := c.client.endpointByAlloc(ctx, allocID)
	switch {
	case errors.Is(err, ErrEndpointNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return ep, nil
}

// waitReady polls until the endpoint holds a real security identity.
func (c *Cilium) waitReady(ctx context.Context, allocID string) (*endpoint, error) {
	ctx, cancel := context.WithTimeout(ctx, c.identityTimeout)
	defer cancel()

	ticker := time.NewTicker(identityPollInterval)
	defer ticker.Stop()

	var last *endpoint
	for {
		ep, err := c.client.endpointByAlloc(ctx, allocID)
		switch {
		case err == nil:
			last = ep
			if ep.ready() && validIP(ep.ipv4()) {
				return ep, nil
			}
		case errors.Is(err, ErrAgentUnavailable):
			return nil, err // no amount of polling fixes a dead agent
		}

		select {
		case <-ctx.Done():
			return nil, notReadyError(allocID, last, c.identityTimeout)
		case <-ticker.C:
		}
	}
}

// notReadyError explains *why* the endpoint is not usable, because "timeout" on
// its own sends an operator to the wrong place. An endpoint stuck with
// reserved:init points at the kvstore or identity allocation; one that never
// appeared points at CNI.
func notReadyError(allocID string, last *endpoint, timeout time.Duration) error {
	if last == nil {
		return fmt.Errorf("endpoint for %s never appeared within %v", allocID, timeout)
	}
	return fmt.Errorf("endpoint for %s not ready within %v: state=%q identity=%d ip=%q labels=%v",
		allocID, timeout, last.Status.State, last.Status.Identity.ID,
		last.ipv4(), last.Status.Identity.Labels)
}

// validateAttach rejects specs the datapath cannot represent.
func validateAttach(spec runtime.AllocSpec) error {
	if len(spec.ID) < runtime.MinAllocIDLength {
		// Cilium builds a temporary interface name from the first 5 characters
		// of "<container-id>:<ifname>"; a shorter id leaks the ':' into an
		// interface name and CNI ADD fails with a bare "invalid argument".
		return fmt.Errorf("network: alloc id %q is %d characters, need at least %d",
			spec.ID, len(spec.ID), runtime.MinAllocIDLength)
	}
	if err := validateLabelValue("project", spec.Project); err != nil {
		return err
	}
	return validateLabelValue("service", spec.Service)
}
