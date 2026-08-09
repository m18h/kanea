package provision

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Supervising cilium-agent as a containerd task (PRD §5.2.12).
//
// The agent runs from its image rather than from binaries extracted onto the
// host: it needs its bundled helpers, its iptables and its BPF templates, and
// M0 spike ① validated exactly this form. systemd supervises processes, not
// tasks, so `kanea supervise cilium` is the process — it creates the task,
// puts its cgroup under kanea.slice, and exits with it.

// Default CIDRs. Both are RFC 1918 space chosen not to collide with the
// defaults of the things Kanea sits next to (Docker's 172.17/16, and the
// 10.42/16 k3s uses).
const (
	DefaultNodeCIDR    = "10.244.0.0/24"
	DefaultClusterCIDR = "10.244.0.0/16"
)

// CiliumOptions configures the agent.
type CiliumOptions struct {
	NodeCIDR    string
	ClusterCIDR string
}

// Supervisor runs an image-backed component as a task.
type Supervisor struct {
	client *containerd.Client
	layout Layout
	log    *slog.Logger
}

// NewSupervisor connects to containerd.
func NewSupervisor(socket string, layout Layout, log *slog.Logger) (*Supervisor, error) {
	client, err := containerd.New(socket, containerd.WithDefaultNamespace(SystemNamespace))
	if err != nil {
		return nil, fmt.Errorf("dial containerd at %s: %w", socket, err)
	}
	return &Supervisor{client: client, layout: layout, log: log}, nil
}

// Close releases the connection.
func (s *Supervisor) Close() error { return s.client.Close() }

// ciliumContainerID is stable, so a restart adopts or replaces rather than
// accumulating. A second cilium-agent on one node is not a degraded state, it
// is two things programming one dataplane.
const ciliumContainerID = "kanea-cilium-agent"

// RunCilium starts the agent and blocks until it exits or ctx is cancelled.
func (s *Supervisor) RunCilium(ctx context.Context, c *Component, opts CiliumOptions) error {
	if opts.NodeCIDR == "" {
		opts.NodeCIDR = DefaultNodeCIDR
	}
	if opts.ClusterCIDR == "" {
		opts.ClusterCIDR = DefaultClusterCIDR
	}
	if err := s.prepareCiliumHost(); err != nil {
		return err
	}

	image, err := s.client.GetImage(ctx, c.Ref())
	if err != nil {
		return fmt.Errorf("cilium image %s is not present — run `kanea install`: %w", c.Ref(), err)
	}

	// A container left behind by a previous run is deleted rather than
	// reused: its spec was built from the flags and paths of that run, and
	// silently keeping it is how a configuration change stops taking effect.
	if err := s.removeExisting(ctx, ciliumContainerID); err != nil {
		return err
	}

	container, err := s.client.NewContainer(ctx, ciliumContainerID,
		containerd.WithImage(image),
		containerd.WithNewSnapshot(ciliumContainerID+"-snapshot", image),
		containerd.WithNewSpec(s.ciliumSpec(image, opts)...),
	)
	if err != nil {
		return fmt.Errorf("create the cilium container: %w", err)
	}
	defer func() {
		// A best-effort cleanup on the way out. The next start deletes it
		// anyway, so a failure here is not worth failing the shutdown over.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := container.Delete(cleanupCtx, containerd.WithSnapshotCleanup); err != nil &&
			!errdefs.IsNotFound(err) {
			s.log.Warn("could not remove the cilium container", "error", err)
		}
	}()

	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		return fmt.Errorf("create the cilium task: %w", err)
	}

	exitCh, err := task.Wait(ctx)
	if err != nil {
		return fmt.Errorf("watch the cilium task: %w", err)
	}
	if err := task.Start(ctx); err != nil {
		return fmt.Errorf("start cilium-agent: %w", err)
	}
	s.log.Info("cilium-agent started", "image", c.Ref(), "node-cidr", opts.NodeCIDR)

	select {
	case status := <-exitCh:
		code := status.ExitCode()
		if _, err := task.Delete(context.WithoutCancel(ctx)); err != nil && !errdefs.IsNotFound(err) {
			s.log.Warn("could not remove the cilium task", "error", err)
		}
		if code != 0 {
			// Returned as an error so systemd's Restart=always sees a failure
			// and the journal records the code.
			return fmt.Errorf("cilium-agent exited with status %d", code)
		}
		return nil

	case <-ctx.Done():
		s.log.Info("stopping cilium-agent")
		return s.stopTask(task)
	}
}

// stopTask asks the agent to stop, then insists.
func (s *Supervisor) stopTask(task containerd.Task) error {
	stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	exitCh, err := task.Wait(stopCtx)
	if err != nil {
		return fmt.Errorf("watch the cilium task while stopping: %w", err)
	}
	if err := task.Kill(stopCtx, syscall.SIGTERM); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("signal cilium-agent: %w", err)
	}
	select {
	case <-exitCh:
	case <-stopCtx.Done():
		// SIGKILL rather than leaving it: systemd's TimeoutStopSec is about to
		// do the same to this process, and a cilium-agent that outlives its
		// supervisor keeps programming a dataplane nothing is managing.
		if err := task.Kill(context.Background(), syscall.SIGKILL); err != nil && !errdefs.IsNotFound(err) {
			s.log.Warn("could not kill cilium-agent", "error", err)
		}
	}
	if _, err := task.Delete(context.Background()); err != nil && !errdefs.IsNotFound(err) {
		s.log.Warn("could not remove the cilium task", "error", err)
	}
	return nil
}

func (s *Supervisor) removeExisting(ctx context.Context, id string) error {
	existing, err := s.client.LoadContainer(ctx, id)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look up %s: %w", id, err)
	}
	if task, err := existing.Task(ctx, nil); err == nil {
		if err := task.Kill(ctx, syscall.SIGKILL); err != nil && !errdefs.IsNotFound(err) {
			s.log.Warn("could not kill the previous cilium task", "error", err)
		}
		if _, err := task.Delete(ctx); err != nil && !errdefs.IsNotFound(err) {
			s.log.Warn("could not remove the previous cilium task", "error", err)
		}
	}
	if err := existing.Delete(ctx, containerd.WithSnapshotCleanup); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("remove the previous cilium container: %w", err)
	}
	return nil
}

// ciliumSpec is the OCI spec for the agent.
//
// Privileged, host network and host PID — all three are what an eBPF dataplane
// is. This is the one workload on the node that gets them, and it gets them
// because it *is* the isolation mechanism rather than a thing being isolated:
// every alloc still runs with ALL capabilities dropped, no-new-privileges and
// the default seccomp profile (§14, constraint #6). Reading this as a
// precedent for a `privileged` escape hatch in the job spec would be reading
// it backwards.
func (s *Supervisor) ciliumSpec(image containerd.Image, opts CiliumOptions) []oci.SpecOpts {
	mounts := []specs.Mount{
		bind(CiliumRunDir, CiliumRunDir, "rw"),
		bind("/sys/fs/bpf", "/sys/fs/bpf", "rw"),
		bind("/run/cilium/cgroupv2", "/run/cilium/cgroupv2", "rw"),
		bind("/run/xtables.lock", "/run/xtables.lock", "rw"),
		bind("/lib/modules", "/lib/modules", "ro"),
		// The CNI plugin and its config are written where containerd looks,
		// which is Kanea's prefix rather than /opt/cni/bin.
		bind(s.layout.CNIBinDir(), s.layout.CNIBinDir(), "rw"),
		bind(filepath.Join(s.layout.ConfDir, "cni", "net.d"), filepath.Join(s.layout.ConfDir, "cni", "net.d"), "rw"),
	}

	return []oci.SpecOpts{
		oci.WithImageConfig(image),
		oci.WithPrivileged,
		oci.WithHostNamespace(specs.NetworkNamespace),
		oci.WithHostNamespace(specs.PIDNamespace),
		oci.WithHostHostsFile,
		oci.WithHostResolvconf,
		oci.WithMounts(mounts),
		oci.WithEnv([]string{"CILIUM_CNI_CHAINING_MODE=none"}),
		oci.WithProcessArgs(CiliumArgs(s.layout, opts.NodeCIDR, opts.ClusterCIDR)...),
		// Under kanea.slice, so constraint #11's floor covers the dataplane.
		// The unit's own Slice= only governs this supervisor process; the task
		// is containerd's child and needs telling separately.
		oci.WithCgroup("/kanea.slice/kanea-cilium.service/agent"),
	}
}

// bind builds a recursive bind mount. Always rbind: these are host paths that
// may themselves carry submounts (/sys/fs/bpf is one), and a plain bind would
// silently give the agent the directory without them.
func bind(source, dest string, options ...string) specs.Mount {
	return specs.Mount{
		Source:      source,
		Destination: dest,
		Type:        "bind",
		Options:     append([]string{"rbind"}, options...),
	}
}

// prepareCiliumHost creates the mount points and files the agent needs.
//
// The bpf and cgroup2 mounts themselves are left to the host: mounting
// filesystems from here would mean this process has to know whether a previous
// run already did, and getting that wrong leaves stacked mounts nobody can see.
// They are checked instead, and named if missing.
func (s *Supervisor) prepareCiliumHost() error {
	for _, dir := range []string{
		CiliumRunDir,
		filepath.Join(CiliumRunDir, "policies"),
		"/run/cilium/cgroupv2",
		"/sys/fs/bpf",
	} {
		// #nosec G301 — Cilium's own paths, and the agent runs as a task that
		// bind-mounts them. 0755 is what every Cilium deployment uses; these
		// hold a socket and two control files, not secrets.
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	// iptables' lock file. The agent bind-mounts it, and a bind mount of a
	// path that does not exist fails at task start with a message about the
	// mount rather than about the file.
	f, err := os.OpenFile("/run/xtables.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create /run/xtables.lock: %w", err)
	}
	if f != nil {
		return f.Close()
	}
	return nil
}
