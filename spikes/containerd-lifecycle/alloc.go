package main

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	containerd "github.com/containerd/containerd/v2/client"
)

// alloc describes one workload placement, mirroring what M1's reconciler will
// derive from a job spec: command + mandatory resource limits + cgroup placement.
type alloc struct {
	ID         string
	Cmd        []string
	MemLimitMB int64  // -> memory.max (hard; breach OOM-kills the alloc)
	CPUQuota   int64  // -> cpu.max quota per CPUPeriod
	CPUPeriod  uint64 // default 100000 (100ms)
	PidsLimit  int64  // -> pids.max
	CgroupPath string // runc cgroupsPath, e.g. "/kanea-workloads.slice/alloc-web-1"
	BinMount   string // host path to bind-mount ro at /spike (memhog inside the alloc)
}

// withResources applies PRD §6.2 R11 limits and §5.2.11 placement via the OCI spec.
func withResources(a alloc) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if s.Linux == nil {
			s.Linux = &specs.Linux{}
		}
		if s.Linux.Resources == nil {
			s.Linux.Resources = &specs.LinuxResources{}
		}
		if a.MemLimitMB > 0 {
			l := a.MemLimitMB << 20
			// Swap == Limit => zero swap headroom (memory.swap.max = 0 equivalent).
			s.Linux.Resources.Memory = &specs.LinuxMemory{Limit: &l, Swap: &l}
		}
		if a.CPUQuota > 0 {
			period := a.CPUPeriod
			if period == 0 {
				period = 100000
			}
			s.Linux.Resources.CPU = &specs.LinuxCPU{Quota: &a.CPUQuota, Period: &period}
		}
		if a.PidsLimit > 0 {
			l := a.PidsLimit
			s.Linux.Resources.Pids = &specs.LinuxPids{Limit: &l}
		}
		if a.CgroupPath != "" {
			s.Linux.CgroupsPath = a.CgroupPath
		}
		if a.BinMount != "" {
			s.Mounts = append(s.Mounts, specs.Mount{
				Destination: "/spike",
				Type:        "bind",
				Source:      a.BinMount,
				Options:     []string{"bind", "ro"},
			})
		}
		return nil
	}
}

// startAlloc creates the container + task and starts it. Caller watches Wait().
func startAlloc(ctx context.Context, client *containerd.Client, img containerd.Image, a alloc) (containerd.Task, error) {
	specOpts := []oci.SpecOpts{oci.WithImageConfig(img)}
	if len(a.Cmd) > 0 {
		specOpts = append(specOpts, oci.WithProcessArgs(a.Cmd...))
	}
	specOpts = append(specOpts, withResources(a))

	container, err := client.NewContainer(ctx, a.ID,
		containerd.WithImage(img),
		containerd.WithNewSnapshot(a.ID+"-snap", img),
		containerd.WithNewSpec(specOpts...),
	)
	if err != nil {
		return nil, fmt.Errorf("new container %s: %w", a.ID, err)
	}
	task, err := container.NewTask(ctx, cio.NullIO)
	if err != nil {
		return nil, fmt.Errorf("new task %s: %w", a.ID, err)
	}
	if err := task.Start(ctx); err != nil {
		return nil, fmt.Errorf("start task %s: %w", a.ID, err)
	}
	return task, nil
}

// removeAlloc tears down task, CNI state, container and snapshot. Best-effort.
func removeAlloc(ctx context.Context, client *containerd.Client, id string) {
	c, err := client.LoadContainer(ctx, id)
	if err != nil {
		return
	}
	if task, err := c.Task(ctx, nil); err == nil {
		_ = cniDel(id, task.Pid()) // while netns is still valid
		_, _ = task.Delete(ctx, containerd.WithProcessKill)
	}
	_ = c.Delete(ctx, containerd.WithSnapshotCleanup)
}

// execIn runs a command inside the task's namespaces and returns combined output.
func execIn(ctx context.Context, task containerd.Task, id string, args ...string) (string, uint32, error) {
	var out bytes.Buffer
	pspec := &specs.Process{
		Args: args,
		Cwd:  "/",
		Env:  []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}
	proc, err := task.Exec(ctx, id, pspec, cio.NewCreator(cio.WithStreams(nil, &out, &out)))
	if err != nil {
		return "", 0, fmt.Errorf("exec create: %w", err)
	}
	defer proc.Delete(ctx)
	statusC, err := proc.Wait(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("exec wait: %w", err)
	}
	if err := proc.Start(ctx); err != nil {
		return "", 0, fmt.Errorf("exec start: %w", err)
	}
	select {
	case st := <-statusC:
		time.Sleep(150 * time.Millisecond) // let FIFO IO drain into the buffer
		return out.String(), st.ExitCode(), nil
	case <-ctx.Done():
		_ = proc.Kill(ctx, 9)
		return out.String(), 0, ctx.Err()
	}
}

// execDetached starts a long-running exec (for pids/cpu abuse tests); caller kills.
func execDetached(ctx context.Context, task containerd.Task, id string, args ...string) (containerd.Process, error) {
	pspec := &specs.Process{
		Args: args,
		Cwd:  "/",
		Env:  []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}
	proc, err := task.Exec(ctx, id, pspec, cio.NullIO)
	if err != nil {
		return nil, err
	}
	if err := proc.Start(ctx); err != nil {
		return nil, err
	}
	return proc, nil
}

func mustSeconds(d time.Duration) string { return fmt.Sprintf("%.1fs", d.Seconds()) }
