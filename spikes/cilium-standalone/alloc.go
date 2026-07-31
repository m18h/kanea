package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// alloc is one workload placement: what M2's reconciler will derive from a job
// spec. Labels are the Cilium security identity — Kanea's isolation boundary.
type alloc struct {
	ID     string   // >= 5 chars, DNS-1123-ish (see cniRuntime)
	Labels []string // e.g. kanea=true, project=shop, service=web
	Cmd    []string
}

type running struct {
	alloc
	IP       string // from the CNI result
	EpID     int64  // Cilium endpoint id
	Identity int64  // Cilium security identity
	Task     containerd.Task
}

func netnsPath(id string) string { return "/run/netns/" + id }

// createNetns makes a persistent named netns so the network can be wired up
// BEFORE the workload's first instruction runs.
func createNetns(id string) error {
	_ = exec.Command("ip", "netns", "delete", id).Run()
	if out, err := exec.Command("ip", "netns", "add", id).CombinedOutput(); err != nil {
		return fmt.Errorf("ip netns add %s: %w (%s)", id, err, bytes.TrimSpace(out))
	}
	// The Cilium CNI plugin does not touch lo; a down loopback breaks any
	// workload that talks to itself.
	if out, err := exec.Command("ip", "netns", "exec", id, "ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		return fmt.Errorf("set lo up in %s: %w (%s)", id, err, bytes.TrimSpace(out))
	}
	return nil
}

func deleteNetns(id string) {
	_ = exec.Command("ip", "netns", "delete", id).Run()
	_ = os.Remove(netnsPath(id))
}

func ensureImage(ctx context.Context, client *containerd.Client) (containerd.Image, error) {
	if img, err := client.GetImage(ctx, imageRef); err == nil {
		return img, nil
	}
	return client.Pull(ctx, imageRef, containerd.WithPullUnpack)
}

// setupAlloc performs the full M2 attach sequence:
//
//	netns -> CNI ADD -> identity labels via agent API -> identity -> task start
//
// Labelling before start matters: between CNI ADD and the endpoint patch the
// endpoint carries reserved:init, which is policy-enforced (deny) in both
// directions — a workload started in that window sees its traffic dropped.
func setupAlloc(ctx context.Context, e *env, img containerd.Image, a alloc) (*running, error) {
	if err := createNetns(a.ID); err != nil {
		return nil, err
	}
	ip, err := cniAdd(ctx, a.ID)
	if err != nil {
		deleteNetns(a.ID)
		return nil, err
	}
	r := &running{alloc: a, IP: ip}
	e.allocs[a.ID] = r // registered early so teardown always cleans up

	if err := e.cil.setIdentityLabels(ctx, a.ID, a.Labels); err != nil {
		return r, err
	}
	ep, err := e.cil.waitIdentity(ctx, a.ID, 30*time.Second)
	if err != nil {
		return r, err
	}
	r.EpID, r.Identity = ep.ID, ep.Status.Identity.ID

	task, err := startTask(ctx, e.client, img, a)
	if err != nil {
		return r, err
	}
	r.Task = task
	return r, nil
}

func startTask(ctx context.Context, client *containerd.Client, img containerd.Image, a alloc) (containerd.Task, error) {
	specOpts := []oci.SpecOpts{
		oci.WithImageConfig(img),
		oci.WithProcessArgs(a.Cmd...),
		// Join the netns the CNI plugin already wired up.
		oci.WithLinuxNamespace(specs.LinuxNamespace{
			Type: specs.NetworkNamespace,
			Path: netnsPath(a.ID),
		}),
	}
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

// removeAlloc tears down task, container, CNI state and netns. Best-effort:
// CNI DEL runs while the netns still exists (spike ② lesson).
func removeAlloc(ctx context.Context, client *containerd.Client, id string) {
	if c, err := client.LoadContainer(ctx, id); err == nil {
		if task, err := c.Task(ctx, nil); err == nil {
			_, _ = task.Delete(ctx, containerd.WithProcessKill)
		}
		_ = c.Delete(ctx, containerd.WithSnapshotCleanup)
	}
	_ = cniDel(ctx, id)
	deleteNetns(id)
}

// execIn runs a command inside the alloc and returns its combined output.
//
// Output goes to a shim-written log file rather than in-process copy goroutines
// (cio.WithStreams): with streams, a finished exec can return before io.Copy has
// drained the FIFO, which silently truncates or empties the result.
func execIn(ctx context.Context, r *running, execID string, args ...string) (string, uint32, error) {
	logFile, err := os.CreateTemp("", "kanea-spike-exec-*.log")
	if err != nil {
		return "", 0, err
	}
	logPath := logFile.Name()
	_ = logFile.Close()
	defer os.Remove(logPath)

	pspec := &specs.Process{
		Args: args,
		Cwd:  "/",
		Env:  []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}
	proc, err := r.Task.Exec(ctx, execID, pspec, cio.LogFile(logPath))
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
		return readExecLog(logPath), st.ExitCode(), nil
	case <-ctx.Done():
		_ = proc.Kill(ctx, 9)
		return readExecLog(logPath), 0, ctx.Err()
	}
}

// readExecLog reads the exec's log file, tolerating the shim still flushing it:
// process exit and the last write to the log are not ordered, so an immediate
// read can come back empty. Commands that legitimately print nothing pay the
// full (short) wait.
func readExecLog(path string) string {
	deadline := time.Now().Add(time.Second)
	for {
		b, err := os.ReadFile(path)
		if (err == nil && len(b) > 0) || time.Now().After(deadline) {
			return string(b)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// httpdCmd serves a one-line body identifying the backend, so LB spread is
// observable from the client.
func httpdCmd(body string) []string {
	return []string{"sh", "-c", fmt.Sprintf(
		"mkdir -p /www && echo %s > /www/index.html && exec httpd -f -p %d -h /www", body, backendPort)}
}
