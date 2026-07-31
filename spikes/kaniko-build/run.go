package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	regUser = "kanea"
	regPass = "kaneabuild" // #nosec G101 — local spike registry
)

type env struct {
	client *containerd.Client
}

func setup(ctx context.Context) (*env, context.Context, error) {
	client, err := containerd.New(containerdSock)
	if err != nil {
		return nil, ctx, fmt.Errorf("dial %s: %w", containerdSock, err)
	}
	if err := waitRegistry(ctx, 60*time.Second); err != nil {
		client.Close()
		return nil, ctx, err
	}
	return &env{client: client}, namespaces.WithNamespace(ctx, ctrNamespace), nil
}

// waitRegistry blocks until the spike registry answers, so a build never races
// a registry restart (`clean` restarts it with empty storage).
func waitRegistry(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+regAddr+"/v2/", nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("registry %s not reachable: %w", regAddr, last)
}

// privilege models the three security postures a build task could run under.
// Kanea's workload default (PRD §14 / AGENTS.md #6) is `hardened`; anything a
// builder needs beyond that is a documented exception for build tasks only.
type privilege int

const (
	privHardened   privilege = iota // drop ALL capabilities + no-new-privileges
	privDefault                     // containerd's default capability set
	privPrivileged                  // all capabilities, nothing masked
)

func (p privilege) String() string {
	switch p {
	case privHardened:
		return "hardened (drop ALL caps + no-new-privs)"
	case privDefault:
		return "default caps"
	default:
		return "privileged"
	}
}

type runOpts struct {
	priv     privilege
	memLimit int64 // bytes; 0 = unlimited
	cpuQuota int64 // per 100ms period; 0 = unlimited
	cgroup   string
}

type runResult struct {
	dur      time.Duration
	exitCode uint32
	logs     string
}

// runBuilder runs one build as a short-lived containerd task, exactly as
// Kanea's pipeline runner would: no Docker socket, no daemon, logs captured
// through containerd IO, exit code observed.
func runBuilder(ctx context.Context, e *env, b *builder, r buildReq, o runOpts) (runResult, error) {
	id := fmt.Sprintf("build-%s-%d", b.Name, time.Now().UnixNano()%100000)
	removeContainer(ctx, e.client, id)
	defer removeContainer(ctx, e.client, id)

	if err := os.MkdirAll(r.OutDir, 0o777); err != nil { // #nosec G301 — rootless builders write here
		return runResult{}, err
	}
	_ = os.Chmod(r.OutDir, 0o777) // #nosec G302 — buildkit-rootless runs as uid 1000

	img, err := e.client.GetImage(ctx, b.Image)
	if err != nil {
		return runResult{}, fmt.Errorf("image %s not pulled: %w", b.Image, err)
	}

	mounts := b.mounts(r)
	// Builders need to resolve registry.docker.io for the base image.
	mounts = append(mounts, roMount("/etc/resolv.conf", "/etc/resolv.conf"))

	specOpts := []oci.SpecOpts{
		oci.WithImageConfig(img),
		oci.WithProcessArgs(b.argv(r)...),
		oci.WithEnv(b.env(r)),
		oci.WithMounts(mounts),
		// Host networking: the spike registry lives on the node's loopback.
		// A real deployment gives the build task a CNI endpoint instead.
		oci.WithHostNamespace(specs.NetworkNamespace),
	}
	if b.runAsRoot {
		specOpts = append(specOpts, oci.WithUser("0:0"))
	}
	switch o.priv {
	case privHardened:
		specOpts = append(specOpts, oci.WithCapabilities([]string{}), oci.WithNoNewPrivileges)
	case privPrivileged:
		specOpts = append(specOpts, oci.WithPrivileged, oci.WithAllDevicesAllowed)
	}
	if o.memLimit > 0 || o.cpuQuota > 0 || o.cgroup != "" {
		specOpts = append(specOpts, withResources(o))
	}

	container, err := e.client.NewContainer(ctx, id,
		containerd.WithImage(img),
		containerd.WithNewSnapshot(id+"-snap", img),
		containerd.WithNewSpec(specOpts...),
	)
	if err != nil {
		return runResult{}, fmt.Errorf("new container: %w", err)
	}

	logFile, err := os.CreateTemp("", "kanea-spike-build-*.log")
	if err != nil {
		return runResult{}, err
	}
	logPath := logFile.Name()
	_ = logFile.Close()
	defer os.Remove(logPath)

	task, err := container.NewTask(ctx, cio.LogFile(logPath))
	if err != nil {
		return runResult{}, fmt.Errorf("new task: %w", err)
	}
	statusC, err := task.Wait(ctx)
	if err != nil {
		return runResult{}, err
	}
	t0 := time.Now()
	if err := task.Start(ctx); err != nil {
		return runResult{}, fmt.Errorf("start task: %w", err)
	}

	var res runResult
	select {
	case st := <-statusC:
		res.dur = time.Since(t0)
		res.exitCode = st.ExitCode()
	case <-time.After(15 * time.Minute):
		_ = task.Kill(ctx, 9)
		res.dur = time.Since(t0)
		res.exitCode = 255
	}
	_, _ = task.Delete(ctx)
	b2, _ := os.ReadFile(logPath)
	res.logs = string(b2)
	return res, nil
}

// withResources applies PRD §10.2 build isolation: builds get hard CPU/memory
// caps so they cannot starve workloads.
func withResources(o runOpts) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if s.Linux == nil {
			s.Linux = &specs.Linux{}
		}
		if s.Linux.Resources == nil {
			s.Linux.Resources = &specs.LinuxResources{}
		}
		if o.memLimit > 0 {
			limit := o.memLimit
			s.Linux.Resources.Memory = &specs.LinuxMemory{Limit: &limit, Swap: &limit}
		}
		if o.cpuQuota > 0 {
			period := uint64(100000)
			quota := o.cpuQuota
			s.Linux.Resources.CPU = &specs.LinuxCPU{Quota: &quota, Period: &period}
		}
		if o.cgroup != "" {
			s.Linux.CgroupsPath = o.cgroup
		}
		return nil
	}
}

func removeContainer(ctx context.Context, client *containerd.Client, id string) {
	c, err := client.LoadContainer(ctx, id)
	if err != nil {
		return
	}
	if task, err := c.Task(ctx, nil); err == nil {
		_, _ = task.Delete(ctx, containerd.WithProcessKill)
	}
	_ = c.Delete(ctx, containerd.WithSnapshotCleanup)
}

// ---- registry helpers: proof that the push actually landed ----

func registryDigest(ctx context.Context, ref string) (string, error) {
	name, tag, ok := strings.Cut(strings.TrimPrefix(ref, regAddr+"/"), ":")
	if !ok {
		return "", fmt.Errorf("cannot split %q", ref)
	}
	url := fmt.Sprintf("http://%s/v2/%s/manifests/%s", regAddr, name, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(regUser+":"+regPass)))
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
	}, ", "))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp.Header.Get("Docker-Content-Digest"), nil
}

func registryTags(ctx context.Context, name string) (string, error) {
	url := fmt.Sprintf("http://%s/v2/%s/tags/list", regAddr, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(regUser+":"+regPass)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return fmt.Sprintf("%s %s", resp.Status, strings.TrimSpace(string(buf[:n]))), nil
}

func tailLog(s string, lines int) string {
	parts := strings.Split(strings.TrimSpace(s), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	out := strings.Join(parts, " | ")
	if len(out) > 200 {
		out = out[len(out)-200:]
	}
	return out
}
