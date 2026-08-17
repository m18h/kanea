package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
)

// The daemon path: BuildKit in its native shape; a long-lived buildkitd running
// ROOTLESS as an unprivileged host user (via rootlesskit), driven by `buildctl`.
//
// This is the alternative to the privileged one-shot task the other phases
// measure. It trades one supervised daemon for: no privileged container, no root
// even on the host, and BuildKit's own cache/concurrency machinery.
const (
	bkUser   = "kanea-buildkit"
	bkSocket = "unix:///home/kanea-buildkit/run/buildkitd.sock"
	bkUnit   = "kanea-spike-buildkitd"
)

// buildctl drives the daemon the way Kanea's pipeline runner would: as root,
// over the daemon's unix socket, with an explicit timeout.
func buildctl(ctx context.Context, timeout time.Duration, args ...string) (string, int, time.Duration, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	full := append([]string{"--addr", bkSocket}, args...)
	cmd := exec.CommandContext(cctx, "buildctl", full...) // #nosec G204: spike
	cmd.Env = append(os.Environ(), "DOCKER_CONFIG=/home/"+bkUser+"/.docker")
	t0 := time.Now()
	out, err := cmd.CombinedOutput()
	dur := time.Since(t0)
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
		err = nil
	}
	return string(out), code, dur, err
}

// dockerfileName picks the build recipe the way Kanea's pipeline runner must:
// either filename is acceptable, and Containerfile wins when both are present
// (the Podman/buildah convention). BuildKit's frontend defaults to "Dockerfile",
// so anything else has to be passed explicitly as `--opt filename=`.
func dockerfileName(contextDir string) string {
	if _, err := os.Stat(contextDir + "/Containerfile"); err == nil {
		return "Containerfile"
	}
	return "Dockerfile"
}

func bkBuildArgs(contextDir, tag, metadataFile string, cache bool) []string {
	args := []string{"build",
		"--frontend", "dockerfile.v0",
		"--local", "context=" + contextDir,
		"--local", "dockerfile=" + contextDir,
		"--opt", "filename=" + dockerfileName(contextDir),
		"--output", fmt.Sprintf("type=image,name=%s,push=true,registry.insecure=true", tag),
		"--metadata-file", metadataFile,
		"--progress", "plain",
	}
	if cache {
		args = append(args,
			"--export-cache", fmt.Sprintf("type=registry,ref=%s,mode=max,registry.insecure=true", cacheRepo),
			"--import-cache", fmt.Sprintf("type=registry,ref=%s,registry.insecure=true", cacheRepo),
		)
	}
	return args
}

// phaseDaemon validates every property the task-based phases check, but against
// the rootless daemon; plus the two properties unique to the daemon shape:
// it must not run as root, and its resource cap is collective rather than
// per build.
func phaseDaemon(ctx context.Context, e *env) error {
	fmt.Println("\n── buildkit: rootless host daemon ──")

	// --- the daemon is alive and NOT root ---
	owner, _ := exec.Command("sh", "-c",
		`ps -o user= -p "$(pgrep -f 'buildkitd --addr' | head -1)"`).Output()
	daemonUser := strings.TrimSpace(string(owner))
	check("buildkitd runs as an unprivileged user (not root)",
		daemonUser == bkUser, fmt.Sprintf("daemon uid=%q socket=%s", daemonUser, bkSocket))

	out, code, _, err := buildctl(ctx, 30*time.Second, "debug", "workers")
	check("root can drive the daemon over its socket (kanead's path)",
		err == nil && code == 0 && strings.Contains(out, "PLATFORMS"),
		fmt.Sprintf("exit %d: %s", code, tailLog(out, 1)))

	// A rootless daemon uses its own snapshotter under $HOME, not containerd's.
	if fi, serr := os.Stat("/home/" + bkUser + "/.local/share/buildkit"); serr == nil && fi.IsDir() {
		info("build storage location",
			"/home/"+bkUser+"/.local/share/buildkit (daemon-owned, not containerd's snapshotter)")
	}

	// --- build + push + digest ---
	outDir := workDir + "/out/buildkitd"
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	metaFile := outDir + "/metadata.json"
	tag := regAddr + "/kanea/buildkitd-build:v1"

	out, code, dur, err := buildctl(ctx, 10*time.Minute, bkBuildArgs(ctxDir, tag, metaFile, false)...)
	check("rootless daemon builds and pushes (no privileged container anywhere)",
		err == nil && code == 0, fmt.Sprintf("%v; %s", dur.Round(time.Millisecond), tailLog(out, 1)))
	if code != 0 {
		return nil
	}

	digest, derr := registryDigest(ctx, tag)
	check("image is retrievable from the registry", derr == nil && digest != "",
		fmt.Sprintf("%s -> %s", tag, digest))

	reported := ""
	if raw, rerr := os.ReadFile(metaFile); rerr == nil {
		var meta map[string]any
		if json.Unmarshal(raw, &meta) == nil {
			reported, _ = meta["containerimage.digest"].(string)
		}
	}
	check("reports the produced image digest, pinnable by the deploy",
		strings.HasPrefix(reported, "sha256:"), reported)

	// --- cache ---
	cold := dur
	tag2 := regAddr + "/kanea/buildkitd-cache:v1"
	_, _, _, _ = buildctl(ctx, 10*time.Minute, bkBuildArgs(ctxDir, tag2, metaFile, true)...)
	tag3 := regAddr + "/kanea/buildkitd-cache2:v1"
	warmOut, warmCode, warm, _ := buildctl(ctx, 10*time.Minute, bkBuildArgs(ctxDir, tag3, metaFile, true)...)
	check("warm build reuses cached layers",
		warmCode == 0 && strings.Contains(warmOut, "CACHED"),
		fmt.Sprintf("cold %v -> warm %v", cold.Round(time.Millisecond), warm.Round(time.Millisecond)))

	// --- failure surfacing ---
	badTag := regAddr + "/kanea/buildkitd-bad:v1"
	badOut, badCode, _, _ := buildctl(ctx, 5*time.Minute, bkBuildArgs(badDir, badTag, metaFile, false)...)
	check("failing build exits non-zero with an actionable log",
		badCode != 0 && strings.Contains(badOut, "17"),
		fmt.Sprintf("exit %d: %s", badCode, tailLog(badOut, 1)))
	if d, err := registryDigest(ctx, badTag); err == nil && d != "" {
		check("nothing is pushed on failure", false, "image present: "+d)
	} else {
		check("nothing is pushed on failure", true, "registry has no such tag")
	}

	// --- Dockerfile / Containerfile: both must build ---
	cfTag := regAddr + "/kanea/buildkitd-containerfile:v1"
	cfOut, cfCode, _, _ := buildctl(ctx, 10*time.Minute,
		bkBuildArgs(workDir+"/context-containerfile", cfTag, metaFile, false)...)
	cfDigest, _ := registryDigest(ctx, cfTag)
	check("builds a context that has only a Containerfile",
		cfCode == 0 && cfDigest != "",
		fmt.Sprintf("exit %d -> %s", cfCode, firstNonEmpty(cfDigest, tailLog(cfOut, 1))))

	// Precedence when both exist: the image prints which recipe built it.
	bothTag := regAddr + "/kanea/buildkitd-both:v1"
	_, bothCode, _, _ := buildctl(ctx, 10*time.Minute,
		bkBuildArgs(workDir+"/context-both", bothTag, metaFile, false)...)
	which := ""
	if bothCode == 0 {
		which = runBuiltImage(ctx, e, bothTag)
	}
	check("Containerfile takes precedence when both are present",
		bothCode == 0 && strings.Contains(which, "containerfile-wins"),
		fmt.Sprintf("built image prints %q", strings.TrimSpace(which)))

	// --- resource isolation: collective, not per build ---
	// This is the real cost of the daemon shape. PRD §10.2 assumes a per-build
	// cgroup cap; with a daemon the cap belongs to the unit and every build
	// shares it, so concurrency must be bounded inside buildkitd instead.
	memMax := systemdProp(bkUnit, "MemoryMax")
	cpuQuota := systemdProp(bkUnit, "CPUQuotaPerSecUSec")
	capped := memMax != "" && memMax != "infinity"
	check("daemon runs under a systemd resource cap",
		capped, fmt.Sprintf("MemoryMax=%s CPUQuota=%s (COLLECTIVE: all builds share it)", memMax, cpuQuota))

	current := systemdProp(bkUnit, "MemoryCurrent")
	if n, cerr := strconv.ParseInt(current, 10, 64); cerr == nil {
		info("daemon resident cost", fmt.Sprintf("MemoryCurrent=%.1f MiB (permanent, unlike a one-shot task)",
			float64(n)/(1<<20)))
	}

	return nil
}

func systemdProp(unit, prop string) string {
	out, err := exec.Command("systemctl", "show", unit, "-p", prop, "--value").Output() // #nosec G204: spike
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// runBuiltImage pulls the freshly built image back through containerd and runs
// it, so the check asserts on what the image actually does rather than on build
// output. This is also the deploy path: pull by ref, run, observe.
func runBuiltImage(ctx context.Context, e *env, ref string) string {
	// The spike registry requires auth and speaks plain HTTP, so the pull needs
	// an explicit resolver: the same shape Kanea's runtime needs when pulling
	// from a private registry with credentials from the secret store.
	resolver := docker.NewResolver(docker.ResolverOptions{
		Hosts: docker.ConfigureDefaultRegistries(
			docker.WithPlainHTTP(func(string) (bool, error) { return true, nil }),
			docker.WithAuthorizer(docker.NewDockerAuthorizer(
				docker.WithAuthCreds(func(string) (string, string, error) {
					return regUser, regPass, nil
				}))),
		),
	})
	img, err := e.client.Pull(ctx, ref, containerd.WithPullUnpack, containerd.WithResolver(resolver))
	if err != nil {
		return "pull failed: " + err.Error()
	}
	id := "verify-" + fmt.Sprint(time.Now().UnixNano()%100000)
	removeContainer(ctx, e.client, id)
	defer removeContainer(ctx, e.client, id)

	logFile, err := os.CreateTemp("", "kanea-spike-verify-*.log")
	if err != nil {
		return err.Error()
	}
	logPath := logFile.Name()
	_ = logFile.Close()
	defer os.Remove(logPath)

	container, err := e.client.NewContainer(ctx, id,
		containerd.WithImage(img),
		containerd.WithNewSnapshot(id+"-snap", img),
		containerd.WithNewSpec(oci.WithImageConfig(img)),
	)
	if err != nil {
		return err.Error()
	}
	task, err := container.NewTask(ctx, cio.LogFile(logPath))
	if err != nil {
		return err.Error()
	}
	statusC, err := task.Wait(ctx)
	if err != nil {
		return err.Error()
	}
	if err := task.Start(ctx); err != nil {
		return err.Error()
	}
	select {
	case <-statusC:
	case <-time.After(60 * time.Second):
		_ = task.Kill(ctx, 9)
	}
	_, _ = task.Delete(ctx)
	out, _ := os.ReadFile(logPath)
	return string(out)
}
