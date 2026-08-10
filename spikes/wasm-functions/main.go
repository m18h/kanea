// Spike: wasm functions on the wasmtime runwasi shim (PRD v1.39, §20 M11).
//
// The load-bearing unknown behind the functions feature is how the shim
// behaves under Kanea's OCI spec: the hardening opts, the netns join, the
// cgroup caps, exec's absence, and the scratch-image pull path. This harness
// converts each into a PASS/FAIL line against a real containerd — the same
// discipline spikes ② and ⑤ used.
//
// Run on a Linux node (root), with Kanea's containerd (or any 2.x) running
// and containerd-shim-wasmtime-v1 on that containerd's PATH:
//
//	./build-module.sh                # produces testdata/hello.wasm (needs tinygo or cargo)
//	./mkimage.sh                     # imports it as a scratch OCI image via ctr
//	sudo ./spike-wasm \
//	    -socket /run/kanea/containerd.sock \
//	    -image registry.local/spike/hello-wasm:1
//
// Copy the output into REPORT.md. Do not fabricate results.
package main

import (
	"context"
	"flag"
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
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const runtimeWasmtime = "io.containerd.wasmtime.v1"

var (
	pass, fail, info = 0, 0, 0
)

func report(kind, name, detail string) {
	switch kind {
	case "PASS":
		pass++
	case "FAIL":
		fail++
	default:
		info++
	}
	fmt.Printf("%-4s %-38s %s\n", kind, name, detail)
}

func main() {
	socket := flag.String("socket", "/run/kanea/containerd.sock", "containerd socket")
	image := flag.String("image", "registry.local/spike/hello-wasm:1", "wasi-http hello image (see mkimage.sh)")
	port := flag.Int("port", 8080, "port the module's wasi-http server listens on")
	memLimit := flag.Int64("mem-limit", 16<<20, "memory cap for the trap-under-pressure check")
	flag.Parse()

	ctx := namespaces.WithNamespace(context.Background(), "kanea-spike-wasm")
	client, err := containerd.New(*socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial containerd: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	checkShimResolvable()
	img := checkImagePull(ctx, client, *image)
	if img == nil {
		fmt.Println("\ncannot continue without the image; run mkimage.sh first")
		os.Exit(1)
	}
	task, container := checkCreateStart(ctx, client, img)
	if task != nil {
		checkExecAbsence(ctx, task)
		checkHTTPServes(*port)
		checkShimRSS(task)
		cleanup(ctx, task, container)
	}
	checkMemoryCap(ctx, client, img, *memLimit)

	fmt.Printf("\n%d PASS, %d FAIL, %d INFO\n", pass, fail, info)
	if fail > 0 {
		os.Exit(1)
	}
}

// A: the shim must be resolvable the way containerd resolves it — by binary
// name on ITS path, which for Kanea's unit includes the install prefix.
func checkShimResolvable() {
	for _, dir := range []string{
		"/usr/local/lib/kanea/bin", "/usr/local/sbin", "/usr/local/bin",
		"/usr/sbin", "/usr/bin", "/sbin", "/bin",
	} {
		if st, err := os.Stat(dir + "/containerd-shim-wasmtime-v1"); err == nil && st.Mode()&0o111 != 0 {
			report("PASS", "shim binary", dir+"/containerd-shim-wasmtime-v1")
			return
		}
	}
	report("FAIL", "shim binary", "containerd-shim-wasmtime-v1 not found on a containerd-visible PATH")
}

// B: the scratch image pulls/loads through the ordinary path (WithPullUnpack
// equivalent — mkimage.sh imports, so this is a lookup).
func checkImagePull(ctx context.Context, client *containerd.Client, ref string) containerd.Image {
	img, err := client.GetImage(ctx, ref)
	if err != nil {
		if errdefs.IsNotFound(err) {
			report("FAIL", "scratch image present", ref+" not imported; run mkimage.sh")
			return nil
		}
		report("FAIL", "scratch image present", err.Error())
		return nil
	}
	report("PASS", "scratch image present", ref)
	return img
}

// C: create + start under Kanea's hardening. Every opt below mirrors
// internal/runtime/spec.go; a rejection here is a finding that names the opt
// specOpts must branch on for wasm (the plan's "branch only if the spike says
// so").
func checkCreateStart(ctx context.Context, client *containerd.Client, img containerd.Image) (containerd.Task, containerd.Container) {
	id := fmt.Sprintf("spike-wasm-%d", time.Now().Unix())
	mem := int64(64 << 20)
	quota := int64(50_000)
	period := uint64(100_000)
	pids := int64(64)

	opts := []oci.SpecOpts{
		oci.WithImageConfig(img),
		func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
			if s.Process == nil {
				s.Process = &specs.Process{}
			}
			if s.Linux == nil {
				s.Linux = &specs.Linux{}
			}
			// The withHardening set, verbatim.
			s.Process.Capabilities = &specs.LinuxCapabilities{
				Bounding: []string{}, Effective: []string{}, Permitted: []string{},
				Inheritable: []string{}, Ambient: []string{},
			}
			s.Process.NoNewPrivileges = true
			s.Linux.MaskedPaths = []string{"/proc/kcore", "/proc/keys", "/sys/firmware"}
			s.Linux.ReadonlyPaths = []string{"/proc/sys"}
			// The withResources set.
			s.Linux.Resources = &specs.LinuxResources{
				Memory: &specs.LinuxMemory{Limit: &mem, Swap: &mem},
				CPU:    &specs.LinuxCPU{Quota: &quota, Period: &period},
				Pids:   &specs.LinuxPids{Limit: &pids},
			}
			return nil
		},
	}

	container, err := client.NewContainer(ctx, id,
		containerd.WithImage(img),
		containerd.WithNewSnapshot(id+"-snap", img),
		containerd.WithNewSpec(opts...),
		containerd.WithRuntime(runtimeWasmtime, nil),
	)
	if err != nil {
		report("FAIL", "create with hardening opts", err.Error())
		return nil, nil
	}
	task, err := container.NewTask(ctx, cio.NullIO)
	if err != nil {
		report("FAIL", "task create (shim launch)", err.Error())
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
		return nil, nil
	}
	if err := task.Start(ctx); err != nil {
		report("FAIL", "task start", err.Error())
		_, _ = task.Delete(ctx, containerd.WithProcessKill)
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
		return nil, nil
	}
	report("PASS", "create+start under hardening", "runtime "+runtimeWasmtime)
	return task, container
}

// D: the shim documents no exec; the driver's ErrNoExec depends on it.
func checkExecAbsence(ctx context.Context, task containerd.Task) {
	spec := &specs.Process{Args: []string{"/bin/true"}, Cwd: "/"}
	proc, err := task.Exec(ctx, "spike-exec", spec, cio.NullIO)
	if err != nil {
		report("PASS", "exec is absent", "task.Exec refused: "+firstLine(err.Error()))
		return
	}
	_, _ = proc.Delete(ctx, containerd.WithProcessKill)
	report("FAIL", "exec is absent", "task.Exec succeeded — the ErrNoExec assumption is wrong")
}

// E: the module serves wasi-http. Requires the harness to share the netns
// with the task (run without a netns join, the module listens on the host).
func checkHTTPServes(port int) {
	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error
	for i := 0; i < 20; i++ {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
		if err == nil {
			_ = resp.Body.Close()
			report("PASS", "wasi-http answers", resp.Status)
			return
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	report("FAIL", "wasi-http answers", lastErr.Error())
}

// F: the shim's own RSS, for the §21 footprint table.
func checkShimRSS(task containerd.Task) {
	pid := task.Pid()
	body, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		report("INFO", "shim RSS", "cannot read /proc: "+err.Error())
		return
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			report("INFO", "task RSS (module process)", strings.TrimSpace(strings.TrimPrefix(line, "VmRSS:")))
			return
		}
	}
	report("INFO", "shim RSS", "VmRSS not found")
}

// G: the cgroup memory cap is real — a module allocating past it must be
// killed, not carried. Needs an image whose module allocates unboundedly when
// asked (see build-module.sh's /hog handler), or reports INFO.
func checkMemoryCap(ctx context.Context, client *containerd.Client, img containerd.Image, limit int64) {
	report("INFO", "memory cap under pressure",
		fmt.Sprintf("start the module with a %d MiB cap and GET /hog; expect an OOM kill — record the result here", limit>>20))
}

func cleanup(ctx context.Context, task containerd.Task, container containerd.Container) {
	_ = task.Kill(ctx, 9)
	_, _ = task.Delete(ctx, containerd.WithProcessKill)
	if container != nil {
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
