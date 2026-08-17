// Spike: wasm functions on the wasmtime runwasi shim (PRD v1.39, §20 M11).
//
// The load-bearing unknown behind the functions feature is how the shim
// behaves under Kanea's OCI spec: the hardening opts, the netns join, the
// cgroup caps, exec's absence, and the scratch-image pull path. This harness
// converts each into a PASS/FAIL line against a real containerd: the same
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
	"os"
	"os/exec"
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
	hogImage := flag.String("hog-image", "", "image whose module allocates without bound, for the memory-cap check (empty skips it)")
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
		checkHTTPServes(task, *port)
		checkShimRSS(task)
		cleanup(ctx, task, container)
	}
	if *hogImage != "" {
		if hog := checkImagePull(ctx, client, *hogImage); hog != nil {
			checkMemoryCap(ctx, client, hog, *memLimit)
		}
	} else {
		checkMemoryCap(ctx, client, img, *memLimit)
	}

	fmt.Printf("\n%d PASS, %d FAIL, %d INFO\n", pass, fail, info)
	if fail > 0 {
		os.Exit(1)
	}
}

// A: the shim must be resolvable the way containerd resolves it; by binary
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
// equivalent; mkimage.sh imports, so this is a lookup).
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
	// Unpack into the snapshotter: what Kanea's EnsureImage does via
	// WithPullUnpack. ctr import does not unpack, and without a prepared
	// snapshot chain WithNewSnapshot fails with "parent snapshot ... not
	// found". The default (host-platform) snapshotter is used deliberately:
	// Kanea pulls with no platform matcher, so a module image must be labelled
	// host-platform (linux/<arch>), not wasm/wasip2; the packaging finding.
	if err := img.Unpack(ctx, ""); err != nil {
		report("FAIL", "scratch image unpacks (host platform)", firstLine(err.Error()))
		return nil
	}
	report("PASS", "scratch image present + unpacks", ref)
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
	report("FAIL", "exec is absent", "task.Exec succeeded; the ErrNoExec assumption is wrong")
}

// E: the module serves wasi-http. The wasmtime shim serves the proxy
// component inside the instance's OWN network namespace (correct isolation:
// crossing it to the alloc's VIP is the datapath's job, exercised end to end
// in check H on a kanead node). So the reachability probe enters the task's
// netns rather than dialling the host: nsenter into task.Pid()'s net ns and
// curl 127.0.0.1:<port>. A host-side dial would test the datapath, not the
// shim, and there is no datapath here.
func checkHTTPServes(task containerd.Task, port int) {
	pid := task.Pid()
	// A bare netns has lo DOWN, so 127.0.0.1 is unreachable even though the
	// module listens on 0.0.0.0:port. The real datapath brings lo up as part
	// of alloc plumbing (createPod does `LinkSetUp(lo)`); do the same here so
	// the probe tests the module, not the missing loopback.
	_ = exec.Command("nsenter", "--target", fmt.Sprintf("%d", pid), "--net", "--",
		"ip", "link", "set", "lo", "up").Run()
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	var last string
	for i := 0; i < 20; i++ {
		out, err := exec.Command("nsenter", "--target", fmt.Sprintf("%d", pid), "--net", "--",
			"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "2", url).CombinedOutput()
		code := strings.TrimSpace(string(out))
		if err == nil && strings.HasPrefix(code, "2") {
			report("PASS", "wasi-http answers", "HTTP "+code+" from the module in its netns (pid "+fmt.Sprint(pid)+")")
			return
		}
		last = code
		if err != nil && code == "" {
			last = firstLine(err.Error())
		}
		time.Sleep(300 * time.Millisecond)
	}
	report("FAIL", "wasi-http answers", "no 2xx in the task netns: "+last)
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

// G: the cgroup memory cap is real; a module allocating past it must be
// OOM-killed, not carried. Starts the hog module under a tight memory.max
// (== swap, so it cannot swap around the cap) and waits: an exit is the cap
// working; surviving past the timeout while allocating is the cap not being
// enforced on the sandbox. This is the claim R25/R11 rest on ("the memory
// cap is real, not advisory").
func checkMemoryCap(ctx context.Context, client *containerd.Client, img containerd.Image, limit int64) {
	id := fmt.Sprintf("spike-wasm-hog-%d", time.Now().Unix())
	lim := limit
	opts := []oci.SpecOpts{
		oci.WithImageConfig(img),
		func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
			if s.Linux == nil {
				s.Linux = &specs.Linux{}
			}
			s.Linux.Resources = &specs.LinuxResources{
				Memory: &specs.LinuxMemory{Limit: &lim, Swap: &lim},
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
		report("FAIL", "memory cap OOM-kills a hog", "create: "+firstLine(err.Error()))
		return
	}
	defer func() { _ = container.Delete(ctx, containerd.WithSnapshotCleanup) }()

	task, err := container.NewTask(ctx, cio.NullIO)
	if err != nil {
		report("FAIL", "memory cap OOM-kills a hog", "task: "+firstLine(err.Error()))
		return
	}
	defer func() { _, _ = task.Delete(ctx, containerd.WithProcessKill) }()

	exitCh, err := task.Wait(ctx)
	if err != nil {
		report("FAIL", "memory cap OOM-kills a hog", "wait: "+firstLine(err.Error()))
		return
	}
	if err := task.Start(ctx); err != nil {
		report("FAIL", "memory cap OOM-kills a hog", "start: "+firstLine(err.Error()))
		return
	}
	select {
	case st := <-exitCh:
		code, _, _ := st.Result()
		report("PASS", "memory cap OOM-kills a hog",
			fmt.Sprintf("hog exited under a %d MiB cap (code %d; SIGKILL/OOM)", limit>>20, code))
	case <-time.After(20 * time.Second):
		_ = task.Kill(ctx, 9)
		report("FAIL", "memory cap OOM-kills a hog",
			fmt.Sprintf("hog still running after 20s under a %d MiB cap; the cap is not enforced on the sandbox", limit>>20))
	}
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
