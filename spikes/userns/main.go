// Spike ⑧: user namespaces for workload allocs (PRD §19.3, THREAT_MODEL §7).
//
// The parked question behind the "real isolation bump": can a Kanea-shaped
// alloc run in a user namespace - container uid 0 an unprivileged host uid -
// on Kanea's pinned containerd, with the pre-created netns, the full
// hardening opt set, a rootfs whose ownership is correct, and the host-side
// ownership arithmetic (R24 volume chown, the secrets tmpfs) shifted by the
// map? And what breaks: the PUID image class, and host grants that cannot be
// honoured under a map (the R21 refusal the feature would carry).
//
// Run on a Linux node (root) with Kanea's containerd running:
//
//	GOOS=linux go build -o spike-linux .
//	sudo ./spike-linux -socket /run/kanea/containerd.sock
//	sudo ./spike-linux clean          # removes everything the spike made
//
// Copy the output into REPORT.md. Nothing here ships. Do not fabricate
// results.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	spikeNamespace = "kanea-spike-userns"
	scratchRoot    = "/tmp/kanea-spike-userns"
	netnsMain      = "spike-userns-net"
	netnsPUID      = "spike-userns-net2"
	// The map: one contiguous range, clear of the buildkit subuid range at
	// 200000. OCI-spec-only; the spike never writes /etc/subuid (root runc
	// applies mappings without newuidmap).
	mapBase uint32 = 300000
	mapLen  uint32 = 65536
)

var pass, fail, info = 0, 0, 0

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
	image := flag.String("image", "docker.io/library/alpine:3.20", "probe image (needs busybox applets)")
	puidImage := flag.String("puid-image", "lscr.io/linuxserver/nginx:latest",
		"a PUID/s6 image for check H (empty skips it)")
	flag.Parse()

	ctx := namespaces.WithNamespace(context.Background(), spikeNamespace)
	client, err := containerd.New(*socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial containerd: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	if flag.Arg(0) == "clean" {
		clean(ctx, client, *image, *puidImage)
		return
	}

	checkIdmapCapability(ctx, client)

	img := pullImage(ctx, client, *image)
	if img == nil {
		fmt.Println("\ncannot continue without the probe image")
		os.Exit(1)
	}
	if err := setupScratch(); err != nil {
		fmt.Fprintf(os.Stderr, "scratch setup: %v\n", err)
		os.Exit(1)
	}
	if err := createNetns(netnsMain); err != nil {
		report("FAIL", "pre-created netns", err.Error())
		os.Exit(1)
	}

	task, container := checkCreateStart(ctx, client, img)
	if task != nil {
		checkMapIsReal(ctx, task, container)
		checkNetnsForeignOwned(ctx, task, container)
		checkPortFloor(ctx, task, container)
		checkVolumeChownArithmetic(ctx, task, container)
		checkSecretsShape(ctx, task, container)
		checkUnmappedGrant(ctx, task, container)
		teardown(ctx, task, container)
	}

	if *puidImage != "" {
		checkPUIDImage(ctx, client, *puidImage)
	} else {
		report("INFO", "PUID image under a map", "skipped (-puid-image empty)")
	}

	fmt.Printf("\n%d PASS, %d FAIL, %d INFO\n", pass, fail, info)
	if fail > 0 {
		os.Exit(1)
	}
}

// A: which rootfs strategy this node supports. The overlay snapshotter
// advertises "remap-ids" when the kernel can idmap its mounts (≥ 5.19 for
// overlayfs); without it, containerd's client falls back to a recursive-chown
// copy of the snapshot, which works everywhere and costs time and disk. The
// feature's kernel gate hangs off this answer.
func checkIdmapCapability(ctx context.Context, client *containerd.Client) {
	if uname, err := exec.Command("uname", "-r").Output(); err == nil {
		report("INFO", "kernel", strings.TrimSpace(string(uname)))
	}
	if v, err := client.Version(ctx); err == nil {
		report("INFO", "containerd", v.Version)
	}
	capabs, err := client.GetSnapshotterCapabilities(ctx, defaults.DefaultSnapshotter)
	if err != nil {
		report("INFO", "snapshotter capabilities", "unreadable: "+firstLine(err.Error()))
		return
	}
	for _, c := range capabs {
		if c == "remap-ids" {
			report("PASS", "idmapped snapshots available",
				defaults.DefaultSnapshotter+" advertises remap-ids (no chown copy needed)")
			return
		}
	}
	report("INFO", "idmapped snapshots available",
		fmt.Sprintf("%s capabilities %v: no remap-ids; the chown-copy fallback will be used",
			defaults.DefaultSnapshotter, capabs))
}

func pullImage(ctx context.Context, client *containerd.Client, ref string) containerd.Image {
	img, err := client.GetImage(ctx, ref)
	if err == nil {
		report("INFO", "image", ref+" (already present)")
		return img
	}
	if !errdefs.IsNotFound(err) {
		report("FAIL", "image", err.Error())
		return nil
	}
	img, err = client.Pull(ctx, ref, containerd.WithPullUnpack)
	if err != nil {
		report("FAIL", "image pull", firstLine(err.Error()))
		return nil
	}
	report("INFO", "image", ref+" (pulled)")
	return img
}

func setupScratch() error {
	for _, d := range []string{"scratch", "vol-mapped", "vol-unmapped", "secrets", "grant", "config"} {
		if err := os.MkdirAll(filepath.Join(scratchRoot, d), 0o755); err != nil {
			return err
		}
	}
	// F: the R24 arithmetic pair. A dir chowned base+999 is the shifted chown
	// the feature would perform; one chowned plain 999 is today's arithmetic,
	// which must NOT work under a map.
	if err := os.Chown(filepath.Join(scratchRoot, "vol-mapped"), int(mapBase)+999, int(mapBase)+999); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(scratchRoot, "vol-mapped"), 0o700); err != nil {
		return err
	}
	if err := os.Chown(filepath.Join(scratchRoot, "vol-unmapped"), 999, 999); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(scratchRoot, "vol-unmapped"), 0o700); err != nil {
		return err
	}
	// G: the secrets shape - materializeSecrets writes 0400 owned by the
	// reading uid; under a map that uid is base+uid on the host.
	secret := filepath.Join(scratchRoot, "secrets", "token")
	if err := os.WriteFile(secret, []byte("s3cr3t\n"), 0o400); err != nil {
		return err
	}
	if err := os.Chown(secret, int(mapBase)+999, int(mapBase)+999); err != nil {
		return err
	}
	// I: a host grant nobody mapped - a root-owned socket and a 0600 file,
	// the shape a socket grant bind-mounts today.
	sockPath := filepath.Join(scratchRoot, "grant", "host.sock")
	_ = os.Remove(sockPath)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	// Held open for the process's life; clean removes the path.
	_ = l
	if err := os.WriteFile(filepath.Join(scratchRoot, "grant", "cred"), []byte("host-only\n"), 0o600); err != nil {
		return err
	}
	// H: the PUID image's /config, owned by the mapped container root: the
	// image's own init chowns below it to PUID.
	if err := os.Chown(filepath.Join(scratchRoot, "config"), int(mapBase), int(mapBase)); err != nil {
		return err
	}
	return nil
}

// createNetns is internal/runtime.CreateNetns's exact shape: `ip netns add`
// (persistent bind under /run/netns) then lo up inside - what kanead does
// before any task exists.
func createNetns(name string) error {
	_ = exec.Command("ip", "netns", "del", name).Run()
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		return fmt.Errorf("ip netns add: %v: %s", err, out)
	}
	if out, err := exec.Command("ip", "netns", "exec", name, "ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		return fmt.Errorf("lo up: %v: %s", err, out)
	}
	return nil
}

func idMaps() ([]specs.LinuxIDMapping, []specs.LinuxIDMapping) {
	m := []specs.LinuxIDMapping{{ContainerID: 0, HostID: mapBase, Size: mapLen}}
	return m, m
}

func bind(dst, src string, ro bool) specs.Mount {
	opts := []string{"rbind", "nosuid", "nodev"}
	if ro {
		opts = append(opts, "ro")
	}
	return specs.Mount{Destination: dst, Type: "bind", Source: src, Options: opts}
}

// B: create + start under the full Kanea opt set plus the user namespace.
// The snapshot goes through containerd's remapper labels, which select
// idmapped mounts where the snapshotter supports them and a client-side
// chown copy where it does not; the prep time is recorded either way,
// because it is the cost a deploy would pay per alloc create.
func checkCreateStart(ctx context.Context, client *containerd.Client, img containerd.Image) (containerd.Task, containerd.Container) {
	id := fmt.Sprintf("spike-userns-%d", time.Now().Unix())
	uidMaps, gidMaps := idMaps()

	mounts := []specs.Mount{
		bind("/scratch", filepath.Join(scratchRoot, "scratch"), false),
		bind("/vol-mapped", filepath.Join(scratchRoot, "vol-mapped"), false),
		bind("/vol-unmapped", filepath.Join(scratchRoot, "vol-unmapped"), false),
		bind("/secrets", filepath.Join(scratchRoot, "secrets"), true),
		bind("/grant", filepath.Join(scratchRoot, "grant"), true),
	}
	opts := []oci.SpecOpts{
		oci.WithImageConfig(img),
		oci.WithProcessArgs("sleep", "3600"),
		withKaneaHardening(id, compatBaseline, "/run/netns/"+netnsMain, mounts),
		oci.WithUserNamespace(uidMaps, gidMaps),
	}

	start := time.Now()
	container, err := client.NewContainer(ctx, id,
		containerd.WithImage(img),
		containerd.WithNewSnapshot(id+"-snap", img, containerd.WithUserNSRemapperLabels(uidMaps, gidMaps)),
		containerd.WithNewSpec(opts...),
	)
	if err != nil {
		report("FAIL", "create under hardening + userns", firstLine(err.Error()))
		return nil, nil
	}
	prep := time.Since(start)

	task, err := container.NewTask(ctx, cio.NullIO)
	if err != nil {
		report("FAIL", "task create (userns)", firstLine(err.Error()))
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
		return nil, nil
	}
	if err := task.Start(ctx); err != nil {
		report("FAIL", "task start (userns)", firstLine(err.Error()))
		_, _ = task.Delete(ctx, containerd.WithProcessKill)
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
		return nil, nil
	}
	report("PASS", "create+start under hardening + userns",
		fmt.Sprintf("map 0:%d:%d", mapBase, mapLen))
	report("INFO", "snapshot prep (create call)", prep.Round(time.Millisecond).String())
	return task, container
}

var execSeq int

// execIn runs one command inside the running container as the given uid/gid,
// the driver's exec shape: copy the container's own process spec, replace
// Args (and here User, which is how the R24/G probes impersonate the
// workload's uid). Returns the exit code and combined output.
func execIn(ctx context.Context, task containerd.Task, container containerd.Container, uid uint32, args ...string) (uint32, string, error) {
	spec, err := container.Spec(ctx)
	if err != nil {
		return 0, "", err
	}
	proc := *spec.Process
	proc.Args = args
	proc.User = specs.User{UID: uid, GID: uid}

	execSeq++
	var out bytes.Buffer
	p, err := task.Exec(ctx, fmt.Sprintf("spike-exec-%d", execSeq), &proc,
		cio.NewCreator(cio.WithStreams(nil, &out, &out)))
	if err != nil {
		return 0, "", err
	}
	defer p.Delete(ctx) //nolint:errcheck
	exitCh, err := p.Wait(ctx)
	if err != nil {
		return 0, "", err
	}
	if err := p.Start(ctx); err != nil {
		return 0, "", err
	}
	select {
	case st := <-exitCh:
		code, _, err := st.Result()
		if ioc := p.IO(); ioc != nil {
			ioc.Wait()
		}
		return code, strings.TrimSpace(out.String()), err
	case <-time.After(30 * time.Second):
		_ = p.Kill(ctx, 9)
		return 0, strings.TrimSpace(out.String()), fmt.Errorf("exec timed out")
	}
}

// C (and J): the map is real, in both directions, and exec works. The host
// sees the task as mapBase; the task sees itself as 0; a file it writes to a
// bind mount lands on the host owned by mapBase.
func checkMapIsReal(ctx context.Context, task containerd.Task, container containerd.Container) {
	body, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", task.Pid()))
	if err != nil {
		report("FAIL", "host uid is mapped", "cannot read /proc: "+err.Error())
	} else {
		hostUID := ""
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				hostUID = strings.Fields(line)[1]
				break
			}
		}
		if hostUID == fmt.Sprint(mapBase) {
			report("PASS", "host uid is mapped", "task Uid on the host is "+hostUID)
		} else {
			report("FAIL", "host uid is mapped",
				fmt.Sprintf("task Uid on the host is %s, want %d", hostUID, mapBase))
		}
	}

	code, out, err := execIn(ctx, task, container, 0, "id", "-u")
	switch {
	case err != nil:
		report("FAIL", "exec into the userns task", err.Error())
		return
	default:
		report("PASS", "exec into the userns task", "the driver's copy-the-process-spec shape works")
	}
	if code == 0 && out == "0" {
		report("PASS", "container root is uid 0 inside", "id -u = 0")
	} else {
		report("FAIL", "container root is uid 0 inside", fmt.Sprintf("id -u = %q (exit %d)", out, code))
	}

	if code, out, err := execIn(ctx, task, container, 0, "touch", "/scratch/probe"); err != nil || code != 0 {
		report("FAIL", "a written file is mapped on the host", fmt.Sprintf("touch: exit %d %s %v", code, out, err))
	} else if st, err := os.Stat(filepath.Join(scratchRoot, "scratch", "probe")); err != nil {
		report("FAIL", "a written file is mapped on the host", err.Error())
	} else {
		uid := hostUIDOf(st)
		if uid == int(mapBase) {
			report("PASS", "a written file is mapped on the host", fmt.Sprintf("host owner is %d", uid))
		} else {
			report("FAIL", "a written file is mapped on the host",
				fmt.Sprintf("host owner is %d, want %d", uid, mapBase))
		}
	}
}

// D: the task joined the netns kanead pre-created, and cannot modify it: the
// netns belongs to the init user namespace, so the container's in-namespace
// CAP_NET_ADMIN (which the baseline does not even grant) counts for nothing.
func checkNetnsForeignOwned(ctx context.Context, task containerd.Task, container containerd.Container) {
	code, out, err := execIn(ctx, task, container, 0, "ip", "link", "show", "lo")
	if err != nil || code != 0 || !strings.Contains(out, "UP") {
		report("FAIL", "joins the pre-created netns", fmt.Sprintf("lo not up inside: exit %d %s %v", code, out, err))
		return
	}
	report("PASS", "joins the pre-created netns", "lo is up inside the joined netns")

	code, out, _ = execIn(ctx, task, container, 0, "ip", "link", "set", "lo", "down")
	if code != 0 {
		report("PASS", "cannot modify the foreign-owned netns", "ip link set lo down refused: "+firstLine(out))
	} else {
		report("FAIL", "cannot modify the foreign-owned netns", "the mapped root downed lo")
	}
}

// E: the port floor under a foreign-owned netns. The bind check is
// ns_capable(net->user_ns, CAP_NET_BIND_SERVICE): the netns belongs to init,
// the container's capability lives in its own userns, so with the netns's
// default floor a mapped root cannot bind :80 at all - and with v1.103's
// ip_unprivileged_port_start=0 it can. The sysctl kanead already writes is
// load-bearing for userns, not a convenience.
func checkPortFloor(ctx context.Context, task containerd.Task, container containerd.Container) {
	// busybox httpd: parent exits 0 once the daemonized child has bound, and
	// non-zero when the bind fails, which is exactly the probe shape needed.
	code, out, err := execIn(ctx, task, container, 0, "httpd", "-p", "127.0.0.1:8080", "-h", "/tmp")
	if err != nil || code != 0 {
		report("FAIL", "unprivileged bind in the netns", fmt.Sprintf("httpd :8080: exit %d %s %v", code, out, err))
		return
	}
	report("PASS", "unprivileged bind in the netns", ":8080 binds (netns + lo work end to end)")

	code, out, _ = execIn(ctx, task, container, 0, "httpd", "-p", "127.0.0.1:80", "-h", "/tmp")
	if code != 0 {
		report("PASS", "the default floor blocks :80 for mapped root", firstLine(out))
	} else {
		report("FAIL", "the default floor blocks :80 for mapped root",
			"bound :80 under the netns default floor; the ownership reasoning is wrong")
	}

	if out, err := exec.Command("ip", "netns", "exec", netnsMain, "sh", "-c",
		"echo 0 > /proc/sys/net/ipv4/ip_unprivileged_port_start").CombinedOutput(); err != nil {
		report("FAIL", "v1.103 floor sysctl in the netns", fmt.Sprintf("%v: %s", err, out))
		return
	}
	code, out, _ = execIn(ctx, task, container, 0, "httpd", "-p", "127.0.0.1:80", "-h", "/tmp")
	if code == 0 {
		report("PASS", "ip_unprivileged_port_start=0 restores :80", "the v1.103 sysctl is load-bearing under userns")
	} else {
		report("FAIL", "ip_unprivileged_port_start=0 restores :80", firstLine(out))
	}
}

// F: the R24 chown arithmetic. The host dir chowned base+999 must be
// writable by container uid 999 (the shifted chown the feature would do);
// the one chowned plain 999 - today's arithmetic - must not be.
func checkVolumeChownArithmetic(ctx context.Context, task containerd.Task, container containerd.Container) {
	code, out, err := execIn(ctx, task, container, 999, "touch", "/vol-mapped/ok")
	if err == nil && code == 0 {
		report("PASS", "shifted chown (base+999) is writable", "uid 999 wrote its volume")
	} else {
		report("FAIL", "shifted chown (base+999) is writable", fmt.Sprintf("exit %d %s %v", code, out, err))
	}

	code, out, _ = execIn(ctx, task, container, 999, "touch", "/vol-unmapped/no")
	if code != 0 {
		report("PASS", "today's chown (plain 999) is not", "refused: "+firstLine(out)+
			" - the feature must shift every host-side chown, and host volumes (R15) stay incompatible")
	} else {
		report("FAIL", "today's chown (plain 999) is not",
			"uid 999 wrote a host-uid-999 dir; the map is not doing what the design assumes")
	}
}

// G: the secrets shape. materializeSecrets writes 0400 owned by the reading
// uid; under a map that host-side owner must be base+uid for the workload to
// read it, and 0400 must still exclude every other container uid.
func checkSecretsShape(ctx context.Context, task containerd.Task, container containerd.Container) {
	code, out, err := execIn(ctx, task, container, 999, "cat", "/secrets/token")
	if err == nil && code == 0 && strings.Contains(out, "s3cr3t") {
		report("PASS", "a shifted 0400 secret is readable", "uid 999 read its secret")
	} else {
		report("FAIL", "a shifted 0400 secret is readable", fmt.Sprintf("exit %d %s %v", code, out, err))
	}
	code, _, _ = execIn(ctx, task, container, 1000, "cat", "/secrets/token")
	if code != 0 {
		report("PASS", "0400 still excludes other uids", "uid 1000 refused")
	} else {
		report("FAIL", "0400 still excludes other uids", "uid 1000 read the secret")
	}
}

// I: a host grant nobody mapped. A root-owned socket bind-mounted into the
// userns stats as the overflow uid and its 0600 sibling is unreadable: the
// evidence behind the feature's R21 rule that a device/socket grant under a
// map is refused, never fudged.
func checkUnmappedGrant(ctx context.Context, task containerd.Task, container containerd.Container) {
	_, out, err := execIn(ctx, task, container, 0, "stat", "-c", "%u", "/grant/host.sock")
	if err != nil {
		report("INFO", "an unmapped grant is unusable", "stat failed: "+err.Error())
		return
	}
	code, _, _ := execIn(ctx, task, container, 0, "cat", "/grant/cred")
	if out == "65534" && code != 0 {
		report("INFO", "an unmapped grant is unusable",
			"host-root socket stats as the overflow uid 65534 and its 0600 sibling is unreadable: grants must be refused under a map (R21)")
	} else {
		report("INFO", "an unmapped grant is unusable",
			fmt.Sprintf("owner inside = %s, 0600 read exit = %d (expected 65534 and non-zero)", out, code))
	}
}

// H: the v1.56 question with mapped ids: does a PUID/s6 image boot inside a
// userns under the compatible baseline? Its init runs as container root,
// chowns /config, drops to PUID - all in-namespace operations against
// mapped-ownership files, so the design says yes; this is where the design
// meets an image nobody here wrote.
func checkPUIDImage(ctx context.Context, client *containerd.Client, ref string) {
	img := pullImage(ctx, client, ref)
	if img == nil {
		return
	}
	if err := createNetns(netnsPUID); err != nil {
		report("FAIL", "PUID image under a map", err.Error())
		return
	}
	// Mirror kanead: the floor sysctl before any task exists (nginx binds :80).
	if out, err := exec.Command("ip", "netns", "exec", netnsPUID, "sh", "-c",
		"echo 0 > /proc/sys/net/ipv4/ip_unprivileged_port_start").CombinedOutput(); err != nil {
		report("FAIL", "PUID image under a map", fmt.Sprintf("floor sysctl: %v: %s", err, out))
		return
	}

	id := fmt.Sprintf("spike-userns-puid-%d", time.Now().Unix())
	uidMaps, gidMaps := idMaps()
	logPath := filepath.Join(scratchRoot, "puid.log")
	mounts := []specs.Mount{bind("/config", filepath.Join(scratchRoot, "config"), false)}
	opts := []oci.SpecOpts{
		oci.WithImageConfig(img),
		oci.WithEnv([]string{"PUID=1000", "PGID=1000", "TZ=Etc/UTC"}),
		withKaneaHardening(id, compatBaseline, "/run/netns/"+netnsPUID, mounts),
		oci.WithUserNamespace(uidMaps, gidMaps),
	}
	container, err := client.NewContainer(ctx, id,
		containerd.WithImage(img),
		containerd.WithNewSnapshot(id+"-snap", img, containerd.WithUserNSRemapperLabels(uidMaps, gidMaps)),
		containerd.WithNewSpec(opts...),
	)
	if err != nil {
		report("FAIL", "PUID image under a map", "create: "+firstLine(err.Error()))
		return
	}
	task, err := container.NewTask(ctx, cio.LogFile(logPath))
	if err != nil {
		report("FAIL", "PUID image under a map", "task: "+firstLine(err.Error()))
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
		return
	}
	exitCh, err := task.Wait(ctx)
	if err == nil {
		err = task.Start(ctx)
	}
	if err != nil {
		report("FAIL", "PUID image under a map", "start: "+firstLine(err.Error()))
		teardown(ctx, task, container)
		return
	}

	deadline := time.After(120 * time.Second)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case st := <-exitCh:
			code, _, _ := st.Result()
			report("FAIL", "PUID image under a map",
				fmt.Sprintf("the image's init exited with code %d; log tail: %s", code, logTail(logPath)))
			teardown(ctx, task, container)
			return
		case <-deadline:
			report("FAIL", "PUID image under a map",
				"init did not finish within 120s; log tail: "+logTail(logPath))
			teardown(ctx, task, container)
			return
		case <-tick.C:
			body, _ := os.ReadFile(logPath)
			if bytes.Contains(body, []byte("[ls.io-init] done")) {
				report("PASS", "PUID image under a map",
					"the s6 init completed: chown /config, drop to PUID, serve - all inside the userns")
				st, err := os.Stat(filepath.Join(scratchRoot, "config", "nginx"))
				if err == nil {
					report("INFO", "PUID chown lands mapped on the host",
						fmt.Sprintf("/config/nginx host owner is %d (base+PUID is %d)", hostUIDOf(st), int(mapBase)+1000))
				}
				teardown(ctx, task, container)
				return
			}
		}
	}
}

func teardown(ctx context.Context, task containerd.Task, container containerd.Container) {
	if task != nil {
		_ = task.Kill(ctx, 9)
		_, _ = task.Delete(ctx, containerd.WithProcessKill)
	}
	if container != nil {
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
	}
}

// clean removes everything the spike made: containers, both images, both
// netns binds, and the scratch tree. Safe to run twice.
func clean(ctx context.Context, client *containerd.Client, image, puidImage string) {
	containers, _ := client.Containers(ctx)
	for _, c := range containers {
		if task, err := c.Task(ctx, nil); err == nil {
			_ = task.Kill(ctx, 9)
			_, _ = task.Delete(ctx, containerd.WithProcessKill)
		}
		_ = c.Delete(ctx, containerd.WithSnapshotCleanup)
		fmt.Println("removed container", c.ID())
	}
	for _, ref := range []string{image, puidImage} {
		if ref == "" {
			continue
		}
		if err := client.ImageService().Delete(ctx, ref); err == nil {
			fmt.Println("removed image", ref)
		}
	}
	for _, ns := range []string{netnsMain, netnsPUID} {
		if exec.Command("ip", "netns", "del", ns).Run() == nil {
			fmt.Println("removed netns", ns)
		}
	}
	if err := os.RemoveAll(scratchRoot); err == nil {
		fmt.Println("removed", scratchRoot)
	}
}

func logTail(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return "(no log)"
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	return strings.Join(lines, " | ")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// hostUIDOf reads a stat's host-side owner uid.
func hostUIDOf(st os.FileInfo) int {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid)
	}
	return -1
}
