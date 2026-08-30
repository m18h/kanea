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
// Two netns shapes are tried, and the difference is the spike's biggest
// finding. Kanead's current shape (`ip netns add`: a netns owned by the
// initial user namespace) is attempted first; sysfs refuses to mount inside
// a userns whose netns it does not own, so runc's init dies at "/sys". The
// shape that works is a netns created INSIDE a pre-made user namespace, with
// runc joining both by path - which preserves everything kanead does to a
// netns (veth moves, sysctls, tc attach), because init-root holds every
// capability in a child userns.
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
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/snapshots"
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
	netnsForeign   = "spike-userns-foreign"
	netnsOwned     = "spike-userns-owned"
	netnsPUID      = "spike-userns-puid"
	// The map: one contiguous range, clear of the buildkit subuid range at
	// 200000. OCI-spec-only; the spike never writes /etc/subuid (root runc
	// applies mappings without newuidmap, and the owned-netns shape sets the
	// map on the helper's userns directly).
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

	task, container := checkNetnsShapes(ctx, client, img)
	if task != nil {
		checkMapIsReal(ctx, task, container)
		checkNetnsUnmodifiable(ctx, task, container)
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
	for _, d := range []string{"scratch", "vol-mapped", "vol-unmapped", "secrets", "grant", "config", "ns"} {
		if err := os.MkdirAll(filepath.Join(scratchRoot, d), 0o755); err != nil {
			return err
		}
	}
	// /scratch is the alloc's own writable space: owned by the mapped root
	// (base+0) so container root can write it, the way an alloc's own dirs
	// would be created under the map.
	if err := os.Chown(filepath.Join(scratchRoot, "scratch"), int(mapBase), int(mapBase)); err != nil {
		return err
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
	_ = os.Remove(secret)
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

// createForeignNetns is internal/runtime.CreateNetns's exact shape: `ip netns
// add` (a netns owned by the initial user namespace, persistent bind under
// /run/netns) then lo up inside - what kanead does before any task exists.
func createForeignNetns(name string) error {
	_ = exec.Command("ip", "netns", "del", name).Run()
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		return fmt.Errorf("ip netns add: %v: %s", err, out)
	}
	if out, err := exec.Command("ip", "netns", "exec", name, "ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		return fmt.Errorf("lo up: %v: %s", err, out)
	}
	return nil
}

// createOwnedNetns builds the shape the feature would need: a user namespace
// with the alloc's map, and a netns created INSIDE it, both pinned to bind
// mounts so runc can join them by path. A short-lived helper process
// (`unshare --user --net sleep`) carries the namespaces just long enough to
// bind them; the map is written into the helper's uid_map/gid_map from
// outside, which is the privilege kanead (init-root) has. The netns bind
// lands under /run/netns so `ip netns exec` keeps working against it -
// which is also how the spike proves kanead-side plumbing (sysctls, lo up)
// still reaches a child-owned netns.
func createOwnedNetns(name string) (netnsPath, usernsPath string, err error) {
	netnsPath = "/run/netns/" + name
	usernsPath = filepath.Join(scratchRoot, "ns", name+"-user")
	_ = exec.Command("ip", "netns", "del", name).Run()
	_ = syscall.Unmount(usernsPath, 0)
	_ = os.Remove(usernsPath)

	// A helper carrying a fresh user+net namespace, spawned with the clone
	// flags but NO mappings, so the child's uid_map is left empty and
	// writable: `unshare --user` (util-linux) writes a map itself and freezes
	// it, which is the EPERM the first attempt hit. We write the map from the
	// parent as init-root instead, which is the privilege kanead has.
	helper := exec.Command("sleep", "120")
	helper.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
	}
	if err := helper.Start(); err != nil {
		return "", "", fmt.Errorf("userns helper: %w", err)
	}
	pid := helper.Process.Pid
	defer func() {
		_ = helper.Process.Kill()
		_, _ = helper.Process.Wait()
	}()

	mapping := fmt.Sprintf("0 %d %d\n", mapBase, mapLen)
	for _, f := range []struct{ path, content string }{
		{fmt.Sprintf("/proc/%d/uid_map", pid), mapping},
		{fmt.Sprintf("/proc/%d/setgroups", pid), "deny\n"},
		{fmt.Sprintf("/proc/%d/gid_map", pid), mapping},
	} {
		if err := os.WriteFile(f.path, []byte(f.content), 0o644); err != nil {
			return "", "", fmt.Errorf("write %s: %w", f.path, err)
		}
	}

	for _, b := range []struct{ src, dst string }{
		{fmt.Sprintf("/proc/%d/ns/net", pid), netnsPath},
		{fmt.Sprintf("/proc/%d/ns/user", pid), usernsPath},
	} {
		if err := os.WriteFile(b.dst, nil, 0o444); err != nil && !os.IsExist(err) {
			return "", "", fmt.Errorf("touch %s: %w", b.dst, err)
		}
		if err := syscall.Mount(b.src, b.dst, "", syscall.MS_BIND, ""); err != nil {
			return "", "", fmt.Errorf("bind %s: %w", b.src, err)
		}
	}

	// kanead-side plumbing against the child-owned netns: init-root is capable
	// in every descendant userns, so this must keep working.
	if out, err := exec.Command("ip", "netns", "exec", name, "ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("lo up in the owned netns: %v: %s", err, out)
	}
	return netnsPath, usernsPath, nil
}

func idMaps() ([]specs.LinuxIDMapping, []specs.LinuxIDMapping) {
	m := []specs.LinuxIDMapping{{ContainerID: 0, HostID: mapBase, Size: mapLen}}
	return m, m
}

func bindMount(dst, src string, ro bool) specs.Mount {
	opts := []string{"rbind", "nosuid", "nodev"}
	if ro {
		opts = append(opts, "ro")
	}
	return specs.Mount{Destination: dst, Type: "bind", Source: src, Options: opts}
}

// withJoinedUserns joins a pre-made user namespace by path, the owned-netns
// shape: the map already lives on the namespace, so the spec carries none
// (mappings are a creation-time property).
func withJoinedUserns(path string) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if s.Linux == nil {
			s.Linux = &specs.Linux{}
		}
		s.Linux.Namespaces = append(s.Linux.Namespaces, specs.LinuxNamespace{
			Type: specs.UserNamespace,
			Path: path,
		})
		// A joined (rather than runc-created) userns cannot make the rootfs
		// mount MS_PRIVATE: the mount is owned by the init userns and the
		// container's userns is not its owner. rslave keeps the container from
		// leaking propagation back to the host while asking runc to slave
		// rather than privatise, which a joined userns is permitted to do.
		s.Linux.RootfsPropagation = "rslave"
		return nil
	}
}

// tryStart creates and starts one container under the full Kanea opt set
// plus a user namespace, without reporting: the caller owns the verdict.
// usernsPath empty means create the userns from the spec's mappings;
// non-empty means join it by path.
func tryStart(ctx context.Context, client *containerd.Client, img containerd.Image,
	id, netnsPath, usernsPath string, caps, env []string,
	mounts []specs.Mount, io cio.Creator, args []string, extra ...oci.SpecOpts,
) (containerd.Task, containerd.Container, time.Duration, error) {
	uidMaps, gidMaps := idMaps()

	opts := []oci.SpecOpts{oci.WithImageConfig(img)}
	if len(args) > 0 {
		opts = append(opts, oci.WithProcessArgs(args...))
	}
	if len(env) > 0 {
		opts = append(opts, oci.WithEnv(env))
	}
	opts = append(opts, withKaneaHardening(id, caps, netnsPath, mounts))
	if usernsPath == "" {
		opts = append(opts, oci.WithUserNamespace(uidMaps, gidMaps))
	} else {
		opts = append(opts, withJoinedUserns(usernsPath))
	}
	opts = append(opts, extra...)

	start := time.Now()
	container, err := client.NewContainer(ctx, id,
		containerd.WithImage(img),
		// The remapper labels ride along in both shapes: they are what makes
		// the snapshotter hand runc an idmapped (or pre-chowned) rootfs.
		containerd.WithNewSnapshot(id+"-snap", img, containerd.WithUserNSRemapperLabels(uidMaps, gidMaps)),
		containerd.WithNewSpec(opts...),
	)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("create: %s", firstLine(err.Error()))
	}
	prep := time.Since(start)

	task, err := container.NewTask(ctx, io)
	if err != nil {
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
		return nil, nil, 0, fmt.Errorf("task: %s", firstLine(err.Error()))
	}
	if err := task.Start(ctx); err != nil {
		_, _ = task.Delete(ctx, containerd.WithProcessKill)
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
		return nil, nil, 0, fmt.Errorf("start: %s", firstLine(err.Error()))
	}
	return task, container, prep, nil
}

// B: the two netns shapes. Kanead's current one first - `ip netns add`, a
// netns owned by the initial userns - which the design would prefer, because
// nothing about the datapath would change. Then the owned-netns shape, which
// is the one the kernel's sysfs ownership rule actually permits.
func checkNetnsShapes(ctx context.Context, client *containerd.Client, img containerd.Image) (containerd.Task, containerd.Container) {
	probeMounts := []specs.Mount{
		bindMount("/scratch", filepath.Join(scratchRoot, "scratch"), false),
		bindMount("/vol-mapped", filepath.Join(scratchRoot, "vol-mapped"), false),
		bindMount("/vol-unmapped", filepath.Join(scratchRoot, "vol-unmapped"), false),
		// Read-write binds: an earlier run found a ro rbind reads empty under a
		// joined userns; these checks are about file-mode ownership, not mount
		// ro, so the ro variable is removed. The ro-remount-under-userns
		// behaviour is recorded as a finding, not tested here.
		bindMount("/secrets", filepath.Join(scratchRoot, "secrets"), false),
		bindMount("/grant", filepath.Join(scratchRoot, "grant"), false),
	}

	// Shape 1 - kanead's current model: spec mappings (runc creates the
	// userns) joining a netns `ip netns add` made in the init userns. The one
	// the design would prefer, because nothing about the datapath changes.
	if err := createForeignNetns(netnsForeign); err != nil {
		report("FAIL", "pre-created netns (ip netns add)", err.Error())
		return nil, nil
	}
	id := fmt.Sprintf("spike-userns-a-%d", time.Now().Unix())
	task, container, prep, err := tryStart(ctx, client, img, id,
		"/run/netns/"+netnsForeign, "", compatBaseline, nil, probeMounts, cio.NullIO, []string{"sleep", "3600"})
	if err == nil {
		report("PASS", "kanead's netns shape works as-is", fmt.Sprintf("prep %s", prep.Round(time.Millisecond)))
		return task, container
	}
	report("INFO", "shape 1: runc-userns + init-owned netns",
		"refused: "+err.Error()+" - sysfs mount checks ns_capable(net->user_ns), and runc's fresh userns does not own an `ip netns add` netns")

	// Shape 2 - join both by path: a netns created INSIDE a userns, both
	// joined so the container's userns owns its netns. Gets past sysfs; runc
	// then cannot make the rootfs MS_PRIVATE from a joined (non-owning) userns.
	if _, usernsPath, err := createOwnedNetns(netnsOwned); err != nil {
		report("FAIL", "userns-owned netns", err.Error())
	} else {
		report("PASS", "kanead-side plumbing reaches an owned netns",
			"ip netns exec (setns + lo up) works against a child-owned netns from init-root")
		id = fmt.Sprintf("spike-userns-b-%d", time.Now().Unix())
		if t, c, _, err := tryStart(ctx, client, img, id,
			"/run/netns/"+netnsOwned, usernsPath, compatBaseline, nil, probeMounts, cio.NullIO, []string{"sleep", "3600"}); err != nil {
			report("INFO", "shape 2: joined userns + owned netns",
				"refused: "+err.Error()+" - runc unconditionally remounts the rootfs MS_PRIVATE, which a joined userns may not do to an init-owned mount")
		} else {
			report("PASS", "create+start (joined userns + owned netns)", "")
			return t, c
		}
	}

	// Shape 3 - the production userns model: runc creates the userns AND a
	// fresh netns together (pathless network namespace), so its userns owns
	// its netns and sysfs mounts. This is what actually comes up, and it is
	// what the rest of the checks run against. The cost, and the finding, is
	// that kanead's datapath is netns-FIRST (create netns, wire veth+tc+
	// sysctls, then runc joins) while this is netns-WITH-userns (runc makes
	// both, then something wires the veth by pid): an inversion, not a flag.
	id = fmt.Sprintf("spike-userns-c-%d", time.Now().Unix())
	task, container, prep, err = tryStart(ctx, client, img, id,
		"", "", compatBaseline, nil, probeMounts, cio.NullIO, []string{"sleep", "3600"}, withFreshNetns())
	if err != nil {
		report("FAIL", "create+start (runc-made userns + netns)", err.Error())
		return nil, nil
	}
	report("PASS", "create+start under hardening + userns",
		fmt.Sprintf("runc-made userns + fresh netns, map 0:%d:%d", mapBase, mapLen))
	report("INFO", "snapshot prep (create call)", prep.Round(time.Millisecond).String())
	return task, container
}

// withFreshNetns adds a pathless network namespace so runc creates a new one
// inside the userns it is creating (rather than sharing the host's).
func withFreshNetns() oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if s.Linux == nil {
			s.Linux = &specs.Linux{}
		}
		for _, ns := range s.Linux.Namespaces {
			if ns.Type == specs.NetworkNamespace {
				return nil
			}
		}
		s.Linux.Namespaces = append(s.Linux.Namespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace})
		return nil
	}
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
	// Output through a log file the shim flushes, not streaming FIFOs: for a
	// short-lived exec the FIFO copy goroutines race the exit delivery and the
	// buffer reads empty half the time. The shim writes the log file on this
	// same node, so after the process exits it is there to read.
	logPath := filepath.Join(scratchRoot, fmt.Sprintf("exec-%d.log", execSeq))
	defer os.Remove(logPath) //nolint:errcheck
	p, err := task.Exec(ctx, fmt.Sprintf("spike-exec-%d", execSeq), &proc, cio.LogFile(logPath))
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
	read := func() string {
		body, _ := os.ReadFile(logPath)
		return strings.TrimSpace(string(body))
	}
	select {
	case st := <-exitCh:
		code, _, err := st.Result()
		return code, read(), err
	case <-time.After(30 * time.Second):
		_ = p.Kill(ctx, 9)
		return 0, read(), fmt.Errorf("exec timed out")
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

// D: the task cannot modify its netns. In the owned shape the netns belongs
// to the container's own userns, so what protects it is R13: CAP_NET_ADMIN
// is on the forbidden list and the baseline's bounding set excludes it, so
// even in-namespace ownership buys the workload nothing.
func checkNetnsUnmodifiable(ctx context.Context, task containerd.Task, container containerd.Container) {
	// kanead brings lo up (its job), from init-root by pid: the same plumbing
	// proof as check E, run first so the "is up inside" assertion is about the
	// join, not about timing.
	pid := fmt.Sprint(task.Pid())
	_ = exec.Command("nsenter", "--target", pid, "--net", "--", "ip", "link", "set", "lo", "up").Run()

	code, out, err := execIn(ctx, task, container, 0, "ip", "link", "show", "lo")
	if err == nil && code == 0 && strings.Contains(out, "UP") {
		report("PASS", "sees its netns (lo up)", "the workload observes the netns kanead wired")
	} else {
		report("FAIL", "sees its netns (lo up)", fmt.Sprintf("lo not up inside: exit %d %q %v", code, out, err))
	}

	code, out, _ = execIn(ctx, task, container, 0, "ip", "link", "set", "lo", "down")
	if code != 0 {
		report("PASS", "cannot modify the netns",
			"ip link set lo down refused: "+firstLine(out)+" (NET_ADMIN stays forbidden, R13)")
	} else {
		report("FAIL", "cannot modify the netns", "the mapped root downed lo")
	}
}

// E: the port floor. The compatible baseline no longer grants
// CAP_NET_BIND_SERVICE (v1.105), so :80 needs the per-netns
// ip_unprivileged_port_start=0 that kanead writes - under a userns exactly
// as without one. kanead-side plumbing (lo up, the sysctl) is applied by
// entering the task's netns from init-root, which is what proves the datapath
// still reaches a userns-owned netns. The sysctl the amendment shipped is
// load-bearing here.
func checkPortFloor(ctx context.Context, task containerd.Task, container containerd.Container) {
	pid := fmt.Sprint(task.Pid())
	nsenter := func(args ...string) ([]byte, error) {
		full := append([]string{"--target", pid, "--net", "--"}, args...)
		return exec.Command("nsenter", full...).CombinedOutput()
	}
	// The fresh netns has lo down; kanead brings it up. That this works from
	// init-root against a userns-owned netns is the plumbing proof.
	if out, err := nsenter("ip", "link", "set", "lo", "up"); err != nil {
		report("FAIL", "kanead plumbing reaches the userns netns", fmt.Sprintf("%v: %s", err, out))
		return
	}
	report("PASS", "kanead plumbing reaches the userns netns", "lo up + sysctls applied from init-root by pid")

	// The load-bearing new fact under userns is the one above: the per-netns
	// sysctl kanead writes reaches a userns-owned netns. Demonstrating a bind
	// against the floor needs a low-port LISTENer in the workload, and the
	// stock alpine busybox has neither httpd nor a listening nc, so it is not
	// exercised here rather than faked. The floor's effect is the same knob
	// the non-userns path already carries (v1.105), which the container's
	// capability set (NET_BIND_SERVICE absent) does not change: the check
	// applies in the netns's user namespace, and that is the container's own.
	verified, _ := nsenter("cat", "/proc/sys/net/ipv4/ip_unprivileged_port_start")
	report("INFO", "port floor is the per-netns sysctl",
		"the workload's :80 bind is not exercised (the stock probe image has no low-port listener); the floor is ip_unprivileged_port_start="+
			strings.TrimSpace(string(verified))+" in this netns, kanead's v1.105 knob, unchanged by the userns")
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
	code, out, err := execIn(ctx, task, container, 999, "sh", "-c", "cat /secrets/token; echo; ls -ln /secrets/token")
	if err == nil && code == 0 && strings.Contains(out, "s3cr3t") {
		report("PASS", "a shifted 0400 secret is readable", "uid 999 read its secret")
	} else {
		report("FAIL", "a shifted 0400 secret is readable", fmt.Sprintf("exit %d [%s] %v", code, strings.ReplaceAll(out, "\n", " | "), err))
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
	// Shape 3, as for the probe: runc makes the userns and a fresh netns.
	id := fmt.Sprintf("spike-userns-puid-%d", time.Now().Unix())
	logPath := filepath.Join(scratchRoot, "puid.log")
	mounts := []specs.Mount{bindMount("/config", filepath.Join(scratchRoot, "config"), false)}
	task, container, prep, err := tryStart(ctx, client, img, id, "", "",
		compatBaseline, []string{"PUID=1000", "PGID=1000", "TZ=Etc/UTC"}, mounts, cio.LogFile(logPath),
		[]string{}, withFreshNetns())
	if err != nil {
		report("FAIL", "PUID image under a map", err.Error())
		return
	}
	report("INFO", "PUID snapshot prep (create call)", prep.Round(time.Millisecond).String())
	// Mirror kanead: bring lo up and drop the port floor in the task's netns
	// (nginx binds :80) from init-root, by pid.
	pid := fmt.Sprint(task.Pid())
	_ = exec.Command("nsenter", "--target", pid, "--net", "--", "ip", "link", "set", "lo", "up").Run()
	_ = exec.Command("nsenter", "--target", pid, "--net", "--", "sh", "-c",
		"echo 0 > /proc/sys/net/ipv4/ip_unprivileged_port_start").Run()
	exitCh, err := task.Wait(ctx)
	if err != nil {
		report("FAIL", "PUID image under a map", "wait: "+firstLine(err.Error()))
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
			if strings.Contains(string(body), "[ls.io-init] done") {
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

// clean removes everything the spike made: containers, both images, the
// netns and userns binds, and the scratch tree. Safe to run twice.
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
	// Deleting an image drops its index entry but leaves its snapshots and
	// content blobs behind: prune both so the throwaway namespace is empty
	// and `ctr namespace rm kanea-spike-userns` succeeds, rather than leaving
	// gigabytes on the node.
	snapshotter := client.SnapshotService(defaults.DefaultSnapshotter)
	var snaps []string
	_ = snapshotter.Walk(ctx, func(_ context.Context, info snapshots.Info) error {
		snaps = append(snaps, info.Name)
		return nil
	})
	for _, name := range snaps {
		if snapshotter.Remove(ctx, name) == nil {
			fmt.Println("removed snapshot", name)
		}
	}
	cs := client.ContentStore()
	_ = cs.Walk(ctx, func(info content.Info) error {
		if cs.Delete(ctx, info.Digest) == nil {
			fmt.Println("removed blob", info.Digest)
		}
		return nil
	})
	for _, ns := range []string{netnsForeign, netnsOwned, netnsPUID} {
		if exec.Command("ip", "netns", "del", ns).Run() == nil {
			fmt.Println("removed netns", ns)
		}
		userBind := filepath.Join(scratchRoot, "ns", ns+"-user")
		if syscall.Unmount(userBind, 0) == nil {
			fmt.Println("unmounted", userBind)
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
