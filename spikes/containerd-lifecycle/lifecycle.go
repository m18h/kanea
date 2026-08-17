package main

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
)

// runLifecycle answers spike questions ① (task lifecycle via raw v2 client) and
// ② (CNI invoked by our own process): pull, create, start, network, exec-verify,
// events, kill detection, restart, teardown.
func runLifecycle(ctx context.Context) error {
	client, ctx, err := dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	fmt.Println("── image ──")
	var img containerd.Image
	t0 := time.Now()
	img, err = ensureImage(ctx, client)
	if err != nil {
		return fmt.Errorf("pull %s: %w", imageRef, err)
	}
	check("image pull (cached ok)", true, fmt.Sprintf("%s in %v", imageRef, time.Since(t0).Round(time.Millisecond)))

	if err := writeCNINetConf(); err != nil {
		return err
	}

	fmt.Println("── start two allocs ──")
	var t1, t2 containerd.Task
	if err = timed("create+start lc-1", func() error {
		t1, err = startAlloc(ctx, client, img, alloc{ID: "lc-1", Cmd: []string{"sleep", "infinity"}})
		return err
	}); err != nil {
		return err
	}
	if err = timed("create+start lc-2", func() error {
		t2, err = startAlloc(ctx, client, img, alloc{ID: "lc-2", Cmd: []string{"sleep", "infinity"}})
		return err
	}); err != nil {
		return err
	}
	defer removeAlloc(ctx, client, "lc-1")
	defer removeAlloc(ctx, client, "lc-2")

	// Watch for lc-2's exit BEFORE killing it (reconciler crash-detection primitive).
	exit2C, err := t2.Wait(ctx)
	if err != nil {
		return err
	}
	evC, evErrC := client.Subscribe(ctx, `topic=="/tasks/exit"`)

	fmt.Println("── CNI from our own process ──")
	var ips1, ips2 []string
	if err = timed("CNI ADD lc-1 (netns=/proc/pid/ns/net)", func() error {
		ips1, err = cniAdd(ctx, "lc-1", t1.Pid())
		return err
	}); err != nil {
		return err
	}
	if err = timed("CNI ADD lc-2", func() error {
		ips2, err = cniAdd(ctx, "lc-2", t2.Pid())
		return err
	}); err != nil {
		return err
	}
	check("CNI allocated IPv4 per alloc", len(ips1) == 1 && len(ips2) == 1,
		fmt.Sprintf("lc-1=%s lc-2=%s", strings.Join(ips1, ","), strings.Join(ips2, ",")))

	eth0OK, eth0Out := false, ""
	for i := 0; i < 3 && !eth0OK; i++ { // exec-IO capture can race a fast exit; retry
		out, code, err := execIn(ctx, t1, "x1", "ip", "-4", "addr", "show", "dev", "eth0")
		eth0OK = err == nil && code == 0 && strings.Contains(out, "inet ")
		eth0Out = out
	}
	check("eth0 present inside alloc", eth0OK,
		strings.TrimSpace(strings.ReplaceAll(eth0Out, "\n", " | ")))

	ip2Bare, _, _ := strings.Cut(ips2[0], "/")
	_, code, _ := execIn(ctx, t1, "x2", "ping", "-c", "2", "-W", "2", ip2Bare)
	check("east-west: lc-1 ping lc-2", code == 0, ip2Bare)

	_, code, _ = execIn(ctx, t1, "x3", "ping", "-c", "2", "-W", "2", "10.200.0.1")
	check("alloc -> bridge gateway", code == 0, "10.200.0.1")

	// Raw TCP connect is authoritative: no DNS anywhere (bridge conf has no
	// dns{} section; M2 owns DNS). 1.1.1.1:80 answers SYN; wget would chase
	// a 301 to a DNS name and fail for the wrong reason.
	_, code, _ = execIn(ctx, t1, "x4", "nc", "-z", "-w", "3", "1.1.1.1", "80")
	check("north-south: alloc -> internet (ipMasq, TCP)", code == 0, "1.1.1.1:80")
	_, icmpCode, _ := execIn(ctx, t1, "x4b", "ping", "-c", "2", "-W", "3", "1.1.1.1")
	check("north-south ICMP (informational, VM NAT artifact)", icmpCode == 0, "1.1.1.1")

	fmt.Println("── crash detection + restart ──")
	if err := timed("SIGKILL lc-2", func() error { return t2.Kill(ctx, syscall.SIGKILL) }); err != nil {
		return err
	}
	select {
	case st := <-exit2C:
		check("task.Wait reported exit", st.ExitCode() == 137, fmt.Sprintf("code=%d at %s", st.ExitCode(), st.ExitTime().Format(time.RFC3339)))
	case <-time.After(10 * time.Second):
		check("task.Wait reported exit", false, "timeout")
	}
	select {
	case env := <-evC:
		check("/tasks/exit event received", env.Topic == "/tasks/exit", fmt.Sprintf("topic=%s ns=%s", env.Topic, env.Namespace))
	case err := <-evErrC:
		check("/tasks/exit event received", false, err.Error())
	case <-time.After(10 * time.Second):
		check("/tasks/exit event received", false, "timeout")
	}

	// Restart on the same container object (what the reconciler does after a crash):
	// delete the dead task, release its CNI state, then re-task + re-network.
	if _, err := t2.Delete(ctx); err != nil {
		return err
	}
	_ = cniDel("lc-2", t2.Pid()) // netns is dead; releases IPAM lease + iptables rules
	c2, err := client.LoadContainer(ctx, "lc-2")
	if err != nil {
		return err
	}
	t2b, err := c2.NewTask(ctx, nullIO())
	if err != nil {
		return fmt.Errorf("restart task: %w", err)
	}
	if err := t2b.Start(ctx); err != nil {
		return err
	}
	ips2b, err := cniAdd(ctx, "lc-2", t2b.Pid())
	reOK := err == nil && len(ips2b) == 1
	check("restart same container + re-network", reOK,
		fmt.Sprintf("new pid=%d ip=%s err=%v", t2b.Pid(), strings.Join(ips2b, ","), err))
	if reOK {
		_, code, _ = execIn(ctx, t1, "x5", "ping", "-c", "2", "-W", "2", strings.Split(ips2b[0], "/")[0])
		check("east-west after restart", code == 0, "")
	}

	fmt.Println("── teardown ──")
	_ = timed("CNI DEL + kill + delete lc-1", func() error {
		removeAlloc(ctx, client, "lc-1")
		return nil
	})
	_ = timed("CNI DEL + kill + delete lc-2", func() error {
		removeAlloc(ctx, client, "lc-2")
		return nil
	})
	left, _ := client.Containers(ctx)
	check("namespace clean after teardown", len(left) == 0, fmt.Sprintf("%d containers left", len(left)))

	return summary()
}
