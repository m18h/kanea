package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// runContainer answers the question that actually matters for PRD §8: can a
// FUSE mount on the host be handed to a workload as a volume, and does the
// workload see it; including objects written after the container started?
func runContainer(ctx context.Context, d *driver) error {
	fmt.Printf("\n── %s: as a container volume ──\n", d.Name)
	if err := resetBucket(); err != nil {
		return err
	}

	seed := "seeded-before-start\n"
	if err := os.WriteFile(d.path("vol.txt"), []byte(seed), 0o644); err != nil {
		check(d.Name+": seed file on the host mount", false, trimErr(err))
		return nil
	}

	client, err := containerd.New(containerdSock)
	if err != nil {
		return fmt.Errorf("dial containerd: %w", err)
	}
	defer client.Close()
	cctx := namespaces.WithNamespace(ctx, ctrNamespace)

	img, err := client.GetImage(cctx, imageRef)
	if err != nil {
		img, err = client.Pull(cctx, imageRef, containerd.WithPullUnpack)
		if err != nil {
			return fmt.Errorf("pull %s: %w", imageRef, err)
		}
	}

	id := "s3vol-" + d.Name
	removeContainer(cctx, client, id)
	defer removeContainer(cctx, client, id)

	container, err := client.NewContainer(cctx, id,
		containerd.WithImage(img),
		containerd.WithNewSnapshot(id+"-snap", img),
		containerd.WithNewSpec(
			oci.WithImageConfig(img),
			oci.WithProcessArgs("sleep", "infinity"),
			// This is exactly how a Kanea `storage "s3"` volume would be attached:
			// the FUSE mount is established on the host, then rbind-ed into the alloc.
			oci.WithMounts([]specs.Mount{{
				Destination: "/data",
				Type:        "bind",
				Source:      d.Mount,
				Options:     []string{"rbind", "rw"},
			}}),
		),
	)
	if err != nil {
		check(d.Name+": container with the mount as a volume", false, trimErr(err))
		return nil
	}
	task, err := container.NewTask(cctx, cio.NullIO)
	if err != nil {
		check(d.Name+": container with the mount as a volume", false, trimErr(err))
		return nil
	}
	if err := task.Start(cctx); err != nil {
		check(d.Name+": container with the mount as a volume", false, trimErr(err))
		return nil
	}
	check(d.Name+": alloc starts with the FUSE mount rbind-ed at /data", true, "")

	// --- read a file that existed before the container started ---
	out, code, err := execIn(cctx, task, "read", "cat", "/data/vol.txt")
	check(d.Name+": alloc reads a file created before it started",
		err == nil && code == 0 && strings.Contains(out, "seeded-before-start"),
		oneLine(out))

	// --- write from inside the alloc, verify it lands in the object store ---
	_, code, err = execIn(cctx, task, "write", "sh", "-c", "echo written-by-alloc > /data/from-alloc.txt")
	wroteOK := err == nil && code == 0
	var inStore bool
	var storeDetail string
	if wroteOK {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if out, err := mc("cat", fmt.Sprintf("kaneaspike/%s/from-alloc.txt", bucket)); err == nil &&
				strings.Contains(out, "written-by-alloc") {
				inStore = true
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if !inStore {
			storeDetail = "object never appeared in the bucket"
		}
	}
	check(d.Name+": alloc write reaches the bucket", wroteOK && inStore, storeDetail)

	// --- host writes AFTER the container started: does the alloc see them? ---
	late := "written-after-start\n"
	hostErr := os.WriteFile(d.path("late.txt"), []byte(late), 0o644)
	var sawLate bool
	var lateDetail string
	if hostErr == nil {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			out, code, _ := execIn(cctx, task, fmt.Sprintf("late-%d", time.Now().UnixNano()), "cat", "/data/late.txt")
			if code == 0 && strings.Contains(out, "written-after-start") {
				sawLate = true
				break
			}
			lateDetail = oneLine(out)
			time.Sleep(500 * time.Millisecond)
		}
	} else {
		lateDetail = trimErr(hostErr)
	}
	check(d.Name+": alloc sees host writes made after it started", sawLate, lateDetail)

	return nil
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

// execIn runs a command inside the task and returns combined output. Output is
// captured through a shim-written log file (spike ① lesson: cio.WithStreams can
// return before io.Copy has drained the FIFO).
func execIn(ctx context.Context, task containerd.Task, execID string, args ...string) (string, uint32, error) {
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
	proc, err := task.Exec(ctx, execID, pspec, cio.LogFile(logPath))
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

func oneLine(s string) string {
	s = strings.TrimSpace(string(bytes.ReplaceAll([]byte(s), []byte("\n"), []byte(" | "))))
	if len(s) > 70 {
		s = s[:70] + "…"
	}
	return s
}
