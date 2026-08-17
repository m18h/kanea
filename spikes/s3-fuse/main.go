// Command spike is throwaway M0 validation code (PRD §20, spike ③).
// It compares the candidate S3 FUSE drivers on the kanea-spike VM:
//
//	s3fs 1.93 · rclone 1.74.4 (mount) · mountpoint-s3 1.23.0
//
// against a local MinIO endpoint, on the four axes that decide which one Kanea
// ships as its `storage "s3"` volume driver (PRD §8):
//
//  1. POSIX semantics: what a workload can actually do on the mount
//  2. throughput and metadata cost
//  3. usability as a container volume (bind into a containerd task)
//  4. behaviour when the object store goes away, and recovery
//
// goofys (named in the PRD) is not tested: its last release is v0.24.0
// (April 2020) and ships an amd64 binary only, so it cannot run on arm64.
//
// Nothing here ships. M2 implements the winner in internal/runtime volumes.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	containerdSock = "/run/containerd/containerd.sock"
	ctrNamespace   = "kanea-spike-s3"
	imageRef       = "docker.io/library/busybox:1.37"

	bucket     = "kanea-spike"
	s3Endpoint = "http://127.0.0.1:9000"
	minioUnit  = "kanea-spike-minio"
	accessKey  = "kaneaspike"       // spike-only; provision-vm.sh writes the same pair
	secretKey  = "kaneaspikesecret" // #nosec G101: local MinIO, throwaway
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: spike <matrix|perf|container|unpriv|failure|all|clean>\n")
		os.Exit(2)
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "matrix":
		err = withDrivers(ctx, runMatrix)
	case "perf":
		// Optional argument: added one-way delay on loopback (e.g. "15ms"), so
		// the numbers reflect a real S3 round trip instead of a local socket.
		if len(os.Args) > 2 {
			if derr := setNetem(os.Args[2]); derr != nil {
				fmt.Fprintf(os.Stderr, "netem: %v\n", derr)
				os.Exit(1)
			}
			defer clearNetem()
			fmt.Printf("loopback shaped: +%s one-way (%s RTT); emulating a same-region S3\n\n",
				os.Args[2], os.Args[2])
		}
		err = withDrivers(ctx, runPerf)
	case "container":
		err = withDrivers(ctx, runContainer)
	case "unpriv":
		err = withDrivers(ctx, runUnpriv)
	case "failure":
		err = withDrivers(ctx, runFailure)
	case "all":
		err = withDrivers(ctx, runMatrix, runPerf, runContainer, runUnpriv, runFailure)
	case "clean":
		err = runClean(ctx)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nOVERALL: FAIL (%v)\n", err)
		os.Exit(1)
	}
	fmt.Println("\nOVERALL: PASS")
}

type phase func(context.Context, *driver) error

// withDrivers runs each phase against every driver, mounting fresh per phase so
// no test inherits another's page cache or VFS cache state.
func withDrivers(ctx context.Context, phases ...phase) error {
	for _, p := range phases {
		for i := range drivers {
			d := &drivers[i]
			if err := d.mount(); err != nil {
				check(d.Name+": mount", false, err.Error())
				continue
			}
			err := p(ctx, d)
			if uerr := d.unmount(); uerr != nil {
				fmt.Printf("note: unmount %s: %v\n", d.Name, uerr)
			}
			if err != nil {
				return err
			}
		}
	}
	return summary()
}

// ---- PASS/FAIL bookkeeping (feeds REPORT.md verbatim) ----

type checkResult struct {
	name   string
	ok     bool
	detail string
}

var results []checkResult

func check(name string, ok bool, detail string) {
	results = append(results, checkResult{name, ok, detail})
	mark := "PASS"
	if !ok {
		mark = "FAIL"
	}
	if detail != "" {
		fmt.Printf("%s  %-52s %s\n", mark, name, detail)
	} else {
		fmt.Printf("%s  %s\n", mark, name)
	}
}

// capability records a semantic difference between drivers. Not a go/no-go:
// the point of the matrix is that the drivers genuinely differ, and Kanea must
// document which operations its volumes support.
func capability(driver, op string, supported bool, detail string) {
	mark := "yes"
	if !supported {
		mark = "NO "
	}
	caps[driver] = append(caps[driver], capResult{op, supported, detail})
	fmt.Printf("  %-4s %-10s %-22s %s\n", mark, driver, op, detail)
}

type capResult struct {
	op        string
	supported bool
	detail    string
}

var caps = map[string][]capResult{}

func summary() error {
	bad := 0
	for _, r := range results {
		if !r.ok {
			bad++
		}
	}
	fmt.Printf("\n== %d/%d checks passed ==\n", len(results)-bad, len(results))
	if len(caps) > 0 {
		fmt.Println("\n== capability matrix ==")
		ops := []string{}
		seen := map[string]bool{}
		for _, d := range drivers {
			for _, c := range caps[d.Name] {
				if !seen[c.op] {
					seen[c.op] = true
					ops = append(ops, c.op)
				}
			}
		}
		fmt.Printf("%-24s", "operation")
		for _, d := range drivers {
			fmt.Printf("%-12s", d.Name)
		}
		fmt.Println()
		for _, op := range ops {
			fmt.Printf("%-24s", op)
			for _, d := range drivers {
				mark := "-"
				for _, c := range caps[d.Name] {
					if c.op == op {
						mark = "yes"
						if !c.supported {
							mark = "NO"
						}
					}
				}
				fmt.Printf("%-12s", mark)
			}
			fmt.Println()
		}
	}
	if bad > 0 {
		return fmt.Errorf("%d checks failed", bad)
	}
	return nil
}

// setNetem adds one-way delay to loopback so metadata-heavy workloads pay a
// realistic per-operation round trip. Affects every loopback socket on the box
// for the duration of the run.
func setNetem(delay string) error {
	clearNetem()
	out, err := exec.Command("tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", delay).CombinedOutput() // #nosec G204; spike
	if err != nil {
		return fmt.Errorf("tc qdisc add: %w (%s)", err, bytes.TrimSpace(out))
	}
	return nil
}

func clearNetem() {
	_ = exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run()
}

func mib(bytes int64, d time.Duration) string {
	return fmt.Sprintf("%.1f MiB/s", float64(bytes)/(1<<20)/d.Seconds())
}
