// Command spike is throwaway M0 validation code (PRD §20, spike ②).
// It validates, on the kanea-spike OrbStack VM:
//  1. containerd task lifecycle with the raw v2 client (no CRI, no k8s)
//  2. CNI ADD/DEL invoked by OUR process against a task's netns
//  3. single-scrape /v1/metrics coverage of all allocs' cgroup metrics
//  4. the PRD §5.2.11 cgroups v2 isolation hierarchy under pressure
//
// Nothing here ships. M1 reimplements the validated patterns in internal/runtime.
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

const (
	socketPath  = "/run/containerd/containerd.sock"
	namespace   = "kanea-spike"
	imageRef    = "docker.io/library/alpine:3.21"
	metricsURL  = "http://127.0.0.1:1338/v1/metrics"
	cniBinDir   = "/opt/cni/bin"
	cniConfPath = "/etc/cni/net.d/10-kanea-spike.conflist"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: spike <lifecycle|metrics|cgroups|clean|memhog> [args]\n")
		os.Exit(2)
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "lifecycle":
		err = runLifecycle(ctx)
	case "metrics":
		err = runMetrics(ctx)
	case "cgroups":
		err = runCgroups(ctx)
	case "clean":
		err = runClean(ctx)
	case "up": // debug helper: start one alloc + CNI, leave it running
		err = runUp(ctx, os.Args[2:])
	case "memhog":
		err = runMemhog(os.Args[2:])
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

func dial(ctx context.Context) (*containerd.Client, context.Context, error) {
	client, err := containerd.New(socketPath)
	if err != nil {
		return nil, ctx, fmt.Errorf("dial %s: %w", socketPath, err)
	}
	return client, namespaces.WithNamespace(ctx, namespace), nil
}

func ensureImage(ctx context.Context, client *containerd.Client) (containerd.Image, error) {
	if img, err := client.GetImage(ctx, imageRef); err == nil {
		return img, nil
	}
	return client.Pull(ctx, imageRef, containerd.WithPullUnpack)
}

// parseSize parses "512", "128M", "2G" into bytes.
func parseSize(s string) (int64, error) {
	if s == "" || s == "0" {
		return 0, nil
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, s[:len(s)-1]
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, s[:len(s)-1]
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n * mult, err
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
		fmt.Printf("%s  %-58s %s\n", mark, name, detail)
	} else {
		fmt.Printf("%s  %s\n", mark, name)
	}
}

func summary() error {
	bad := 0
	for _, r := range results {
		if !r.ok {
			bad++
		}
	}
	fmt.Printf("\n== %d/%d checks passed ==\n", len(results)-bad, len(results))
	if bad > 0 {
		return fmt.Errorf("%d checks failed", bad)
	}
	return nil
}

func timed(name string, f func() error) error {
	t0 := time.Now()
	err := f()
	d := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		fmt.Printf("  ✗ %-46s %v (%v)\n", name, err, d)
		return err
	}
	fmt.Printf("  ✓ %-46s %v\n", name, d)
	return nil
}

func touch(p string) {
	if f, err := os.Create(p); err == nil {
		f.Close()
	}
}

func waitFile(p string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p); err == nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
