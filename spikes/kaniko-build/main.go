// Command spike is throwaway M0 validation code (PRD §20, spike ④).
// It answers whether Kanea can build images on the node, inside containerd,
// without a Docker daemon and without a privileged container, and which build
// driver it should ship (PRD §10.2 defers that decision to this spike).
//
// Candidates: kaniko v1.24.0 (the PRD's incumbent, upstream ARCHIVED),
// buildkit v0.32.0 (rootless), buildah v1.45.0.
//
// Nothing here ships. M7 implements the winner in internal/gitops.
package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

const (
	containerdSock = "/run/containerd/containerd.sock"
	ctrNamespace   = "kanea-spike-build"

	kanikoImage   = "gcr.io/kaniko-project/executor:v1.24.0"
	buildkitImage = "docker.io/moby/buildkit:v0.32.0-rootless"
	buildahImage  = "quay.io/buildah/stable:v1.43.1" // newest published image; source is at v1.45.0

	regAddr = "127.0.0.1:5000"
	workDir = "/var/lib/kanea-spike-build"
	authDir = workDir + "/auth"
	ctxDir  = workDir + "/context"
	badDir  = workDir + "/context-bad"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: spike <build|cache|hardening|limits|failure|daemon|all|clean>\n")
		os.Exit(2)
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "build":
		err = withBuilders(ctx, phaseBuild)
	case "cache":
		err = withBuilders(ctx, phaseCache)
	case "hardening":
		err = withBuilders(ctx, phaseHardening)
	case "limits":
		err = withBuilders(ctx, phaseLimits)
	case "failure":
		err = withBuilders(ctx, phaseFailure)
	case "daemon":
		err = withEnv(ctx, phaseDaemon)
	case "all":
		if err = withBuilders(ctx, phaseBuild, phaseCache, phaseHardening, phaseLimits, phaseFailure); err == nil {
			err = withEnv(ctx, phaseDaemon)
		}
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

type phase func(context.Context, *env, *builder) error

// envPhase is a phase that is not per-builder: the daemon path has no builder
// image, it talks to a host service.
type envPhase func(context.Context, *env) error

func withEnv(ctx context.Context, phases ...envPhase) error {
	e, ctx, err := setup(ctx)
	if err != nil {
		return err
	}
	defer e.client.Close()
	for _, p := range phases {
		if err := p(ctx, e); err != nil {
			return err
		}
	}
	return summary()
}

func withBuilders(ctx context.Context, phases ...phase) error {
	e, ctx, err := setup(ctx)
	if err != nil {
		return err
	}
	defer e.client.Close()

	for _, p := range phases {
		for i := range builders {
			b := &builders[i]
			if err := p(ctx, e, b); err != nil {
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
		fmt.Printf("%s  %-50s %s\n", mark, name, detail)
	} else {
		fmt.Printf("%s  %s\n", mark, name)
	}
}

func info(name, detail string) {
	fmt.Printf("INFO  %-50s %s\n", name, detail)
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

func timed(name string, f func() error) (time.Duration, error) {
	t0 := time.Now()
	err := f()
	d := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		fmt.Printf("  ✗ %-42s %v (%v)\n", name, err, d)
		return d, err
	}
	fmt.Printf("  ✓ %-42s %v\n", name, d)
	return d, nil
}
