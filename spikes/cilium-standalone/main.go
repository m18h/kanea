// Command spike is throwaway M0 validation code (PRD §20, spike ①).
// It validates, on the kanea-spike OrbStack VM, that Cilium works standalone
// (no Kubernetes anywhere) for everything Kanea needs from it:
//
//  1. CNI ADD driven by OUR process against a pre-created netns -> Cilium endpoint
//  2. endpoint labels + identity (the CNI plugin cannot carry them -> agent API)
//  3. service load balancing programmed through the agent API (Maglev)
//  4. network policy import + enforcement (default-deny per project)
//  5. Hubble metrics without a k8s ConfigMap
//
// Nothing here ships. M2 reimplements the validated patterns in internal/network.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
)

const (
	containerdSock = "/run/containerd/containerd.sock"
	ctrNamespace   = "kanea-spike-cilium"
	// busybox rather than alpine: alpine's busybox build has no httpd applet,
	// and the LB phase needs a real listener in each backend.
	imageRef = "docker.io/library/busybox:1.37"

	ciliumSock  = "/var/run/cilium/cilium.sock"
	cniBinDir   = "/opt/cni/bin"
	cniConfPath = "/etc/cni/net.d/05-cilium.conflist"

	hubbleMetricsURL = "http://127.0.0.1:9965/metrics"

	// Service frontend ("ClusterIP"): deliberately outside the endpoint
	// allocation CIDR (10.200.1.0/24), like Kanea's future service CIDR.
	serviceVIP  = "10.201.0.1"
	servicePort = 80
	backendPort = 8080
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: spike <net|lb|policy|hubble|all|hazard|up|clean>\n")
		os.Exit(2)
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "net":
		err = runPhases(ctx, phaseNet)
	case "lb":
		err = runPhases(ctx, phaseNet, phaseLB)
	case "policy":
		err = runPhases(ctx, phaseNet, phasePolicy)
	case "hubble":
		err = runPhases(ctx, phaseNet, phasePolicy, phaseHubble)
	case "all":
		err = runPhases(ctx, phaseNet, phaseLB, phasePolicy, phaseHubble)
	case "hazard": // destructive: what an invalid policy file does to the agent
		err = runHazard(ctx)
	case "up": // debug helper: set up the allocs and leave them running
		err = runUp(ctx)
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

// env carries everything the phases share: clients plus the running allocs.
type env struct {
	client *containerd.Client
	cil    *ciliumClient
	allocs map[string]*running
}

type phase func(context.Context, *env) error

// runPhases sets up the shared world, runs the phases in order, tears down.
func runPhases(ctx context.Context, phases ...phase) error {
	e, ctx, err := setup(ctx)
	if err != nil {
		return err
	}
	defer teardown(ctx, e)

	for _, p := range phases {
		if err := p(ctx, e); err != nil {
			return err
		}
	}
	return summary()
}

func setup(ctx context.Context) (*env, context.Context, error) {
	client, err := containerd.New(containerdSock)
	if err != nil {
		return nil, ctx, fmt.Errorf("dial %s: %w", containerdSock, err)
	}
	ctx = namespaces.WithNamespace(ctx, ctrNamespace)
	return &env{client: client, cil: newCiliumClient(), allocs: map[string]*running{}}, ctx, nil
}

func teardown(ctx context.Context, e *env) {
	fmt.Println("\n── teardown ──")
	_ = removePolicy(isolationFile)
	_ = removePolicy(dnsPolicyFile)
	_ = os.Remove(lbStateFile)
	for id := range e.allocs {
		removeAlloc(ctx, e.client, id)
	}
	_ = e.client.Close()
}

func runUp(ctx context.Context) error {
	e, ctx, err := setup(ctx)
	if err != nil {
		return err
	}
	defer e.client.Close()
	if err := phaseNet(ctx, e); err != nil {
		return err
	}
	fmt.Println("\nallocs left running; `spike clean` to remove")
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
		fmt.Printf("%s  %-56s %s\n", mark, name, detail)
	} else {
		fmt.Printf("%s  %s\n", mark, name)
	}
}

// info records an observation that is not a go/no-go criterion.
func info(name, detail string) {
	fmt.Printf("INFO  %-56s %s\n", name, detail)
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
