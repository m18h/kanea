package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/m18h/kanea/internal/logging"
	"github.com/m18h/kanea/internal/provision"
)

// `kanea supervise <component>` — the ExecStart for an image-backed host
// component (PRD §5.2.12).
//
// It exists because cilium-agent runs as a containerd task rather than a host
// binary, and systemd supervises processes rather than tasks. This is the
// process: it creates the task, places its cgroup under kanea.slice, streams
// its output, and exits with it.
//
// A shell wrapper around `ctr run` would work, and would also mean "container
// orchestration in one binary" quietly acquired a second file that has to be
// installed, versioned and kept in step with the flags in
// internal/provision.CiliumArgs. Going through the runtime driver keeps one
// copy of both.
//
// Not a command anyone types. It is in the table because a command that only
// systemd invokes still has to be discoverable by whoever is reading the unit
// file and wondering what it does.

func runSupervise(args []string) error {
	fs := flag.NewFlagSet("supervise", flag.ContinueOnError)
	socket := fs.String("containerd", provision.DefaultRunDir+"/containerd.sock", "containerd socket")
	prefix := fs.String("prefix", provision.DefaultPrefix, "component install prefix")
	dataDir := fs.String("data-dir", provision.DefaultDataDir, "component state directory")
	runDir := fs.String("run-dir", provision.DefaultRunDir, "component socket directory")
	nodeCIDR := fs.String("node-cidr", provision.DefaultNodeCIDR, "this node's pod CIDR")
	clusterCIDR := fs.String("cluster-cidr", provision.DefaultClusterCIDR, "native routing CIDR")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea supervise <component> — " +
			"run by systemd, not by hand; the only supervised component is `cilium`")
	}

	name := fs.Arg(0)
	if name != "cilium" {
		return fmt.Errorf("cannot supervise %q: cilium is the only component that runs as a task "+
			"(buildkitd and the rest are host binaries with their own units)", name)
	}

	manifest, err := provision.Load()
	if err != nil {
		return err
	}
	component, err := manifest.Get(name)
	if err != nil {
		return err
	}

	layout := provision.Layout{
		Prefix: *prefix, DataDir: *dataDir, RunDir: *runDir,
		ConfDir: provision.DefaultConfDir, UnitDir: defaultUnitDir,
	}

	// systemd sends SIGTERM on stop; the task has to be told, not merely
	// orphaned. A cilium-agent left running after its unit stopped would keep
	// programming the dataplane that nothing is managing any more.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Text to stderr: systemd captures it into the journal, which is where
	// someone debugging `systemctl status kanea-cilium` is already looking.
	log, closer, err := logging.New(logging.Config{Level: "info", Format: "text"})
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }() //nolint:errcheck // cleanup path
	supervisor, err := provision.NewSupervisor(*socket, layout, log)
	if err != nil {
		return err
	}
	defer func() { _ = supervisor.Close() }() //nolint:errcheck // cleanup path
	return supervisor.RunCilium(ctx, component, provision.CiliumOptions{
		NodeCIDR:    *nodeCIDR,
		ClusterCIDR: *clusterCIDR,
	})
}
