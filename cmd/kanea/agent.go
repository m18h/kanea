package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/logging"
	"github.com/kanea-dev/kanea/internal/network"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/runtime"
	"github.com/kanea-dev/kanea/internal/store"
)

// Default filesystem layout. PRD §15.1 makes these configurable; M1 takes the
// defaults and the flags below.
const (
	defaultDataDir = "/var/lib/kanea"
	defaultLogDir  = "/var/log/kanea/allocs"
	// volumeSubdir is where local volumes live under the data dir (PRD §8).
	volumeSubdir = "volumes"
)

// runAgent is kanead: the control plane. It owns the state file — bbolt is
// single-writer, so nothing else may open it — and therefore also serves the
// API that the CLI uses to reach that state.
func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "state directory")
	logDir := fs.String("log-dir", defaultLogDir, "per-alloc log directory")
	volumeDir := fs.String("volume-dir", "", "local volume root (default <data-dir>/volumes)")
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	containerdSocket := fs.String("containerd", runtime.DefaultSocket, "containerd socket")
	networkMode := fs.String("network", networkCilium,
		"network driver: cilium, or netns for development (no policy, no service LB)")
	ciliumSocket := fs.String("cilium", network.DefaultSocketPath, "cilium-agent API socket")
	cniConf := fs.String("cni-conf", network.DefaultCNIConfPath, "CNI configuration list")
	cniBin := fs.String("cni-bin", network.DefaultCNIBinDir, "CNI plugin directory")
	policyDir := fs.String("policy-dir", network.DefaultPolicyDir, "cilium --static-cnp-path directory")
	logLevel := fs.String("log-level", "info", "debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger, closer, err := logging.New(logging.Config{Level: *logLevel, Format: "text"})
	if err != nil {
		return fmt.Errorf("logging: %w", err)
	}
	defer func() {
		if err := closer.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "kanea: close log sink:", err)
		}
	}()

	// Signals first: a Ctrl-C during startup should still shut down cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	statePath := filepath.Join(*dataDir, "state.db")
	st, err := store.Open(store.Options{Path: statePath, Logger: logger})
	if err != nil {
		return fmt.Errorf("open state %s: %w", statePath, err)
	}
	defer func() {
		// A store that fails to close may not have flushed; say so rather than
		// exiting 0 on a possibly-corrupt shutdown.
		if err := st.Close(); err != nil {
			logger.Error("close state store", "error", err)
		}
	}()

	driver, err := runtime.New(runtime.Config{Socket: *containerdSocket, Logger: logger})
	if err != nil {
		return fmt.Errorf("containerd: %w", err)
	}
	defer func() {
		if err := driver.Close(); err != nil {
			logger.Error("close containerd client", "error", err)
		}
	}()

	if err := os.MkdirAll(*logDir, 0o750); err != nil {
		return fmt.Errorf("log dir: %w", err)
	}
	volumes := *volumeDir
	if volumes == "" {
		volumes = filepath.Join(*dataDir, volumeSubdir)
	}
	if err := os.MkdirAll(volumes, 0o750); err != nil {
		return fmt.Errorf("volume dir: %w", err)
	}

	net, err := buildNetwork(ctx, *networkMode, network.Config{
		SocketPath:  *ciliumSocket,
		CNIConfPath: *cniConf,
		CNIBinDir:   *cniBin,
		PolicyDir:   *policyDir,
		Logger:      logger,
	}, logger)
	if err != nil {
		return err
	}

	// The API wakes the reconciler after every apply, so a deploy converges
	// immediately rather than waiting out the interval.
	notify := make(chan struct{}, 1)

	rec, err := reconciler.New(reconciler.Config{
		Store:     st,
		Driver:    driver,
		Network:   net,
		Logger:    logger,
		LogDir:    *logDir,
		VolumeDir: volumes,
	})
	if err != nil {
		return err
	}

	server, err := api.NewServer(api.ServerConfig{
		Store: st, Logger: logger, Socket: *socket,
		Version: version, LogDir: *logDir, Notify: notify,
	})
	if err != nil {
		return err
	}
	// Bind before announcing readiness: a socket collision must fail loudly at
	// startup, not silently later.
	if err := server.Listen(); err != nil {
		return err
	}

	logger.Info("kanead starting",
		"version", version, "state", statePath, "socket", *socket,
		"log_dir", *logDir, "volume_dir", volumes, "network", *networkMode)

	errs := make(chan error, 2)
	go func() { errs <- server.Serve(ctx) }()
	go func() { errs <- rec.Run(ctx, notify) }()

	// Wait for both to finish; a context cancellation is a clean shutdown.
	var firstErr error
	for range 2 {
		if err := <-errs; err != nil && !errors.Is(err, context.Canceled) && firstErr == nil {
			firstErr = err
		}
	}
	logger.Info("kanead stopped")
	return firstErr
}

// Network driver names for --network.
const (
	// networkCilium is the product: eBPF datapath, per-project policy, service LB.
	networkCilium = "cilium"
	// networkNetns gives each alloc a bare namespace and nothing else. It exists
	// so kanead can run on a host without Cilium — a laptop, a CI job — and is
	// not a supported deployment: no policy is enforced and no service is load
	// balanced, so allocs are unreachable by name.
	networkNetns = "netns"
)

// buildNetwork selects the network driver.
//
// An unreachable cilium-agent is a warning, not a startup failure. Refusing to
// start would take the control API down with it — and the API is exactly what
// an operator needs in order to see why the node is unhealthy. The reconciler
// already treats a failed action as retryable, so attaches resume on their own
// once the agent is back.
func buildNetwork(ctx context.Context, mode string, cfg network.Config, logger *slog.Logger) (reconciler.Network, error) {
	switch mode {
	case networkNetns:
		logger.Warn("network policy and service load balancing are disabled",
			"network", networkNetns, "detail", "development mode: allocs get a bare namespace")
		return reconciler.NetnsNetwork{}, nil

	case networkCilium:
		net, err := network.New(cfg)
		if err != nil {
			return nil, fmt.Errorf("network: %w", err)
		}
		healthCtx, cancel := context.WithTimeout(ctx, ciliumHealthTimeout)
		defer cancel()
		if err := net.Health(healthCtx); err != nil {
			logger.Warn("cilium agent is not answering; allocs cannot attach until it is",
				"socket", cfg.SocketPath, "error", err)
		}
		return net, nil

	default:
		return nil, fmt.Errorf("unknown --network %q: want %s or %s", mode, networkCilium, networkNetns)
	}
}

// ciliumHealthTimeout bounds the startup probe. It is short on purpose: this is
// a diagnostic, and kanead starts either way.
const ciliumHealthTimeout = 5 * time.Second
