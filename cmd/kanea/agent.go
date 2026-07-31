package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/logging"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/runtime"
	"github.com/kanea-dev/kanea/internal/store"
)

// Default filesystem layout. PRD §15.1 makes these configurable; M1 takes the
// defaults and the flags below.
const (
	defaultDataDir = "/var/lib/kanea"
	defaultLogDir  = "/var/log/kanea/allocs"
)

// runAgent is kanead: the control plane. It owns the state file — bbolt is
// single-writer, so nothing else may open it — and therefore also serves the
// API that the CLI uses to reach that state.
func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "state directory")
	logDir := fs.String("log-dir", defaultLogDir, "per-alloc log directory")
	socket := fs.String("socket", api.DefaultSocket, "control API unix socket")
	containerdSocket := fs.String("containerd", runtime.DefaultSocket, "containerd socket")
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

	// The API wakes the reconciler after every apply, so a deploy converges
	// immediately rather than waiting out the interval.
	notify := make(chan struct{}, 1)

	rec, err := reconciler.New(reconciler.Config{
		Store:   st,
		Driver:  driver,
		Network: reconciler.NetnsNetwork{},
		Logger:  logger,
		LogDir:  *logDir,
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
		"version", version, "state", statePath, "socket", *socket, "log_dir", *logDir)

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
