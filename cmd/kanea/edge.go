package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/logging"
	"github.com/m18h/kanea/internal/nodeconfig"
)

// runEdge is kanea-edge: the public ingress proxy.
//
// It is a separate process from kanead by design (PRD §5.2.6), and everything
// about how it starts follows from that. It opens no database: bbolt is
// single-writer, and the edge holding a handle would mean a control-plane
// restart could not proceed. It reads one file kanead publishes. It needs no
// containerd, no datapath, no state directory. A kanead that is down,
// crashed, or mid-upgrade is invisible here: the last route table keeps
// serving.
func runEdge(args []string) error {
	if len(args) > 0 {
		return daemonArgs("edge", args)
	}
	// The edge reads the same file kanead does (PRD §15.1, v1.115), and only
	// its own two stanzas of it: a mistake in a stanza that is kanead's to
	// validate must not take the public listeners down with it.
	file, err := nodeconfig.LoadEdge(nodeconfig.DefaultPath)
	if err != nil {
		return err
	}
	s := resolveEdgeSettings(file)

	logger, closer, err := logging.New(logging.Config{Level: s.logLevel, Format: "text"})
	if err != nil {
		return fmt.Errorf("logging: %w", err)
	}
	defer func() {
		if err := closer.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "kanea:", "close log sink:", err)
		}
	}()

	// A soft memory limit rather than a hard one: the edge sits inside the
	// §21 platform budget, and GC pressure is a better failure mode than an
	// OOM kill for the process holding public traffic.
	if s.memLimit != "" {
		limit, err := jobspec.ParseByteSize(s.memLimit)
		if err != nil {
			return fmt.Errorf("edge.memory_limit: %w", err)
		}
		debug.SetMemoryLimit(limit)
		logger.Info("memory limit set", "bytes", limit)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	status := s.statusAddr
	if status == statusOff {
		status = ""
	}
	// Without TLS the edge still serves :80: a node with no certificate yet
	// must be reachable, or the HTTP-01 validation that would produce one
	// cannot complete (PRD §7.3).
	tlsAddr := s.httpsAddr
	if tlsAddr == tlsOff {
		tlsAddr = ""
		logger.Warn("TLS is disabled; serving plaintext only")
	}

	server, err := edge.New(edge.Config{
		HTTPAddr:     s.httpAddr,
		HTTPSAddr:    tlsAddr,
		BundlePath:   s.certs,
		StatusAddr:   status,
		SnapshotPath: s.snapshot,
		PollInterval: s.poll,
		DrainTimeout: s.drain,
		// Separate from edge.drain_timeout on purpose: a game session or a psql
		// connection is not an HTTP request, and an operator may well want 60 s
		// here and 15 s on :443.
		PublishDrain:      s.publishDrain,
		MaxPublishedConns: s.maxPublishedConns,
		FunctionsPort:     s.functionsPort,
		Version:           version,
		Logger:            logger,
		Proxy: edge.ProxyConfig{
			BodyTimeout:           s.bodyTimeout,
			ResponseHeaderTimeout: s.upstreamTimeout,
			SecurityHeaders:       s.securityHeaders,
			LimiterCapacity:       s.limiterCap,
		},
	})
	if err != nil {
		return err
	}
	// Bind before the process claims to be up: :80 is contended, and a
	// collision must be a startup failure rather than a silent one.
	if err := server.Listen(); err != nil {
		return err
	}

	if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// statusOff disables the diagnostics listener; tlsOff disables the TLS one.
const (
	statusOff = "off"
	tlsOff    = "off"
)
