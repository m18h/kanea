package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/kanea-dev/kanea/internal/edge"
	"github.com/kanea-dev/kanea/internal/logging"
	"github.com/kanea-dev/kanea/internal/ratelimit"
)

// runEdge is kanea-edge: the public ingress proxy.
//
// It is a separate process from kanead by design (PRD §5.2.6), and everything
// about how it starts follows from that. It opens no database — bbolt is
// single-writer, and the edge holding a handle would mean a control-plane
// restart could not proceed. It reads one file kanead publishes. It needs no
// containerd, no Cilium socket, no state directory. A kanead that is down,
// crashed, or mid-upgrade is invisible here: the last route table keeps
// serving.
func runEdge(args []string) error {
	fs := flag.NewFlagSet("edge", flag.ContinueOnError)
	snapshot := fs.String("routes", edge.DefaultSnapshotPath, "route table kanead publishes")
	httpAddr := fs.String("http", edge.DefaultHTTPAddr, "public HTTP listen address")
	httpsAddr := fs.String("https", edge.DefaultHTTPSAddr,
		"public HTTPS listen address (\"off\" serves plaintext only)")
	certs := fs.String("certs", edge.DefaultBundlePath, "certificate bundle kanead publishes")
	statusAddr := fs.String("status", edge.DefaultStatusAddr,
		"loopback health/diagnostics address (\"off\" disables)")
	poll := fs.Duration("poll", edge.DefaultPollInterval, "how often to re-read the route table")
	drain := fs.Duration("drain", edge.DefaultDrainTimeout, "how long in-flight requests get on shutdown")
	bodyTimeout := fs.Duration("body-timeout", edge.DefaultBodyTimeout,
		"bound on reading a request body (0 disables)")
	upstreamTimeout := fs.Duration("upstream-timeout", edge.DefaultResponseHeaderTimeout,
		"bound on an upstream starting to answer (does not bound the body)")
	securityHeaders := fs.Bool("security-headers", true,
		"add the default security response headers (PRD §14 A05)")
	limiterCap := fs.Int("rate-limit-buckets", ratelimit.DefaultCapacity,
		"maximum tracked rate-limit buckets before least-recently-used eviction")
	memLimit := fs.String("memory-limit", "", "GOMEMLIMIT for this process, e.g. 128MiB")
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
			fmt.Fprintln(os.Stderr, "kanea:", "close log sink:", err)
		}
	}()

	// A soft memory limit rather than a hard one: the edge sits inside the
	// §21 platform budget, and GC pressure is a better failure mode than an
	// OOM kill for the process holding public traffic.
	if *memLimit != "" {
		limit, err := parseByteSize(*memLimit)
		if err != nil {
			return fmt.Errorf("--memory-limit: %w", err)
		}
		debug.SetMemoryLimit(limit)
		logger.Info("memory limit set", "bytes", limit)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	status := *statusAddr
	if status == statusOff {
		status = ""
	}
	// Without TLS the edge still serves :80 — a node with no certificate yet
	// must be reachable, or the HTTP-01 validation that would produce one
	// cannot complete (PRD §7.3).
	tlsAddr := *httpsAddr
	if tlsAddr == tlsOff {
		tlsAddr = ""
		logger.Warn("TLS is disabled; serving plaintext only")
	}

	server, err := edge.New(edge.Config{
		HTTPAddr:     *httpAddr,
		HTTPSAddr:    tlsAddr,
		BundlePath:   *certs,
		StatusAddr:   status,
		SnapshotPath: *snapshot,
		PollInterval: *poll,
		DrainTimeout: *drain,
		Version:      version,
		Logger:       logger,
		Proxy: edge.ProxyConfig{
			BodyTimeout:           *bodyTimeout,
			ResponseHeaderTimeout: *upstreamTimeout,
			SecurityHeaders:       *securityHeaders,
			LimiterCapacity:       *limiterCap,
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

// byteUnits are the suffixes parseByteSize accepts, longest first so "GiB" is
// matched before "G".
var byteUnits = []struct {
	suffix string
	scale  int64
}{
	{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10},
	{"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1},
}

// parseByteSize reads "128MiB", "1GiB", or a plain byte count.
func parseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	for _, u := range byteUnits {
		rest, ok := strings.CutSuffix(s, u.suffix)
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%q: %w", s, err)
		}
		if n <= 0 {
			return 0, fmt.Errorf("%q: must be positive", s)
		}
		return n * u.scale, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q: want a byte count or a size like 128MiB", s)
	}
	return n, nil
}
