package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kanea-dev/kanea/internal/gitops"
	"github.com/kanea-dev/kanea/internal/jobspec"
	"github.com/kanea-dev/kanea/internal/logging"
	"github.com/kanea-dev/kanea/internal/mcp"
	"github.com/kanea-dev/kanea/internal/reconciler"
)

// runMCP serves the MCP stdio transport (PRD §16.3).
//
// It is a client of kanead, not a second copy of it: every tool call goes over
// the unix socket to the running daemon, through the same routes the CLI uses.
// A local agent that launches this gets exactly the authority the socket
// confers — which, per §13.1, is the authority of the user who can open it.
func runMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	socket := socketFlag(fs)
	verbose := fs.Bool("verbose", false, "log protocol activity to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// stderr, never stdout. stdout is the protocol channel, and one log line on
	// it corrupts the stream in a way that presents to the user as an MCP client
	// that connects and then does nothing.
	// The default sink is stderr, which is exactly right here.
	level := "warn"
	if *verbose {
		level = "debug"
	}
	log, closer, err := logging.New(logging.Config{Level: level, Format: "text"})
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closer.Close(); cerr != nil {
			fmt.Fprintln(os.Stderr, "kanea mcp: closing the log sink:", cerr)
		}
	}()

	server, err := mcp.New(mcp.Config{
		Backend:   mcp.NewSocketBackend(*socket),
		Logger:    log,
		Version:   version,
		ParseSpec: parseSpecSource,
	})
	if err != nil {
		return err
	}

	// SIGINT and SIGTERM end the session cleanly. An agent that kills its
	// subprocess is the normal way this exits, and a half-written reply on the
	// way out is worse than none.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Debug("serving MCP over stdio", "socket", *socket)
	if err := server.ServeStdio(ctx, os.Stdin, os.Stdout); err != nil {
		return fmt.Errorf("mcp: %w", err)
	}
	return nil
}

// parseSpecSource turns job-spec source into desired state, for the plan_spec
// and apply_spec tools.
//
// The same parse and the same conversion the CLI performs, so a spec an agent
// applies and a spec a person applies mean the same thing. The diagnostics are
// returned rather than printed: an agent reads them as the tool's error text,
// and they are what tells it which line to fix.
func parseSpecSource(source []byte) ([]reconciler.Desired, []gitops.Config, error) {
	spec, diags := jobspec.ParseSource(jobspec.Options{}, "spec.hcl", source)
	if diags.HasErrors() {
		return nil, nil, errors.New(jobspec.FormatDiagnostics(diags))
	}
	desired, err := toDesired(spec)
	if err != nil {
		return nil, nil, err
	}
	return desired, pipelineConfigs(spec), nil
}
