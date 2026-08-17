package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/logging"
	"github.com/m18h/kanea/internal/mcp"
	"github.com/m18h/kanea/internal/reconciler"
)

// runMCP serves the MCP stdio transport (PRD §16.3).
//
// It is a client of kanead, not a second copy of it: every tool call goes over
// the unix socket to the running daemon, through the same routes the CLI uses.
// A local agent that launches this gets exactly the authority the socket
// confers, which, per §13.1, is the authority of the user who can open it.
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

	// The node's shared variables (R30), fetched once: the file behind them
	// is load-once, so a session-long value is the daemon's own behaviour. A
	// failed fetch (older daemon, unreachable socket) parses without them:
	// the unknown-variable diagnostic reaches the agent as the tool's error.
	nodeVars, varsErr := api.NewClient(*socket).Vars(context.Background())
	if varsErr != nil {
		log.Debug("node variables unavailable; specs parse without them", "error", varsErr)
	}

	server, err := mcp.New(mcp.Config{
		Backend:   mcp.NewSocketBackend(*socket),
		Logger:    log,
		Version:   version,
		ParseSpec: specParser(nodeVars),
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

// specParser turns job-spec source into desired state, for the plan_spec and
// apply_spec tools, with the node's shared variables (R30) in scope: handed
// over directly on the daemon, fetched over the API by `kanea mcp`.
//
// The same parse and the same conversion the CLI performs, so a spec an agent
// applies and a spec a person applies mean the same thing. The diagnostics are
// returned rather than printed: an agent reads them as the tool's error text,
// and they are what tells it which line to fix.
func specParser(nodeVars map[string]string) func([]byte) ([]reconciler.Desired, []gitops.Config, error) {
	return func(source []byte) ([]reconciler.Desired, []gitops.Config, error) {
		spec, diags := jobspec.ParseSource(jobspec.Options{NodeVars: nodeVars}, "spec.hcl", source)
		if diags.HasErrors() {
			return nil, nil, errors.New(jobspec.FormatDiagnostics(diags))
		}
		desired, err := toDesired(spec)
		if err != nil {
			return nil, nil, err
		}
		return desired, pipelineConfigs(spec), nil
	}
}
