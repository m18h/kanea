// Command kanea is the single binary of the Kanea platform: control plane
// (agent), ingress (edge), MCP server, and CLI — all subcommands of one
// static binary (PRD §2, G1).
//
// See PRD.md (the project north star) and AGENTS.md before making any
// architectural change. Deviations require a PRD amendment first.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
)

// version is injected at build time:
//
//	go build -ldflags "-X main.version=vX.Y.Z" ./cmd/kanea
var version = "0.0.0-dev"

// errNotImplemented marks subcommands belonging to a future milestone (PRD §20).
var errNotImplemented = errors.New("not implemented yet — see PRD §20 milestones")

type command struct {
	name string
	desc string
	run  func(args []string) error
}

// commands is the CLI surface defined in PRD §16.2, in usage order.
var commands = []command{
	{"init", "interactive first-install: config, auth, deps/kernel/NTP checks, key ceremony", runInit},
	{"install", "install the pinned host components: containerd, runc, buildkit (PRD §5.2.12)", runInstall},
	{"bundle", "author an offline component bundle for an air-gapped node: create", runBundle},
	{"agent", "run the control-plane daemon (kanead)", runAgent},
	{"edge", "run the edge ingress proxy (kanea-edge, separate process — PRD §5.2.6)", runEdge},
	{"doctor", "verify node health: deps, versions, disk, clock", runDoctor},
	{"plan", "dry-run diff of a job spec", runPlan},
	{"run", "apply a job spec (or --image for a bare image); alias: apply", runRun},
	{"stop", "stop a service (scale to zero; --rm deletes it)", runStop},
	{"start", "start a stopped service (one replica unless a count is given)", runStart},
	{"restart", "roll a service's allocs through its update policy", runRestart},
	{"ps", "list allocations (-a adds stopped and not-yet-created)", runPs},
	{"describe", "one service in full: spec, routes, allocs, stats, events", runDescribe},
	{"status", "service and platform status", runStatus},
	{"logs", "stream service logs", runLogs},
	{"exec", "debug shell into an alloc (admin-only, audited)", runExec},
	{"scale", "manually scale a service", runScale},
	{"build", "trigger a build pipeline", runBuild},
	{"functions", "wasm functions: list (triggers, invocation rate, status)", runFunctions},
	{"project", "project operations: sync, builds", runProject},
	{"backup", "backup create|list|verify", runBackup},
	{"restore", "restore state from a snapshot", runRestore},
	{"secret", "manage secrets: put, ls, rm (write-only — there is no get)", runSecret},
	{"ca", "this node's self-signed CA, to install on your devices: show, info", runCA},
	{"user", "manage accounts: add, ls, rm", runUser},
	{"token", "manage API tokens: create, ls, rm", runToken},
	{"upgrade", "drain edge, restart services, run state migrations", runUpgrade},
	{"mcp", "stdio MCP server for local AI agents (PRD §16.3)", runMCP},
	{"ui", "open the dashboard URL", runUI},
	{"version", "print version and exit", runVersion},
}

func main() {
	err := run(os.Args[1:])
	if err == nil {
		return
	}
	// A command that ran something else propagates its exit code and says
	// nothing: `kanea exec web -- test -f /x` has to be usable in a script, and
	// printing "kanea: exit status 1" over a program's own output would make it
	// unusable in one.
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		os.Exit(coded.ExitCode())
	}
	fmt.Fprintln(os.Stderr, "kanea:", err)
	os.Exit(1)
}

// aliases map a second spelling onto a command, resolved before dispatch —
// one table entry, one handler, so the spellings cannot drift (PRD v1.52).
// The usage output deliberately keeps one row per verb; the alias rides the
// target's description instead.
var aliases = map[string]string{"apply": "run"}

func run(args []string) error {
	if len(args) == 0 {
		return printUsage(os.Stdout)
	}
	name := args[0]
	if target, ok := aliases[name]; ok {
		name = target
	}
	for _, c := range commands {
		if c.name == name {
			return c.run(args[1:])
		}
	}
	if err := printUsage(os.Stderr); err != nil {
		return err
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func todo([]string) error { return errNotImplemented }

func runVersion([]string) error {
	_, err := fmt.Fprintln(os.Stdout, "kanea", version)
	return err
}

func printUsage(w io.Writer) error {
	if _, err := fmt.Fprintln(w, "kanea — lightweight container orchestration (north star: PRD.md)"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "\nUsage: kanea <command> [args]\n\nCommands:"); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range commands {
		if _, err := fmt.Fprintf(tw, "  %s\t%s\n", c.name, c.desc); err != nil {
			return err
		}
	}
	return tw.Flush()
}
