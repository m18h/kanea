package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/reconciler"
)

// runExec is `kanea exec` (PRD §16.2): a debug shell inside a running alloc.
//
// Admin-only and audited, and both of those are the daemon's doing rather than
// this command's — the route is marked mutating, so the same wrapper that
// guards every other mutation guards this one, and the audit entry records the
// command that was asked for whether or not the session established.
func runExec(args []string) error {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	socket := socketFlag(fs)
	project := fs.String("project", "", "project name")
	alloc := fs.String("alloc", "", "alloc id (default: the first running alloc of the service)")
	user := fs.String("user", "", "numeric uid to run as (default: the workload's own)")
	interactive := fs.Bool("it", false, "allocate a terminal and forward stdin (a shell needs this)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	service, command, err := splitExecArgs(fs.Args())
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client := api.NewClient(*socket)
	target := *alloc
	if target == "" {
		target, err = pickAlloc(ctx, client, *project, service)
		if err != nil {
			return err
		}
	}

	code, err := client.Exec(ctx, api.ExecOptions{
		Project: *project, Alloc: target, Command: command,
		TTY: *interactive, User: *user,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	})
	if err != nil {
		return err
	}
	if code != 0 {
		// The remote exit code is this command's exit code, so `kanea exec … --
		// test -f /x` is usable in a script. It is not an error to report on top
		// of, which would print a message over a program's own output.
		return &exitCodeError{code: int(code)}
	}
	return nil
}

// splitExecArgs separates the service from the command after `--`.
//
// The separator is required. Without it, `kanea exec web ls -la` is ambiguous —
// `-la` could be a flag of kanea's — and guessing produces the failure where a
// flag meant for the remote command is silently eaten here.
func splitExecArgs(args []string) (service string, command []string, err error) {
	if len(args) == 0 {
		return "", nil, errors.New("usage: kanea exec [--project P] [-it] <service> -- <command> [args…]")
	}
	service = args[0]
	rest := args[1:]
	if len(rest) == 0 {
		return "", nil, fmt.Errorf(
			"no command given: kanea exec %s -- /bin/sh", service)
	}
	if rest[0] != "--" {
		return "", nil, fmt.Errorf(
			"put the command after `--`, so its flags are not read as kanea's: "+
				"kanea exec %s -- %s", service, strings.Join(rest, " "))
	}
	command = rest[1:]
	if len(command) == 0 {
		return "", nil, errors.New("nothing after `--`")
	}
	return service, command, nil
}

// pickAlloc chooses a running alloc of a service.
//
// Deterministic — the lowest index that is running — rather than arbitrary. An
// operator who runs the same command twice and lands in two different
// containers has been given a debugging tool that lies about what it is
// showing them.
func pickAlloc(ctx context.Context, client *api.Client, project, service string) (string, error) {
	allocs, err := client.Allocs(ctx, project, service)
	if err != nil {
		return "", err
	}

	best := reconciler.AllocRecord{Index: -1}
	for _, alloc := range allocs {
		if alloc.State != reconciler.AllocRunning {
			continue
		}
		if best.Index < 0 || alloc.Index < best.Index {
			best = alloc
		}
	}
	if best.Index < 0 {
		if len(allocs) == 0 {
			return "", fmt.Errorf("no allocs for %s; is it running?", serviceLabel(project, service))
		}
		return "", fmt.Errorf("no running alloc for %s (%d exist but none are running) — "+
			"`kanea ps` shows why", serviceLabel(project, service), len(allocs))
	}
	return best.ID, nil
}

func serviceLabel(project, service string) string {
	if project == "" {
		return service
	}
	return project + "/" + service
}

// exitCodeError carries a remote exit code out to main without a message.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// ExitCode reports the status this process should exit with.
func (e *exitCodeError) ExitCode() int { return e.code }
