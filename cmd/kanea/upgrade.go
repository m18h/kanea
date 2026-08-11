package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/api"
)

// runUpgrade is `kanea upgrade` (PRD §15.4).
//
// It orchestrates a restart; it does not fetch a binary. Installing software is
// the package manager's job — or `scripts/install.sh` — and a command that both
// downloaded and restarted would be a command nobody could safely run twice.
// What it owns is the *order*, which is the part §15.4 specifies and the part
// that is easy to get wrong.
//
// The order is: back up, drain the edge and restart it, then restart kanead.
// The edge goes first because it is the thing carrying traffic and it comes
// back in seconds; kanead goes last because it is the thing that will migrate
// the schema, and a migration should happen once every other moving part has
// already settled. Running allocs are untouched throughout — that is what
// KillMode=process in the unit is for.
func runUpgrade(args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	socket := socketFlag(fs)
	skipBackup := fs.Bool("skip-backup", false,
		"do not take a backup first (the schema migration takes its own local copy either way)")
	dryRun := fs.Bool("dry-run", false, "print what would run and stop")
	timeout := fs.Duration("timeout", 2*time.Minute, "how long to wait for each service")
	if err := fs.Parse(args); err != nil {
		return err
	}

	o := newOut()
	ctx := context.Background()
	client := api.NewClient(*socket)

	installed, err := client.Health(ctx)
	if err != nil {
		return fmt.Errorf("cannot reach kanead: %w", err)
	}
	o.printf("Running version: %s\n", installed.Version)
	o.printf("Binary version:  %s\n", version)
	if installed.Version == version && !*dryRun {
		// Not an error: the units may still need restarting after a package
		// upgrade that replaced the binary in place, and a restart is harmless.
		o.println("\nThe daemon is already running this version. Restarting anyway is safe;")
		o.println("stop here if that is not what you meant.")
	}

	if !*skipBackup {
		o.println("\nTaking a pre-upgrade backup…")
		manifest, err := client.CreateBackup(ctx, "pre-upgrade")
		switch {
		case err == nil:
			o.printf("  archive %s at index %d\n", manifest.ID, manifest.Index)
		case isNotConfigured(err):
			// Said clearly rather than swallowed. The schema migration takes its
			// own local copy, so this is not fatal — but an operator upgrading a
			// node with no backup destination should know that is what they are
			// doing.
			o.println("  no backup destination is configured on this daemon.")
			o.println("  The schema migration still takes a local copy before it runs,")
			o.println("  but nothing is leaving this node. See docs/DR_RUNBOOK.md.")
		default:
			return fmt.Errorf("pre-upgrade backup failed: %w "+
				"(re-run with --skip-backup to upgrade anyway)", err)
		}
	}

	steps := []struct{ what, unit string }{
		// The edge first, and on its own: it drains and comes back in seconds,
		// and it must be current before the control plane starts publishing
		// route projections a newer format might describe differently.
		{"edge proxy", "kanea-edge"},
		// kanead last. It runs the schema migration at startup, and that should
		// happen when everything else has settled.
		{"control plane", "kanead"},
	}

	o.println()
	for _, step := range steps {
		if *dryRun {
			o.printf("would run: systemctl restart %s\n", step.unit)
			continue
		}
		o.printf("Restarting the %s (%s)…\n", step.what, step.unit)
		if err := restartUnit(ctx, step.unit, *timeout); err != nil {
			return err
		}
	}
	if *dryRun {
		return o.Err()
	}

	// Confirmed rather than assumed. "systemctl restart returned 0" and "the
	// daemon is answering" are different facts, and only the second one means
	// the upgrade worked.
	o.println("\nWaiting for the control plane…")
	health, err := waitForDaemon(ctx, client, *timeout)
	if err != nil {
		return fmt.Errorf("%w — check `journalctl -u kanead`; if a schema migration "+
			"failed, its pre-migration copy is named in the log", err)
	}
	o.printf("kanead is up at %s\n", health.Version)

	o.println()
	o.println("Running allocs were not touched. If a schema migration ran, its")
	o.println("pre-migration copy is in the data directory — delete it once this")
	o.println("upgrade is confirmed good.")
	return o.Err()
}

// restartUnit restarts a systemd unit.
func restartUnit(ctx context.Context, unit string, timeout time.Duration) error {
	return systemctl(ctx, timeout, "restart", unit)
}

// healthAPI is the one call waitForDaemon needs; `kanea init`'s bootstrap
// passes its own client seam through it.
type healthAPI interface {
	Health(ctx context.Context) (api.Health, error)
}

// waitForDaemon polls health until the daemon answers or the deadline passes.
func waitForDaemon(ctx context.Context, client healthAPI, timeout time.Duration) (api.Health, error) {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		health, err := client.Health(ctx)
		if err == nil {
			return health, nil
		}
		last = err
		select {
		case <-ctx.Done():
			return api.Health{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return api.Health{}, fmt.Errorf("kanead did not come back within %s: %w", timeout, last)
}

// isNotConfigured reports a 503 from a subsystem that is simply absent, which
// is different from one that failed.
func isNotConfigured(err error) bool {
	var status *api.StatusError
	return errors.As(err, &status) && status.Status == 503
}

// runUI prints — and optionally opens — the dashboard URL.
//
// It prints by default rather than opening. `kanea ui` is most often run over
// SSH on the node itself, where "open a browser" means either nothing or an
// error, and a command whose useful output is a URL should print the URL.
func runUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	socket := socketFlag(fs)
	addr := fs.String("addr", "", "dashboard address (default: ask the daemon)")
	open := fs.Bool("open", false, "open it in a browser")
	if err := fs.Parse(args); err != nil {
		return err
	}

	target := *addr
	if target == "" {
		client := api.NewClient(*socket)
		health, err := client.Health(context.Background())
		if err != nil {
			return fmt.Errorf("cannot reach kanead to ask where the dashboard is: %w", err)
		}
		if health.Listen == "" {
			return errors.New("this daemon has no network listener, so the dashboard is not " +
				"reachable: start kanead with --listen (and --serve-dashboard), or pass --addr")
		}
		target = dashboardURL(health.Listen, health.TLS)
	}

	o := newOut()
	o.println(target)
	if !*open {
		return o.Err()
	}
	if err := openBrowser(target); err != nil {
		return err
	}
	return o.Err()
}

// dashboardURL turns a listen address into something a browser accepts.
func dashboardURL(listen string, secure bool) string {
	scheme := "http"
	if secure {
		scheme = "https"
	}
	// A wildcard bind is not an address anyone can visit. Rewritten to
	// localhost, which is where the person running this command is.
	host := listen
	if strings.HasPrefix(host, ":") {
		host = "localhost" + host
	}
	host = strings.Replace(host, "0.0.0.0:", "localhost:", 1)
	host = strings.Replace(host, "[::]:", "localhost:", 1)
	return scheme + "://" + host
}

// openBrowser hands a URL to the desktop.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url) // #nosec G204 — a URL this process built
	case "linux":
		cmd = exec.Command("xdg-open", url) // #nosec G204 — same
	default:
		return fmt.Errorf("cannot open a browser on %s; the URL is above", runtime.GOOS)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open a browser: %w (the URL is above)", err)
	}
	return nil
}
