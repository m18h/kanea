package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/m18h/kanea/internal/api"
)

// daemonUpgrader implements api.Upgrader over the v1.59 fetch half (PRD
// v1.107): the dashboard's upgrade is `kanea upgrade` run by the daemon on
// itself. It lives in this package on purpose, beside selfupdate.go, so the
// release contract (assetName, checksums, cosign, the rename(2) swap) has
// exactly one implementation with two callers.
type daemonUpgrader struct {
	log *slog.Logger
	// version is the running daemon's own stamp: what "running" means in a
	// check, and what a downgrade is measured against.
	version string
	// requireSig mirrors install.sh's KANEA_REQUIRE_SIGNATURE=1 (v1.105): a
	// missing cosign, or a release without its signature pair, becomes a
	// refusal instead of a note.
	requireSig bool
	// underSystemd is whether an exit comes back: Restart=always is the whole
	// safety of the restart half, so without a supervisor CanRestart says no
	// and the API stages the install instead.
	underSystemd bool
	// stop is the signal context's own stop function, so an upgrade restart
	// and a SIGTERM are the same clean-shutdown path.
	stop func()
	// restartEdge and source are seam-shaped for tests; the real ones are
	// systemctl and newReleaseSource.
	restartEdge func(ctx context.Context) error
	source      func() *releaseSource
}

// edgeRestartTimeout bounds the edge's drain-and-restart, `kanea upgrade`'s
// own default.
const edgeRestartTimeout = 2 * time.Minute

func newDaemonUpgrader(log *slog.Logger, stop func()) *daemonUpgrader {
	return &daemonUpgrader{
		log: log, version: version,
		requireSig:   os.Getenv("KANEA_REQUIRE_SIGNATURE") == "1",
		underSystemd: os.Getenv("INVOCATION_ID") != "",
		stop:         stop,
		restartEdge: func(ctx context.Context) error {
			return systemctl(ctx, edgeRestartTimeout, "restart", "kanea-edge")
		},
		source: newReleaseSource,
	}
}

// Check resolves the latest release the way the installer does and compares
// it to the running daemon.
func (u *daemonUpgrader) Check(ctx context.Context) (api.UpgradeCheck, error) {
	latest, err := u.source().latest(ctx)
	if err != nil {
		return api.UpgradeCheck{}, err
	}
	return api.UpgradeCheck{
		Running: u.version, Latest: latest,
		// A dev build compares equal to everything (compareReleaseTags), so
		// it never claims an update it cannot reason about.
		UpdateAvailable: compareReleaseTags(latest, u.version) > 0,
	}, nil
}

// Upgrade resolves, verifies and installs target over the running binary.
func (u *daemonUpgrader) Upgrade(ctx context.Context, target string) (api.UpgradeOutcome, error) {
	if target != "" && !releaseTag.MatchString(target) {
		return api.UpgradeOutcome{}, fmt.Errorf("%w: %q", api.ErrUpgradeBadTarget, target)
	}
	source := u.source()
	if target == "" {
		var err error
		if target, err = source.latest(ctx); err != nil {
			return api.UpgradeOutcome{}, err
		}
	}
	// K-41, with no override here: `--allow-downgrade` is the CLI's, on the
	// node, where the operator who means it is standing.
	if compareReleaseTags(target, u.version) < 0 {
		return api.UpgradeOutcome{}, fmt.Errorf("%w (%s < %s)", api.ErrUpgradeDowngrade, target, u.version)
	}
	if target == u.version {
		return api.UpgradeOutcome{
			Installed: target,
			Notes:     []string{fmt.Sprintf("the daemon is already running %s; nothing to do", target)},
		}, nil
	}
	asset, err := assetName(target)
	if err != nil {
		return api.UpgradeOutcome{}, err
	}
	binPath, err := runningBinaryPath()
	if err != nil {
		return api.UpgradeOutcome{}, err
	}
	notes, err := source.selfUpdate(ctx, target, asset, binPath, u.requireSig)
	if err != nil {
		return api.UpgradeOutcome{Notes: notes}, err
	}
	return api.UpgradeOutcome{Installed: target, Notes: notes, RestartNeeded: true}, nil
}

// Restart restarts the edge, then exits this daemon so systemd restarts it
// onto the new binary. Called after the API response has been written.
func (u *daemonUpgrader) Restart(ctx context.Context) error {
	// The edge first, the v1.59 order: it drains and returns in seconds, and
	// it must be current before the control plane starts publishing
	// projections a newer format might describe differently.
	if err := u.restartEdge(ctx); err != nil {
		// Said, not fatal: the binary is already swapped, and stopping here
		// would leave both daemons on the old image with nothing saying so.
		u.log.Error("restart kanea-edge", "error", err,
			"detail", "restart it by hand; kanead restarts regardless")
	}
	u.log.Info("kanead exiting for upgrade",
		"detail", "systemd restarts it on the new binary (Restart=always)")
	u.stop()
	return nil
}

// CanRestart reports whether an exiting kanead comes back.
func (u *daemonUpgrader) CanRestart() bool { return u.underSystemd }
