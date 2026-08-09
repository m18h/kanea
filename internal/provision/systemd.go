package provision

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// systemd control.
//
// Shelling out to `systemctl` rather than speaking to systemd over D-Bus: the
// operations are four, they are the ones an operator would type, and a D-Bus
// client is a dependency graph plus a socket to get wrong for no behaviour
// that is not already available. It also means the failure messages are the
// ones people can search for.
//
// PRD §21 makes systemd a platform requirement, so its absence is a supported
// configuration only in the sense that `kanea install` says what it cannot do
// and installs the binaries anyway (§5.2.11: on a non-systemd host kanead
// builds the cgroup hierarchy itself).

// systemctlTimeout bounds one systemctl call. `enable --now` on a unit that
// fails to start returns promptly; this is for a wedged systemd.
const systemctlTimeout = 2 * time.Minute

// SystemdAvailable reports whether systemd is running this machine.
//
// /run/systemd/system is systemd's own marker for "I am PID 1 here" — the one
// documented way to ask, and true inside a systemd-managed container as well.
func SystemdAvailable() bool {
	info, err := os.Stat("/run/systemd/system")
	return err == nil && info.IsDir()
}

// Systemd runs systemctl.
type Systemd struct{}

func (Systemd) run(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, systemctlTimeout)
	defer cancel()

	// #nosec G204 — every argument is a constant or a unit name this package
	// composed from a validated component name.
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	// systemctl's own message is the useful part — "Job for X failed because
	// the control process exited" plus the journalctl line to run next.
	return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, detail)
}

// DaemonReload makes systemd read newly written units.
func (s Systemd) DaemonReload(ctx context.Context) error {
	return s.run(ctx, "daemon-reload")
}

// EnableNow enables and starts units.
func (s Systemd) EnableNow(ctx context.Context, units ...string) error {
	if len(units) == 0 {
		return nil
	}
	return s.run(ctx, append([]string{"enable", "--now"}, units...)...)
}

// Restart restarts units that are already installed.
func (s Systemd) Restart(ctx context.Context, units ...string) error {
	if len(units) == 0 {
		return nil
	}
	return s.run(ctx, append([]string{"restart"}, units...)...)
}

// IsActive reports whether a unit is running.
func (s Systemd) IsActive(ctx context.Context, unit string) bool {
	return s.run(ctx, "is-active", "--quiet", unit) == nil
}

// ErrSocketTimeout is returned when a daemon does not come up.
var ErrSocketTimeout = errors.New("the socket did not appear")

// WaitForSocket blocks until a unix socket accepts a connection.
//
// Dialled rather than stat'ed: a socket file left behind by a crashed daemon
// looks identical to a live one until something connects — the same reason
// cmd/kanea/preflight.go dials rather than stats.
func WaitForSocket(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("unix", path, 2*time.Second)
		if err == nil {
			return conn.Close()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w at %s after %s", ErrSocketTimeout, path, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
