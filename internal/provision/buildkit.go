package provision

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// The rootless build daemon (PRD §5.2.11, §10.2).
//
// spike ④ chose BuildKit as the only build driver precisely because it is
// unprivileged and non-root end to end, which is why no §14 hardening
// exception is needed for builds. That property is not free: it needs a system
// user, subordinate uid/gid ranges for the user namespaces rootlesskit
// creates, and a socket somewhere rootlesskit's copy-up does not hide.
//
// This is the part of §5.2.11 that had been specified since v1.1 and never
// built.

// subIDCount is the size of the subordinate range, matching the convention
// every distribution's useradd uses. 65536 is one full uid namespace, which is
// what a build's container needs to map.
const subIDCount = 65536

// subIDBase is where Kanea's range starts. Well above the 100000 default that
// adduser hands out, so a node with ordinary users does not collide.
const subIDBase = 200000

// SetupBuildkit creates everything rootless buildkitd needs.
//
// Idempotent: each step checks before acting, because this runs on every
// `kanea install` and an operator re-running it must not end up with a second
// subuid range or a reset home directory.
func SetupBuildkit(ctx context.Context, l Layout, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if err := EnsureUser(ctx, BuildkitUser, log); err != nil {
		return err
	}
	u, err := user.Lookup(BuildkitUser)
	if err != nil {
		return fmt.Errorf("look up %s after creating it: %w", BuildkitUser, err)
	}
	uid, gid, err := numericIDs(u)
	if err != nil {
		return err
	}

	for _, file := range []string{"/etc/subuid", "/etc/subgid"} {
		if err := ensureSubID(file, BuildkitUser, log); err != nil {
			return err
		}
	}

	// The socket lives here and *not* under /run: rootlesskit copy-ups /run
	// into a namespace-private tmpfs, so a socket there is invisible to every
	// client outside the namespace. Spike ④ found that the expensive way.
	//
	// The home's parent is the data directory, which `kanea init` and kanead
	// both create 0750 root:root; a mode the daemon's user can neither own
	// nor join, so without the group grant below every path under it answers
	// EACCES and buildkitd's report of that is maximally misleading: a fatal
	// "permission denied" for an optional config file that does not exist.
	home := filepath.Join(l.DataDir, "buildkit")
	if err := os.MkdirAll(l.DataDir, 0o710); err != nil {
		return fmt.Errorf("create %s: %w", l.DataDir, err)
	}
	if err := ensureTraversal(l.DataDir, gid); err != nil {
		return err
	}
	for _, dir := range []string{home, filepath.Join(home, "run")} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		// 0750 and owned by the daemon user: root reaches the socket, nobody
		// else does. A build daemon's socket is a root-equivalent interface
		// even when the daemon itself is not root.
		if err := os.Chown(dir, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", dir, err)
		}
		// #nosec G302; this is a directory, not a file, and 0750 is the
		// tightest mode that works: buildkitd runs as its owner and has to
		// traverse it to reach its own socket. 0600 would leave the daemon
		// unable to open the thing it listens on.
		if err := os.Chmod(dir, 0o750); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
	}

	if _, err := lookupTool("newuidmap"); err != nil {
		// Not fatal: the binaries are installed and the unit is written, and
		// an operator who installs uidmap afterwards gets a working daemon
		// without re-running anything. Refusing here would fail an install
		// over a package that takes ten seconds to add.
		log.Warn("newuidmap is not on PATH; rootless buildkitd needs it",
			"fix", "install the uidmap package (apt install uidmap / dnf install shadow-utils)")
	}
	return nil
}

// EnsureUser creates a system account if it does not exist. Idempotent, like
// EnsureGroup, and built for the same caller: `kanea init`, which creates the
// build daemon's account and the edge's (PRD §5.2.6).
func EnsureUser(ctx context.Context, name string, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if _, err := user.Lookup(name); err == nil {
		return nil
	} else if !isUnknownUser(err) {
		return fmt.Errorf("look up %s: %w", name, err)
	}

	useradd, err := lookupTool("useradd")
	if err != nil {
		return fmt.Errorf("cannot create the %s account: %w; install the passwd (Debian) or shadow-utils (RHEL) package", name, err)
	}
	// --system: no ageing, no mail spool, a uid below the login range.
	// --no-create-home: the home directory is under Kanea's data directory and
	// is created above with the mode it needs, not by useradd's skeleton.
	// #nosec G204: the path comes from lookupTool over fixed directories, and
	// every caller passes a compile-time constant name.
	cmd := exec.CommandContext(ctx, useradd,
		"--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create the %s account: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	log.Info("created the system account", "user", name)
	return nil
}

func isUnknownUser(err error) bool {
	var unknown user.UnknownUserError
	return errors.As(err, &unknown)
}

func numericIDs(u *user.User) (uid, gid int, err error) {
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("uid %q is not numeric: %w", u.Uid, err)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("gid %q is not numeric: %w", u.Gid, err)
	}
	return uid, gid, nil
}

// ensureSubID adds a subordinate id range if the user has none.
//
// Written directly rather than through usermod --add-subuids, which not every
// distribution's shadow-utils carries. The format is three colon-separated
// fields and has been stable for thirty years.
func ensureSubID(path, name string, log *slog.Logger) error {
	existing, err := os.ReadFile(path) // #nosec G304; a package constant
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", path, err)
	}

	highest := subIDBase
	scanner := bufio.NewScanner(strings.NewReader(string(existing)))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 3 {
			continue
		}
		if fields[0] == name {
			// Already has a range. Leaving it alone matters: a second range
			// for one user is accepted by the file format and then behaves
			// unpredictably depending on which tool reads it first.
			return nil
		}
		start, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		if end := start + count; end > highest {
			highest = end
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}

	line := fmt.Sprintf("%s:%d:%d\n", name, highest, subIDCount)
	// Appended rather than rewritten: this file belongs to the system and
	// carries every other user's ranges.
	// #nosec G304,G302; /etc/subuid and /etc/subgid are system files with a
	// fixed 0644 mode: newuidmap and newgidmap read them as an unprivileged
	// user, which is the entire mechanism rootless containers rely on.
	// Tightening them here would break every rootless runtime on the node,
	// not only Kanea's.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := f.WriteString(line); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", path, err), f.Close())
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	log.Info("allocated a subordinate id range", "file", path, "user", name,
		"start", highest, "count", subIDCount)
	return nil
}

// ensureTraversal grants dir's traversal to the daemon's group.
//
// Group ownership plus the execute bit is the containerd directory's 0710
// pattern: traverse, never list. The mode's other bits are left exactly as
// found: the data directory belongs to kanead, and this function's only
// claim on it is the one bit the daemon needs to reach its own home.
func ensureTraversal(dir string, gid int) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if err := os.Chown(dir, -1, gid); err != nil {
		return fmt.Errorf("chown %s: %w", dir, err)
	}
	if mode := info.Mode().Perm(); mode&0o010 == 0 {
		if err := os.Chmod(dir, mode|0o010); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
	}
	return nil
}

// BuildkitSocket is where the provisioned daemon listens, given a layout.
// The unit's --addr is rendered from the same home path, and
// gitops.DefaultBuildkitSocket must equal this over DefaultLayout: both
// pinned by test, because the constant once named a path nothing creates and
// every provisioned node's builds dialed it.
func BuildkitSocket(l Layout) string {
	return "unix://" + filepath.Join(l.DataDir, "buildkit", "run", "buildkitd.sock")
}
