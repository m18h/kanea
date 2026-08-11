package provision

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"os/user"
	"strings"
)

// EnsureGroup creates a system group if it does not exist. Idempotent, like
// ensureUser, and built for the same caller: `kanea init`, which creates the
// CLI socket group (PRD v1.48, §13.1) empty — a group with no members grants
// nothing, and init never adds one; joining is the operator's explicit
// `usermod -aG`.
func EnsureGroup(ctx context.Context, name string, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if _, err := user.LookupGroup(name); err == nil {
		return nil
	} else if !isUnknownGroup(err) {
		return fmt.Errorf("look up group %s: %w", name, err)
	}

	groupadd, err := lookupTool("groupadd")
	if err != nil {
		return fmt.Errorf("cannot create the %s group: %w — install the passwd (Debian) or shadow-utils (RHEL) package", name, err)
	}
	// #nosec G204 — the path comes from lookupTool over fixed directories, and
	// every caller passes a compile-time constant name.
	cmd := exec.CommandContext(ctx, groupadd, "--system", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create the %s group: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	log.Info("created the CLI socket group", "group", name)
	return nil
}

func isUnknownGroup(err error) bool {
	var unknown user.UnknownGroupError
	return errors.As(err, &unknown)
}
