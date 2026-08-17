package provision

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// The FUSE stack for S3 volumes (PRD §8, M0 spike ③).
//
// Two pieces of host state that internal/storage has always assumed and
// nothing has ever created: `user_allow_other` in /etc/fuse.conf, and an
// unprivileged account for the mount helpers to run as.
//
// The first is not optional and not cosmetic. An S3 volume is mounted by an
// unprivileged helper and traversed by root-run containerd, which needs
// `allow_other`; libfuse refuses that option unless `user_allow_other` is set,
// so without this every S3 volume fails at the first deploy with an error
// about a mount option rather than about a missing line in a config file.

// FuseConfPath is libfuse's configuration.
const FuseConfPath = "/etc/fuse.conf"

// fuseOption is the line that has to be there.
const fuseOption = "user_allow_other"

// S3HelperUser is the unprivileged account the mount helpers run as. Their
// credential files are 0600 and owned by it (§8), which is the only thing
// standing between one project's S3 volume and another's credentials.
const S3HelperUser = "kanea-s3"

// SetupFUSE establishes what S3 volumes need.
//
// Idempotent, and tolerant of a host that has no FUSE at all: a node that
// never mounts an S3 volume should not fail its install over a package it does
// not use. What it must not do is stay quiet: a warning here is how the
// operator finds out before the first deploy rather than during it.
func SetupFUSE(ctx context.Context, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if err := ensureFuseConf(log); err != nil {
		return err
	}
	return EnsureUser(ctx, S3HelperUser, log)
}

// ensureFuseConf adds user_allow_other if it is not already effective.
func ensureFuseConf(log *slog.Logger) error {
	raw, err := os.ReadFile(FuseConfPath) // #nosec G304; a package constant
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", FuseConfPath, err)
	}
	if fuseAllowOtherSet(string(raw)) {
		return nil
	}

	// Appended rather than rewritten. /etc/fuse.conf may carry a mount_max the
	// operator chose, and replacing the file to add one line is the kind of
	// helpfulness that loses somebody's configuration.
	body := string(raw)
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	body += "# Added by kanea: S3 volumes are mounted by an unprivileged helper and\n" +
		"# traversed by root-run containerd, which needs allow_other (PRD §8).\n" +
		fuseOption + "\n"

	if err := writeFileAtomic(FuseConfPath, strings.NewReader(body), 0o644); err != nil {
		return err
	}
	log.Info("enabled user_allow_other", "file", FuseConfPath)
	return nil
}

// fuseAllowOtherSet reports whether the option is set and not commented out.
func fuseAllowOtherSet(body string) bool {
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// libfuse parses the bare word; a commented-out one is exactly the
		// state this function exists to distinguish from a set one, because
		// every distribution ships the file with it commented.
		if line == fuseOption {
			return true
		}
	}
	return false
}
