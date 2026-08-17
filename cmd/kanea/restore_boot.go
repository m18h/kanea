package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/m18h/kanea/internal/backup"
	"github.com/m18h/kanea/internal/secrets"
	"github.com/m18h/kanea/internal/store"
)

// Restore at start (PRD §15.3).
//
// This runs before anything opens the Store, which is the whole reason it
// exists as a separate step: §15.3 puts a restore on a stopped node, and the
// moment just before the daemon opens its database is the only point inside the
// daemon's own lifetime where that is true.
//
// Two triggers, and they are different situations. A *staged* request is an
// operator saying "this node is wrong, put back the archive I verified". An
// *empty* data directory with replication configured is a node that has lost
// its disk, which §15.3 calls first-boot auto-restore.

// bootRestoreOptions is what the agent knows when it reaches this point.
type bootRestoreOptions struct {
	dataDir   string
	statePath string
	keyPath   string
	sink      sinkOptions
	// autoRestore permits the empty-directory case. Off by default: bringing a
	// node's entire state back is not something to do because a disk looked
	// empty, and an operator who wants it says so.
	autoRestore bool
	log         *slog.Logger
}

// restoreAtStart applies a staged or first-boot restore, if either applies.
//
// It returns without doing anything in the ordinary case, which is almost every
// start.
func restoreAtStart(ctx context.Context, opts bootRestoreOptions) error {
	request, err := backup.ReadRequest(opts.dataDir)
	if err != nil {
		return err
	}
	stateExists := true
	if _, err := os.Stat(opts.statePath); errors.Is(err, fs.ErrNotExist) {
		stateExists = false
	}

	switch {
	case request != nil:
		// Explicitly asked for. This one proceeds even over live state: that
		// is what staging it meant.
	case !stateExists && opts.autoRestore && opts.sink.configured():
		opts.log.Warn("no state on this node and a backup destination is configured",
			"detail", "restoring the newest archive (first-boot auto-restore, §15.3)")
		request = &backup.Request{RequestedAt: time.Now().UTC(), RequestedBy: "first-boot"}
	default:
		return nil
	}

	if !opts.sink.configured() {
		return errors.New("a restore is staged but no backup destination is configured; " +
			"point --backup-dir or --backup-s3-endpoint at where the archives are, " +
			"or delete " + filepath.Join(opts.dataDir, backup.RequestFileName))
	}

	master, err := secrets.LoadKey(opts.keyPath)
	if err != nil {
		return err
	}
	keys, err := backup.DeriveKeys(master)
	if err != nil {
		return err
	}
	sink, err := sinkFromFlags(opts.sink, opts.log)
	if err != nil {
		return err
	}
	archiver, err := backup.New(backup.Config{
		Sink: sink, Keys: keys, Snapshotter: refusingSnapshotter{},
		WorkDir: opts.dataDir, Logger: opts.log, Version: version,
	})
	if err != nil {
		return err
	}

	// The existing state is moved aside, never deleted. If the restore turns
	// out to be the wrong archive, or the right archive of the wrong node:
	// the thing that was there is still there.
	if stateExists {
		aside := opts.statePath + ".before-restore-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(opts.statePath, aside); err != nil {
			return fmt.Errorf("cannot move the current state aside: %w", err)
		}
		opts.log.Warn("moved the current state aside for a restore",
			"from", opts.statePath, "to", aside,
			"detail", "delete it once the restored node is confirmed good")
	}

	result, err := archiver.Restore(ctx, backup.RestoreOptions{
		ArchiveID: request.ArchiveID, Target: opts.statePath,
		SkipReplay: request.SkipReplay, Logger: opts.log,
	})
	if err != nil {
		// The request is deliberately left in place. A restore that failed
		// half-way is a node an operator has to look at, and clearing the
		// marker would let the next start come up on whatever is there, which,
		// after the rename above, is nothing.
		return fmt.Errorf("restore failed; the request is still staged and the previous "+
			"state was moved aside: %w", err)
	}

	// Cleared only after the restore succeeded. A request that survives its own
	// restore restores again on the next start, and again after that.
	if err := backup.ClearRequest(opts.dataDir); err != nil {
		return err
	}
	opts.log.Warn("restored state from an archive",
		"archive", result.Archive.ID, "taken", result.Archive.CreatedAt,
		"index", result.Index, "replayed", result.Replayed,
		"requested_by", request.RequestedBy,
		"detail", "the network datapath is derived state and is rebuilt, not restored; "+
			"images are re-pulled as services converge")
	return nil
}

// migrateAtStart runs pending schema migrations, after taking the copy that
// makes a bad one survivable (PRD §15.4).
//
// The ordering is the whole point and it is why the Store does not migrate
// itself at Open: a migration rewrites state in place, and the only way back
// from one that goes wrong is a copy of what was there. That copy needs the
// database open, and the migration must not have started, which leaves exactly
// this window.
func migrateAtStart(ctx context.Context, st store.Store, dataDir string, log *slog.Logger) error {
	pending, err := store.PendingMigration(ctx, st)
	if err != nil {
		return err
	}
	if !pending.Needed() {
		return nil
	}

	copyPath := filepath.Join(dataDir,
		fmt.Sprintf("%s.pre-v%d-%s", stateFile, pending.To, time.Now().UTC().Format("20060102T150405Z")))
	// A local file copy, not an archive: it needs no key, no bucket and no
	// network, and the operator putting it back is a `mv`. The replicator's own
	// snapshot happens too, when one is configured, but a migration must not
	// depend on a bucket being reachable to be safe.
	if err := store.Compact(ctx, st, copyPath); err != nil {
		return fmt.Errorf("cannot take the pre-migration copy: %w", err)
	}
	log.Warn("migrating the state schema",
		"plan", pending.Describe(), "copy", copyPath,
		"detail", "to roll back: stop kanead, move this copy over "+
			filepath.Join(dataDir, stateFile)+", and run the previous binary")

	if _, err := store.Migrate(ctx, st); err != nil {
		return fmt.Errorf("%w: the pre-migration copy is at %s", err, copyPath)
	}
	log.Info("state schema migrated", "to", pending.To, "copy", copyPath,
		"detail", "delete the copy once the upgrade is confirmed good")
	return nil
}
