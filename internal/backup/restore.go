package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/m18h/kanea/internal/store"
)

// Restore (PRD §15.3).
//
// The recovery order §15.3 sets is: master key, then the Store snapshot and its
// segment replay, then the Cilium kvstore is *wiped and rebuilt* from desired
// state, then images are re-pulled, then endpoints and edge routes come back.
//
// Only the first two steps live here. The rest are the reconciler's ordinary
// job — a restored Store is a Store with desired state in it, and convergence
// is what the reconciler does with one. That is the point of §18's rule that
// derived state is never restored: there is no third code path for "coming back
// from a backup", because it is the same path as "starting up".

// RestoreResult reports what a restore recovered.
type RestoreResult struct {
	Archive Manifest
	// Replayed is how many changes were applied on top of the snapshot.
	Replayed int
	// Index is the Store index after the replay.
	Index uint64
	// Path is the restored database.
	Path string
}

// RestoreOptions configures a restore.
type RestoreOptions struct {
	// ArchiveID selects an archive. Empty takes the newest.
	ArchiveID string
	// Target is where the restored database is written. It must not exist:
	// overwriting a live state file is not something to do by accident.
	Target string
	// SkipReplay restores the snapshot alone, without segments. It exists for
	// the case where a segment is the thing that is corrupt, and an older but
	// intact state is better than none.
	SkipReplay bool
	Logger     *slog.Logger
}

// Restore fetches an archive, replays the segments above it, and leaves a
// database at the target path.
//
// It does not touch a running node. The caller stops the daemon, restores, and
// starts it — which is what `kanea restore` does, and why the target must not
// already exist.
func (a *Archiver) Restore(ctx context.Context, opts RestoreOptions) (RestoreResult, error) {
	log := opts.Logger
	if log == nil {
		log = a.log
	}
	if opts.Target == "" {
		return RestoreResult{}, errors.New("backup: a restore target path is required")
	}
	if _, err := os.Stat(opts.Target); err == nil {
		return RestoreResult{}, fmt.Errorf(
			"backup: %s already exists; move it aside first (a restore never overwrites state)",
			opts.Target)
	}

	manifest, err := a.Find(ctx, opts.ArchiveID)
	if err != nil {
		return RestoreResult{}, err
	}
	log.Info("restoring from an archive",
		"archive", manifest.ID, "created", manifest.CreatedAt, "index", manifest.Index,
		"node", manifest.Node, "sink", a.sink.Describe())

	if err := os.MkdirAll(filepath.Dir(opts.Target), 0o700); err != nil {
		return RestoreResult{}, fmt.Errorf("backup: create the restore directory: %w", err)
	}
	if err := a.Fetch(ctx, manifest, opts.Target); err != nil {
		return RestoreResult{}, err
	}

	result := RestoreResult{Archive: manifest, Index: manifest.Index, Path: opts.Target}
	if opts.SkipReplay {
		log.Warn("skipping segment replay",
			"detail", "the restored state is as of the snapshot; changes after it are not applied")
		return result, nil
	}

	replayed, index, err := a.replay(ctx, opts.Target, manifest.Index, log)
	if err != nil {
		return result, err
	}
	result.Replayed, result.Index = replayed, index
	log.Info("restore complete",
		"archive", manifest.ID, "replayed", replayed, "index", index, "path", opts.Target)
	return result, nil
}

// replay applies every segment above the snapshot's index onto the restored
// database.
func (a *Archiver) replay(
	ctx context.Context, path string, from uint64, log *slog.Logger,
) (_ int, _ uint64, err error) {
	segments, err := a.Segments(ctx)
	if err != nil {
		return 0, from, err
	}

	restored, err := store.Open(store.Options{Path: path})
	if err != nil {
		return 0, from, fmt.Errorf("backup: open the restored state: %w", err)
	}
	defer func() { err = errors.Join(err, restored.Close()) }()

	applied := 0
	index := from
	for _, segment := range segments {
		// A segment entirely below the snapshot is already in it.
		if segment.To <= from {
			continue
		}
		changes, err := a.GetSegment(ctx, segment)
		if err != nil {
			// Stated and stopped, not skipped. Replaying a later segment over a
			// gap would produce a state that never existed: a delete that was
			// in the missing segment would never happen, and the record it
			// removed would come back from the dead.
			return applied, index, fmt.Errorf(
				"%w — restored state is good up to index %d; "+
					"re-run with --skip-replay to accept the snapshot alone", err, index)
		}

		count, last, err := applyChanges(ctx, restored, changes, from)
		if err != nil {
			return applied, index, err
		}
		applied += count
		index = max(index, last)
	}
	if applied > 0 {
		log.Info("replayed change segments", "changes", applied, "to_index", index)
	}
	return applied, index, nil
}

// applyChanges writes a segment's changes into a store, skipping any at or
// below the snapshot's index.
//
// Changes are grouped by index and each group applied as one batch, which is
// how they were written: the Store stamps one index per Apply, so replaying
// change-by-change would allocate one index per change and drift the counter
// upward from where it was. Monotonicity is what correctness needs, but landing
// on the same numbers means an index recorded anywhere else still means what it
// meant.
func applyChanges(
	ctx context.Context, target store.Store, changes []store.Change, skipUpto uint64,
) (int, uint64, error) {
	applied := 0
	var last uint64

	for i := 0; i < len(changes); {
		index := changes[i].Index
		j := i
		for j < len(changes) && changes[j].Index == index {
			j++
		}
		group := changes[i:j]
		i = j

		if index <= skipUpto {
			continue // already in the snapshot
		}

		muts := make([]store.Mutation, 0, len(group))
		for _, change := range group {
			// Unconditional: a replay is not a concurrent writer, and carrying
			// the original preconditions forward would fail every one of them
			// against a database whose indexes are being rebuilt.
			muts = append(muts, store.Mutation{
				Op: change.Op, Kind: change.Kind, Key: change.Key, Value: change.Value,
			})
		}
		if _, err := target.Apply(ctx, muts...); err != nil {
			return applied, last, fmt.Errorf("backup: replay index %d: %w", index, err)
		}
		applied += len(group)
		last = index
	}
	return applied, last, nil
}
