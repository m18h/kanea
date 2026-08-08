package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/kanea-dev/kanea/internal/store"
)

// The replicator (PRD §15.3): ship change segments continuously, snapshot
// periodically, and never let the change log grow without bound.
//
// It is a background loop in kanead and it is deliberately unable to break the
// control plane. Nothing here writes to the Store except PruneChanges, and that
// only after the changes it drops are durably in the bucket. A sink that is
// down means backups stop and say so; it never means the platform stops.

// Replication defaults.
const (
	// DefaultSegmentInterval is how often changes are shipped. Five minutes is
	// the RPO §15.3 promises, so the interval has to be comfortably inside it —
	// at one minute, a failure loses at most a minute of mutations plus
	// whatever the upload was retrying.
	DefaultSegmentInterval = time.Minute
	// DefaultSnapshotInterval is how often a full snapshot is taken. Snapshots
	// are what keep replay bounded; segments are what keep the RPO short.
	DefaultSnapshotInterval = 6 * time.Hour
	// DefaultRetention is how many snapshots are kept.
	DefaultRetention = 7
	// DefaultMaxChanges bounds one segment. A burst — a fleet-wide apply — must
	// produce several segments rather than one enormous object, because an
	// upload that fails is retried whole.
	DefaultMaxChanges = 2000
)

// Replicator ships Store changes to a sink.
type Replicator struct {
	archiver *Archiver
	store    store.Store
	log      *slog.Logger

	segmentEvery  time.Duration
	snapshotEvery time.Duration
	retention     int
	maxChanges    int
	// counts summarises the Store for a manifest. Optional.
	counts func(context.Context) map[string]int
	now    func() time.Time

	// shipped is the highest index known to be in the sink.
	shipped atomic.Uint64
	// stats are observable so a dashboard can say when replication last
	// succeeded — which is the number that matters, and the one an operator
	// never has until the restore.
	lastSegmentAt  atomic.Int64
	lastSnapshotAt atomic.Int64
	failures       atomic.Int64
}

// ReplicatorConfig configures the loop.
type ReplicatorConfig struct {
	Archiver *Archiver
	Store    store.Store
	Logger   *slog.Logger
	// SegmentInterval, SnapshotInterval, Retention and MaxChanges take their
	// defaults when zero.
	SegmentInterval  time.Duration
	SnapshotInterval time.Duration
	Retention        int
	MaxChanges       int
	// Counts summarises the Store into a manifest.
	Counts func(context.Context) map[string]int
	Now    func() time.Time
}

// NewReplicator builds the loop.
func NewReplicator(cfg ReplicatorConfig) (*Replicator, error) {
	if cfg.Archiver == nil {
		return nil, errors.New("backup: an archiver is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("backup: a store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.SegmentInterval <= 0 {
		cfg.SegmentInterval = DefaultSegmentInterval
	}
	if cfg.SnapshotInterval <= 0 {
		cfg.SnapshotInterval = DefaultSnapshotInterval
	}
	if cfg.Retention <= 0 {
		cfg.Retention = DefaultRetention
	}
	if cfg.MaxChanges <= 0 {
		cfg.MaxChanges = DefaultMaxChanges
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Replicator{
		archiver: cfg.Archiver, store: cfg.Store, log: cfg.Logger,
		segmentEvery: cfg.SegmentInterval, snapshotEvery: cfg.SnapshotInterval,
		retention: cfg.Retention, maxChanges: cfg.MaxChanges,
		counts: cfg.Counts, now: cfg.Now,
	}, nil
}

// Run ships changes until the context ends.
func (r *Replicator) Run(ctx context.Context) {
	// The cursor comes from the sink, so a restarted daemon resumes where the
	// bucket actually is rather than where it last remembered being.
	if shipped, err := r.archiver.ShippedTo(ctx); err != nil {
		r.log.Error("cannot read what has already been replicated",
			"sink", r.archiver.Sink(), "error", err,
			"detail", "starting from zero; the first segment will re-ship what is already there")
	} else {
		r.shipped.Store(shipped)
		r.log.Info("replication resuming", "sink", r.archiver.Sink(), "shipped_to", shipped)
	}

	// A snapshot on start, so a node that has been up for five minutes already
	// has a restorable archive. Without it, a fresh install that dies in its
	// first six hours has segments and no base to replay them onto.
	if err := r.Snapshot(ctx, "startup"); err != nil && ctx.Err() == nil {
		r.log.Error("cannot take the startup snapshot", "error", err)
	}

	segments := time.NewTicker(r.segmentEvery)
	defer segments.Stop()
	snapshots := time.NewTicker(r.snapshotEvery)
	defer snapshots.Stop()

	for {
		select {
		case <-ctx.Done():
			// One last ship on the way out. Shutdown is the moment a lost
			// minute of changes is most avoidable, and the context is already
			// cancelled — so this runs on a detached one with its own bound.
			final, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownShipTimeout)
			defer cancel()
			if err := r.ShipOnce(final); err != nil {
				r.log.Warn("could not ship the last changes before shutting down", "error", err)
			}
			return

		case <-segments.C:
			if err := r.ShipOnce(ctx); err != nil && ctx.Err() == nil {
				r.failures.Add(1)
				r.log.Error("cannot ship changes", "sink", r.archiver.Sink(), "error", err)
			}

		case <-snapshots.C:
			if err := r.Snapshot(ctx, "scheduled"); err != nil && ctx.Err() == nil {
				r.failures.Add(1)
				r.log.Error("cannot take a snapshot", "sink", r.archiver.Sink(), "error", err)
			}
		}
	}
}

// shutdownShipTimeout bounds the final ship. Long enough for one upload on a
// slow link, short enough that a dead sink does not hold up a restart.
const shutdownShipTimeout = 30 * time.Second

// ShipOnce sends everything new, in bounded batches.
func (r *Replicator) ShipOnce(ctx context.Context) error {
	for {
		since := r.shipped.Load()
		changes, err := r.store.Changes(ctx, since, r.maxChanges)
		if err != nil {
			return fmt.Errorf("backup: read changes: %w", err)
		}
		if len(changes) == 0 {
			return nil
		}

		segment, err := r.archiver.PutSegment(ctx, changes)
		if err != nil {
			return err
		}
		r.shipped.Store(segment.To)
		r.lastSegmentAt.Store(r.now().UnixNano())
		r.log.Debug("shipped a change segment",
			"from", segment.From, "to", segment.To, "changes", len(changes), "bytes", segment.Size)

		// Pruned only after the upload returned. This is the ordering the whole
		// subsystem rests on: a change dropped from the log before it is
		// durably in the bucket is a change that exists nowhere.
		if _, err := r.store.PruneChanges(ctx, segment.To); err != nil {
			// Not fatal. The changes are safe; the log is merely longer than it
			// needs to be, and the next pass will try again.
			r.log.Warn("cannot prune the change log", "upto", segment.To, "error", err)
		}

		if len(changes) < r.maxChanges {
			return nil
		}
		// A full batch means there is more waiting. Continue rather than
		// waiting out the interval, so a burst catches up in seconds.
	}
}

// Snapshot takes a full snapshot, then prunes what it makes redundant.
func (r *Replicator) Snapshot(ctx context.Context, reason string) error {
	var counts map[string]int
	if r.counts != nil {
		counts = r.counts(ctx)
	}

	manifest, err := r.archiver.Create(ctx, reason, counts)
	if err != nil {
		return err
	}
	r.lastSnapshotAt.Store(r.now().UnixNano())
	r.shipped.Store(max(r.shipped.Load(), manifest.Index))
	r.log.Info("wrote a state snapshot",
		"archive", manifest.ID, "index", manifest.Index, "reason", reason,
		"sink", r.archiver.Sink())

	// Retention runs after the new archive exists, never before: pruning first
	// would leave a window where the oldest archive is gone and the newest has
	// not arrived.
	if removed, err := r.archiver.Prune(ctx, r.retention); err != nil {
		r.log.Warn("cannot apply snapshot retention", "keep", r.retention, "error", err)
	} else if removed > 0 {
		r.log.Info("pruned old archives", "removed", removed, "kept", r.retention)
	}

	// Segments below the *oldest kept* snapshot, not below this one: a segment
	// is only redundant once every archive that might need it is gone.
	oldest, err := r.oldestIndex(ctx)
	if err != nil {
		r.log.Warn("cannot determine the oldest archive; keeping every segment", "error", err)
		return nil
	}
	if removed, err := r.archiver.PruneSegments(ctx, oldest); err != nil {
		r.log.Warn("cannot prune shipped segments", "upto", oldest, "error", err)
	} else if removed > 0 {
		r.log.Debug("pruned segments covered by a snapshot", "removed", removed, "upto", oldest)
	}
	return nil
}

// oldestIndex is the index of the oldest archive still kept.
func (r *Replicator) oldestIndex(ctx context.Context) (uint64, error) {
	all, err := r.archiver.List(ctx)
	if err != nil {
		return 0, err
	}
	if len(all) == 0 {
		return 0, nil
	}
	// List is newest-first.
	return all[len(all)-1].Index, nil
}

// Status reports the replicator's own health.
//
// "When did this last succeed" is the number that decides whether a backup
// strategy is real, and it is the one an operator normally does not have until
// the restore. It is on the node stats route for that reason.
type Status struct {
	Sink           string    `json:"sink"`
	ShippedTo      uint64    `json:"shipped_to"`
	LastSegmentAt  time.Time `json:"last_segment_at,omitzero"`
	LastSnapshotAt time.Time `json:"last_snapshot_at,omitzero"`
	Failures       int64     `json:"failures"`
}

// Status returns the current state of replication.
func (r *Replicator) Status() Status {
	out := Status{
		Sink:      r.archiver.Sink(),
		ShippedTo: r.shipped.Load(),
		Failures:  r.failures.Load(),
	}
	if at := r.lastSegmentAt.Load(); at != 0 {
		out.LastSegmentAt = time.Unix(0, at).UTC()
	}
	if at := r.lastSnapshotAt.Load(); at != 0 {
		out.LastSnapshotAt = time.Unix(0, at).UTC()
	}
	return out
}
