package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// DefaultPollInterval is how often the edge re-reads the snapshot.
//
// Polling rather than an inotify watch: the file is small, one stat-and-read a
// second is nothing, and it has no missed-event semantics to get wrong. A watch
// would also have to handle the rename that publishing does: the inode the
// watch was registered on is not the one that ends up in place.
const DefaultPollInterval = time.Second

// Watcher keeps one in-memory projection in step with a published file.
//
// One implementation serves both the route table and the certificate bundle:
// the polling, the change detection and the "a bad file must not take routing
// down" behaviour are identical, and only the decoding differs.
type Watcher struct {
	name     string
	path     string
	interval time.Duration
	log      *slog.Logger
	apply    func([]byte) error
	// metrics records reload outcomes (§9.1.1). Optional: the watcher is also
	// used in tests and by tooling that has no collector.
	metrics *Metrics
	now     func() time.Time

	// last is the raw bytes last successfully loaded, so an unchanged file
	// costs a read and a compare rather than a parse and a rebuild.
	last []byte
	// rejected is the raw bytes last refused. Held separately from last so a
	// bad file is retried rather than remembered as loaded, but still only
	// reported once, because a snapshot that stays broken would otherwise log
	// an error on every poll, forever, at whatever the poll interval is.
	rejected []byte
	// missing tracks whether the absence of the file has already been
	// reported, for the same reason.
	missing bool
}

// WatcherConfig configures the reloader.
type WatcherConfig struct {
	// Name identifies the projection in log messages ("routes", "certificates").
	Name     string
	Path     string
	Interval time.Duration
	Logger   *slog.Logger
	// Apply decodes and installs a changed file. An error is reported and the
	// previous projection is kept. It is called from the watcher goroutine.
	Apply func(body []byte) error
	// Metrics records reload outcomes. Optional.
	Metrics *Metrics
	// Now is injectable so a reload-timestamp assertion does not depend on
	// the clock.
	Now func() time.Time
}

// NewWatcher builds a reloader.
func NewWatcher(cfg WatcherConfig) (*Watcher, error) {
	if cfg.Path == "" {
		return nil, errors.New("edge: watcher needs a snapshot path")
	}
	if cfg.Apply == nil {
		return nil, errors.New("edge: watcher needs an Apply function")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultPollInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Name == "" {
		cfg.Name = "projection"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Watcher{
		name:     cfg.Name,
		path:     cfg.Path,
		interval: cfg.Interval,
		log:      cfg.Logger,
		apply:    cfg.Apply,
		metrics:  cfg.Metrics,
		now:      cfg.Now,
	}, nil
}

// Run polls until the context is cancelled.
//
// It never returns an error for a bad or absent snapshot. The edge holds public
// traffic: "kanead is down" or "someone hand-edited the file" must not become
// "the site is down", so a load failure leaves the last good table serving and
// says so in the log (PRD §5.2.6).
func (w *Watcher) Run(ctx context.Context) error {
	w.reload()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			w.reload()
		}
	}
}

// reload reads the snapshot and applies it if it changed.
func (w *Watcher) reload() {
	body, err := os.ReadFile(w.path) // #nosec G304; the path is operator configuration
	switch {
	case errors.Is(err, os.ErrNotExist):
		if !w.missing {
			w.log.Info("projection absent; keeping what is loaded until kanead publishes one",
				"projection", w.name, "path", w.path, "loaded", len(w.last) > 0)
			w.missing = true
		}
		return
	case err != nil:
		w.log.Warn("cannot read projection; keeping the current one",
			"projection", w.name, "path", w.path, "error", err)
		return
	}
	w.missing = false

	if bytes.Equal(body, w.last) {
		return
	}

	if err := w.apply(body); err != nil {
		// Deliberately not fatal, and deliberately loud, but only once per
		// distinct bad file. A rejected projection means routing is frozen at
		// the last good state, which is a degraded control plane rather than a
		// degraded site; a file that stays broken must not also fill the disk
		// with one error per poll.
		if !bytes.Equal(body, w.rejected) {
			w.log.Error("projection rejected; keeping the current one",
				"projection", w.name, "path", w.path, "error", err)
			w.rejected = body
		}
		// Counted on every rejected poll, not once per distinct bad file. The
		// log is deduplicated because a repeated line buries everything else; a
		// counter has the opposite problem, and a rate that stays flat at one
		// failure would read as a single transient rather than a stuck edge.
		w.record(false)
		return
	}

	// Recorded only after a successful apply, so a broken file is retried on
	// the next tick instead of being remembered as "seen".
	w.last = body
	w.rejected = nil
	w.record(true)
	w.log.Info("projection reloaded", "projection", w.name, "path", w.path)
}

// record reports a reload outcome, if a collector is attached.
func (w *Watcher) record(ok bool) {
	if w.metrics != nil {
		w.metrics.Reloaded(ok, w.now())
	}
}

// ParseTable decodes and indexes a route snapshot body.
func ParseTable(body []byte) (*Table, error) {
	var snap Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSnapshot, err)
	}
	return NewTable(snap)
}

// ParseBundle decodes a certificate bundle body.
func ParseBundle(body []byte) (Bundle, error) {
	var bundle Bundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return Bundle{}, fmt.Errorf("%w: %w", ErrInvalidBundle, err)
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}
