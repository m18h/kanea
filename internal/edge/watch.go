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
// would also have to handle the rename that publishing does — the inode the
// watch was registered on is not the one that ends up in place.
const DefaultPollInterval = time.Second

// Watcher keeps a Proxy's route table in step with the published snapshot.
type Watcher struct {
	path     string
	interval time.Duration
	log      *slog.Logger
	apply    func(*Table)

	// last is the raw bytes last successfully loaded, so an unchanged file
	// costs a read and a compare rather than a parse and a rebuild.
	last []byte
	// rejected is the raw bytes last refused. Held separately from last so a
	// bad file is retried rather than remembered as loaded — but still only
	// reported once, because a snapshot that stays broken would otherwise log
	// an error on every poll, forever, at whatever the poll interval is.
	rejected []byte
	// missing tracks whether the absence of the file has already been
	// reported, for the same reason.
	missing bool
}

// WatcherConfig configures the reloader.
type WatcherConfig struct {
	Path     string
	Interval time.Duration
	Logger   *slog.Logger
	// Apply receives each new table. It is called from the watcher goroutine.
	Apply func(*Table)
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
	return &Watcher{
		path:     cfg.Path,
		interval: cfg.Interval,
		log:      cfg.Logger,
		apply:    cfg.Apply,
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
	body, err := os.ReadFile(w.path) // #nosec G304 — the path is operator configuration
	switch {
	case errors.Is(err, os.ErrNotExist):
		if !w.missing {
			w.log.Info("no route snapshot; serving the current table until kanead publishes one",
				"path", w.path, "routes", len(w.last) > 0)
			w.missing = true
		}
		return
	case err != nil:
		w.log.Warn("cannot read route snapshot; keeping the current table",
			"path", w.path, "error", err)
		return
	}
	w.missing = false

	if bytes.Equal(body, w.last) {
		return
	}

	table, err := parseTable(body)
	if err != nil {
		// Deliberately not fatal, and deliberately loud — but only once per
		// distinct bad file. A rejected snapshot means routing is frozen at the
		// last good state, which is a degraded control plane rather than a
		// degraded site; a file that stays broken must not also fill the disk
		// with one error per poll.
		if !bytes.Equal(body, w.rejected) {
			w.log.Error("route snapshot rejected; keeping the current table",
				"path", w.path, "error", err)
			w.rejected = body
		}
		return
	}

	// Recorded only after a successful parse, so a broken file is retried on
	// the next tick instead of being remembered as "seen".
	w.last = body
	w.rejected = nil
	w.apply(table)
	w.log.Info("route table reloaded",
		"index", table.Index(), "hosts", table.Len(), "path", w.path)
}

// parseTable decodes and indexes a snapshot body.
func parseTable(body []byte) (*Table, error) {
	var snap Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSnapshot, err)
	}
	return NewTable(snap)
}
