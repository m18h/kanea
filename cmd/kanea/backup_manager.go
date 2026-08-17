package main

// The backup manager (PRD v1.46): the swappable owner of the replication
// pipeline. Before it, "which destination" was decided once at startup; now a
// PUT on /v1/settings/backup replaces the destination at runtime, and this is
// the machinery that makes the swap safe: the one property it must never give
// up is that a bad new destination cannot stop a working old one.

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/backup"
)

// Effective sources for the settings view.
const (
	sourceStore = "store"
	sourceFlags = "flags"
	sourceNone  = "none"
)

// destinationProbeTimeout bounds the swap's test write, so a black-hole
// endpoint cannot pin the settings handler.
const destinationProbeTimeout = 30 * time.Second

// backupManager implements api.Backups over a replaceable pipeline. It is
// always non-nil (a node can go unconfigured → configured at runtime now) so
// "nothing is configured" is ErrNotConfigured from a method rather than a nil
// interface, and the API maps it to the same 503 it always answered.
type backupManager struct {
	mu     sync.Mutex
	base   context.Context //nolint:containedctx // the parent every replicator run derives from
	log    *slog.Logger
	svc    *backupService
	cancel context.CancelFunc
	done   chan struct{}
	source string
}

func newBackupManager(log *slog.Logger) *backupManager {
	return &backupManager{log: log, source: sourceNone}
}

// adopt installs a pipeline without probing it: the startup path, where the
// destination was either running yesterday or written by the operator into
// the unit, and where a down bucket must not keep the daemon from starting.
func (m *backupManager) adopt(svc *backupService, source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.svc, m.source = svc, source
}

// run launches whatever is adopted and holds the manager's parent context.
// Called once, alongside the other daemon goroutines; on shutdown it waits for
// the running replicator's final ship.
func (m *backupManager) run(ctx context.Context) {
	m.mu.Lock()
	m.base = ctx
	if m.svc != nil && m.cancel == nil {
		m.launchLocked()
	}
	m.mu.Unlock()

	<-ctx.Done()
	m.mu.Lock()
	done := m.done
	m.mu.Unlock()
	if done != nil {
		// Run's own shutdown path bounds the final ship at 30 s.
		<-done
	}
}

// launchLocked starts the current pipeline's replicator. Callers hold mu.
func (m *backupManager) launchLocked() {
	ctx, cancel := context.WithCancel(m.base)
	m.cancel = cancel
	done := make(chan struct{})
	m.done = done
	svc := m.svc
	go func() {
		defer close(done)
		svc.replicator.Run(ctx)
	}()
}

// stopLocked halts the current pipeline and waits for its final ship, which
// lands in the *old* destination, so nothing pending is lost to the swap.
// Callers hold mu.
func (m *backupManager) stopLocked() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel, m.done = nil, nil
	}
	m.svc, m.source = nil, sourceNone
}

// swap replaces the pipeline, in the one order that keeps the safety property:
// probe the new destination first (the old replication untouched), then commit
// the caller's record, then stop the old pipeline, then start the new one. A
// nil svc is a deliberate transition to unconfigured.
func (m *backupManager) swap(
	ctx context.Context, svc *backupService, source string, commit func() error,
) error {
	if svc != nil {
		probeCtx, cancel := context.WithTimeout(ctx, destinationProbeTimeout)
		defer cancel()
		if err := svc.archiver.Probe(probeCtx); err != nil {
			// The old replicator never stopped and the record was never
			// written: a refused destination costs the operator nothing but
			// the retype.
			return fmt.Errorf("%w: the destination failed its probe "+
				"(nothing was changed): %v", api.ErrInvalidSettings, err)
		}
	}
	if err := commit(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
	if svc == nil {
		m.log.Info("state replication stopped", "source", source)
		return nil
	}
	m.svc, m.source = svc, source
	if m.base != nil {
		m.launchLocked()
	}
	m.log.Info("state replication swapped", "sink", svc.archiver.Sink(), "source", source)
	return nil
}

// configured reports whether anything is behind the manager.
func (m *backupManager) configured() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.svc != nil
}

// Source reports where the effective configuration came from.
func (m *backupManager) Source() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.source
}

// current is the guarded read every delegating method goes through.
func (m *backupManager) current() (*backupService, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.svc == nil {
		return nil, backup.ErrNotConfigured
	}
	return m.svc, nil
}

// The api.Backups surface, by delegation.

func (m *backupManager) List(ctx context.Context) ([]backup.Manifest, error) {
	svc, err := m.current()
	if err != nil {
		return nil, err
	}
	return svc.List(ctx)
}

func (m *backupManager) Create(ctx context.Context, reason string) (backup.Manifest, error) {
	svc, err := m.current()
	if err != nil {
		return backup.Manifest{}, err
	}
	return svc.Create(ctx, reason)
}

func (m *backupManager) Verify(ctx context.Context, id string) error {
	svc, err := m.current()
	if err != nil {
		return err
	}
	return svc.Verify(ctx, id)
}

func (m *backupManager) Stage(
	ctx context.Context, id string, skipReplay bool, by string,
) (backup.Manifest, error) {
	svc, err := m.current()
	if err != nil {
		return backup.Manifest{}, err
	}
	return svc.Stage(ctx, id, skipReplay, by)
}

func (m *backupManager) Status() backup.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.svc == nil {
		return backup.Status{}
	}
	return m.svc.Status()
}
