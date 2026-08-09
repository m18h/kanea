// Package autoupdate follows the image tag a service declares and pins the
// digest behind it when it moves (PRD §6.2 R19).
//
// This is the feature people run watchtower for, and it is deliberately not
// built the way watchtower is. Nothing here talks to the container runtime,
// creates a container or stops one. It resolves a tag, writes one field on the
// desired state, and lets the reconciler converge — the same seam §10.2's
// pipeline uses to deploy a built image, and the same relationship the
// autoscaler has with the scheduler: *it is not a second deployer, it writes a
// digest and something else does the work.*
//
// What that buys is that an automatic update is not a special kind of deploy.
// It rolls with `max_parallel`, waits `min_healthy`, is gated by the service's
// health check and trips the same circuit breaker, because it *is* an ordinary
// deploy that nobody typed.
package autoupdate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"

	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/store"
)

// Store is the slice of the state store this package needs: read the services
// and allocs, write one field back.
type Store interface {
	store.Reader
	store.Applier
}

// Resolver reports what an image reference points at in its registry now.
type Resolver interface {
	ResolveRemote(ctx context.Context, img runtime.ImageRef) (string, error)
}

// Secrets resolves the registry credential a service names.
type Secrets interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

// Config configures the watcher.
type Config struct {
	Store    Store
	Resolver Resolver
	// Secrets may be nil; a service naming a credential is then skipped with a
	// logged error rather than polled anonymously, because an anonymous poll of
	// a private repository fails in a way that reads like the tag vanished.
	Secrets Secrets
	Logger  *slog.Logger
	// Emit publishes update events (§11). Optional.
	Emit func(notify.Event)
	// Tick is how often the watcher looks for work. It is not the poll
	// interval: each service has its own, and this only bounds how late a due
	// poll can be.
	Tick time.Duration
	// Now is injectable for tests.
	Now func() time.Time
	// Wake is signalled after a pin so the reconciler converges promptly
	// instead of waiting out its own interval. Optional.
	Wake chan<- struct{}
}

// DefaultTick bounds how late a due poll can be.
const DefaultTick = time.Minute

// Watcher polls registries and pins digests.
type Watcher struct {
	store    Store
	resolver Resolver
	secrets  Secrets
	log      *slog.Logger
	emit     func(notify.Event)
	tick     time.Duration
	now      func() time.Time
	wake     chan<- struct{}
}

// New builds a watcher.
func New(cfg Config) (*Watcher, error) {
	if cfg.Store == nil {
		return nil, errors.New("autoupdate: a store is required")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("autoupdate: a resolver is required")
	}
	w := &Watcher{
		store:    cfg.Store,
		resolver: cfg.Resolver,
		secrets:  cfg.Secrets,
		log:      cfg.Logger,
		emit:     cfg.Emit,
		tick:     cfg.Tick,
		now:      cfg.Now,
		wake:     cfg.Wake,
	}
	if w.log == nil {
		w.log = slog.New(slog.DiscardHandler)
	}
	if w.emit == nil {
		w.emit = func(notify.Event) {}
	}
	if w.tick <= 0 {
		w.tick = DefaultTick
	}
	if w.now == nil {
		w.now = time.Now
	}
	return w, nil
}

// Run polls until the context is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.tick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := w.Once(ctx); err != nil && !errors.Is(err, context.Canceled) {
				// A sweep failure is never fatal: a registry that is down now
				// is a registry that may be up in a minute, and a watcher that
				// exited would stop updating every other service too.
				w.log.Warn("auto-update sweep failed", "error", err)
			}
		}
	}
}

// Once runs a single sweep.
func (w *Watcher) Once(ctx context.Context) error {
	services, err := w.services(ctx)
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return nil
	}

	allocs, err := w.allocs(ctx)
	if err != nil {
		return err
	}

	for _, svc := range services {
		if err := w.sweepOne(ctx, svc.desired, svc.index, allocs); err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			w.log.Warn("auto-update failed",
				"service", key(svc.desired), "error", err)
		}
	}
	return nil
}

// sweepOne advances one service by at most one step.
//
// A service with an update in flight is never polled: settling the one that is
// running matters more than noticing the next one, and stacking a second pin
// on top of an unconverged deploy is how a bad image gets a rollback target
// that is also bad.
func (w *Watcher) sweepOne(ctx context.Context, d reconciler.Desired, index uint64,
	allocs map[string][]reconciler.AllocRecord,
) error {
	if !d.Update.Auto {
		return nil
	}
	if d.ImageUpdatedAt.IsZero() {
		return w.pollIfDue(ctx, d, index)
	}
	return w.settle(ctx, d, index, allocs[key(d)])
}

// settle decides an in-flight update: converged, or out of time.
func (w *Watcher) settle(ctx context.Context, d reconciler.Desired, index uint64,
	allocs []reconciler.AllocRecord,
) error {
	switch {
	case converged(d, allocs):
		// The rollback target is dropped rather than kept: it is only useful
		// while there is doubt, and a stale one would revert a later failure
		// to an image two updates old.
		updated := d
		updated.RollbackImage = ""
		updated.ImageUpdatedAt = time.Time{}
		if err := w.write(ctx, updated, index); err != nil {
			return err
		}
		w.log.Info("auto-update converged", "service", key(d), "image", d.PinnedImage)
		w.publish(notify.EventImageUpdated, d,
			fmt.Sprintf("updated to %s", d.PinnedImage))
		return nil

	case w.now().Sub(d.ImageUpdatedAt) < d.Update.RevertDeadline():
		return nil // still within its deadline; leave it alone
	}

	// Out of time. Revert to what was running, which is the whole reason the
	// previous reference was kept: unattended is exactly the case where nobody
	// is watching to notice and fix it.
	failed := d.PinnedImage
	reverted := d
	reverted.PinnedImage = d.RollbackImage
	reverted.RollbackImage = ""
	reverted.ImageUpdatedAt = time.Time{}
	// Not retried on the next tick: ImageCheckedAt stays where the poll left
	// it, so the same broken digest is not re-pinned a minute later. It will be
	// tried again one interval on, by which time the tag may have moved again.
	if err := w.write(ctx, reverted, index); err != nil {
		return err
	}
	w.log.Warn("auto-update did not converge; reverting",
		"service", key(d), "failed", failed, "reverted_to", reverted.RunImage())
	w.publish(notify.EventImageUpdateFailed, d,
		fmt.Sprintf("%s did not become healthy within %s; reverted to %s",
			failed, d.Update.RevertDeadline(), reverted.RunImage()))
	return nil
}

// pollIfDue re-resolves the tag when the interval has elapsed.
func (w *Watcher) pollIfDue(ctx context.Context, d reconciler.Desired, index uint64) error {
	if !d.ImageCheckedAt.IsZero() && w.now().Sub(d.ImageCheckedAt) < d.Update.PollInterval() {
		return nil
	}

	auth, err := w.auth(ctx, d)
	if err != nil {
		return err
	}
	digest, err := w.resolver.ResolveRemote(ctx, runtime.ImageRef{
		Project: d.Project, Ref: d.Image, Auth: auth,
	})
	if err != nil {
		// The check is still recorded, so an unreachable registry is retried on
		// the service's own interval rather than on every tick.
		checked := d
		checked.ImageCheckedAt = w.now()
		if writeErr := w.write(ctx, checked, index); writeErr != nil {
			return writeErr
		}
		return fmt.Errorf("resolve %s: %w", d.Image, err)
	}

	pinned, err := pinDigest(d.Image, digest)
	if err != nil {
		return err
	}

	updated := d
	updated.ImageCheckedAt = w.now()
	if pinned == d.PinnedImage {
		return w.write(ctx, updated, index) // nothing moved; just record the check
	}

	updated.RollbackImage = d.PinnedImage
	updated.PinnedImage = pinned
	updated.ImageUpdatedAt = w.now()
	if err := w.write(ctx, updated, index); err != nil {
		return err
	}

	w.log.Info("auto-update pinned a new digest",
		"service", key(d), "image", pinned, "previous", d.RunImage())
	w.wakeReconciler()
	return nil
}

// converged reports whether every alloc is running the pinned image and is as
// healthy as the service can be known to be.
//
// The health half is conditional on purpose. AllocRecord.Healthy is only ever
// written by a probe, so a service with no `check` block has it false for every
// alloc for its whole life — testing it unconditionally would call every
// check-free service permanently failed and revert every update it ever made.
// Without a check, "running and not crash-looping" is the strongest true
// statement available, and it is the same standard the rest of the reconciler
// applies.
func converged(d reconciler.Desired, allocs []reconciler.AllocRecord) bool {
	want := reconciler.SpecHash(d)
	count := 0
	for _, a := range allocs {
		if a.SpecHash != want || a.State != reconciler.AllocRunning {
			continue
		}
		if d.Check != nil && !a.Healthy {
			continue
		}
		count++
	}
	return count >= d.Count && d.Count > 0
}

// pinDigest composes the digest-pinned reference for a tag.
//
// The tag is dropped rather than kept alongside: `repo:tag@sha256:…` is legal
// and reads as though the tag is meaningful, when only the digest is consulted.
func pinDigest(image, raw string) (string, error) {
	named, err := reference.ParseDockerRef(image)
	if err != nil {
		return "", fmt.Errorf("image reference %q: %w", image, err)
	}
	canonical, err := reference.WithDigest(reference.TrimNamed(named), digest.Digest(raw))
	if err != nil {
		return "", fmt.Errorf("pin %q at %s: %w", image, raw, err)
	}
	return canonical.String(), nil
}

type serviceRecord struct {
	desired reconciler.Desired
	index   uint64
}

// services reads every service that has auto-update turned on.
func (w *Watcher) services(ctx context.Context) ([]serviceRecord, error) {
	var out []serviceRecord
	opts := store.ListOptions{}
	for {
		// Records rather than ListValues: the index is what makes the write
		// back a compare-and-set instead of a clobber.
		values, page, err := store.ListValues[reconciler.Desired](ctx, w.store, store.KindService, opts)
		if err != nil {
			return nil, fmt.Errorf("list services: %w", err)
		}
		for i, d := range values {
			if d.Update.Auto {
				out = append(out, serviceRecord{desired: d, index: page.Records[i].Index})
			}
		}
		if !page.More || page.NextAfter == "" {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

// allocs indexes alloc records by "project/service".
func (w *Watcher) allocs(ctx context.Context) (map[string][]reconciler.AllocRecord, error) {
	out := map[string][]reconciler.AllocRecord{}
	opts := store.ListOptions{}
	for {
		values, page, err := store.ListValues[reconciler.AllocRecord](ctx, w.store, store.KindAlloc, opts)
		if err != nil {
			return nil, fmt.Errorf("list allocs: %w", err)
		}
		for _, a := range values {
			k := a.Project + "/" + a.Service
			out[k] = append(out[k], a)
		}
		if !page.More || page.NextAfter == "" {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

// auth resolves the registry credential, if one is named.
func (w *Watcher) auth(ctx context.Context, d reconciler.Desired) ([]byte, error) {
	if d.RegistryAuthRef == "" {
		return nil, nil
	}
	if w.secrets == nil {
		return nil, errors.New("service names a registry credential but no secret store is configured")
	}
	auth, err := w.secrets.Resolve(ctx, d.RegistryAuthRef)
	if err != nil {
		return nil, fmt.Errorf("registry credential %q: %w", d.RegistryAuthRef, err)
	}
	return auth, nil
}

// write updates the service record, refusing a lost update.
//
// Read-modify-write against the index it was read at, like every other partial
// update: an operator editing the spec while a poll is in flight must not have
// their change overwritten by a watcher that read the record first.
func (w *Watcher) write(ctx context.Context, d reconciler.Desired, index uint64) error {
	mut, err := store.UpdateMutation(store.KindService, key(d), d, index)
	if err != nil {
		return err
	}
	if _, err := w.store.Apply(ctx, mut); err != nil {
		return fmt.Errorf("update %s: %w", key(d), err)
	}
	return nil
}

func (w *Watcher) wakeReconciler() {
	if w.wake == nil {
		return
	}
	select {
	case w.wake <- struct{}{}:
	default: // a wake is already pending; one is enough
	}
}

func (w *Watcher) publish(name string, d reconciler.Desired, message string) {
	w.emit(notify.NewEvent(name, d.Project, d.Service, message, w.now()))
}

func key(d reconciler.Desired) string { return d.Project + "/" + d.Service }
