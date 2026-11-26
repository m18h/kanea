// Package imagegc collects the containerd images nothing on the node needs
// any more (PRD §5.2.4, v1.111).
//
// Nothing else deletes an image: every deploy, auto-update pin and rollback
// leaves its predecessor behind, and §5.2.4's one promise about the disk is
// that pressure must never surprise the control plane. The collector is the
// R19 watcher's loop shape carrying the internal registry sweep's doctrine:
// mark what is referenced, delete what is not, log failures and keep going,
// and say nothing at all in steady state.
//
// An image survives a sweep when any of three rules protects it. It is in the
// in-use set: the union, over every service and alloc record, of the declared
// image, the pinned digest, the rollback target, every init step's image and
// the image each live alloc actually runs - allocs lag the desired state
// mid-roll, so both sides are consulted, and the union is global across
// projects on purpose (conservative beats clever here). It is younger than
// MinAge, which is also the guard against the race where a pull lands before
// the alloc record that references it. Or it is among the newest Keep images
// of a repository something still references - §5.2.4's "keep-last-N in use",
// rollback material; a repository nothing references gets no keep-N, or a
// deleted project's images would never collect.
//
// Every comparison happens on normalised references: the Store holds
// `nginx:1.27` where containerd holds `docker.io/library/nginx:1.27`, and an
// unnormalised comparison is a silent mass deletion.
package imagegc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/distribution/reference"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/store"
)

// Images is the slice of the runtime driver the collector needs: enumerate,
// list, delete. Satisfied by runtime.Driver (interfaces at the consumer).
type Images interface {
	ImageProjects(ctx context.Context) ([]string, error)
	ListImages(ctx context.Context, project string) ([]runtime.OwnedImage, error)
	RemoveImage(ctx context.Context, project, ref string) error
}

// Config configures the collector.
type Config struct {
	Store  store.Reader
	Images Images
	Logger *slog.Logger
	// NodePullPolicy is the node's resolved default (images.pull_policy, then
	// if-not-present). "never" refuses the whole collector: preloaded images
	// cannot be re-pulled, so deletion there is unrecoverable.
	NodePullPolicy string
	// Disabled records that the operator turned the collector off
	// (images.gc.enabled = false). The manual trigger
	// then refuses too: a sweep the config forbids is a sweep, however it
	// was asked for.
	Disabled bool
	// Interval is the sweep cadence; <= 0 means DefaultInterval.
	Interval time.Duration
	// MinAge is how old an unreferenced image must be before it is garbage;
	// <= 0 means DefaultMinAge.
	MinAge time.Duration
	// Keep is how many of an in-use repository's newest images survive even
	// unreferenced. Nil means DefaultKeep; zero is a legal value and means
	// none ("no data is never zero").
	Keep *int
	// Now is injectable for tests.
	Now func() time.Time
}

// Defaults (PRD §15.1, v1.111). Conservative on purpose: 48 hours is long
// enough that anything younger might still be mid-deploy or worth a quick
// rollback, and two kept images per repository is the previous deploy plus
// the one before it.
const (
	DefaultInterval = 12 * time.Hour
	DefaultMinAge   = 48 * time.Hour
	DefaultKeep     = 2
)

// ErrRefused is returned by Once when the collector may not sweep at all;
// the API maps it to a 409 naming the reason.
var ErrRefused = errors.New("image gc refused")

// Summary is what one sweep did.
type Summary struct {
	// Removed counts deleted image references.
	Removed int `json:"removed"`
	// ReclaimedBytes counts the content behind them, once per digest and
	// only when no surviving reference in the namespace still holds it:
	// deleting one of two names for the same bytes reclaims nothing.
	ReclaimedBytes int64 `json:"reclaimed_bytes"`
}

// Image is one image as the node holds it, with the collector's verdict on
// whether anything references it. The images API serves this directly.
type Image struct {
	Project   string    `json:"project"`
	Ref       string    `json:"ref"`
	Digest    string    `json:"digest"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
	InUse     bool      `json:"in_use"`
}

// Collector sweeps unused images on an interval.
type Collector struct {
	store    store.Reader
	images   Images
	log      *slog.Logger
	interval time.Duration
	minAge   time.Duration
	keep     int
	refusal  string
	now      func() time.Time
}

// New builds a collector.
func New(cfg Config) (*Collector, error) {
	if cfg.Store == nil {
		return nil, errors.New("imagegc: a store is required")
	}
	if cfg.Images == nil {
		return nil, errors.New("imagegc: an image driver is required")
	}
	c := &Collector{
		store:    cfg.Store,
		images:   cfg.Images,
		log:      cfg.Logger,
		interval: cfg.Interval,
		minAge:   cfg.MinAge,
		keep:     DefaultKeep,
		now:      cfg.Now,
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.interval <= 0 {
		c.interval = DefaultInterval
	}
	if c.minAge <= 0 {
		c.minAge = DefaultMinAge
	}
	if cfg.Keep != nil {
		if *cfg.Keep < 0 {
			return nil, fmt.Errorf("imagegc: keep %d is negative; it counts images", *cfg.Keep)
		}
		c.keep = *cfg.Keep
	}
	if c.now == nil {
		c.now = time.Now
	}
	// The refusals, in order of severity. The policy one wins the message:
	// it is the one that holds even after the operator flips enabled back on.
	switch {
	case cfg.NodePullPolicy == runtime.PullNever:
		c.refusal = "the node's default pull policy is \"never\": preloaded images cannot be re-pulled, so deleting one is unrecoverable"
	case cfg.Disabled:
		c.refusal = "image gc is disabled (images.gc.enabled = false in /etc/kanea/kanea.hcl)"
	}
	return c, nil
}

// Refusal is why the collector will not sweep, or empty when it will. The
// agent reads it to decide whether Run is worth starting; the API reads it
// to answer 409 instead of sweeping.
func (c *Collector) Refusal() string { return c.refusal }

// Interval is the resolved sweep cadence, for the agent's startup log line.
func (c *Collector) Interval() time.Duration { return c.interval }

// Run sweeps until the context is cancelled: once at start, because the
// ticker never ran for whatever the last process left behind (the registry
// sweep's boot-half reasoning), then on the interval.
func (c *Collector) Run(ctx context.Context) error {
	if c.refusal != "" {
		return fmt.Errorf("%w: %s", ErrRefused, c.refusal)
	}
	c.sweepAndLog(ctx)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			c.sweepAndLog(ctx)
		}
	}
}

func (c *Collector) sweepAndLog(ctx context.Context) {
	// A sweep failure is never fatal: a containerd that cannot answer now
	// may answer in twelve hours, and a collector that exited would never
	// try again.
	if _, err := c.Once(ctx); err != nil && !errors.Is(err, context.Canceled) {
		c.log.Warn("image gc sweep failed", "error", err)
	}
}

// Once runs a single sweep.
func (c *Collector) Once(ctx context.Context) (Summary, error) {
	if c.refusal != "" {
		return Summary{}, fmt.Errorf("%w: %s", ErrRefused, c.refusal)
	}
	inUse, err := c.inUse(ctx)
	if err != nil {
		return Summary{}, err
	}
	projects, err := c.images.ImageProjects(ctx)
	if err != nil {
		return Summary{}, err
	}
	sort.Strings(projects)

	var sum Summary
	for _, project := range projects {
		imgs, err := c.images.ListImages(ctx, project)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return sum, err
			}
			// One unreadable namespace must not stop the others' sweep.
			c.log.Warn("image gc cannot list a project's images",
				"project", project, "error", err)
			continue
		}
		c.sweepProject(ctx, project, imgs, inUse, &sum)
	}
	if sum.Removed > 0 {
		c.log.Info("image gc removed unused images",
			"removed", sum.Removed, "reclaimed_bytes", sum.ReclaimedBytes)
	}
	return sum, nil
}

// sweepProject deletes one namespace's garbage and accounts for it.
func (c *Collector) sweepProject(ctx context.Context, project string,
	imgs []runtime.OwnedImage, inUse *inUseSet, sum *Summary,
) {
	kept := c.keepNewest(imgs, inUse)
	holders := map[string]int{} // digest -> surviving references
	for _, img := range imgs {
		holders[img.Digest]++
	}

	for _, img := range imgs {
		switch {
		case inUse.refs[img.Ref]:
			continue
		case c.now().Sub(img.CreatedAt) < c.minAge:
			continue
		case kept[img.Ref]:
			continue
		}
		if err := c.images.RemoveImage(ctx, project, img.Ref); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			c.log.Warn("image gc cannot remove an image",
				"project", project, "image", img.Ref, "error", err)
			continue
		}
		sum.Removed++
		// The bytes count once, and only when the digest's last name in this
		// namespace is gone: deleting one of two names for the same content
		// reclaims nothing.
		if holders[img.Digest]--; holders[img.Digest] == 0 {
			sum.ReclaimedBytes += img.SizeBytes
		}
		c.log.Debug("image gc removed an image", "project", project, "image", img.Ref)
	}
}

// keepNewest marks the newest Keep images of every in-use repository:
// §5.2.4's "keep-last-N in use". Repositories nothing references get no
// keep-N, or a deleted project's images would survive forever.
func (c *Collector) keepNewest(imgs []runtime.OwnedImage, inUse *inUseSet) map[string]bool {
	kept := map[string]bool{}
	if c.keep == 0 {
		return kept
	}
	byRepo := map[string][]runtime.OwnedImage{}
	for _, img := range imgs {
		repo, ok := repoOf(img.Ref)
		if !ok || !inUse.repos[repo] {
			continue
		}
		byRepo[repo] = append(byRepo[repo], img)
	}
	for _, group := range byRepo {
		sort.Slice(group, func(i, j int) bool {
			return group[i].CreatedAt.After(group[j].CreatedAt)
		})
		for i := 0; i < len(group) && i < c.keep; i++ {
			kept[group[i].Ref] = true
		}
	}
	return kept
}

// List reports every image on the node with the collector's in-use verdict:
// the read half of the images API. It works on a refused collector too - a
// node that may not delete may still look.
func (c *Collector) List(ctx context.Context) ([]Image, error) {
	inUse, err := c.inUse(ctx)
	if err != nil {
		return nil, err
	}
	projects, err := c.images.ImageProjects(ctx)
	if err != nil {
		return nil, err
	}
	sort.Strings(projects)

	var out []Image
	for _, project := range projects {
		imgs, err := c.images.ListImages(ctx, project)
		if err != nil {
			return nil, err
		}
		for _, img := range imgs {
			out = append(out, Image{
				Project:   project,
				Ref:       img.Ref,
				Digest:    img.Digest,
				SizeBytes: img.SizeBytes,
				CreatedAt: img.CreatedAt,
				InUse:     inUse.refs[img.Ref],
			})
		}
	}
	return out, nil
}

// inUseSet is every reference the desired state or a live alloc still names,
// plus the repositories those references belong to (the keep-N scope).
type inUseSet struct {
	refs  map[string]bool
	repos map[string]bool
}

// inUse builds the set. Global across projects on purpose: a reference any
// project names survives in every namespace, which errs exactly the way a
// deleter should.
func (c *Collector) inUse(ctx context.Context) (*inUseSet, error) {
	set := &inUseSet{refs: map[string]bool{}, repos: map[string]bool{}}

	opts := store.ListOptions{}
	for {
		values, page, err := store.ListValues[reconciler.Desired](ctx, c.store, store.KindService, opts)
		if err != nil {
			return nil, fmt.Errorf("list services: %w", err)
		}
		for _, d := range values {
			set.add(c.log, d.Image, d.PinnedImage, d.RollbackImage)
			for _, init := range d.Init {
				set.add(c.log, init.Image)
			}
		}
		if !page.More || page.NextAfter == "" {
			break
		}
		opts.After = page.NextAfter
	}

	// Alloc records too: they lag the desired state mid-roll, and the image
	// an old replica still runs must survive until the roll replaces it.
	opts = store.ListOptions{}
	for {
		values, page, err := store.ListValues[reconciler.AllocRecord](ctx, c.store, store.KindAlloc, opts)
		if err != nil {
			return nil, fmt.Errorf("list allocs: %w", err)
		}
		for _, a := range values {
			set.add(c.log, a.Image)
		}
		if !page.More || page.NextAfter == "" {
			return set, nil
		}
		opts.After = page.NextAfter
	}
}

// add normalises and records references. A reference that does not parse is
// logged and skipped: it cannot match a containerd name anyway, because every
// pull went through the same normalisation.
func (s *inUseSet) add(log *slog.Logger, refs ...string) {
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		named, err := reference.ParseDockerRef(ref)
		if err != nil {
			log.Warn("image gc cannot parse a stored reference; it is not protected",
				"reference", ref, "error", err)
			continue
		}
		s.refs[named.String()] = true
		s.repos[reference.TrimNamed(named).Name()] = true
	}
}

// repoOf is the repository a containerd image name belongs to: the grouping
// key for keep-N.
func repoOf(ref string) (string, bool) {
	named, err := reference.ParseDockerRef(ref)
	if err != nil {
		return "", false
	}
	return reference.TrimNamed(named).Name(), true
}
