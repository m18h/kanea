package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/scaling"
	"github.com/kanea-dev/kanea/internal/store"
)

// storeFleet is the autoscaler's view of desired state.
//
// It reads and writes the same `services` bucket the API writes, so a scale
// decision is indistinguishable from an operator running `kanea scale` — which
// is the point. The autoscaler is not a second scheduler; it moves one number
// and the reconciler converges (§9.2).
type storeFleet struct {
	store  store.Store
	notify chan<- struct{}
	log    *slog.Logger
}

// Services lists what is running and what policy governs it.
func (f storeFleet) Services(ctx context.Context) ([]scaling.Service, error) {
	desired, err := listAllServices(ctx, f.store)
	if err != nil {
		return nil, err
	}

	out := make([]scaling.Service, 0, len(desired))
	for _, d := range desired {
		out = append(out, scaling.Service{
			Key:    d.Project + "/" + d.Service,
			Count:  d.Count,
			Policy: toPolicy(d.Scaling, f.log),
		})
	}
	return out, nil
}

// SetCount writes a new desired count.
//
// Read-modify-write rather than a blind put: the record carries everything
// about the service, and writing a Desired built from the autoscaler's own
// partial view would silently drop the image, the volumes and the policy.
func (f storeFleet) SetCount(ctx context.Context, service string, count int) error {
	current, index, err := store.GetValue[reconciler.Desired](ctx, f.store, store.KindService, service)
	if err != nil {
		return fmt.Errorf("read %s: %w", service, err)
	}
	current.Count = count

	mut, err := store.UpdateMutation(store.KindService, service, current, index)
	if err != nil {
		return err
	}
	// Compare-and-set on the index: an operator editing the same service at the
	// same moment must not have their change silently overwritten by a scale
	// decision made against the version before it.
	if _, err := f.store.Apply(ctx, mut); err != nil {
		return fmt.Errorf("scale %s: %w", service, err)
	}

	// The reconciler converges on its own schedule; this only stops the change
	// waiting out an interval it does not need to.
	select {
	case f.notify <- struct{}{}:
	default:
	}
	return nil
}

// toPolicy converts the stored policy into the evaluator's.
//
// A malformed cooldown is dropped to the default rather than failing the pass:
// the spec was validated when it was applied, so a bad value here means a
// hand-edited or restored record, and refusing to scale the whole node over one
// unparseable string is the wrong trade.
func toPolicy(policy *reconciler.ScalingPolicy, log *slog.Logger) scaling.Policy {
	if policy == nil {
		return scaling.Policy{}
	}
	out := scaling.Policy{Min: policy.Min, Max: policy.Max}
	for _, m := range policy.Metrics {
		out.Rules = append(out.Rules, scaling.Rule{Metric: m.Name, Target: m.Target})
	}
	if policy.Cooldown != "" {
		cooldown, err := time.ParseDuration(policy.Cooldown)
		if err != nil {
			log.Warn("ignoring an unparseable scaling cooldown",
				"cooldown", policy.Cooldown, "error", err)
		} else {
			out.Cooldown = cooldown
		}
	}
	return out
}

// allocResolver maps containerd container ids to the allocs they belong to.
//
// The scraper sees a container id and nothing else; which service that is lives
// in the Store. The map is rebuilt on a timer rather than looked up per sample:
// a scrape at the §21 target carries thousands of samples, and a Store read per
// sample would make the metrics pipeline the most expensive thing on the node.
type allocResolver struct {
	store store.Store
	log   *slog.Logger

	current atomic.Pointer[map[string]scaling.AllocInfo]
}

func newAllocResolver(st store.Store, log *slog.Logger) *allocResolver {
	r := &allocResolver{store: st, log: log}
	empty := map[string]scaling.AllocInfo{}
	r.current.Store(&empty)
	return r
}

// Alloc resolves one container id.
func (r *allocResolver) Alloc(id string) (scaling.AllocInfo, bool) {
	info, ok := (*r.current.Load())[id]
	return info, ok
}

// Refresh rebuilds the map from the Store.
func (r *allocResolver) Refresh(ctx context.Context) error {
	allocs, err := listAllAllocs(ctx, r.store)
	if err != nil {
		return err
	}
	services, err := listAllServices(ctx, r.store)
	if err != nil {
		return err
	}

	limits := make(map[string]reconciler.Desired, len(services))
	for _, d := range services {
		limits[d.Project+"/"+d.Service] = d
	}

	next := make(map[string]scaling.AllocInfo, len(allocs))
	for _, alloc := range allocs {
		service := alloc.Project + "/" + alloc.Service
		desired, ok := limits[service]
		if !ok {
			// An alloc whose service is gone. Its metrics would be attributed
			// to nothing, and its limits are unknown, so it is skipped.
			continue
		}
		next[alloc.ID] = scaling.AllocInfo{
			Subject:     service + "/" + alloc.ID,
			Service:     service,
			CPUMillis:   int64(desired.Resources.CPUMillis),
			MemoryBytes: desired.Resources.MemoryBytes,
		}
	}
	r.current.Store(&next)
	return nil
}

// Run refreshes on a ticker until the context ends.
func (r *allocResolver) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if err := r.Refresh(ctx); err != nil && ctx.Err() == nil {
			r.log.Warn("cannot refresh the alloc metric map", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// allocRefreshInterval is how often the container-id map is rebuilt. Allocs
// change when the reconciler acts, which is far slower than the scrape.
const allocRefreshInterval = 15 * time.Second

// listAllAllocs reads every alloc record from the Store.
func listAllAllocs(ctx context.Context, st store.Store) ([]reconciler.AllocRecord, error) {
	var out []reconciler.AllocRecord
	opts := store.ListOptions{}
	for {
		values, page, err := store.ListValues[reconciler.AllocRecord](ctx, st, store.KindAlloc, opts)
		if err != nil {
			return nil, fmt.Errorf("list allocs: %w", err)
		}
		out = append(out, values...)
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

// metricsSettings is what startMetrics needs to build the pipeline.
type metricsSettings struct {
	metrics       *scaling.Metrics
	containerdURL string
	edgeURL       string
	interval      time.Duration
	autoscale     bool
	store         store.Store
	notify        chan<- struct{}
}

// off disables a scrape target.
const scrapeOff = "off"

// startMetrics launches the §9 pipeline: two scrapers, a sweeper, and the
// autoscaling loop.
//
// Each piece is optional and says so when it is not running. A node with no
// exposed services has no edge to scrape, a node whose containerd has no
// metrics listener still runs workloads, and a node where nobody declared a
// scaling policy still wants the graphs.
func startMetrics(ctx context.Context, cfg metricsSettings, logger *slog.Logger) {
	resolver := newAllocResolver(cfg.store, logger)
	go resolver.Run(ctx, allocRefreshInterval)

	if cfg.containerdURL != scrapeOff {
		scraper, err := scaling.NewContainerdScraper(scaling.ContainerdConfig{
			URL: cfg.containerdURL, Metrics: cfg.metrics, Allocs: resolver, Logger: logger,
		})
		if err != nil {
			logger.Error("cannot start the containerd metrics scrape", "error", err)
		} else {
			go scraper.Run(ctx, cfg.interval)
			logger.Info("scraping cgroup metrics", "url", cfg.containerdURL, "interval", cfg.interval)
		}
	} else {
		logger.Warn("cgroup metrics are disabled; cpu and memory scaling rules will never fire")
	}

	if cfg.edgeURL != scrapeOff {
		scraper, err := scaling.NewEdgeScraper(scaling.EdgeConfig{
			URL: cfg.edgeURL, Metrics: cfg.metrics, Logger: logger,
		})
		if err != nil {
			logger.Error("cannot start the edge metrics scrape", "error", err)
		} else {
			go scraper.Run(ctx, cfg.interval)
			logger.Info("scraping edge L7 metrics", "url", cfg.edgeURL, "interval", cfg.interval)
		}
	} else {
		logger.Warn("edge metrics are disabled; rps and latency scaling rules will never fire")
	}

	// Sweeping is housekeeping: Forget covers the services that leave cleanly,
	// and this covers the ones nobody noticed leaving.
	go func() {
		ticker := time.NewTicker(scaling.RollupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if dropped := cfg.metrics.Sweep(); dropped > 0 {
				logger.Debug("swept stale metric series", "series", dropped)
			}
		}
	}()

	if !cfg.autoscale {
		logger.Warn("autoscaling is disabled; declared scaling policies are recorded but not acted on")
		return
	}

	evaluator, err := scaling.NewEvaluator(scaling.EvaluatorConfig{Metrics: cfg.metrics, Logger: logger})
	if err != nil {
		logger.Error("cannot start the autoscaler", "error", err)
		return
	}
	loop, err := scaling.NewLoop(scaling.LoopConfig{
		Evaluator: evaluator,
		Fleet:     storeFleet{store: cfg.store, notify: cfg.notify, log: logger},
		Logger:    logger,
	})
	if err != nil {
		logger.Error("cannot start the autoscaler", "error", err)
		return
	}
	go loop.Run(ctx)
	logger.Info("autoscaling enabled", "interval", scaling.DefaultEvaluationInterval)
}
