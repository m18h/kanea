package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/m18h/kanea/internal/datapath"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/scaling"
	"github.com/m18h/kanea/internal/store"
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
	emit   func(notify.Event)
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
	previous := current.Count
	current.Count = count

	mut, err := store.UpdateMutation(store.KindService, service, current, index)
	if err != nil {
		return err
	}
	// The cooldown clock rides in the same batch (v1.37): the Store is being
	// written anyway, so making the evaluator's last-change time durable costs
	// no extra replication — and a daemon restarted mid-cooldown no longer
	// forgets it and re-scales a service the running daemon would have held.
	cool, err := store.PutMutation(store.KindKV, cooldownKey(service),
		scaleCooldownRecord{At: time.Now()})
	if err != nil {
		return err
	}
	// Compare-and-set on the index: an operator editing the same service at the
	// same moment must not have their change silently overwritten by a scale
	// decision made against the version before it.
	if _, err := f.store.Apply(ctx, mut, cool); err != nil {
		return fmt.Errorf("scale %s: %w", service, err)
	}

	if f.emit != nil {
		// Named by direction rather than by "scale": §11 lists scale.up and
		// scale.down separately because an operator filtering notifications
		// usually cares about one of them and not the other.
		name := notify.EventScaleUp
		if count < previous {
			name = notify.EventScaleDown
		}
		project, svc, _ := strings.Cut(service, "/")
		f.emit(notify.NewEvent(name, project, svc,
			fmt.Sprintf("scaled %d → %d", previous, count), time.Now()))
	}

	// The reconciler converges on its own schedule; this only stops the change
	// waiting out an interval it does not need to.
	select {
	case f.notify <- struct{}{}:
	default:
	}
	return nil
}

// scaleCooldownRecord is the evaluator's durable last-change time (v1.37).
//
// One small record per service that ever autoscaled, written only inside a
// scale action's own Apply batch. The stabilization history is deliberately
// not persisted — that would be a metric stream through the Store (AGENTS.md
// #2); the evaluator's warm-up guard covers what its loss would have cost.
type scaleCooldownRecord struct {
	At time.Time `json:"at"`
}

// cooldownKeyPrefix is where the records live in the kv bucket.
const cooldownKeyPrefix = "scaling/cooldown/"

// cooldownKey is the record's kv key; service is already "project/service".
func cooldownKey(service string) string { return cooldownKeyPrefix + service }

// seedCooldowns replays persisted cooldowns into a fresh evaluator, and reaps
// records for services that no longer exist — the one moment the whole prefix
// is read anyway.
func seedCooldowns(ctx context.Context, st store.Store, evaluator *scaling.Evaluator, log *slog.Logger) {
	services, err := listAllServices(ctx, st)
	if err != nil {
		log.Warn("cannot seed scaling cooldowns; starting cold", "error", err)
		return
	}
	live := make(map[string]bool, len(services))
	for _, d := range services {
		live[d.Project+"/"+d.Service] = true
	}

	var stale []store.Mutation
	opts := store.ListOptions{Prefix: cooldownKeyPrefix}
	for {
		page, err := st.List(ctx, store.KindKV, opts)
		if err != nil {
			log.Warn("cannot seed scaling cooldowns; starting cold", "error", err)
			return
		}
		for _, rec := range page.Records {
			service := strings.TrimPrefix(rec.Key, cooldownKeyPrefix)
			if !live[service] {
				stale = append(stale, store.DeleteMutation(store.KindKV, rec.Key))
				continue
			}
			var cool scaleCooldownRecord
			if err := json.Unmarshal(rec.Value, &cool); err != nil {
				log.Warn("dropping an unreadable scaling cooldown", "key", rec.Key, "error", err)
				stale = append(stale, store.DeleteMutation(store.KindKV, rec.Key))
				continue
			}
			evaluator.Applied(service, cool.At)
		}
		if !page.More {
			break
		}
		opts.After = page.NextAfter
	}

	if len(stale) > 0 {
		if _, err := st.Apply(ctx, stale...); err != nil {
			log.Warn("cannot reap stale scaling cooldowns", "count", len(stale), "error", err)
		}
	}
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

// datapathFlows adapts the datapath's counter view to scaling's FlowSource.
//
// Connects already come back keyed by "project/service". Drops are keyed by
// destination address and reason, and the address becomes a service through
// the datapath's own attachment view — the same live query the reconciler
// trusts, never the Store (constraint #2). Anything unattributable — a VIP
// with no backends, metadata-service egress, an alloc that detached between
// the drop and this read — folds into the node subject rather than being
// lost: a number nobody can break down is still a number worth having.
type datapathFlows struct {
	source   *datapath.CounterSource
	datapath *datapath.Datapath
}

// ServiceConnects returns cumulative connection attempts per service.
func (f datapathFlows) ServiceConnects(ctx context.Context) (map[string]uint64, error) {
	return f.source.ServiceConnects(ctx)
}

// Drops returns cumulative datapath drops per service.
func (f datapathFlows) Drops(ctx context.Context) (map[string]uint64, error) {
	raw, err := f.source.Drops()
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint64, len(raw))
	if len(raw) == 0 {
		return out, nil
	}

	attachments, err := f.datapath.Attachments(ctx)
	if err != nil {
		return nil, err
	}
	byAddr := make(map[netip.Addr]string, len(attachments))
	for _, att := range attachments {
		if att.Service.Project == "" || att.Service.Service == "" {
			continue
		}
		if addr, err := netip.ParseAddr(att.IPv4); err == nil {
			byAddr[addr] = att.Service.String()
		}
	}
	for key, count := range raw {
		subject, ok := byAddr[netip.AddrFrom4(key.DstIP)]
		if !ok {
			subject = scaling.NodeSubject
		}
		out[subject] += count
	}
	return out, nil
}

// metricsSettings is what startMetrics needs to build the pipeline.
type metricsSettings struct {
	metrics *scaling.Metrics
	// exposition receives the edge's labelled families for the exporter
	// (§9.1.1). It never reaches the time series above.
	exposition    *scaling.EdgeExposition
	containerdURL string
	edgeURL       string
	// flows is the datapath's east-west counter view; nil in netns mode,
	// which has no counters.
	flows     scaling.FlowSource
	interval  time.Duration
	autoscale bool
	store     store.Store
	notify    chan<- struct{}
	emit      func(notify.Event)
	breaker   scaling.Breaker
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
			Exposition: cfg.exposition,
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

	// East-west metrics come from the datapath's own per-CPU counters, on by
	// default (PRD v1.36): reading a pinned map costs nothing per request,
	// which is what lets this be a default where Hubble — 152.8 MiB of
	// resident cilium-agent as M0 spike ① measured it — had to be opt-in.
	if cfg.flows != nil {
		scraper, err := scaling.NewDatapathScraper(scaling.DatapathConfig{
			Source: cfg.flows, Metrics: cfg.metrics, Logger: logger,
		})
		if err != nil {
			logger.Error("cannot start the east-west metrics scrape", "error", err)
		} else {
			go scraper.Run(ctx, cfg.interval)
			logger.Info("scraping east-west metrics from the datapath", "interval", cfg.interval)
		}
	} else {
		logger.Info("east-west metrics are disabled",
			"detail", "the netns network mode has no datapath counters; "+
				"flows_per_second and drops_per_second rules will never fire")
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
	// Cooldowns survive the restart (v1.37); the metrics rings deliberately do
	// not, and for the first stabilization window the evaluator refuses to
	// scale down on the history it therefore does not have.
	seedCooldowns(ctx, cfg.store, evaluator, logger)
	loop, err := scaling.NewLoop(scaling.LoopConfig{
		Evaluator: evaluator,
		Fleet:     storeFleet{store: cfg.store, notify: cfg.notify, emit: cfg.emit, log: logger},
		Breaker:   cfg.breaker,
		Logger:    logger,
	})
	if err != nil {
		logger.Error("cannot start the autoscaler", "error", err)
		return
	}
	go loop.Run(ctx)
	logger.Info("autoscaling enabled", "interval", scaling.DefaultEvaluationInterval)
}
