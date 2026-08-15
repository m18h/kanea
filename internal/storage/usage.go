package storage

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m18h/kanea/internal/notify"
)

// Measuring what a volume actually uses (PRD v1.69, §8, §6.2 R31).
//
// R31's `size` is a budget, not a quota — nothing enforces it — so the whole
// value of declaring one is that the number gets compared against reality. That
// is this file: a slow background walk, an in-memory result, and an event when
// a volume crosses its budget in either direction.
//
// Three constraints shape it, and none of them is negotiable:
//
//   - It never touches the Store (constraint #2). Usage is a metric, and
//     metrics live in memory.
//   - It never runs on a request path. A walk over a large media directory
//     takes minutes, and `GET /v1/volumes` has to answer now.
//   - It reports absence as absence (§9.2). A volume not yet measured, one
//     whose walk timed out, and one on a driver that is not walked are all
//     gaps — never zero, which would read as "empty" and is a completely
//     different fact.

// UsageTarget is one volume to measure.
type UsageTarget struct {
	// Key identifies the volume across passes. The reconciler builds it from
	// project/service/volume, so a redeployed service keeps its history.
	Key string
	// Project, Service and Volume name it, for the event.
	Project string
	Service string
	Volume  string
	// Path is the host directory to walk.
	Path string
	// Type is the storage driver, which decides whether it is walked at all.
	Type string
	// BudgetBytes is R31's declared size, or 0 for none. A target with no
	// budget is still measured — the number is worth showing on its own.
	BudgetBytes int64
}

// measurable reports whether this target's usage can honestly be sampled.
//
// s3 is excluded by name. A walk over a FUSE object-store mount is a LIST per
// directory: it would time out every cycle, and it would spend real money to
// produce a number that timed out.
func (t UsageTarget) measurable() bool {
	return t.Path != "" && t.Type != TypeS3
}

// Usage is one volume's measured size.
type Usage struct {
	// Bytes is the volume's own usage. Meaningful only when Known.
	Bytes int64
	// At is when it was measured.
	At time.Time
	// Known is false until a walk has succeeded. False is not "empty": it is
	// "nobody has looked yet", or "the walk did not come back".
	Known bool
	// Err is why the last attempt failed, when it did.
	Err string
}

// UsageConfig configures the sampler.
type UsageConfig struct {
	// Runner executes the measurement. Nil uses the real one.
	Runner Runner
	// Interval is how often every target is re-measured. A budget is not a
	// metric anyone watches by the second, and the walk is the expensive part.
	Interval time.Duration
	// Timeout bounds one measurement.
	Timeout time.Duration
	// Emit publishes events (§11). Nil disables them, exactly as it does for
	// the reconciler.
	Emit func(notify.Event)
	// Now is injectable for tests.
	Now    func() time.Time
	Logger *slog.Logger
}

// Sampler defaults. The interval is deliberately slow: a walk costs real I/O,
// and a budget that is checked every five minutes is checked often enough to
// act on and rarely enough not to be felt.
const (
	DefaultUsageInterval = 5 * time.Minute
	DefaultUsageTimeout  = 2 * time.Minute
)

// UsageSampler measures volumes in the background.
type UsageSampler struct {
	cfg     UsageConfig
	targets atomic.Pointer[[]UsageTarget]

	mu sync.RWMutex
	// usage is the latest reading per key.
	usage map[string]Usage
	// overBudget records the last verdict per key, so an event fires on the
	// transition rather than once per sample. A breached budget persists for
	// hours; an event per pass would be a notification every interval, forever.
	overBudget map[string]bool
}

// NewUsageSampler builds a sampler. It measures nothing until Run is called.
func NewUsageSampler(cfg UsageConfig) *UsageSampler {
	if cfg.Runner == nil {
		cfg.Runner = execRunner{}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultUsageInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultUsageTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	s := &UsageSampler{
		cfg:        cfg,
		usage:      map[string]Usage{},
		overBudget: map[string]bool{},
	}
	s.targets.Store(&[]UsageTarget{})
	return s
}

// SetTargets replaces the set of volumes being measured.
//
// Latest-wins behind an atomic pointer, the shape the notification dispatcher's
// SetRoutes uses (PRD v1.46): the reconciler pulses it every pass, and a pass
// that changed nothing costs one pointer store.
func (s *UsageSampler) SetTargets(targets []UsageTarget) {
	next := append([]UsageTarget(nil), targets...)
	sort.Slice(next, func(i, j int) bool { return next[i].Key < next[j].Key })
	s.targets.Store(&next)

	// Forget volumes that are gone, so a deleted service does not keep a
	// reading — or an over-budget verdict that would re-fire if its name were
	// ever reused.
	live := make(map[string]struct{}, len(next))
	for _, t := range next {
		live[t.Key] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.usage {
		if _, ok := live[key]; !ok {
			delete(s.usage, key)
			delete(s.overBudget, key)
		}
	}
}

// Snapshot returns the latest readings, keyed by target key.
func (s *UsageSampler) Snapshot() map[string]Usage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Usage, len(s.usage))
	for k, v := range s.usage {
		out[k] = v
	}
	return out
}

// Run measures every target on the configured interval until ctx is done.
//
// The first pass happens immediately: waiting a full interval would mean a
// freshly started node reports every volume as unmeasured for five minutes,
// which reads like something is broken.
func (s *UsageSampler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	s.measureAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.measureAll(ctx)
		}
	}
}

// measureAll walks every measurable target once, in sequence.
//
// Sequentially on purpose: these are disk walks, and running them in parallel
// turns a background housekeeping task into an I/O storm competing with the
// workloads it is measuring.
func (s *UsageSampler) measureAll(ctx context.Context) {
	for _, t := range *s.targets.Load() {
		if ctx.Err() != nil {
			return
		}
		if !t.measurable() {
			continue
		}
		s.record(t, s.measure(ctx, t))
	}
}

// measure runs one measurement, bounded by the timeout.
func (s *UsageSampler) measure(ctx context.Context, t UsageTarget) Usage {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	// -s totals, -x stays on one filesystem so a volume containing another
	// mount does not report that mount's contents as its own, and -B1 asks for
	// bytes rather than the block count the default would give.
	out, err := s.cfg.Runner.Run(ctx, "du", "-s", "-x", "-B", "1", t.Path)
	if err != nil {
		return Usage{At: s.cfg.Now(), Err: strings.TrimSpace(string(out))}
	}
	bytes, err := parseDuTotal(string(out))
	if err != nil {
		return Usage{At: s.cfg.Now(), Err: err.Error()}
	}
	return Usage{Bytes: bytes, At: s.cfg.Now(), Known: true}
}

// record stores a reading and fires the budget event on a transition.
func (s *UsageSampler) record(t UsageTarget, u Usage) {
	s.mu.Lock()
	s.usage[t.Key] = u
	was := s.overBudget[t.Key]
	// An unmeasured volume has no verdict. Treating a failed walk as
	// "under budget" would clear a real breach with an absence, which is the
	// §9.2 mistake wearing a notification's clothes.
	if !u.Known || t.BudgetBytes <= 0 {
		s.mu.Unlock()
		if !u.Known && u.Err != "" {
			s.cfg.Logger.Warn("cannot measure volume usage",
				"project", t.Project, "service", t.Service, "volume", t.Volume,
				"path", t.Path, "error", u.Err)
		}
		return
	}
	now := u.Bytes > t.BudgetBytes
	s.overBudget[t.Key] = now
	s.mu.Unlock()

	if now == was || s.cfg.Emit == nil {
		return
	}
	name, verb := notify.EventVolumeUnderBudget, "is back under"
	if now {
		name, verb = notify.EventVolumeOverBudget, "is over"
	}
	s.cfg.Emit(notify.NewEvent(name, t.Project, t.Service,
		fmt.Sprintf("volume %s %s its budget: %s of %s",
			t.Volume, verb, HumanBytes(u.Bytes), HumanBytes(t.BudgetBytes)),
		u.At).WithDetail(t.Path))
}

// parseDuTotal reads the byte count out of `du -s` output, which is
// "<bytes>\t<path>" — possibly preceded by warnings on stderr, which the
// Runner combines in.
func parseDuTotal(out string) (int64, error) {
	var last string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) != "" {
			last = line
		}
	}
	fields := strings.Fields(last)
	if len(fields) == 0 {
		return 0, fmt.Errorf("du produced no output")
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("du reported %q, which is not a byte count", fields[0])
	}
	return n, nil
}

// HumanBytes renders a byte count in the largest unit that stays readable. It
// is exported because the CLI and the events should word a size identically.
func HumanBytes(n int64) string {
	const unit = 1024
	switch {
	case n < unit:
		return fmt.Sprintf("%d B", n)
	case n < unit*unit:
		return fmt.Sprintf("%.1f KiB", float64(n)/unit)
	case n < unit*unit*unit:
		return fmt.Sprintf("%.1f MiB", float64(n)/(unit*unit))
	case n < unit*unit*unit*unit:
		return fmt.Sprintf("%.1f GiB", float64(n)/(unit*unit*unit))
	default:
		return fmt.Sprintf("%.1f TiB", float64(n)/(unit*unit*unit*unit))
	}
}
