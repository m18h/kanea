package api

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/scaling"
	"github.com/m18h/kanea/internal/store"
)

// emitFunc delivers one payload to a subscriber. It reports whether the payload
// was queued.
//
// The return value exists for the lossy topics (PRD v1.70, §12.1): a feed whose
// frames may be dropped is the only thing that can account for what it lost, so
// it has to be told. Feeds on the snapshot topics ignore it: a full buffer
// there still closes the connection, so there is nothing to account for.
type emitFunc func(payload any) bool

// feedFunc runs a subscription until its context is cancelled.
type feedFunc func(ctx context.Context, emit emitFunc)

// FeedInterval is how often a Store-backed feed looks for changes.
//
// Polling the Store rather than being notified by it: the Store has no change
// stream yet (that is the CDC replicator, §15.3), and adding one just for
// the dashboard would be a second source of truth for "what changed". A second
// is well inside what a human watching a page notices, and the poll is a
// bounded, paginated read: the shape §5.2.2 requires.
const FeedInterval = time.Second

// budgetFunc reports whether a seed of this many points may be sent. It is the
// session's, because the budget is a per-connection resource like the
// subscription cap; a feed only asks.
type budgetFunc func(points int) bool

// feedFor resolves a subscription request to the feed that serves it.
func (s *Server) feedFor(frame ClientFrame, budget budgetFunc) (feedFunc, error) {
	switch frame.Topic {
	case TopicServices:
		return s.feedServices, nil
	case TopicAllocs:
		return s.feedAllocs, nil
	case TopicLogs:
		if frame.Project == "" || frame.Service == "" {
			return nil, fmt.Errorf("api: the %s topic needs a project and a service", TopicLogs)
		}
		return s.feedLogs(frame), nil
	case TopicStats:
		if s.metrics == nil {
			return nil, fmt.Errorf("api: the %s topic needs the metrics pipeline", TopicStats)
		}
		if frame.Project == "" || frame.Service == "" {
			return nil, fmt.Errorf("api: the %s topic needs a project and a service", TopicStats)
		}
		if err := s.checkSeedRequest(frame, "service"); err != nil {
			return nil, err
		}
		return s.feedStats(frame, budget), nil
	case TopicNode:
		if s.metrics == nil {
			return nil, fmt.Errorf("api: the %s topic needs the metrics pipeline", TopicNode)
		}
		if frame.Project != "" || frame.Service != "" {
			return nil, fmt.Errorf(
				"api: the %s topic is the node's own; it takes no project or service", TopicNode)
		}
		if err := s.checkSeedRequest(frame, "node"); err != nil {
			return nil, err
		}
		return s.feedNode(frame, budget), nil
	default:
		return nil, fmt.Errorf("api: unknown topic %q", frame.Topic)
	}
}

// checkSeedRequest refuses a malformed seed request at subscribe time.
//
// At subscribe rather than at the first emit, so a typo answers with an error
// frame naming it instead of a subscription that quietly seeds nothing: the
// same reason the REST route refuses an unknown series by name.
func (s *Server) checkSeedRequest(frame ClientFrame, view string) error {
	if !frame.History {
		return nil
	}
	if frame.HistoryWindow != "" {
		if _, err := time.ParseDuration(frame.HistoryWindow); err != nil {
			return fmt.Errorf("api: history_window is not a duration")
		}
	}
	known := func(n string) bool { _, ok := nodeSeries[n]; return ok }
	fallback := defaultNodeSeries
	if view == "service" {
		known = func(n string) bool { _, ok := serviceSeries[n]; return ok }
		fallback = defaultServiceSeries
	}
	_, err := resolveSeries(frame.HistorySeries, fallback, known, view)
	return err
}

// seedRequestFrom turns a subscribe frame into a seed request.
func seedRequestFrom(frame ClientFrame) seedRequest {
	window := defaultHistoryWindow
	if frame.HistoryWindow != "" {
		if parsed, err := time.ParseDuration(frame.HistoryWindow); err == nil {
			window = parsed
		}
	}
	return seedRequest{
		window: clampWindow(window),
		series: frame.HistorySeries,
		allocs: frame.HistoryAllocs,
	}
}

// seedFor builds a subscription's seed, or reports that the budget refused it.
//
// A build error cannot happen here (the request was validated at subscribe) but
// is treated as "no seed" rather than as a failure: the live samples are the
// point of the subscription and a seed is an optimisation on top of them.
func (s *Server) seedFor(ctx context.Context, subject string, frame ClientFrame, budget budgetFunc) (*StatsHistorySeed, bool) {
	if !frame.History {
		return nil, false
	}
	seed, err := s.buildSeed(ctx, subject, seedRequestFrom(frame))
	if err != nil || seed == nil {
		if err != nil {
			s.log.Debug("cannot build a history seed", "subject", subject, "error", err)
		}
		return nil, false
	}

	points := countPoints(seed.HistoryBlock)
	for _, block := range seed.Allocs {
		points += countPoints(block)
	}
	if budget != nil && !budget(points) {
		return nil, true
	}
	return seed, false
}

// StatsSample is one service's live numbers.
//
// Sent whole rather than as a stream of individual points: a dashboard drawing
// four series wants them from the same instant, and reassembling that from
// interleaved single-metric frames is work every client would have to repeat.
type StatsSample struct {
	Service string    `json:"service"`
	At      time.Time `json:"at"`
	// Service-level values. Absent when the metric has nothing recent, which a
	// chart draws as a gap rather than as a zero.
	CPU    *float64 `json:"cpu,omitempty"`
	Memory *float64 `json:"memory,omitempty"`
	RPS    *float64 `json:"rps,omitempty"`
	P95    *float64 `json:"p95_latency_ms,omitempty"`
	// Allocs carries the per-alloc breakdown the service detail page shows.
	Allocs []AllocStats `json:"allocs,omitempty"`
	// Edge carries the labelled totals from kanea-edge (§9.1.1): the status
	// code split and the bytes moved. Absent when the edge has not been
	// scraped or the service is not exposed, which is a different fact from a
	// service that has served nothing.
	Edge *scaling.ServiceBreakdown `json:"edge,omitempty"`
	// History is the seed (v1.79), on the FIRST frame of a subscription that
	// asked for one and absent on every frame after it. That placement is what
	// keeps §12.1's rule true: a frame is still a superset of the one it
	// supersedes, so a client merges the seed under its live samples rather
	// than replacing its state per frame.
	History *StatsHistorySeed `json:"history,omitempty"`
	// HistoryOmitted says a requested seed was refused by the session's budget
	// rather than being empty. A chart that starts blank should be able to say
	// why: §9.2's distinction, applied to the seed itself.
	HistoryOmitted bool `json:"history_omitted,omitempty"`
}

// AllocStats is one alloc's resource use.
type AllocStats struct {
	AllocID     string   `json:"alloc_id"`
	CPU         *float64 `json:"cpu,omitempty"`
	Memory      *float64 `json:"memory,omitempty"`
	MemoryBytes *float64 `json:"memory_bytes,omitempty"`
}

// feedStats streams live samples for one service.
func (s *Server) feedStats(frame ClientFrame, budget budgetFunc) feedFunc {
	service := frame.Project + "/" + frame.Service

	return func(ctx context.Context, emit emitFunc) {
		// Sampled on the scrape interval rather than the Store's poll: these
		// numbers change every five seconds by construction, and emitting more
		// often would send the same values repeatedly.
		ticker := time.NewTicker(scaling.RawInterval)
		defer ticker.Stop()

		// The seed rides the first frame and no frame after it (v1.79): built
		// once, here, rather than per tick.
		first := s.statsFor(ctx, service)
		first.History, first.HistoryOmitted = s.seedFor(ctx, service, frame, budget)
		emit(first)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				emit(s.statsFor(ctx, service))
			}
		}
	}
}

// NodeSample is what the node topic pushes: the same body GET /v1/stats serves,
// plus the seed.
//
// Embedded rather than duplicated so the REST route and the feed cannot drift
// about what a node summary is, and so a client parses both with one schema.
type NodeSample struct {
	NodeStats
	History        *StatsHistorySeed `json:"history,omitempty"`
	HistoryOmitted bool              `json:"history_omitted,omitempty"`
}

// feedNode streams the node's own summary and machine statistics.
//
// It exists so the Overview stops polling GET /v1/stats every ten seconds
// beside a socket it was already holding (v1.79), and so those charts can be
// seeded like every other.
func (s *Server) feedNode(frame ClientFrame, budget budgetFunc) feedFunc {
	return func(ctx context.Context, emit emitFunc) {
		ticker := time.NewTicker(scaling.RawInterval)
		defer ticker.Stop()

		sample := func() NodeSample {
			stats, err := s.nodeStats(ctx)
			if err != nil {
				s.log.Debug("node feed: cannot read node stats", "error", err)
				return NodeSample{}
			}
			return NodeSample{NodeStats: stats}
		}

		first := sample()
		first.History, first.HistoryOmitted = s.seedFor(ctx, scaling.NodeSubject, frame, budget)
		emit(first)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				emit(sample())
			}
		}
	}
}

// statsFor gathers one sample for a service and its allocs.
// allocsAtCurrentIndex lists alloc records, cached per store index (K-18):
// every stats subscriber asks every interval, and the answer cannot change
// without a write moving the index, so a miss recomputes and a hit serves the
// same slice to every asker.
func (s *Server) allocsAtCurrentIndex(ctx context.Context) ([]reconciler.AllocRecord, error) {
	index, err := s.store.Index(ctx)
	if err != nil {
		return nil, err
	}

	s.allocCache.mu.Lock()
	defer s.allocCache.mu.Unlock()
	if s.allocCache.valid && s.allocCache.index == index {
		return s.allocCache.allocs, nil
	}
	allocs, err := listAll[reconciler.AllocRecord](ctx, s.store, store.KindAlloc)
	if err != nil {
		return nil, err
	}
	s.allocCache.index = index
	s.allocCache.allocs = allocs
	s.allocCache.valid = true
	return allocs, nil
}

func (s *Server) statsFor(ctx context.Context, service string) StatsSample {
	sample := StatsSample{Service: service, At: time.Now()}
	sample.CPU = s.latestValue(service, scaling.MetricCPU)
	sample.Memory = s.latestValue(service, scaling.MetricMemory)
	sample.RPS = s.latestValue(service, scaling.MetricRPS)
	sample.P95 = s.latestValue(service, scaling.MetricP95)

	// Not gated on metricStaleAfter, unlike the gauges above. Those are rates
	// this process derived and a stale one is a wrong answer; these are the
	// edge's own cumulative counters, and the last known total is still the
	// last known total.
	if s.edgeMetrics != nil {
		if breakdown, ok := s.edgeMetrics.Breakdown(service); ok {
			sample.Edge = &breakdown
		}
	}

	// The alloc list comes from the Store rather than from the metric subjects:
	// an alloc that started a second ago has a record and no samples yet, and
	// leaving it out of the table would make it look like it does not exist.
	// Cached per store index (K-18): a stats feed asks every interval per
	// subscriber, and a full alloc listing is the same answer until a write
	// moves the index.
	allocs, err := s.allocsAtCurrentIndex(ctx)
	if err != nil {
		s.log.Debug("stats feed: cannot list allocs", "error", err)
		return sample
	}
	for _, alloc := range allocs {
		if alloc.Project+"/"+alloc.Service != service {
			continue
		}
		subject := service + "/" + alloc.ID
		sample.Allocs = append(sample.Allocs, AllocStats{
			AllocID:     alloc.ID,
			CPU:         s.latestValue(subject, scaling.MetricCPU),
			Memory:      s.latestValue(subject, scaling.MetricMemory),
			MemoryBytes: s.latestValue(subject, scaling.MetricMemoryBytes),
		})
	}
	return sample
}

// latestValue reads one current metric, or nil when there is nothing recent.
//
// A pointer rather than a zero: "no data" and "zero" are different facts, and a
// chart that draws them the same way tells an operator a stopped scraper is an
// idle service.
func (s *Server) latestValue(subject, metric string) *float64 {
	point, ok := s.metrics.Latest(scaling.Key{Subject: subject, Metric: metric})
	if !ok || time.Since(point.At) > metricStaleAfter {
		return nil
	}
	value := point.Value
	return &value
}

// feedServices streams the desired-state set whenever it changes.
func (s *Server) feedServices(ctx context.Context, emit emitFunc) {
	s.feedStoreKind(ctx, emit, func(ctx context.Context) (any, error) {
		services, err := listAll[reconciler.Desired](ctx, s.store, store.KindService)
		if err != nil {
			return nil, err
		}
		return ServicesResponse{Services: serviceViews(services)}, nil
	})
}

// feedAllocs streams alloc records whenever they change.
func (s *Server) feedAllocs(ctx context.Context, emit emitFunc) {
	s.feedStoreKind(ctx, emit, func(ctx context.Context) (any, error) {
		allocs, err := listAll[reconciler.AllocRecord](ctx, s.store, store.KindAlloc)
		if err != nil {
			return nil, err
		}
		return AllocsResponse{Allocs: allocs}, nil
	})
}

// feedStoreKind sends a snapshot immediately, then again whenever the Store's
// index moves.
//
// Gating on the index rather than diffing: every mutation bumps it (§15.2), so
// it is a cheap, exact "has anything changed" that costs one read instead of a
// full comparison. It over-sends (an unrelated alloc write re-sends the service
// list) which is the right trade at this scale and stops being one only when
// the payload is large enough to notice.
func (s *Server) feedStoreKind(ctx context.Context, emit emitFunc,
	snapshot func(context.Context) (any, error),
) {
	send := func() uint64 {
		index, err := s.store.Index(ctx)
		if err != nil {
			s.log.Debug("feed: cannot read store index", "error", err)
			return 0
		}
		payload, err := snapshot(ctx)
		if err != nil {
			s.log.Warn("feed: cannot read snapshot", "error", err)
			return 0
		}
		emit(payload)
		return index
	}

	last := send()

	ticker := time.NewTicker(FeedInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		index, err := s.store.Index(ctx)
		if err != nil {
			s.log.Debug("feed: cannot read store index", "error", err)
			continue
		}
		if index == last {
			continue
		}
		last = send()
	}
}

// LogLine is one workload log line as the dashboard receives it.
//
// Text, never markup. The dashboard renders it escaped and never through
// dangerouslySetInnerHTML (PRD §14, A03): workload output is attacker-controlled
// whenever the workload is, and a log viewer that interprets it is an XSS hole
// with extra steps.
type LogLine struct {
	AllocID string `json:"alloc_id"`
	Line    string `json:"line"`
}

// LogBatch is one poll tick's worth of log lines for a subscription.
//
// One frame per tick rather than one per line (PRD v1.70). Per line, a 200-line
// tail is 200 frames into a 64-slot send buffer, which is a closed connection
// before the panel has painted, and it closed the whole multiplexed socket,
// taking every other topic with it. Batching bounds the frame count at the tick
// rate whatever the workload writes, at a cost of at most one PollInterval of
// latency.
type LogBatch struct {
	// Lines is never empty: a tick that produced nothing emits no frame.
	Lines []LogLine `json:"lines"`
	// Dropped counts lines this subscription will never deliver: trimmed by
	// the per-frame cap, clamped off an oversized tail request, or lost with a
	// frame the send buffer refused. It rides in the frame so the gap is
	// visible where the gap is, rather than in a number elsewhere that nobody
	// correlates. Absent when zero, so the ordinary frame is unchanged.
	Dropped int `json:"dropped,omitempty"`
}

// Bounds on one log frame and one subscription's history.
const (
	// maxBatchLines and maxBatchBytes bound a single frame. Without them,
	// batching trades an unbounded frame *count* for an unbounded frame *size*:
	// one line may be maxLineBytes (64 KiB), so a thousand-line frame could be
	// 64 MiB; allocated per tick, per subscriber, on a write with a timeout.
	// The byte bound is the load-bearing one; the line bound keeps a chatty but
	// terse workload from building an equally large frame out of small lines.
	// Both are measured over the raw line bytes rather than the encoded JSON:
	// escaping can expand a line, so the bound holds within a constant factor,
	// and a factor is all this needs; the difference it exists to prevent is
	// 256 KiB against 64 MiB.
	maxBatchLines = 1000
	maxBatchBytes = 256 << 10
	// maxTailLines bounds the history one subscription may ask for. A cost
	// bound before it is a frame bound: seekToLastLines reads the file
	// *backwards* to satisfy it, and §17 caps a service's logs at 100 MiB, so
	// an unbounded tail is a 100 MiB backwards scan whose result the frame cap
	// would discard anyway. Clamped rather than refused (a refusal blanks the
	// panel) and the clamp is not silent: what it removed is counted into the
	// first batch's Dropped like any other gap. The REST log route keeps its
	// unbounded tail; it is a plain stream with no queue behind it.
	maxTailLines = 1000
)

// feedLogs follows one service's logs.
func (s *Server) feedLogs(frame ClientFrame) feedFunc {
	return func(ctx context.Context, emit emitFunc) {
		tail := frame.Tail
		clamped := 0
		if tail > maxTailLines {
			clamped = tail - maxTailLines
			tail = maxTailLines
		}
		opts := LogOptions{
			Project: frame.Project,
			Service: frame.Service,
			Tail:    tail,
			Follow:  true,
		}

		f := &logFollower{
			server:  s,
			opts:    opts,
			tail:    tail,
			service: frame.Project + "/" + frame.Service,
			tails:   map[string]*tailer{},
			// Whatever the tail clamp removed is a gap like any other, and it
			// belongs to the first frame this subscription sends.
			carry: clamped,
		}
		defer f.closeAll()

		ticker := time.NewTicker(PollInterval)
		defer ticker.Stop()
		for {
			f.resync(ctx)
			f.drain()
			f.flush(emit)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
}

// logFollower holds one log subscription's tailers and its pending batch.
//
// The tailers are a map rather than a slice because the set changes: allocs
// come and go with every deploy, restart and scale-up, and choosing them once
// at subscribe is what used to leave a live subscription streaming nothing
// after any of those, with no error and an open socket (PRD v1.70).
type logFollower struct {
	server  *Server
	opts    LogOptions
	tail    int
	service string

	tails map[string]*tailer
	// writers hold the split state for a line straddling two reads, which
	// belongs to a file rather than to the loop, so it is keyed like the
	// tailers and torn down with them.
	writers map[string]*lineWriter

	// lastIndex is the Store index the alloc set was last resolved at, and
	// nextResync is the earliest the next attempt may happen. Two gates rather
	// than one: the index is what says anything *could* have changed, but it
	// moves on any write to any kind, so on a busy node it would authorise a
	// full alloc listing on every 250 ms tick, per subscriber. The interval
	// bounds that to the rate the Store-backed feeds already poll at. Zero
	// values mean the first pass always resolves.
	lastIndex  uint64
	nextResync time.Time
	resolved   bool

	batch LogBatch
	bytes int
	// carry counts lines lost with a frame that was itself refused, plus
	// anything the tail clamp removed. A count, never a queue: holding the
	// lines would be the unbounded daemon-side buffer §17 forbids.
	carry int
}

// resync brings the tailer set in line with the allocs the service has now.
//
// Gated on the Store index having moved (the pattern feedStoreKind uses) plus
// an unconditional retry whenever nothing is being tailed. The retry is the case
// the index gate cannot see: the alloc record exists and its log file does not
// yet, which is every alloc for the moment between creation and its first write.
func (f *logFollower) resync(ctx context.Context) {
	now := time.Now()
	if f.resolved && now.Before(f.nextResync) {
		return
	}
	f.nextResync = now.Add(FeedInterval)

	index, err := f.server.store.Index(ctx)
	if err != nil {
		// An unreadable index is not a reason to stop tailing what is already
		// open; the next pass asks again.
		f.server.log.Debug("log feed: cannot read store index", "error", err)
		if f.resolved && len(f.tails) > 0 {
			return
		}
	} else if f.resolved && index == f.lastIndex && len(f.tails) > 0 {
		return
	}
	f.lastIndex = index

	allocs, err := f.server.selectAllocs(ctx, f.opts)
	if err != nil {
		f.server.log.Warn("log feed: cannot select allocs", "service", f.service, "error", err)
		return
	}
	f.resolved = true

	wanted := make(map[string]struct{}, len(allocs))
	for _, alloc := range allocs {
		wanted[alloc.ID] = struct{}{}
		if _, ok := f.tails[alloc.ID]; ok {
			continue
		}
		path, err := logPathFor(f.server.logDir, alloc.ID)
		if err != nil {
			// Same refusal as the REST tail: a traversal-shaped ID in the
			// Store is skipped, never read outside the log directory.
			f.server.log.Warn("refusing log path", "alloc", alloc.ID, "error", err)
			continue
		}
		// prefix=false: the alloc id travels in the frame, so the dashboard can
		// attribute a line without parsing it back out of the text.
		//
		// A late-arriving alloc opens at the subscription's own tail rather than
		// at end-of-file: a freshly started alloc's file is usually shorter than
		// that anyway, and after a restart the recent output is exactly what
		// someone watching a crash loop wants. Only safe because the batch caps
		// above bound what that can turn into.
		t, err := newTailer(path, alloc.ID, f.tail, false)
		if err != nil {
			// Normal for an alloc that has not written anything yet; the next
			// pass tries again.
			f.server.log.Debug("no log file", "alloc", alloc.ID, "error", err)
			continue
		}
		f.add(t)
	}

	for id, t := range f.tails {
		if _, ok := wanted[id]; ok {
			continue
		}
		// Closing is what releases the descriptor: the deferred sweep only runs
		// when the whole subscription ends, and a long-lived page watching a
		// service that redeploys would otherwise accumulate one fd per alloc.
		if err := t.Close(); err != nil {
			f.server.log.Debug("close log tailer", "alloc", id, "error", err)
		}
		delete(f.tails, id)
		delete(f.writers, id)
	}
}

// add registers a tailer and the line writer that accumulates its output.
func (f *logFollower) add(t *tailer) {
	if f.writers == nil {
		f.writers = map[string]*lineWriter{}
	}
	allocID := t.allocID
	f.tails[allocID] = t
	f.writers[allocID] = &lineWriter{emit: func(line string) {
		f.append(LogLine{AllocID: allocID, Line: line})
	}}
}

// append adds a line to the pending batch, dropping the oldest past the caps.
//
// Oldest-first is the end the client's own buffer trims, so the two agree on
// which lines survive; and the batch always keeps at least one line, even one
// over the byte cap, or a workload writing megabytes without a newline stalls
// the stream forever while the drop count climbs.
func (f *logFollower) append(line LogLine) {
	f.batch.Lines = append(f.batch.Lines, line)
	f.bytes += len(line.Line)
	for len(f.batch.Lines) > 1 && (len(f.batch.Lines) > maxBatchLines || f.bytes > maxBatchBytes) {
		f.bytes -= len(f.batch.Lines[0].Line)
		f.batch.Lines = f.batch.Lines[1:]
		f.batch.Dropped++
	}
}

// drain reads whatever each tailer has produced since the last tick.
func (f *logFollower) drain() {
	for id, t := range f.tails {
		if _, err := t.copyTo(f.writers[id]); err != nil {
			f.server.log.Debug("read log", "alloc", id, "error", err)
		}
	}
}

// flush sends the tick's batch, if there is anything to say.
func (f *logFollower) flush(emit emitFunc) {
	if len(f.batch.Lines) == 0 {
		// A drop with no lines to carry it has to wait: a frame with no lines
		// would be a gap reported against nothing.
		return
	}
	f.batch.Dropped += f.carry
	if emit(f.batch) {
		f.carry = 0
	} else {
		// The frame reached nobody, so everything in it is a gap the next one
		// reports. A count, never a queue.
		f.carry = len(f.batch.Lines) + f.batch.Dropped
	}
	f.batch = LogBatch{}
	f.bytes = 0
}

// closeAll releases every tailer the subscription holds.
func (f *logFollower) closeAll() {
	for id, t := range f.tails {
		if err := t.Close(); err != nil {
			f.server.log.Debug("close log tailer", "alloc", id, "error", err)
		}
	}
}

// lineWriter turns the tailer's byte stream into whole lines.
//
// A read can end mid-line, so the remainder is held until the rest arrives.
// Emitting a partial line would show the dashboard a truncated message and then
// a fragment, which reads as corruption rather than as buffering.
type lineWriter struct {
	emit    func(line string)
	partial []byte
}

// maxLineBytes bounds an unterminated line. A workload writing megabytes with
// no newline (a stack trace, a progress bar, a hostile one) must not grow
// this buffer without limit, so it is flushed as-is at the cap.
const maxLineBytes = 64 << 10

func (w *lineWriter) Write(data []byte) (int, error) {
	w.partial = append(w.partial, data...)
	for {
		idx := bytes.IndexByte(w.partial, '\n')
		if idx < 0 {
			break
		}
		w.emit(strings.TrimRight(string(w.partial[:idx]), "\r"))
		w.partial = w.partial[idx+1:]
	}
	if len(w.partial) > maxLineBytes {
		w.emit(string(w.partial))
		w.partial = nil
	}
	return len(data), nil
}
