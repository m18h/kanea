package api

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/scaling"
	"github.com/m18h/kanea/internal/store"
)

// emitFunc delivers one payload to a subscriber.
type emitFunc func(payload any)

// feedFunc runs a subscription until its context is cancelled.
type feedFunc func(ctx context.Context, emit emitFunc)

// FeedInterval is how often a Store-backed feed looks for changes.
//
// Polling the Store rather than being notified by it: the Store has no change
// stream yet (that is the CDC replicator, §15.3, M10), and adding one just for
// the dashboard would be a second source of truth for "what changed". A second
// is well inside what a human watching a page notices, and the poll is a
// bounded, paginated read — the shape §5.2.2 requires.
const FeedInterval = time.Second

// feedFor resolves a subscription request to the feed that serves it.
func (s *Server) feedFor(frame ClientFrame) (feedFunc, error) {
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
		return s.feedStats(frame), nil
	default:
		return nil, fmt.Errorf("api: unknown topic %q", frame.Topic)
	}
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
}

// AllocStats is one alloc's resource use.
type AllocStats struct {
	AllocID     string   `json:"alloc_id"`
	CPU         *float64 `json:"cpu,omitempty"`
	Memory      *float64 `json:"memory,omitempty"`
	MemoryBytes *float64 `json:"memory_bytes,omitempty"`
}

// feedStats streams live samples for one service.
func (s *Server) feedStats(frame ClientFrame) feedFunc {
	service := frame.Project + "/" + frame.Service

	return func(ctx context.Context, emit emitFunc) {
		// Sampled on the scrape interval rather than the Store's poll: these
		// numbers change every five seconds by construction, and emitting more
		// often would send the same values repeatedly.
		ticker := time.NewTicker(scaling.RawInterval)
		defer ticker.Stop()

		emit(s.statsFor(ctx, service))
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

// statsFor gathers one sample for a service and its allocs.
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
	allocs, err := listAll[reconciler.AllocRecord](ctx, s.store, store.KindAlloc)
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
		return ServicesResponse{Services: services}, nil
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
// full comparison. It over-sends — an unrelated alloc write re-sends the service
// list — which is the right trade at this scale and stops being one only when
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

// feedLogs follows one service's logs.
func (s *Server) feedLogs(frame ClientFrame) feedFunc {
	return func(ctx context.Context, emit emitFunc) {
		opts := LogOptions{
			Project: frame.Project,
			Service: frame.Service,
			Tail:    frame.Tail,
			Follow:  true,
		}
		allocs, err := s.selectAllocs(ctx, opts)
		if err != nil {
			s.log.Warn("log feed: cannot select allocs",
				"service", frame.Project+"/"+frame.Service, "error", err)
			return
		}

		tails := make([]*tailer, 0, len(allocs))
		defer func() {
			for _, t := range tails {
				if err := t.Close(); err != nil {
					s.log.Debug("close log tailer", "alloc", t.allocID, "error", err)
				}
			}
		}()

		for _, alloc := range allocs {
			path := filepath.Join(s.logDir, alloc.ID+".log")
			// prefix=false: the alloc id travels in the frame, so the dashboard
			// can attribute a line without parsing it back out of the text.
			t, err := newTailer(path, alloc.ID, opts.Tail, false)
			if err != nil {
				// Normal for an alloc that has not started yet.
				s.log.Debug("no log file", "alloc", alloc.ID, "error", err)
				continue
			}
			tails = append(tails, t)
		}
		if len(tails) == 0 {
			return
		}

		// One writer per tailer: the split state (a line straddling two reads)
		// belongs to that file, not to the loop.
		writers := make([]*lineWriter, len(tails))
		for i, t := range tails {
			allocID := t.allocID
			writers[i] = &lineWriter{emit: func(line string) {
				emit(LogLine{AllocID: allocID, Line: line})
			}}
		}

		ticker := time.NewTicker(PollInterval)
		defer ticker.Stop()
		for {
			for i, t := range tails {
				if _, err := t.copyTo(writers[i]); err != nil {
					s.log.Debug("read log", "alloc", t.allocID, "error", err)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
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
// no newline — a stack trace, a progress bar, a hostile one — must not grow
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
