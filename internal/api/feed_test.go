package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/store"
)

// seedAlloc puts one alloc record in the Store so the log feed can select it.
//
// The index matters: AllocRecord.Key is (project, service, index), so two allocs
// seeded without distinct ones are one record written twice.
func seedAlloc(t *testing.T, h *harness, project, service string, index int) reconciler.AllocRecord {
	t.Helper()
	rec := reconciler.AllocRecord{
		ID:      fmt.Sprintf("%s-%s-%d", project, service, index),
		Project: project, Service: service, Index: index,
		State: reconciler.AllocRunning,
	}
	if _, err := store.PutValue(context.Background(), h.store, store.KindAlloc, rec.Key(), rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// numberedLines builds n lines, each carrying its own index so a test can say
// which end of a batch was dropped.
func numberedLines(n int) string {
	var sb strings.Builder
	for i := range n {
		fmt.Fprintf(&sb, "line %d\n", i)
	}
	return sb.String()
}

// subscribeLogs opens a socket and asks for one service's logs.
func subscribeLogs(t *testing.T, h *harness, project, service string, tail int) *websocket.Conn {
	t.Helper()
	conn := dialWS(t, h, "")
	send(t, conn, api.ClientFrame{
		Type: "subscribe", Topic: api.TopicLogs,
		Project: project, Service: service, Tail: tail,
	})
	return conn
}

// readBatch reads frames until one carries a log batch, decoding it.
func readBatch(t *testing.T, conn *websocket.Conn) api.LogBatch {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		frame := receive(t, conn)
		if frame.Type == "error" {
			t.Fatalf("feed error: %s", frame.Error)
		}
		if frame.Topic != api.TopicLogs {
			continue
		}
		var batch api.LogBatch
		if err := json.Unmarshal(frame.Data, &batch); err != nil {
			t.Fatalf("decode log batch: %v", err)
		}
		return batch
	}
	t.Fatal("no log batch arrived")
	return api.LogBatch{}
}

// The bug this whole change exists for, as a test: the dashboard asks for a
// 200-line tail, and per-line frames put 200 of them into a 64-slot send buffer
// whose overflow closed the connection. It died in about 20 ms on a real node.
// The ping at the end is the assertion that matters: before the fix there was
// nothing left to answer it.
func TestATailOfTwoHundredLinesArrivesAsOneFrame(t *testing.T) {
	h := newHarness(t)
	seedAlloc(t, h, "shop", "web", 0)
	writeLog(t, h.logDir, "shop-web-0", numberedLines(200))

	conn := subscribeLogs(t, h, "shop", "web", 200)

	batch := readBatch(t, conn)
	if len(batch.Lines) != 200 {
		t.Errorf("first batch carried %d lines, want 200", len(batch.Lines))
	}
	if batch.Dropped != 0 {
		t.Errorf("dropped = %d, want 0: nothing here exceeds any cap", batch.Dropped)
	}

	send(t, conn, api.ClientFrame{Type: "ping"})
	if got := receive(t, conn).Type; got != "pong" {
		t.Fatalf("after the tail the socket answered %q, want a pong; it used to be closed", got)
	}
}

// The casualty that made this a dashboard-wide outage rather than a log-panel
// one: §12.1 mandates a single multiplexed socket, so a log burst that costs
// the connection costs every other topic with it.
func TestTheLogFeedNeverKillsTheSharedSocket(t *testing.T) {
	h := newHarness(t)
	seedAlloc(t, h, "shop", "web", 0)
	// Far past both wsSendBuffer and maxBatchLines.
	writeLog(t, h.logDir, "shop-web-0", numberedLines(5000))

	conn := dialWS(t, h, "")
	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: api.TopicServices})
	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: api.TopicAllocs})
	send(t, conn, api.ClientFrame{
		Type: "subscribe", Topic: api.TopicLogs, Project: "shop", Service: "web", Tail: 5000,
	})

	// Every topic must still be represented once the burst has gone through.
	wanted := []string{api.TopicServices, api.TopicAllocs, api.TopicLogs}
	seen := map[string]bool{}
	allSeen := func() bool {
		for _, topic := range wanted {
			if !seen[topic] {
				return false
			}
		}
		return true
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !allSeen() {
		frame := receive(t, conn)
		if frame.Type == "error" {
			t.Fatalf("feed error: %s", frame.Error)
		}
		seen[frame.Topic] = true
	}
	for _, topic := range wanted {
		if !seen[topic] {
			t.Errorf("no %s frame arrived; the log burst took the socket down", topic)
		}
	}
}

// The one accounting rule: every line the feed produced is either delivered or
// counted. A gap nobody is told about is the §9.2 mistake in a log panel.
func TestALogBatchCountsEveryLineItWillNeverDeliver(t *testing.T) {
	const bigLine = 32 << 10

	tests := []struct {
		name     string
		produced int
		lineLen  int
		tail     int
		want     func(t *testing.T, delivered, dropped int)
	}{
		{
			name: "under every cap", produced: 10, tail: 10,
			want: func(t *testing.T, delivered, dropped int) {
				if delivered != 10 || dropped != 0 {
					t.Errorf("delivered %d dropped %d, want 10 and 0", delivered, dropped)
				}
			},
		},
		{
			name: "past the line cap", produced: 1200, tail: 0,
			want: func(t *testing.T, delivered, dropped int) {
				if delivered > 1000 {
					t.Errorf("delivered %d lines, want no more than maxBatchLines", delivered)
				}
				if dropped == 0 {
					t.Error("dropped = 0, but more lines were produced than a frame may carry")
				}
			},
		},
		{
			name: "past the byte cap", produced: 20, lineLen: bigLine, tail: 0,
			want: func(t *testing.T, delivered, dropped int) {
				if delivered < 1 {
					t.Error("delivered nothing; a batch always carries at least one line")
				}
				if dropped == 0 {
					t.Error("dropped = 0, but 640 KiB of lines cannot fit one frame")
				}
			},
		},
		{
			name: "a tail past the clamp", produced: 3000, tail: 3000,
			want: func(t *testing.T, _, dropped int) {
				// The clamp removes 2000 before the tailer is even built, and
				// says so rather than pretending the history was shorter.
				if dropped < 2000 {
					t.Errorf("dropped = %d, want at least the 2000 the tail clamp removed", dropped)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			seedAlloc(t, h, "shop", "web", 0)

			content := numberedLines(tc.produced)
			if tc.lineLen > 0 {
				var sb strings.Builder
				for range tc.produced {
					sb.WriteString(strings.Repeat("x", tc.lineLen))
					sb.WriteString("\n")
				}
				content = sb.String()
			}
			writeLog(t, h.logDir, "shop-web-0", content)

			conn := subscribeLogs(t, h, "shop", "web", tc.tail)

			// The history may span more than one tick once caps bite; collect
			// until the stream goes quiet.
			delivered, dropped := 0, 0
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_, body, err := conn.Read(ctx)
				cancel()
				if err != nil {
					break
				}
				var frame api.ServerFrame
				if err := json.Unmarshal(body, &frame); err != nil {
					t.Fatalf("decode frame: %v", err)
				}
				if frame.Topic != api.TopicLogs {
					continue
				}
				var batch api.LogBatch
				if err := json.Unmarshal(frame.Data, &batch); err != nil {
					t.Fatalf("decode log batch: %v", err)
				}
				if len(batch.Lines) == 0 {
					t.Error("a batch arrived with no lines; an empty tick emits no frame")
				}
				delivered += len(batch.Lines)
				dropped += batch.Dropped
			}
			tc.want(t, delivered, dropped)
		})
	}
}

// Which end goes is not arbitrary: the client's own buffer trims the oldest, so
// the daemon trims the oldest too and the two agree on what survives.
func TestTheOldestLinesAreTheOnesDropped(t *testing.T) {
	h := newHarness(t)
	seedAlloc(t, h, "shop", "web", 0)
	writeLog(t, h.logDir, "shop-web-0", numberedLines(1500))

	conn := subscribeLogs(t, h, "shop", "web", 0)
	batch := readBatch(t, conn)

	if batch.Dropped == 0 {
		t.Fatal("nothing was dropped; 1500 lines cannot fit one capped frame")
	}
	last := batch.Lines[len(batch.Lines)-1].Line
	if last != "line 1499" {
		t.Errorf("last delivered line = %q, want the newest (line 1499)", last)
	}
	if first := batch.Lines[0].Line; first == "line 0" {
		t.Error("the oldest line survived; the trim is taking from the wrong end")
	}
}

// The feed used to pick its allocs once at subscribe and return outright when
// none had a log file yet, so a subscription that outlived a deploy, restart or
// scale-up streamed nothing, with an open socket and no error (PRD v1.70).
func TestALogFeedPicksUpAnAllocThatStartsLater(t *testing.T) {
	h := newHarness(t)
	seedAlloc(t, h, "shop", "web", 0)
	// Deliberately no log file: this is the alloc that has not written yet.

	conn := subscribeLogs(t, h, "shop", "web", 200)

	// Give the feed a few passes to find nothing, then let the alloc start.
	time.Sleep(500 * time.Millisecond)
	writeLog(t, h.logDir, "shop-web-0", "hello from the new alloc\n")

	batch := readBatch(t, conn)
	if len(batch.Lines) != 1 || batch.Lines[0].Line != "hello from the new alloc" {
		t.Fatalf("batch = %+v, want the line the late alloc wrote", batch)
	}
}

// A tailer whose alloc record went away is closed and forgotten. The deferred
// sweep only runs when the subscription ends, so a page watching a service that
// redeploys repeatedly would otherwise hold one descriptor per dead alloc.
func TestALogFeedDropsATailerForAnAllocThatWentAway(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedAlloc(t, h, "shop", "web", 0)
	retired := seedAlloc(t, h, "shop", "web", 1)
	writeLog(t, h.logDir, "shop-web-0", "from zero\n")
	writeLog(t, h.logDir, "shop-web-1", "from one\n")

	conn := subscribeLogs(t, h, "shop", "web", 200)

	seen := map[string]bool{}
	for len(seen) < 2 {
		for _, line := range readBatch(t, conn).Lines {
			seen[line.AllocID] = true
		}
	}

	// Retire one alloc and remove its file; the surviving one must keep going.
	if _, err := h.store.Apply(ctx, store.DeleteMutation(store.KindAlloc, retired.Key())); err != nil {
		t.Fatalf("delete alloc: %v", err)
	}
	if err := os.Remove(filepath.Join(h.logDir, "shop-web-1.log")); err != nil {
		t.Fatalf("remove log: %v", err)
	}

	// Deliberately not drain(): cancelling a context a websocket read is
	// blocked on closes the connection (coder/websocket's documented
	// behaviour), so a mid-test drain would be indistinguishable from the
	// failure this test is looking for. Instead the marker line is read for,
	// and everything ahead of it is checked on the way past.
	appendLog(t, h.logDir, "shop-web-0", "still here\n")
	for {
		for _, line := range readBatch(t, conn).Lines {
			if line.AllocID == "shop-web-1" {
				t.Fatal("a line arrived for the alloc that went away")
			}
			if line.Line == "still here" {
				return
			}
		}
	}
}

// appendLog adds to an existing alloc log, which is what a running workload does.
func appendLog(t *testing.T, dir, allocID, content string) {
	t.Helper()
	path := filepath.Join(dir, allocID+".log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("append log: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close log: %v", err)
	}
}
