package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

// policyHarness is one session whose send buffer is already full, so every
// emit takes the overflow path. An internal test because the overflow policy is
// the half an end-to-end socket test cannot drive: kernel and library buffers
// absorb a burst, so "the buffer is full" is not a state a client can dictate.
type policyHarness struct {
	session *wsSession
	logs    *bytes.Buffer
	conn    *websocket.Conn
	server  *httptest.Server
}

func newPolicyHarness(t *testing.T) *policyHarness {
	t.Helper()

	// A real connection, because emit closes one on the non-lossy path and a
	// nil conn would panic rather than answer the question.
	accepted := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		accepted <- c
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	client, _, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close(websocket.StatusNormalClosure, "") })
	conn := <-accepted

	logs := &bytes.Buffer{}
	h := &policyHarness{
		logs:   logs,
		conn:   conn,
		server: srv,
		session: &wsSession{
			server: &Server{log: slog.New(slog.NewTextHandler(logs, nil))},
			conn:   conn,
			send:   make(chan ServerFrame, wsSendBuffer),
			subs:   map[string]context.CancelFunc{},
		},
	}
	for range wsSendBuffer {
		h.session.send <- ServerFrame{Type: frameData, Topic: TopicStats}
	}
	return h
}

// closed reports whether emit tore the connection down. A closed connection
// refuses a write; an open one takes it.
func (h *policyHarness) closed(t *testing.T) bool {
	t.Helper()
	err := h.conn.Write(context.Background(), websocket.MessageText, []byte("probe"))
	return err != nil
}

// The whole of PRD v1.70's socket policy in one table. A log *data* frame is
// the only thing a full buffer may discard: every other topic's frames
// supersede the one before, so a silent drop leaves a client believing stale
// data is current, and an error frame nobody receives is a panel that shows no
// error, which is worse than one showing a gap.
func TestOnlyALogDataFrameSurvivesAFullSendBuffer(t *testing.T) {
	tests := []struct {
		name       string
		frame      ServerFrame
		wantQueued bool
		wantClosed bool
	}{
		{
			name:  "a services snapshot closes the connection",
			frame: ServerFrame{Type: frameData, Topic: TopicServices}, wantClosed: true,
		},
		{
			name:  "an allocs snapshot closes the connection",
			frame: ServerFrame{Type: frameData, Topic: TopicAllocs}, wantClosed: true,
		},
		{
			name:  "a stats sample closes the connection",
			frame: ServerFrame{Type: frameData, Topic: TopicStats}, wantClosed: true,
		},
		{
			name:  "a log batch is dropped and the connection lives",
			frame: ServerFrame{Type: frameData, Topic: TopicLogs}, wantClosed: false,
		},
		{
			name:  "a log error still closes the connection",
			frame: ServerFrame{Type: frameError, Topic: TopicLogs, Error: "boom"}, wantClosed: true,
		},
		{
			name:  "a pong closes the connection",
			frame: ServerFrame{Type: framePong}, wantClosed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newPolicyHarness(t)

			if queued := h.session.emit(tc.frame); queued != tc.wantQueued {
				t.Errorf("emit queued = %v, want %v: the buffer is full", queued, tc.wantQueued)
			}
			if got := h.closed(t); got != tc.wantClosed {
				t.Errorf("connection closed = %v, want %v", got, tc.wantClosed)
			}
		})
	}
}

// A client that is behind is behind for thousands of frames, and one log line
// per dropped frame is the second outage (constraint #8, the notify
// dispatcher's rule).
func TestTheDropWarningIsWrittenOnce(t *testing.T) {
	h := newPolicyHarness(t)

	for range 500 {
		if h.session.emit(ServerFrame{Type: frameData, Topic: TopicLogs}) {
			t.Fatal("a frame was queued; the buffer was supposed to be full")
		}
	}

	if got := strings.Count(h.logs.String(), "dropping frames on a lossy topic"); got != 1 {
		t.Errorf("drop warnings logged = %d, want exactly 1", got)
	}
}

// A payload that cannot be encoded reached nobody, so a feed that counts its
// gaps counts this one too rather than treating it as delivered.
func TestAPayloadThatCannotBeEncodedIsNotReportedAsQueued(t *testing.T) {
	logs := &bytes.Buffer{}
	session := &wsSession{
		server: &Server{log: slog.New(slog.NewTextHandler(logs, nil))},
		send:   make(chan ServerFrame, wsSendBuffer),
	}
	if session.emitData(TopicLogs, "logs:shop/web", make(chan int)) {
		t.Error("an unencodable payload reported as queued")
	}
}

// A batch keeps its newest line even when that single line is over the byte
// cap, or a workload writing megabytes without a newline stalls the stream
// forever while the drop count climbs. Unreachable through the tailer with the
// current constants (lineWriter flushes at maxLineBytes, well under
// maxBatchBytes), which is exactly why it is pinned here: the invariant must
// survive someone changing either number.
func TestALineTooLargeForABatchIsStillKept(t *testing.T) {
	f := &logFollower{tails: map[string]*tailer{}}
	huge := strings.Repeat("x", maxBatchBytes+1024)

	f.append(LogLine{AllocID: "shop-web-0", Line: "small"})
	f.append(LogLine{AllocID: "shop-web-0", Line: huge})

	if len(f.batch.Lines) != 1 {
		t.Fatalf("batch holds %d lines, want just the oversized one", len(f.batch.Lines))
	}
	if got := len(f.batch.Lines[0].Line); got != len(huge) {
		t.Errorf("line length = %d, want %d: it must not be truncated", got, len(huge))
	}
	if f.batch.Dropped != 1 {
		t.Errorf("dropped = %d, want 1 for the line the cap pushed out", f.batch.Dropped)
	}
}

// Oldest-first is the end the client's own buffer trims, so the two agree on
// what survives; and the accounting has to close.
func TestAppendDropsTheOldestAndCountsEveryOne(t *testing.T) {
	f := &logFollower{tails: map[string]*tailer{}}

	const produced = maxBatchLines + 250
	for i := range produced {
		f.append(LogLine{AllocID: "shop-web-0", Line: strings.Repeat("x", 4) + string(rune('a'+i%26))})
	}

	if len(f.batch.Lines) != maxBatchLines {
		t.Errorf("batch holds %d lines, want maxBatchLines (%d)", len(f.batch.Lines), maxBatchLines)
	}
	if delivered, dropped := len(f.batch.Lines), f.batch.Dropped; delivered+dropped != produced {
		t.Errorf("delivered %d + dropped %d = %d, want %d: every line is one or the other",
			delivered, dropped, delivered+dropped, produced)
	}
}

// An empty tick emits no frame at all: a batch with no lines would be a gap
// reported against nothing, and the drop it was carrying rides the next real
// frame instead of being lost.
func TestAFlushWithNoLinesSendsNothingAndKeepsItsCarry(t *testing.T) {
	f := &logFollower{tails: map[string]*tailer{}, carry: 7}

	sent := 0
	emit := func(any) bool { sent++; return true }

	f.flush(emit)
	if sent != 0 {
		t.Errorf("flush sent %d frames for an empty tick, want 0", sent)
	}
	if f.carry != 7 {
		t.Errorf("carry = %d, want the 7 still owed to the next frame", f.carry)
	}

	f.append(LogLine{AllocID: "shop-web-0", Line: "at last"})
	var got LogBatch
	f.flush(func(payload any) bool {
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return true
	})
	if got.Dropped != 7 {
		t.Errorf("dropped = %d, want the carried 7", got.Dropped)
	}
	if f.carry != 0 {
		t.Errorf("carry = %d after a delivered frame, want 0", f.carry)
	}
}

// A frame the buffer refused reached nobody, so everything in it (its lines
// and the drops it was reporting) becomes the next frame's gap. A count, never
// a queue: holding the lines would be the unbounded daemon-side buffer §17
// forbids.
func TestARefusedFrameBecomesTheNextFramesDropCount(t *testing.T) {
	f := &logFollower{tails: map[string]*tailer{}, carry: 3}

	f.append(LogLine{AllocID: "shop-web-0", Line: "one"})
	f.append(LogLine{AllocID: "shop-web-0", Line: "two"})
	f.flush(func(any) bool { return false })

	if f.carry != 5 {
		t.Errorf("carry = %d, want 5 (2 lines lost with the frame plus the 3 it reported)", f.carry)
	}
	if len(f.batch.Lines) != 0 {
		t.Errorf("batch still holds %d lines; a refused frame is not requeued", len(f.batch.Lines))
	}
}
