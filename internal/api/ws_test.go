package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/reconciler"
)

// dialWS opens the live-data socket over the harness's unix socket.
func dialWS(t *testing.T, h *harness, origin string) *websocket.Conn {
	t.Helper()

	header := http.Header{}
	if origin != "" {
		header.Set("Origin", origin)
	}
	conn, resp, err := websocket.Dial(context.Background(), "ws://kanead"+api.PathWS,
		&websocket.DialOptions{HTTPClient: h.httpClient(), HTTPHeader: header})
	if err != nil {
		if resp != nil {
			t.Fatalf("dial websocket: %v (status %d)", err, resp.StatusCode)
		}
		t.Fatalf("dial websocket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "") })
	return conn
}

// dialWSStatus attempts a dial and returns the HTTP status of a refusal.
func dialWSStatus(t *testing.T, h *harness, origin string) int {
	t.Helper()

	header := http.Header{}
	if origin != "" {
		header.Set("Origin", origin)
	}
	conn, resp, err := websocket.Dial(context.Background(), "ws://kanead"+api.PathWS,
		&websocket.DialOptions{HTTPClient: h.httpClient(), HTTPHeader: header})
	if err == nil {
		_ = conn.Close(websocket.StatusNormalClosure, "")
		return http.StatusSwitchingProtocols
	}
	if resp == nil {
		t.Fatalf("dial failed with no response: %v", err)
	}
	return resp.StatusCode
}

func send(t *testing.T, conn *websocket.Conn, frame api.ClientFrame) {
	t.Helper()
	body, err := json.Marshal(frame)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func receive(t *testing.T, conn *websocket.Conn) api.ServerFrame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, body, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var frame api.ServerFrame
	if err := json.Unmarshal(body, &frame); err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	return frame
}

// A cross-site WebSocket hijack needs a browser, and browsers always send
// Origin on an Upgrade. Checking it is the whole defence (PRD §14, A01).
func TestWebSocketEnforcesTheOriginAllowlist(t *testing.T) {
	h := newHarness(t, func(cfg *api.ServerConfig) {
		cfg.WSOrigins = []string{"https://kanea.example.com"}
	})

	if got := dialWSStatus(t, h, "https://kanea.example.com"); got != http.StatusSwitchingProtocols {
		t.Errorf("allowed origin = %d, want an upgrade", got)
	}
	// Case-insensitive, because Origin comparison is on scheme and host.
	if got := dialWSStatus(t, h, "https://KANEA.example.com"); got != http.StatusSwitchingProtocols {
		t.Errorf("allowed origin in another case = %d, want an upgrade", got)
	}
	if got := dialWSStatus(t, h, "https://attacker.example.com"); got != http.StatusForbidden {
		t.Errorf("foreign origin = %d, want 403", got)
	}
	// A near-miss must not pass: prefix matching would let
	// kanea.example.com.attacker.test through.
	if got := dialWSStatus(t, h, "https://kanea.example.com.attacker.test"); got != http.StatusForbidden {
		t.Errorf("lookalike origin = %d, want 403", got)
	}
}

// A daemon with no allowlist has no browser dashboard to serve, so any Origin
// at all is someone else's page.
func TestWebSocketDeniesEveryOriginByDefault(t *testing.T) {
	h := newHarness(t)
	if got := dialWSStatus(t, h, "https://kanea.example.com"); got != http.StatusForbidden {
		t.Errorf("origin with no allowlist = %d, want 403", got)
	}
}

// No Origin means no browser, so it cannot be a hijack — that is how the CLI
// connects.
func TestWebSocketAllowsRequestsWithoutAnOrigin(t *testing.T) {
	h := newHarness(t)
	if got := dialWSStatus(t, h, ""); got != http.StatusSwitchingProtocols {
		t.Errorf("no origin = %d, want an upgrade", got)
	}
}

func TestWebSocketCapsConnections(t *testing.T) {
	h := newHarness(t, func(cfg *api.ServerConfig) { cfg.WSMaxConns = 2 })

	first := dialWS(t, h, "")
	second := dialWS(t, h, "")
	// Both are live; the third must be refused rather than accepted and
	// silently starved.
	if got := dialWSStatus(t, h, ""); got != http.StatusServiceUnavailable {
		t.Errorf("third connection = %d, want 503", got)
	}

	// Closing one frees a slot.
	_ = first.Close(websocket.StatusNormalClosure, "")
	waitUntil(t, func() bool {
		return dialWSStatus(t, h, "") == http.StatusSwitchingProtocols
	}, "a slot was never released")

	_ = second.Close(websocket.StatusNormalClosure, "")
}

// One socket carries every view, so a subscription has to say which feed each
// frame belongs to.
func TestWebSocketMultiplexesTopics(t *testing.T) {
	h := newHarness(t)
	h.putService(t, "shop", "web", 2)
	conn := dialWS(t, h, "")

	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: api.TopicServices})
	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: api.TopicAllocs})

	seen := map[string]bool{}
	for range 2 {
		frame := receive(t, conn)
		if frame.Type != "data" {
			t.Fatalf("frame = %+v, want data", frame)
		}
		seen[frame.Topic] = true
	}
	if !seen[api.TopicServices] || !seen[api.TopicAllocs] {
		t.Errorf("received topics %v, want both", seen)
	}
}

func TestWebSocketServicesFeedCarriesTheStore(t *testing.T) {
	h := newHarness(t)
	h.putService(t, "shop", "web", 3)

	conn := dialWS(t, h, "")
	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: api.TopicServices})

	frame := receive(t, conn)
	var payload api.ServicesResponse
	if err := json.Unmarshal(frame.Data, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if len(payload.Services) != 1 || payload.Services[0].Service != "web" {
		t.Fatalf("services = %+v", payload.Services)
	}
	if payload.Services[0].Count != 3 {
		t.Errorf("count = %d, want 3", payload.Services[0].Count)
	}
	// The live surface carries the projected hash too (v1.64) — a dashboard
	// watching the feed must not need a REST round-trip to see a deploy.
	if got, want := payload.Services[0].SpecHash, reconciler.SpecHash(payload.Services[0].Desired); got != want {
		t.Errorf("spec_hash on the feed = %q, want %q", got, want)
	}
}

// The point of a live feed: a change reaches the client without it asking.
func TestWebSocketPushesOnChange(t *testing.T) {
	h := newHarness(t)
	h.putService(t, "shop", "web", 1)

	conn := dialWS(t, h, "")
	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: api.TopicServices})
	receive(t, conn) // the initial snapshot

	h.putService(t, "shop", "api", 2)

	// The feed may re-send the same snapshot before the write lands; wait for
	// the one that reflects it rather than asserting on the very next frame.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		frame := receive(t, conn)
		var payload api.ServicesResponse
		if err := json.Unmarshal(frame.Data, &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if len(payload.Services) == 2 {
			return
		}
	}
	t.Fatal("the new service never arrived on the feed")
}

func TestWebSocketRejectsUnknownTopics(t *testing.T) {
	h := newHarness(t)
	conn := dialWS(t, h, "")

	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: "secrets"})
	frame := receive(t, conn)
	if frame.Type != "error" {
		t.Fatalf("frame = %+v, want an error", frame)
	}
	if !strings.Contains(frame.Error, "secrets") {
		t.Errorf("error = %q, want it to name the topic", frame.Error)
	}
}

// The log topic needs a service; without one it would have to guess, and
// guessing means streaming someone else's output.
func TestWebSocketLogsTopicRequiresAService(t *testing.T) {
	h := newHarness(t)
	conn := dialWS(t, h, "")

	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: api.TopicLogs})
	frame := receive(t, conn)
	if frame.Type != "error" {
		t.Fatalf("frame = %+v, want an error", frame)
	}
}

func TestWebSocketRejectsMalformedFrames(t *testing.T) {
	h := newHarness(t)
	conn := dialWS(t, h, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, []byte("{not json")); err != nil {
		t.Fatalf("write: %v", err)
	}

	frame := receive(t, conn)
	if frame.Type != "error" || !strings.Contains(frame.Error, "malformed") {
		t.Errorf("frame = %+v, want a malformed-frame error", frame)
	}
	// And the connection survives: one bad frame from a buggy client is not a
	// reason to drop a socket carrying other subscriptions.
	send(t, conn, api.ClientFrame{Type: "ping"})
	if got := receive(t, conn); got.Type != "pong" {
		t.Errorf("frame = %+v, want a pong", got)
	}
}

// Resubscribing replaces rather than duplicates: a reconnecting dashboard must
// not end up with two feeds writing the same data to one socket.
func TestWebSocketResubscribeReplaces(t *testing.T) {
	h := newHarness(t)
	h.putService(t, "shop", "web", 1)
	conn := dialWS(t, h, "")

	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: api.TopicServices})
	receive(t, conn)
	send(t, conn, api.ClientFrame{Type: "subscribe", Topic: api.TopicServices})
	receive(t, conn)

	// Unsubscribing once must silence the topic entirely. If the first feed had
	// survived, frames would keep arriving.
	send(t, conn, api.ClientFrame{Type: "unsubscribe", Topic: api.TopicServices})

	// Drain anything already queued, then require quiet.
	time.Sleep(2 * api.FeedInterval)
	drain(t, conn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*api.FeedInterval+time.Second)
	defer cancel()
	if _, _, err := conn.Read(ctx); err == nil {
		t.Error("frames still arriving after unsubscribe; the first feed survived")
	}
}

// drain reads whatever is already buffered without failing on quiet.
func drain(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		_, _, err := conn.Read(ctx)
		cancel()
		if err != nil {
			return
		}
	}
}

func waitUntil(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

// The connection count is what answers "did my dashboard actually connect"
// without reading the daemon log.
func TestHealthReportsWebSocketConnections(t *testing.T) {
	h := newHarness(t)

	health, err := h.client.Health(context.Background())
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if health.WSConnections != 0 {
		t.Fatalf("connections = %d before any dial", health.WSConnections)
	}

	conn := dialWS(t, h, "")
	waitUntil(t, func() bool {
		health, err := h.client.Health(context.Background())
		return err == nil && health.WSConnections == 1
	}, "the open socket was never counted")

	_ = conn.Close(websocket.StatusNormalClosure, "")
	waitUntil(t, func() bool {
		health, err := h.client.Health(context.Background())
		return err == nil && health.WSConnections == 0
	}, "the closed socket was never released")
}
