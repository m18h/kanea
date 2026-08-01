package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// PathWS is the single multiplexed live-data socket (PRD §12.1).
//
// One socket rather than one per view: a dashboard showing an overview, a log
// stream and a service list would otherwise hold three, and the per-user
// connection cap (§14, A07) would be spent on one open browser tab.
const PathWS = "/v1/ws"

// Topics a client may subscribe to.
const (
	// TopicServices carries the desired-state set whenever it changes.
	TopicServices = "services"
	// TopicAllocs carries alloc records.
	TopicAllocs = "allocs"
	// TopicLogs carries workload log lines for one service.
	TopicLogs = "logs"
)

// WS frame types. Client frames are requests; server frames are data or errors.
const (
	frameSubscribe   = "subscribe"
	frameUnsubscribe = "unsubscribe"
	frameData        = "data"
	frameError       = "error"
	framePing        = "ping"
	framePong        = "pong"
)

// ClientFrame is what the dashboard sends.
type ClientFrame struct {
	Type  string `json:"type"`
	Topic string `json:"topic,omitempty"`
	// Project and Service scope a subscription that needs one (logs).
	Project string `json:"project,omitempty"`
	Service string `json:"service,omitempty"`
	// Tail is how many existing log lines to send before following.
	Tail int `json:"tail,omitempty"`
}

// ServerFrame is what the daemon sends back.
type ServerFrame struct {
	Type  string `json:"type"`
	Topic string `json:"topic,omitempty"`
	// Key identifies the subscription a frame belongs to, so a client watching
	// two services' logs can tell them apart on one socket.
	Key string `json:"key,omitempty"`
	// Data is the payload, already encoded.
	Data json.RawMessage `json:"data,omitempty"`
	// Error is set on an error frame.
	Error string `json:"error,omitempty"`
}

// WS limits. All of them are bounds against a client that misbehaves, which for
// a public-facing daemon includes "a browser tab left open for a week".
const (
	// wsMaxMessageBytes bounds one inbound frame. Subscriptions are tiny; a
	// megabyte of JSON is an attack, not a request.
	wsMaxMessageBytes = 32 << 10
	// wsWriteTimeout bounds a single write to a client. A browser that stops
	// reading must not pin the goroutine feeding it.
	wsWriteTimeout = 10 * time.Second
	// wsPingInterval detects a peer that vanished without closing — a laptop
	// lid, a dropped VPN — which TCP alone can take much longer to notice.
	wsPingInterval = 30 * time.Second
	// wsSendBuffer is how many frames may queue for one client before it is
	// disconnected. A slow reader is dropped rather than allowed to grow an
	// unbounded queue in the daemon (PRD §17's backpressure rule, applied to
	// the socket).
	wsSendBuffer = 64
	// wsDefaultMaxConns caps concurrent sockets. Per-user caps arrive with auth
	// in M5; until then this is the whole-daemon bound.
	wsDefaultMaxConns = 32
)

// ErrOriginNotAllowed marks a rejected Upgrade.
var ErrOriginNotAllowed = errors.New("api: websocket origin not allowed")

// wsHub tracks live sockets so the cap can be enforced.
type wsHub struct {
	mu       sync.Mutex
	conns    int
	maxConns int
}

func newWSHub(maxConns int) *wsHub {
	if maxConns <= 0 {
		maxConns = wsDefaultMaxConns
	}
	return &wsHub{maxConns: maxConns}
}

// acquire reserves a connection slot.
func (h *wsHub) acquire() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns >= h.maxConns {
		return false
	}
	h.conns++
	return true
}

func (h *wsHub) release() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conns--
}

func (h *wsHub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns
}

// handleWS upgrades a connection and serves subscriptions on it.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	if err := s.checkOrigin(r); err != nil {
		// A rejected Upgrade is answered before the handshake completes, so the
		// page that tried gets a plain HTTP error rather than a socket that
		// closes for no stated reason.
		s.log.Warn("websocket upgrade refused",
			"origin", r.Header.Get("Origin"), "remote", r.RemoteAddr, "error", err)
		writeError(w, http.StatusForbidden, err)
		return
	}
	if !s.ws.acquire() {
		writeError(w, http.StatusServiceUnavailable,
			fmt.Errorf("api: too many websocket connections (%d)", s.ws.maxConns))
		return
	}
	defer s.ws.release()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Origin was checked above against the configured allowlist; the
		// library's own same-host check would additionally reject a dashboard
		// served from a different origin, which is a supported deployment.
		InsecureSkipVerify: true,
	})
	if err != nil {
		s.log.Debug("websocket accept failed", "error", err)
		return
	}
	conn.SetReadLimit(wsMaxMessageBytes)

	session := &wsSession{
		server: s,
		conn:   conn,
		send:   make(chan ServerFrame, wsSendBuffer),
		subs:   map[string]context.CancelFunc{},
	}
	session.run(r.Context())
}

// checkOrigin enforces the Origin allowlist (PRD §12.1, §14 A01 — CSWSH).
//
// A cross-site WebSocket hijack needs a browser: the attacker's page opens a
// socket to this daemon and the browser attaches the user's cookies. Browsers
// always send Origin on an Upgrade, so checking it is the defence. A request
// with no Origin is not a browser, cannot be a hijack, and is allowed — that is
// how the CLI and `kanea` itself connect.
func (s *Server) checkOrigin(r *http.Request) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	for _, allowed := range s.wsOrigins {
		if strings.EqualFold(allowed, origin) {
			return nil
		}
	}
	// Deny by default, including when no allowlist is configured: a daemon
	// without one has no browser dashboard to serve, so any Origin at all is
	// someone else's page.
	return fmt.Errorf("%w: %q", ErrOriginNotAllowed, origin)
}

// wsSession is one client connection.
type wsSession struct {
	server *Server
	conn   *websocket.Conn
	send   chan ServerFrame

	mu   sync.Mutex
	subs map[string]context.CancelFunc
}

// run serves the session until the client goes away.
func (s *wsSession) run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer s.closeAll()

	// The writer owns the connection's write side entirely: a WebSocket
	// connection has one writer or it has corrupted framing, so every producer
	// goes through the channel.
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.writeLoop(ctx)
	}()

	s.readLoop(ctx)
	cancel()
	<-done

	if err := s.conn.Close(websocket.StatusNormalClosure, ""); err != nil {
		s.server.log.Debug("websocket close", "error", err)
	}
}

// readLoop handles client frames until the connection ends.
func (s *wsSession) readLoop(ctx context.Context) {
	for {
		var frame ClientFrame
		typ, data, err := s.conn.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			s.emitError("", "only text frames are understood")
			continue
		}
		if err := json.Unmarshal(data, &frame); err != nil {
			s.emitError("", "malformed frame: "+err.Error())
			continue
		}

		switch frame.Type {
		case frameSubscribe:
			s.subscribe(ctx, frame)
		case frameUnsubscribe:
			s.unsubscribe(subscriptionKey(frame))
		case framePing:
			s.emit(ServerFrame{Type: framePong})
		default:
			s.emitError(frame.Topic, "unknown frame type "+frame.Type)
		}
	}
}

// writeLoop is the only writer on the connection.
func (s *wsSession) writeLoop(ctx context.Context) {
	ticker := time.NewTicker(wsPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-s.send:
			if err := s.write(ctx, frame); err != nil {
				return
			}
		case <-ticker.C:
			// Detects a peer that vanished without closing. Ping failure is the
			// signal to tear the session down and free its slot.
			pingCtx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
			err := s.conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

func (s *wsSession) write(ctx context.Context, frame ServerFrame) error {
	body, err := json.Marshal(frame)
	if err != nil {
		s.server.log.Error("encode websocket frame", "topic", frame.Topic, "error", err)
		return nil // a bad frame is not a reason to drop the connection
	}
	writeCtx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
	defer cancel()
	return s.conn.Write(writeCtx, websocket.MessageText, body)
}

// emit queues a frame, dropping the connection if the client cannot keep up.
//
// Dropping rather than blocking is deliberate and is the same rule §17 applies
// to log drains: a slow consumer must never become backpressure on the producer.
// Here the producer is a Store poll or a log tail, and blocking it would let one
// stalled browser tab stall the data feeding every other one.
func (s *wsSession) emit(frame ServerFrame) {
	select {
	case s.send <- frame:
	default:
		s.server.log.Warn("websocket client is too slow; closing it",
			"topic", frame.Topic, "buffered", len(s.send))
		if err := s.conn.Close(websocket.StatusPolicyViolation, "too slow"); err != nil {
			s.server.log.Debug("websocket close after overflow", "error", err)
		}
	}
}

func (s *wsSession) emitError(topic, message string) {
	s.emit(ServerFrame{Type: frameError, Topic: topic, Error: message})
}

// emitData sends a payload on a topic.
func (s *wsSession) emitData(topic, key string, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		s.server.log.Error("encode websocket payload", "topic", topic, "error", err)
		return
	}
	s.emit(ServerFrame{Type: frameData, Topic: topic, Key: key, Data: body})
}

// subscriptionKey identifies a subscription within a session.
func subscriptionKey(f ClientFrame) string {
	if f.Project == "" && f.Service == "" {
		return f.Topic
	}
	return f.Topic + ":" + f.Project + "/" + f.Service
}

// subscribe starts a feed, replacing any existing one with the same key.
func (s *wsSession) subscribe(ctx context.Context, frame ClientFrame) {
	key := subscriptionKey(frame)

	feed, err := s.server.feedFor(frame)
	if err != nil {
		s.emitError(frame.Topic, err.Error())
		return
	}

	// Resubscribing to the same key replaces rather than duplicates: a
	// reconnecting dashboard should not end up with two feeds writing the same
	// data to one socket.
	s.unsubscribe(key)

	feedCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.subs[key] = cancel
	s.mu.Unlock()

	go func() {
		defer cancel()
		feed(feedCtx, func(payload any) { s.emitData(frame.Topic, key, payload) })
	}()
}

// unsubscribe stops a feed if it is running.
func (s *wsSession) unsubscribe(key string) {
	s.mu.Lock()
	cancel, ok := s.subs[key]
	delete(s.subs, key)
	s.mu.Unlock()
	if ok {
		cancel()
	}
}

// closeAll stops every feed on this session.
func (s *wsSession) closeAll() {
	s.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(s.subs))
	for key, cancel := range s.subs {
		cancels = append(cancels, cancel)
		delete(s.subs, key)
	}
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}
