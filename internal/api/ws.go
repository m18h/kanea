package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/m18h/kanea/internal/auth"
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
	// TopicStats carries live resource and traffic samples for one service and
	// its allocs (PRD §12.2's service detail graphs).
	TopicStats = "stats"
	// TopicNode carries the node's own summary and machine statistics (v1.79),
	// so the Overview stops polling GET /v1/stats beside the socket it is
	// already holding. It takes no project or service: there is one node.
	TopicNode = "node"
)

// lossyTopic reports whether a data frame on this topic may be dropped rather
// than cost the connection (PRD v1.70, §12.1).
//
// Logs are the one stream whose frames are independent: each carries lines the
// others do not, so a gap can be named to the client and is (LogBatch.Dropped).
// The snapshot topics are deliberately not on this list. Each of their frames
// supersedes the one before it, so a silent drop leaves a client believing
// stale data is current, and feedStoreKind makes that worse, because its
// send() both emits and advances the index it compares against, so a dropped
// snapshot is recorded as sent and the client waits for an unrelated Store
// write to be told anything again. They also tick once a second or slower, so a
// full buffer there means a peer that has stopped reading, which is the case
// the close is genuinely for.
func lossyTopic(topic string) bool { return topic == TopicLogs }

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
	// Container names an init container (R32) whose log to follow instead of
	// the task's, by its *block name*: the server resolves it against the
	// service's own declared sequence, so a client never names a container id.
	//
	// Unlike Tail this IS part of the subscription key: Tail asks for more of
	// the same stream, while this asks for a different one, and keying them
	// together would make a panel switching between steps replace a
	// subscription that is still wanted.
	Container string `json:"container,omitempty"`
	// History asks a stats or node subscription to carry a seed on its first
	// frame (v1.79). Absent means no seed, so a pre-v1.79 client's subscribe
	// frame is byte-identical to what it always sent and gets the frames it
	// always got.
	//
	// Opt-in rather than always-on because the dashboard subscribes stats per
	// table row: a seed nobody asked for, twenty times over, is one send
	// buffer's worth of payload on mount, which is the v1.70 defect in a new
	// place.
	History bool `json:"history,omitempty"`
	// HistoryWindow is how far back, as a Go duration ("15m"). Empty means the
	// default, and it is clamped by the same helper the REST route uses so the
	// two cannot disagree about what a window means.
	HistoryWindow string `json:"history_window,omitempty"`
	// HistorySeries names the series to seed. Empty means the view's default
	// set. An unknown name is refused by name rather than dropped: a chart
	// seeded with nothing looks exactly like a service that has served nothing.
	HistorySeries []string `json:"history_series,omitempty"`
	// HistoryAllocs adds the per-alloc breakdown the allocs table needs.
	// Ignored without History, exactly as Tail is ignored off the logs topic.
	HistoryAllocs bool `json:"history_allocs,omitempty"`
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
	// wsPingInterval detects a peer that vanished without closing (a laptop
	// lid, a dropped VPN) which TCP alone can take much longer to notice.
	wsPingInterval = 30 * time.Second
	// wsSendBuffer is how many frames may queue for one client before the
	// overflow policy applies. A slow reader is never allowed to grow an
	// unbounded queue in the daemon (PRD §17's backpressure rule, applied to
	// the socket); what happens instead is per topic: see lossyTopic.
	wsSendBuffer = 64
	// wsDefaultMaxConns caps concurrent sockets across the daemon.
	wsDefaultMaxConns = 32
	// wsMaxPerViewer bounds one read-only subject's sockets (K-36): a viewer
	// holding every slot would deny the WS/exec channel to everyone else,
	// indefinitely. Write-capable subjects answer to the global cap alone:
	// exec is an operator tool and the global bound still holds it.
	wsMaxPerViewer = 8
)

// ErrOriginNotAllowed marks a rejected Upgrade.
var ErrOriginNotAllowed = errors.New("api: websocket origin not allowed")

// wsHub tracks live sockets so the caps can be enforced: one global bound,
// and a per-subject one for read-only identities (K-36).
type wsHub struct {
	mu        sync.Mutex
	conns     int
	maxConns  int
	bySubject map[string]int
}

func newWSHub(maxConns int) *wsHub {
	if maxConns <= 0 {
		maxConns = wsDefaultMaxConns
	}
	return &wsHub{maxConns: maxConns, bySubject: map[string]int{}}
}

// acquire reserves a connection slot.
func (h *wsHub) acquire(subject string, canWrite bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns >= h.maxConns {
		return false
	}
	if !canWrite && h.bySubject[subject] >= wsMaxPerViewer {
		return false
	}
	h.conns++
	h.bySubject[subject]++
	return true
}

// release returns the slot.
func (h *wsHub) release(subject string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conns--
	if h.bySubject[subject] <= 1 {
		delete(h.bySubject, subject)
	} else {
		h.bySubject[subject]--
	}
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
	// The per-subject cap (K-36) needs the identity the auth middleware
	// attached; a request here is always authenticated (deny-by-default), but
	// an absent one degrades to the global cap rather than refusing.
	subject, canWrite := "", false
	if id, ok := auth.FromContext(r.Context()); ok {
		subject = id.Subject
		canWrite = id.Role.CanWrite()
	}
	if !s.ws.acquire(subject, canWrite) {
		writeError(w, http.StatusServiceUnavailable,
			fmt.Errorf("api: too many websocket connections (%d)", s.ws.maxConns))
		return
	}
	defer s.ws.release(subject)

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

// checkOrigin enforces the Origin allowlist (PRD §12.1, §14 A01: CSWSH).
//
// A cross-site WebSocket hijack needs a browser: the attacker's page opens a
// socket to this daemon and the browser attaches the user's cookies. Browsers
// always send Origin on an Upgrade, so checking it is the defence. A request
// with no Origin is not a browser, cannot be a hijack, and is allowed: that is
// how the CLI and `kanea` itself connect.
func (s *Server) checkOrigin(r *http.Request) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	// Same-origin is allowed without configuration: the page came from this
	// server, so it is the dashboard this daemon is itself serving, and a hijack
	// needs a *different* origin by definition. Without this, the embedded SPA
	// could not open its own socket until someone repeated the daemon's own
	// address back to it in a flag.
	if u, err := url.Parse(origin); err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host) {
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

	// dropWarn keeps a drop storm from becoming a logging storm (constraint #8,
	// the notify dispatcher's rule): a client that is behind is behind for
	// thousands of frames, and one line per frame is the second outage.
	dropWarn sync.Once

	mu   sync.Mutex
	subs map[string]context.CancelFunc
	// seedPoints and seedWindowAt are the seed budget (v1.79). A subscribe
	// frame is about a hundred bytes and the seed it can ask for is about a
	// hundred and thirty kilobytes, and a subscribe is treated as a replace, so
	// subscribe/unsubscribe in a loop would re-seed without limit. A refill
	// window rather than a hard total, because a page legitimately re-seeds all
	// day as the operator navigates.
	seedPoints   int
	seedWindowAt time.Time
}

// The seed budget, per connection.
const (
	// seedBudgetPoints is what one connection may seed per window. Sized so an
	// ordinary page (a node view, a service, a table of rows) re-seeds freely
	// while a loop does not.
	seedBudgetPoints = 12000
	seedBudgetWindow = 30 * time.Second
)

// spendSeedBudget reports whether a seed of this size may be sent.
//
// Over budget the seed is omitted and the omission is stated in the frame; the
// live samples still flow. A gap the client can name, never an error and never
// a closed connection: the topic is not lossy, so failing here by dropping the
// whole frame would cost the socket every other panel is riding on.
func (s *wsSession) spendSeedBudget(points int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.server.now()
	if s.seedWindowAt.IsZero() || now.Sub(s.seedWindowAt) >= seedBudgetWindow {
		s.seedWindowAt = now
		s.seedPoints = 0
	}
	if s.seedPoints+points > seedBudgetPoints {
		return false
	}
	s.seedPoints += points
	return true
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

// emit queues a frame without blocking, and reports whether it was queued.
//
// Never blocking is the same rule §17 applies to log drains: a slow consumer
// must never become backpressure on the producer. Here the producer is a Store
// poll or a log tail, and blocking it would let one stalled browser tab stall
// the data feeding every other one.
//
// What happens on overflow is per topic (PRD v1.70). A data frame on a lossy
// topic is dropped and the caller is told, so the gap can be counted where
// whoever is reading will see it; anything else closes the connection, which is
// what this used to do unconditionally, and unconditionally was the defect: a
// log tail bursting past the buffer took the services, allocs and stats feeds
// on the same socket down with it, and the client reconnected into the same
// burst forever. An error frame is never droppable at any topic, because a
// panel showing no error is worse than one showing a gap.
//
// The peer that reads *nothing* is still caught, by writeLoop's ping under
// wsWriteTimeout: that, not the buffer, is what frees the connection slot.
func (s *wsSession) emit(frame ServerFrame) bool {
	select {
	case s.send <- frame:
		return true
	default:
	}
	if frame.Type == frameData && lossyTopic(frame.Topic) {
		s.dropWarn.Do(func() {
			s.server.log.Warn("websocket client is behind; dropping frames on a lossy topic",
				"topic", frame.Topic, "key", frame.Key, "buffered", len(s.send),
				"note", "the count rides in the next frame this subscription sends")
		})
		return false
	}
	s.server.log.Warn("websocket client is too slow; closing it",
		"topic", frame.Topic, "buffered", len(s.send))
	if err := s.conn.Close(websocket.StatusPolicyViolation, "too slow"); err != nil {
		s.server.log.Debug("websocket close after overflow", "error", err)
	}
	return false
}

func (s *wsSession) emitError(topic, message string) {
	s.emit(ServerFrame{Type: frameError, Topic: topic, Error: message})
}

// emitData sends a payload on a topic, reporting whether it was queued.
//
// A payload that cannot be encoded reports false for the same reason a dropped
// one does: it reached nobody, and a feed that counts its gaps should count
// this one too.
func (s *wsSession) emitData(topic, key string, payload any) bool {
	body, err := json.Marshal(payload)
	if err != nil {
		s.server.log.Error("encode websocket payload", "topic", topic, "error", err)
		return false
	}
	return s.emit(ServerFrame{Type: frameData, Topic: topic, Key: key, Data: body})
}

// subscriptionKey identifies a subscription within a session.
func subscriptionKey(f ClientFrame) string {
	if f.Project == "" && f.Service == "" {
		return f.Topic
	}
	key := f.Topic + ":" + f.Project + "/" + f.Service
	// Container selects a different stream rather than more of one (R32), so
	// it belongs in the key. Appended only when set, so every pre-v1.84
	// subscription keeps the key it always had.
	if f.Container != "" {
		key += ":" + f.Container
	}
	return key
}

// maxSubscriptions bounds one connection's live feeds (K-18): every
// subscription is a goroutine and, for logs, a set of open files, so a client
// that subscribes without bound is a resource leak the server is holding.
// 32 is far past anything the dashboard opens (one per visible panel).
const maxSubscriptions = 32

// subscribe starts a feed, replacing any existing one with the same key.
func (s *wsSession) subscribe(ctx context.Context, frame ClientFrame) {
	key := subscriptionKey(frame)

	feed, err := s.server.feedFor(frame, s.spendSeedBudget)
	if err != nil {
		s.emitError(frame.Topic, err.Error())
		return
	}

	// Resubscribing to the same key replaces rather than duplicates: a
	// reconnecting dashboard should not end up with two feeds writing the same
	// data to one socket.
	s.unsubscribe(key)

	s.mu.Lock()
	if len(s.subs) >= maxSubscriptions {
		s.mu.Unlock()
		// An error frame, never a silent drop: a panel showing no error is
		// worse than one showing a gap (the v1.70 rule).
		s.emitError(frame.Topic, "too many subscriptions on this connection")
		return
	}
	feedCtx, cancel := context.WithCancel(ctx)
	s.subs[key] = cancel
	s.mu.Unlock()

	go func() {
		defer cancel()
		// A feed bug costs one subscription, never the process (K-35): this
		// goroutine runs client-driven code for an authenticated viewer, and
		// an unrecovered panic in it is a remotely triggerable control-plane
		// crash.
		defer func() {
			if r := recover(); r != nil {
				s.server.log.Error("feed panic; the subscription is closed",
					"topic", frame.Topic, "key", key, "panic", r)
			}
		}()
		feed(feedCtx, func(payload any) bool { return s.emitData(frame.Topic, key, payload) })
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
