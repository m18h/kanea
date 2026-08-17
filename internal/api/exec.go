package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/runtime"
)

// PathExec is the debug-shell route (PRD §16.2, §14 A01).
//
// The most privileged thing this API does. An exec is a shell inside a
// workload with the workload's own filesystem, environment and credentials:
// which is why §14 names it specifically as admin-only and audited, and why it
// is the one route here whose audit entry is written whether or not anything
// went wrong.
const PathExec = "/v1/exec"

// The wire protocol.
//
// Binary frames carry data, prefixed with one byte naming the stream. Text
// frames carry control, as JSON. Two frame types rather than one envelope
// because the data path is the hot one: a shell echoing a build log should not
// pay for base64 and a JSON parse per keystroke.
//
//	client → server   binary: raw stdin bytes (no prefix)
//	                  text:   {"type":"resize","width":N,"height":N}
//	                          {"type":"eof"}
//	server → client   binary: [stream byte][data], stream 1 = stdout, 2 = stderr
//	                  text:   {"type":"exit","code":N}
//	                          {"type":"error","message":"…"}
//
// The handshake, for a browser client (PRD v1.64): the WebSocket constructor
// cannot set X-Kanea-CSRF, so a cookie-authenticated dashboard offers
// ["kanea.exec.v1", "kanea-csrf.<token>"] as its subprotocols; the token from
// GET /v1/auth/session. The server echoes only ExecSubprotocol, never the
// token entry; a CLI client over the socket offers nothing and nothing is
// echoed, byte-for-byte the pre-v1.64 handshake.
const (
	streamStdout byte = 1
	streamStderr byte = 2
)

// ExecSubprotocol is the negotiable subprotocol name. A browser client must
// offer it beside its kanea-csrf.<token> entry: the server echoes only this
// one, so the token never reflects into the response, and a browser whose
// offer contains no entry the server echoes fails the connection itself.
const ExecSubprotocol = "kanea.exec.v1"

// ExecFrame is a control message in either direction.
type ExecFrame struct {
	Type    string `json:"type"`
	Width   uint16 `json:"width,omitempty"`
	Height  uint16 `json:"height,omitempty"`
	Code    uint32 `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// Execer is the slice of the runtime driver the exec route needs.
//
// One method. The API can attach a shell to an alloc and can do nothing else to
// the runtime: it cannot create, start, stop or remove one, because those go
// through the reconciler and a second path to them would be a second scheduler.
type Execer interface {
	ExecStream(ctx context.Context, project, id string, opts runtime.ExecOptions) (uint32, error)
}

// maxExecStdinFrame bounds one inbound data frame. A terminal sends keystrokes;
// anything larger is a paste, and anything much larger is not a terminal.
const maxExecStdinFrame = 1 << 20

// handleExec attaches a shell to an alloc.
//
// The audit entry is written by the route wrapper because the policy marks this
// as mutating, which it is, in the sense that matters: an exec can do anything
// the workload's user can do, and the trail has to say who opened one, on what,
// and when.
func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	if s.exec == nil {
		writeError(w, http.StatusServiceUnavailable,
			errors.New("api: this daemon has no runtime driver, so exec is unavailable"))
		return
	}

	q := r.URL.Query()
	alloc := q.Get("alloc")
	project := q.Get("project")
	command := q["command"]
	if project == "" || alloc == "" || len(command) == 0 {
		writeError(w, http.StatusBadRequest,
			errors.New("api: exec needs project, alloc and at least one command argument"))
		return
	}
	// Recorded before the upgrade, so a session that never establishes is still
	// in the trail with what it tried to run.
	auditTarget(r, project+"/"+alloc)
	auditDetail(r, strings.Join(command, " "))

	if err := s.checkOrigin(r); err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}
	// Exec is an operator tool: the identity is writer-capable by route
	// policy, so the per-viewer socket cap (K-36) does not apply, and the
	// global one still does.
	subject := ""
	if id, ok := auth.FromContext(r.Context()); ok {
		subject = id.Subject
	}
	if !s.ws.acquire(subject, true) {
		writeError(w, http.StatusServiceUnavailable, errTooManyConnections)
		return
	}
	defer s.ws.release(subject)

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Origin is checked above, against the same allowlist the live-data
		// socket uses. This disables the library's own check because ours has
		// already run and produced a better error.
		InsecureSkipVerify: true,
		// Echo the protocol name to a browser that offered it (the CSRF token
		// rides Sec-WebSocket-Protocol beside it; see the handshake note
		// above). The token entry is never selected, so it never reflects.
		Subprotocols: []string{ExecSubprotocol},
	})
	if err != nil {
		s.log.Warn("exec upgrade failed", "alloc", alloc, "error", err)
		return
	}
	// The connection is closed exactly once, here. Every path below returns
	// rather than closing, so a close reason is never overwritten by a second.
	session := &execSession{conn: conn, log: s.log, peerGone: make(chan struct{})}
	defer session.close()

	s.log.Info("exec session opened",
		"project", project, "alloc", alloc, "command", command,
		"tty", q.Get("tty") == "true", "source", sourceOf(r))

	// The read loop runs for the whole handler, not just for the exec.
	// Cancelling the context a websocket read is blocked on *closes the
	// connection*: that is coder/websocket's documented behaviour, because a
	// half-read frame leaves the stream unusable, so a read loop scoped to the
	// exec would tear the socket down the instant the process exited, and the
	// exit frame below would be written to a dead connection.
	stdin, stdinWriter := io.Pipe()
	resize := make(chan runtime.TerminalSize, 4)
	go session.readLoop(r.Context(), stdinWriter, resize)

	code, err := s.runExec(r.Context(), session, project, alloc, command, q, stdin, resize)
	// Closed so the driver's stdin copier finishes; the process is already gone.
	// A pipe close only fails if it is already closed, which the read loop may
	// have done: either way stdin is shut, which is all this needs.
	if cerr := stdinWriter.Close(); cerr != nil {
		s.log.Debug("closing exec stdin", "error", cerr)
	}
	if err != nil {
		session.control(r.Context(), ExecFrame{Type: "error", Message: err.Error()})
		s.log.Warn("exec session failed",
			"project", project, "alloc", alloc, "error", err)
		return
	}
	session.control(r.Context(), ExecFrame{Type: "exit", Code: code})
	// The exit frame is the last thing the client needs and the only place the
	// remote status comes from, so the handler waits for the client to hang up
	// before returning. Without this the handler returns, net/http tears the
	// hijacked connection down, and the client sees EOF where the exit code
	// should have been: intermittently, which is worse than never.
	session.awaitPeer(execDrainTimeout)
	s.log.Info("exec session closed", "project", project, "alloc", alloc, "exit_code", code)
}

// runExec wires the socket to the runtime and blocks until the process exits.
func (s *Server) runExec(
	ctx context.Context, session *execSession,
	project, alloc string, command []string, q map[string][]string,
	stdin io.Reader, resize <-chan runtime.TerminalSize,
) (uint32, error) {
	tty := len(q["tty"]) > 0 && q["tty"][0] == "true"

	opts := runtime.ExecOptions{
		Command: command, TTY: tty, Stdin: stdin,
		Stdout: session.writer(streamStdout),
		Resize: resize,
	}
	// With a pseudo-terminal there is one stream by definition; splitting it
	// would mean inventing a distinction the kernel did not make.
	if !tty {
		opts.Stderr = session.writer(streamStderr)
	}
	if user := q["user"]; len(user) > 0 {
		opts.User = user[0]
	}

	return s.exec.ExecStream(ctx, project, alloc, opts)
}

// execDrainTimeout bounds the wait for the client to acknowledge the end of a
// session. A client that has already gone makes this instant; one that is wedged
// must not hold a handler goroutine open.
const execDrainTimeout = 5 * time.Second

// execSession owns one websocket for an exec.
type execSession struct {
	conn *websocket.Conn
	log  logger
	// peerGone closes when the read loop ends, which is how the handler knows
	// the client has seen everything it was sent.
	peerGone chan struct{}
	// mu serialises writes. A websocket connection permits one writer at a
	// time, and stdout, stderr and the control frames are three of them.
	mu     sync.Mutex
	closed bool
}

// logger is the slice of slog this file needs, so the struct above does not
// carry a whole logger's API into a hot write path.
type logger interface {
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

// writer returns an io.Writer that frames output onto the socket.
func (s *execSession) writer(stream byte) io.Writer {
	return &execWriter{session: s, stream: stream}
}

type execWriter struct {
	session *execSession
	stream  byte
}

func (w *execWriter) Write(p []byte) (int, error) {
	// A copy per write, because the frame needs its stream byte in front and
	// the caller's buffer is reused the moment this returns.
	framed := make([]byte, 0, len(p)+1)
	framed = append(framed, w.stream)
	framed = append(framed, p...)

	w.session.mu.Lock()
	defer w.session.mu.Unlock()
	if w.session.closed {
		return 0, io.ErrClosedPipe
	}
	// Background rather than the request context: output produced as a session
	// ends should still reach the terminal, and the socket's own deadline
	// bounds it.
	if err := w.session.conn.Write(context.Background(), websocket.MessageBinary, framed); err != nil {
		return 0, err
	}
	return len(p), nil
}

// control sends a text frame.
func (s *execSession) control(ctx context.Context, frame ExecFrame) {
	body, err := json.Marshal(frame)
	if err != nil {
		s.log.Warn("cannot encode an exec control frame", "type", frame.Type, "error", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if err := s.conn.Write(ctx, websocket.MessageText, body); err != nil {
		s.log.Debug("cannot send an exec control frame", "type", frame.Type, "error", err)
	}
}

// readLoop pumps client frames into stdin and the resize channel.
func (s *execSession) readLoop(ctx context.Context, stdin *io.PipeWriter, resize chan<- runtime.TerminalSize) {
	defer close(s.peerGone)
	defer close(resize)
	defer func() {
		if err := stdin.Close(); err != nil {
			s.log.Debug("closing exec stdin", "error", err)
		}
	}()
	// A read-loop bug costs the session, never the process (K-35): this
	// goroutine parses client frames for an authenticated caller.
	defer func() {
		if r := recover(); r != nil {
			s.log.Warn("exec read loop panic; the session is closed", "panic", r)
		}
	}()

	for {
		typ, body, err := s.conn.Read(ctx)
		if err != nil {
			// The client hung up, or the context ended because the process did.
			// Neither is worth more than a debug line.
			s.log.Debug("exec read loop ended", "error", err)
			return
		}
		if len(body) > maxExecStdinFrame {
			s.log.Warn("exec frame too large", "bytes", len(body))
			return
		}

		switch typ {
		case websocket.MessageBinary:
			if _, err := stdin.Write(body); err != nil {
				return
			}

		case websocket.MessageText:
			var frame ExecFrame
			if err := json.Unmarshal(body, &frame); err != nil {
				s.log.Debug("bad exec control frame", "error", err)
				continue
			}
			switch frame.Type {
			case "resize":
				select {
				case resize <- runtime.TerminalSize{Width: frame.Width, Height: frame.Height}:
				default:
					// A dropped resize is a cosmetic loss and the next one
					// corrects it. Blocking here would stall stdin.
				}
			case "eof":
				// The client closed its stdin. The remote process sees EOF and
				// decides what that means; the socket stays open for output.
				if err := stdin.Close(); err != nil {
					s.log.Debug("closing exec stdin on eof", "error", err)
				}
			}
		}
	}
}

// awaitPeer waits for the client to close, or gives up.
func (s *execSession) awaitPeer(timeout time.Duration) {
	select {
	case <-s.peerGone:
	case <-time.After(timeout):
		s.log.Debug("exec client did not close within the drain window")
	}
}

// close shuts the socket down once.
func (s *execSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if err := s.conn.Close(websocket.StatusNormalClosure, ""); err != nil {
		s.log.Debug("closing an exec socket", "error", err)
	}
}

// ExecQuery builds the query string for an exec request, so the client and the
// server agree about parameter names in exactly one place.
//
// The command is repeated parameters rather than one joined string: joining
// would mean the server has to split, and every splitting rule is wrong for
// some argument someone will eventually pass.
func ExecQuery(project, alloc string, command []string, tty bool, user string) string {
	values := url.Values{"project": {project}, "alloc": {alloc}, "command": command}
	if tty {
		values.Set("tty", "true")
	}
	if user != "" {
		values.Set("user", user)
	}
	return values.Encode()
}

var errTooManyConnections = errors.New("api: too many live connections")
