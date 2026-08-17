package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Backend is how a tool reaches the platform: by making an HTTP request against
// Kanea's own API.
//
// This is the whole of §16.3's "no side channels, no privileged backdoors", and
// it is structural rather than a promise. A tool cannot read the Store, cannot
// hold a secrets store, and cannot decide that an agent is allowed to do
// something: the only verb it has is "send this request", and the request lands
// on the same authenticated, authorized, rate-limited, audited handler the CLI
// and the dashboard reach. A privilege escalation in a tool would have to be a
// privilege escalation in the API, which is the surface that already gets the
// scrutiny.
type Backend interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// Session is what the transport knows about the caller, replayed onto every
// request the tools make on their behalf.
//
// Carrying the credential rather than resolving an identity from it once: the
// API decides who a caller is, on every request, and a token revoked between
// two tool calls stops working at the second one.
type Session struct {
	// Header carries the caller's credentials (Authorization, Cookie, the CSRF
	// token) and nothing else. It is built from an allowlist (see
	// SessionFromRequest), because forwarding a whole request's headers into a
	// synthesized one is how a client-supplied X-Forwarded-For ends up in an
	// audit entry.
	Header http.Header
	// Source is the caller's address, for the audit trail and the rate limiter.
	Source string
}

// forwarded are the request headers a tool call inherits from its caller.
// Everything else is set by the tool.
var forwarded = []string{"Authorization", "Cookie", "X-Kanea-CSRF"}

// SessionFromRequest extracts the caller's credentials from a transport request.
func SessionFromRequest(r *http.Request) *Session {
	sess := &Session{Header: http.Header{}, Source: r.RemoteAddr}
	for _, name := range forwarded {
		if v := r.Header.Values(name); len(v) > 0 {
			sess.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), v...)
		}
	}
	return sess
}

// apply attaches the session's credentials to an outgoing request.
func (s *Session) apply(req *http.Request) {
	if s == nil {
		return
	}
	for name, values := range s.Header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	if s.Source != "" {
		req.RemoteAddr = s.Source
	}
}

// ---- in-process backend ----

// HandlerBackend calls an http.Handler directly, with no socket in between.
//
// This is the streamable-HTTP transport's backend: kanead is already serving
// the handler, so a tool call is a function call that happens to be shaped like
// a request. The alternative (dialling its own unix socket) would be the same
// requests with a round trip and a second set of connection limits, to reach a
// server in the same process.
type HandlerBackend struct {
	// Handler resolves lazily. The API server mounts the MCP transport, and the
	// MCP server calls back into the API server's handler, so one of them has to
	// be told about the other after both exist. A function is the honest way to
	// say that; a nil handler here is a wiring bug and reports itself as one.
	Handler func() http.Handler
}

// Do runs the request through the handler and collects the response.
func (b HandlerBackend) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if b.Handler == nil {
		return nil, errors.New("mcp: no API handler is wired to this backend")
	}
	handler := b.Handler()
	if handler == nil {
		return nil, errors.New("mcp: the API handler is not ready yet")
	}

	rec := &recorder{header: http.Header{}, status: http.StatusOK}
	handler.ServeHTTP(rec, req.WithContext(ctx))

	return &http.Response{
		StatusCode: rec.status,
		Header:     rec.header,
		Body:       io.NopCloser(bytes.NewReader(rec.body.Bytes())),
		Request:    req,
	}, nil
}

// recorder is an http.ResponseWriter that keeps what was written.
//
// Bounded, unlike httptest's: a tool result is capped anyway, and a handler that
// streams (the log routes do) must not be able to fill memory before the cap
// is applied. Writes past the limit are dropped and counted rather than
// erroring, because a handler that gets a write error mid-stream logs it as a
// client disconnect, which is not what happened.
type recorder struct {
	header    http.Header
	status    int
	body      bytes.Buffer
	written   bool
	truncated bool
}

// maxResponseBytes bounds one backend response. Generous next to any JSON this
// API produces, and far below what a followed log stream would be.
const maxResponseBytes = 4 << 20

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if !r.written {
		r.status, r.written = status, true
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	r.written = true
	if room := maxResponseBytes - r.body.Len(); room > 0 {
		if len(b) > room {
			b, r.truncated = b[:room], true
		}
		return r.body.Write(b)
	}
	r.truncated = true
	// Reported as written: the caller asked to write it, and telling a streaming
	// handler that its write was short makes it retry or abort a stream that is
	// already as long as anyone is going to read.
	return len(b), nil
}

// Flush satisfies the streaming handlers, which check for it before they will
// send anything incrementally. There is nothing to flush to.
func (r *recorder) Flush() {}

// ---- socket backend ----

// SocketBackend talks to a running kanead over its unix socket. It is what
// `kanea mcp` uses: a separate process, holding the same credential the CLI
// does; the socket itself.
type SocketBackend struct {
	client *http.Client
	socket string
}

// NewSocketBackend builds a backend for the given socket path.
func NewSocketBackend(socket string) *SocketBackend {
	return &SocketBackend{
		socket: socket,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

// Do sends the request over the socket.
func (b *SocketBackend) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	resp, err := b.client.Do(req.WithContext(ctx))
	if err != nil {
		var netErr *net.OpError
		if errors.As(err, &netErr) {
			return nil, fmt.Errorf("cannot reach kanead at %s (is it running?): %w", b.socket, err)
		}
		return nil, err
	}
	return resp, nil
}

// ---- calling ----

// call makes one request on the caller's behalf and returns the decoded body.
//
// Every tool goes through here, which is what keeps the credential handling,
// the size cap and the error shape in one place instead of thirteen.
func (s *Server) call(
	ctx context.Context, sess *Session, method, path string, body any, out any,
) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	// The host is a placeholder: the unix backend ignores it, and the in-process
	// one never resolves it. It has to be *something* for http.NewRequest.
	req, err := http.NewRequestWithContext(ctx, method, "http://kanead"+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	sess.apply(req)

	resp, err := s.backend.Do(ctx, req)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return statusFrom(resp)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// callText makes a request whose body is not JSON: the log routes.
func (s *Server) callText(ctx context.Context, sess *Session, path string) (_ string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://kanead"+path, nil)
	if err != nil {
		return "", err
	}
	sess.apply(req)

	resp, err := s.backend.Do(ctx, req)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", statusFrom(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// statusError is a refusal from the API, carrying the status so a tool can say
// what kind of refusal it was.
type statusError struct {
	Status  int
	Message string
}

func (e *statusError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		// Named explicitly, because "not authorised" arriving at a model reads
		// as something to work around. It is not: the daemon decided, this
		// server does not overrule it, and another attempt produces the same
		// answer.
		return "not permitted: " + e.Message +
			" (the daemon refused this; the token's role does not allow it)"
	case http.StatusNotFound:
		return "not found: " + e.Message
	default:
		return e.Message
	}
}

// statusFrom reads the API's error body, which is a JSON object with one field.
func statusFrom(resp *http.Response) error {
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err == nil && body.Error != "" {
		return &statusError{Status: resp.StatusCode, Message: body.Error}
	}
	return &statusError{Status: resp.StatusCode, Message: resp.Status}
}

// query builds a path with a query string, omitting empty values.
func query(path string, pairs ...string) string {
	values := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			values.Set(pairs[i], pairs[i+1])
		}
	}
	if len(values) == 0 {
		return path
	}
	return path + "?" + values.Encode()
}

// escape makes a string safe to place in a path segment.
func escape(s string) string { return url.PathEscape(s) }

// trimTo caps a tool's textual result.
//
// Every tool's output passes through this. An agent's context is finite and a
// service with two thousand allocs would fill it with one call, but the reason
// it is here rather than in each tool is §16.3's rule that payloads are capped:
// a rule enforced in one place is a rule, and a rule enforced in thirteen is a
// convention.
func trimTo(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	// Cut at a line boundary where one is near, so the result does not end
	// mid-token and invite the model to reason about a truncated identifier.
	cut := s[:limit]
	if idx := strings.LastIndexByte(cut, '\n'); idx > limit/2 {
		cut = cut[:idx]
	}
	return cut + fmt.Sprintf("\n\n[truncated: %d of %d bytes shown]", len(cut), len(s))
}
