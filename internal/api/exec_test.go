package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/audit"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/runtime"
)

// fakeExecer stands in for the containerd driver.
type fakeExecer struct {
	mu sync.Mutex
	// seen records what was asked for.
	seen []runtime.ExecOptions
	// script is written to stdout; echoStdin copies stdin there instead.
	script    string
	stderr    string
	echoStdin bool
	code      uint32
	err       error
	// resized records terminal sizes that arrived.
	resized []runtime.TerminalSize
}

func (f *fakeExecer) ExecStream(
	ctx context.Context, _, _ string, opts runtime.ExecOptions,
) (uint32, error) {
	f.mu.Lock()
	f.seen = append(f.seen, opts)
	f.mu.Unlock()

	if f.err != nil {
		return 0, f.err
	}
	if f.script != "" && opts.Stdout != nil {
		if _, err := io.WriteString(opts.Stdout, f.script); err != nil {
			return 0, err
		}
	}
	if f.stderr != "" && opts.Stderr != nil {
		if _, err := io.WriteString(opts.Stderr, f.stderr); err != nil {
			return 0, err
		}
	}
	if f.echoStdin && opts.Stdin != nil {
		// Read one buffer's worth: the client sends its input and then waits,
		// so blocking for EOF would deadlock a test that never closes stdin.
		buf := make([]byte, 64)
		n, _ := opts.Stdin.Read(buf)
		if n > 0 && opts.Stdout != nil {
			if _, err := opts.Stdout.Write(buf[:n]); err != nil {
				return 0, err
			}
		}
	}
	if opts.Resize != nil {
		// Drain whatever arrived within a moment, so the assertion below is
		// about what was sent rather than about scheduling.
		deadline := time.After(500 * time.Millisecond)
		for {
			select {
			case size, ok := <-opts.Resize:
				if !ok {
					return f.code, nil
				}
				f.mu.Lock()
				f.resized = append(f.resized, size)
				f.mu.Unlock()
				if len(f.resized) > 0 {
					return f.code, nil
				}
			case <-deadline:
				return f.code, nil
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
	}
	return f.code, nil
}

func (f *fakeExecer) calls() []runtime.ExecOptions {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]runtime.ExecOptions(nil), f.seen...)
}

func withExec(e *fakeExecer) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) { cfg.Exec = e }
}

func TestExecStreamsOutputAndExitCode(t *testing.T) {
	fake := &fakeExecer{script: "hello from inside\n", code: 7}
	h := newHarness(t, withExec(fake))

	var stdout bytes.Buffer
	code, err := h.client.Exec(context.Background(), api.ExecOptions{
		Project: "shop", Alloc: "shop-web-0", Command: []string{"/bin/echo", "hi"},
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if code != 7 {
		t.Errorf("exit code = %d, want 7", code)
	}
	if stdout.String() != "hello from inside\n" {
		t.Errorf("stdout = %q", stdout.String())
	}

	calls := fake.calls()
	if len(calls) != 1 {
		t.Fatalf("driver was called %d times", len(calls))
	}
	// The command survives as an argument array. Joining and re-splitting it
	// anywhere would be the command-injection hazard §14 A03 is about.
	if len(calls[0].Command) != 2 || calls[0].Command[1] != "hi" {
		t.Errorf("command = %q, want the argument array intact", calls[0].Command)
	}
}

func TestExecKeepsStderrSeparateWithoutATTY(t *testing.T) {
	// A pipe has two streams and a pseudo-terminal has one. Merging them here
	// would make `kanea exec … -- cmd 2>/dev/null` impossible.
	fake := &fakeExecer{script: "out", stderr: "err"}
	h := newHarness(t, withExec(fake))

	var stdout, stderr bytes.Buffer
	if _, err := h.client.Exec(context.Background(), api.ExecOptions{
		Project: "shop", Alloc: "shop-web-0", Command: []string{"/bin/sh"},
		Stdout: &stdout, Stderr: &stderr,
	}); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if stdout.String() != "out" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "out")
	}
	if stderr.String() != "err" {
		t.Errorf("stderr = %q, want %q", stderr.String(), "err")
	}
}

func TestExecWithATTYMergesTheStreams(t *testing.T) {
	// With a pseudo-terminal there is one stream by definition; asking the
	// driver for a separate stderr would invent a distinction the kernel did
	// not make.
	fake := &fakeExecer{script: "out"}
	h := newHarness(t, withExec(fake))

	if _, err := h.client.Exec(context.Background(), api.ExecOptions{
		Project: "shop", Alloc: "shop-web-0", Command: []string{"/bin/sh"},
		TTY: true, Stdout: io.Discard,
	}); err != nil {
		t.Fatalf("exec: %v", err)
	}
	calls := fake.calls()
	if len(calls) != 1 || !calls[0].TTY {
		t.Fatalf("the driver was not asked for a TTY: %+v", calls)
	}
	if calls[0].Stderr != nil {
		t.Error("a separate stderr was passed alongside a TTY")
	}
}

func TestExecForwardsStdin(t *testing.T) {
	fake := &fakeExecer{echoStdin: true}
	h := newHarness(t, withExec(fake))

	var stdout bytes.Buffer
	if _, err := h.client.Exec(context.Background(), api.ExecOptions{
		Project: "shop", Alloc: "shop-web-0", Command: []string{"/bin/cat"},
		Stdin: strings.NewReader("typed input"), Stdout: &stdout,
	}); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(stdout.String(), "typed input") {
		t.Errorf("stdin did not reach the process: stdout = %q", stdout.String())
	}
}

func TestExecReportsADriverFailureToTheClient(t *testing.T) {
	fake := &fakeExecer{err: errors.New("no such alloc")}
	h := newHarness(t, withExec(fake))

	_, err := h.client.Exec(context.Background(), api.ExecOptions{
		Project: "shop", Alloc: "nope", Command: []string{"/bin/sh"}, Stdout: io.Discard,
	})
	if err == nil {
		t.Fatal("a failed exec reported success")
	}
	if !strings.Contains(err.Error(), "no such alloc") {
		t.Errorf("the reason did not reach the client: %v", err)
	}
}

func TestExecIs503WithoutARuntimeDriver(t *testing.T) {
	h := newHarness(t)
	_, err := h.client.Exec(context.Background(), api.ExecOptions{
		Project: "shop", Alloc: "shop-web-0", Command: []string{"/bin/sh"},
	})
	if err == nil {
		t.Fatal("exec succeeded on a daemon with no runtime driver")
	}
}

func TestExecRefusesIncompleteRequests(t *testing.T) {
	// Every one of these would otherwise reach the driver with something
	// missing and fail there, with a worse message.
	fake := &fakeExecer{}
	h := newHarness(t, withExec(fake))
	ctx := context.Background()

	cases := map[string]api.ExecOptions{
		"no project": {Alloc: "shop-web-0", Command: []string{"/bin/sh"}},
		"no alloc":   {Project: "shop", Command: []string{"/bin/sh"}},
		"no command": {Project: "shop", Alloc: "shop-web-0"},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := h.client.Exec(ctx, opts); err == nil {
				t.Error("accepted")
			}
		})
	}
	if calls := fake.calls(); len(calls) != 0 {
		t.Errorf("the driver was reached %d times by an invalid request", len(calls))
	}
}

// dialExecWS opens the exec websocket against the auth harness as a browser
// would: cookie for identity, subprotocol entries for whatever else rides the
// handshake. It returns the connection (nil on a refused handshake) and the
// HTTP status of the upgrade response.
func dialExecWS(
	t *testing.T, h *authHarness, cookie *http.Cookie, subprotocols []string,
) (*websocket.Conn, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	header := http.Header{}
	header.Set("Cookie", cookie.Name+"="+cookie.Value)
	url := h.server.URL + api.PathExec + "?" +
		api.ExecQuery("shop", "shop-web-0", []string{"/bin/sh"}, false, "")
	conn, resp, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPClient:   h.client,
		HTTPHeader:   header,
		Subprotocols: subprotocols,
	})
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	if err != nil {
		return nil, status
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn, status
}

func TestExecWithACookieAloneIsRefused(t *testing.T) {
	// A cookie is what a cross-site page can ride. Without the CSRF token the
	// handshake must die exactly as a headerless PUT does: this pins the
	// pre-v1.64 behavior as intended for token-less browsers, not as a bug.
	fake := &fakeExecer{}
	h := newAuthHarness(t, withExec(fake))
	cookie, _ := h.login(t, adminUser, adminPass)

	conn, status := dialExecWS(t, h, cookie, nil)
	if conn != nil || status != http.StatusForbidden {
		t.Fatalf("cookie-only exec handshake = %d, want a 403 refusal", status)
	}
	if calls := fake.calls(); len(calls) != 0 {
		t.Errorf("the driver was reached %d times without a CSRF token", len(calls))
	}
}

func TestExecWithTheSubprotocolTokenRuns(t *testing.T) {
	// The browser carrier (PRD v1.64): the token rides Sec-WebSocket-Protocol
	// beside the negotiable name. The server must echo only the name: an
	// echoed token entry would reflect the credential into the response.
	fake := &fakeExecer{code: 7}
	h := newAuthHarness(t, withExec(fake))
	cookie, csrf := h.login(t, adminUser, adminPass)

	conn, status := dialExecWS(t, h, cookie,
		[]string{api.ExecSubprotocol, api.CSRFProtocolPrefix + csrf})
	if conn == nil {
		t.Fatalf("handshake refused with %d, want it accepted", status)
	}
	if got := conn.Subprotocol(); got != api.ExecSubprotocol {
		t.Errorf("negotiated subprotocol = %q, want %q (and never the token)", got, api.ExecSubprotocol)
	}

	// The session actually runs: the driver exits 7 and the frame arrives.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		kind, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if kind != websocket.MessageText {
			continue // stream data, not control
		}
		var frame api.ExecFrame
		if err := json.Unmarshal(data, &frame); err != nil {
			t.Fatalf("decode %q: %v", data, err)
		}
		if frame.Type != "exit" || frame.Code != 7 {
			t.Fatalf("frame = %+v, want exit 7", frame)
		}
		return
	}
}

func TestExecWithAWrongSubprotocolTokenIsRefused(t *testing.T) {
	fake := &fakeExecer{}
	h := newAuthHarness(t, withExec(fake))
	cookie, _ := h.login(t, adminUser, adminPass)

	conn, status := dialExecWS(t, h, cookie,
		[]string{api.ExecSubprotocol, api.CSRFProtocolPrefix + "not-the-token"})
	if conn != nil || status != http.StatusForbidden {
		t.Fatalf("wrong-token handshake = %d, want a 403 refusal", status)
	}
	if calls := fake.calls(); len(calls) != 0 {
		t.Errorf("the driver was reached %d times with a bad token", len(calls))
	}
}

func TestExecIsAdminOnlyAndAudited(t *testing.T) {
	// §14 names exec specifically. A viewer must not get a shell, and an admin
	// who does must leave a record of what they asked to run.
	fake := &fakeExecer{}
	h := newAuthHarness(t, withExec(fake))

	viewerReq := h.request(t, http.MethodGet,
		api.PathExec+"?"+api.ExecQuery("shop", "shop-web-0", []string{"/bin/sh"}, false, ""), nil)
	viewerReq.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	if resp, body := h.do(t, viewerReq); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a viewer got %d on exec, want 403: %s", resp.StatusCode, body)
	}

	page, err := h.audit.List(context.Background(), audit.Filter{Action: "alloc.exec"})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) == 0 {
		t.Fatal("a refused exec left no audit entry")
	}
	if page.Entries[0].Result != "denied" {
		t.Errorf("the audit entry says %q, want denied", page.Entries[0].Result)
	}
}
