package edge

// The functions port (PRD §7.2.3): path dispatch, prefix stripping, the
// middleware chain, and the bind lifecycle.

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestFunctionsSet binds on an ephemeral port; real sockets, like the
// listener tests, because a bind lifecycle is a property of sockets.
func newTestFunctionsSet(t *testing.T, port int) *functionsSet {
	t.Helper()
	set := newFunctionsSet(NewProxy(ProxyConfig{Logger: slog.New(slog.DiscardHandler)}), Config{
		Logger: slog.New(slog.DiscardHandler), FunctionsPort: port,
	})
	set.listen = func(network, _ string) (net.Listener, error) {
		return net.Listen(network, "127.0.0.1:0")
	}
	t.Cleanup(set.Shutdown)
	return set
}

// echoUpstream answers with the path it was asked for, which is exactly what a
// prefix-strip test needs to see.
func echoUpstream(t *testing.T) fakeUpstream {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "path="+r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return splitUpstream(t, strings.TrimPrefix(srv.URL, "http://"))
}

func getURL(t *testing.T, url string) (string, int) {
	t.Helper()
	resp, err := http.Get(url) // #nosec G107 — test URL
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(body), resp.StatusCode
}

func TestFunctionsPortDispatchesByPathAndStripsThePrefix(t *testing.T) {
	up := echoUpstream(t)
	set := newTestFunctionsSet(t, 9440)
	set.Apply([]FunctionRoute{{
		Project: "shop", Function: "resize-avatar",
		Upstream: up.host, UpstreamPort: up.port,
	}})
	if set.Addr() == "" {
		t.Fatal("the functions port did not bind")
	}

	// The function sees its own namespace, not the dispatch prefix (R26).
	body, code := getURL(t, "http://"+set.Addr()+"/shop/resize-avatar/thumb?w=64")
	if code != http.StatusOK || body != "path=/thumb" {
		t.Fatalf("dispatch = %d %q, want 200 path=/thumb", code, body)
	}

	// A bare prefix means the function's root.
	body, code = getURL(t, "http://"+set.Addr()+"/shop/resize-avatar")
	if code != http.StatusOK || body != "path=/" {
		t.Fatalf("bare prefix = %d %q, want 200 path=/", code, body)
	}

	// An unknown function is a 404, not a fallthrough to some other function.
	if _, code := getURL(t, "http://"+set.Addr()+"/shop/unknown/x"); code != http.StatusNotFound {
		t.Fatalf("unknown function = %d, want 404", code)
	}
	if _, code := getURL(t, "http://"+set.Addr()+"/"); code != http.StatusNotFound {
		t.Fatalf("bare root = %d, want 404", code)
	}
}

// The §7.2.1 chain applies on the functions port the way it does on any http
// listener — a control the spec declared and the dispatcher dropped would be
// R16's silently-ignored rule all over again.
func TestFunctionsPortAppliesMiddleware(t *testing.T) {
	up := echoUpstream(t)
	set := newTestFunctionsSet(t, 9441)
	set.Apply([]FunctionRoute{{
		Project: "shop", Function: "locked",
		Upstream: up.host, UpstreamPort: up.port,
		IPRestriction: &IPRestriction{Allow: []string{"203.0.113.0/24"}},
	}})

	// The test client dials from 127.0.0.1, which the allowlist does not hold.
	if _, code := getURL(t, "http://"+set.Addr()+"/shop/locked/"); code != http.StatusForbidden {
		t.Fatalf("ip-restricted function answered %d, want 403", code)
	}
}

// An emptied table releases the port; a refilled one rebinds it. A port held
// open for nothing is a port something else on the node cannot use.
func TestFunctionsPortLifecycle(t *testing.T) {
	up := echoUpstream(t)
	set := newTestFunctionsSet(t, 9442)
	route := FunctionRoute{
		Project: "shop", Function: "fn",
		Upstream: up.host, UpstreamPort: up.port,
	}

	set.Apply([]FunctionRoute{route})
	if set.Addr() == "" {
		t.Fatal("did not bind on a non-empty table")
	}
	set.Apply(nil)
	if set.Addr() != "" {
		t.Fatal("did not release the port on an empty table")
	}
	set.Apply([]FunctionRoute{route})
	if set.Addr() == "" {
		t.Fatal("did not rebind when routes returned")
	}
}

// No port configured: routes must not bind anything, and must not reject the
// snapshot — the rest of the file serves, and the condition is a warning.
func TestFunctionsPortDisabledIsANoOp(t *testing.T) {
	set := newTestFunctionsSet(t, 0)
	set.Apply([]FunctionRoute{{
		Project: "shop", Function: "fn", Upstream: "10.201.0.7", UpstreamPort: 8080,
	}})
	if set.Addr() != "" {
		t.Fatal("a disabled functions port bound a socket")
	}
}

func TestSplitFunctionPath(t *testing.T) {
	tests := []struct {
		in                      string
		project, function, rest string
		ok                      bool
	}{
		{"/shop/fn", "shop", "fn", "/", true},
		{"/shop/fn/", "shop", "fn", "/", true},
		{"/shop/fn/a/b", "shop", "fn", "/a/b", true},
		{"/", "", "", "", false},
		{"/shop", "", "", "", false},
		{"/shop/", "", "", "", false},
		{"//fn", "", "", "", false},
	}
	for _, tc := range tests {
		project, function, rest, ok := splitFunctionPath(tc.in)
		if project != tc.project || function != tc.function || rest != tc.rest || ok != tc.ok {
			t.Errorf("splitFunctionPath(%q) = (%q, %q, %q, %v), want (%q, %q, %q, %v)",
				tc.in, project, function, rest, ok, tc.project, tc.function, tc.rest, tc.ok)
		}
	}
}

// Snapshot validation covers the functions table like it covers routes and
// listeners: collisions and bad addresses are refused on both sides of the
// file.
func TestSnapshotValidatesFunctions(t *testing.T) {
	base := FunctionRoute{
		Project: "shop", Function: "fn", Upstream: "10.201.0.7", UpstreamPort: 8080,
	}
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		want   string
	}{
		{"valid", func(*Snapshot) {}, ""},
		{
			"duplicate prefix",
			func(s *Snapshot) { s.Functions = append(s.Functions, base) },
			"claimed by both",
		},
		{
			"no function name",
			func(s *Snapshot) { s.Functions[0].Function = "" },
			"no project or function",
		},
		{
			"bad upstream",
			func(s *Snapshot) { s.Functions[0].Upstream = "not-an-address" },
			"not an address",
		},
		{
			"bad upstream port",
			func(s *Snapshot) { s.Functions[0].UpstreamPort = 0 },
			"out of range",
		},
		{
			"uncompilable middleware",
			func(s *Snapshot) {
				s.Functions[0].IPRestriction = &IPRestriction{Allow: []string{"not-a-cidr"}}
			},
			"not-a-cidr",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := Snapshot{Functions: []FunctionRoute{base}}
			tc.mutate(&snap)
			err := snap.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("valid snapshot refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want mention of %q", err, tc.want)
			}
		})
	}
}
