package edge

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeUpstream is an HTTP service the edge can forward to.
type fakeUpstream struct {
	host string
	port int
}

func newFakeUpstream(t *testing.T, body string) fakeUpstream {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return splitUpstream(t, strings.TrimPrefix(srv.URL, "http://"))
}

// newFakeTCPUpstream accepts and holds connections, which is all a relay test
// needs on the far side.
func newFakeTCPUpstream(t *testing.T) fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(conn, conn) }()
		}
	}()
	return splitUpstream(t, ln.Addr().String())
}

func splitUpstream(t *testing.T, addr string) fakeUpstream {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	tcp, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatalf("resolve %q: %v", addr, err)
	}
	_ = port
	return fakeUpstream{host: host, port: tcp.Port}
}

// getWithHost issues a request with an explicit Host header.
func getWithHost(t *testing.T, addr, host string) (string, int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return string(body), resp.StatusCode
}

func testListener(port int, mode string) Listener {
	return Listener{
		Project: "media", Service: "jellyfin",
		Port: port, Mode: mode,
		Upstream: "10.201.0.7", UpstreamPort: 8096,
	}
}

// newTestSet builds a listener set that binds on ephemeral ports.
//
// listen is injected rather than mocked away: the properties worth testing here
// (a socket surviving a config change, one bind failing without taking the
// others down) are properties of real sockets.
func newTestSet(t *testing.T) (*listenerSet, map[int]net.Listener) {
	t.Helper()
	set := newListenerSet(NewProxy(ProxyConfig{Logger: slog.New(slog.DiscardHandler)}), Config{
		Logger: slog.New(slog.DiscardHandler),
	})
	bound := map[int]net.Listener{}
	var mu sync.Mutex
	set.listen = func(network, _ string) (net.Listener, error) {
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		mu.Lock()
		defer mu.Unlock()
		bound[ln.Addr().(*net.TCPAddr).Port] = ln
		return ln, nil
	}
	t.Cleanup(func() { set.Shutdown(0) })
	return set, bound
}

// The property the whole rebind rule exists for: an upstream, CIDR or
// connection-cap edit is a configuration swap behind the socket, so a live
// psql session survives a redeploy. Rebinding for a CIDR typo would drop every
// client on the port.
func TestListenerSetDoesNotRebindOnConfigChange(t *testing.T) {
	set, _ := newTestSet(t)

	cfg := testListener(9101, ListenerTCP)
	set.Apply([]Listener{cfg})

	set.mu.Lock()
	entry, ok := set.entries[entryKey{port: 9101}]
	set.mu.Unlock()
	if !ok {
		t.Fatal("the listener was not bound")
	}
	socket := entry.ln

	changed := cfg
	changed.Upstream = "10.201.0.9"
	changed.MaxConns = 12
	changed.IPRestriction = &IPRestriction{Allow: []string{"192.168.0.0/16"}}
	set.Apply([]Listener{changed})

	set.mu.Lock()
	after := set.entries[entryKey{port: 9101}]
	set.mu.Unlock()
	if after.ln != socket {
		t.Error("a configuration change rebound the socket; every live connection would have dropped")
	}
	if got, _ := after.relay.config(); got.Upstream != "10.201.0.9" || got.MaxConns != 12 {
		t.Errorf("the new configuration did not take effect: %+v", got)
	}
}

// A change of kind is the one thing that has to rebind: an http server and a
// byte relay cannot share a socket.
func TestListenerSetRebindsOnAModeChange(t *testing.T) {
	set, _ := newTestSet(t)

	set.Apply([]Listener{testListener(9102, ListenerTCP)})
	set.mu.Lock()
	before := set.entries[entryKey{port: 9102}].ln
	set.mu.Unlock()

	set.Apply([]Listener{testListener(9102, ListenerHTTP)})
	set.mu.Lock()
	after := set.entries[entryKey{port: 9102}]
	set.mu.Unlock()

	if after.ln == before {
		t.Error("switching from tcp to http kept the same socket")
	}
	if after.srv == nil || after.relay != nil {
		t.Error("the rebound listener is not an http server")
	}
	if !rebindRequired(testListener(1, ListenerTCP), testListener(1, ListenerHTTP)) {
		t.Error("rebindRequired does not see a mode change")
	}
	if rebindRequired(testListener(1, ListenerTCP), testListener(1, ListenerTCP)) {
		t.Error("rebindRequired fires on an unchanged listener")
	}
}

// A port something else on the node already holds must not take the rest of the
// snapshot with it. Apply returns no error at all, and the failure is a state
// an operator can read rather than a rejected file.
func TestListenerBindFailureIsNotFatal(t *testing.T) {
	set, _ := newTestSet(t)
	set.listen = func(network, address string) (net.Listener, error) {
		if strings.HasSuffix(address, ":9201") {
			return nil, errors.New("address already in use")
		}
		return net.Listen(network, "127.0.0.1:0")
	}

	set.Apply([]Listener{testListener(9201, ListenerTCP), testListener(9202, ListenerTCP)})

	set.mu.Lock()
	_, blocked := set.entries[entryKey{port: 9201}]
	_, other := set.entries[entryKey{port: 9202}]
	set.mu.Unlock()
	if blocked {
		t.Error("a port that could not bind is recorded as bound")
	}
	if !other {
		t.Fatal("one failed bind stopped the other listener")
	}

	var reported bool
	for _, state := range set.States() {
		if state.Listener.Port == 9201 {
			reported = true
			if state.Bound || !strings.Contains(state.Error, "in use") {
				t.Errorf("state = %+v, want an unbound listener naming why", state)
			}
		}
	}
	if !reported {
		t.Error("a failed bind vanished instead of being reported")
	}
}

// Removing a published port closes its socket. Otherwise the edge would keep
// answering on a port nothing declares any more.
func TestListenerSetWithdrawsAPort(t *testing.T) {
	set, _ := newTestSet(t)
	set.Apply([]Listener{testListener(9301, ListenerTCP)})

	set.mu.Lock()
	socket := set.entries[entryKey{port: 9301}].ln
	set.mu.Unlock()

	set.Apply(nil)
	set.mu.Lock()
	_, still := set.entries[entryKey{port: 9301}]
	set.mu.Unlock()
	if still {
		t.Fatal("the listener was not withdrawn")
	}
	if _, err := socket.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("the withdrawn socket is still open (accept error = %v)", err)
	}
}

// A published http listener serves the service it was bound for without
// consulting the Host header: the header on a connection to an IP literal
// would match no domain.
func TestPublishedHTTPListenerIgnoresTheHostHeader(t *testing.T) {
	upstream := newFakeUpstream(t, "jellyfin")
	set, _ := newTestSet(t)

	cfg := testListener(9401, ListenerHTTP)
	cfg.Upstream, cfg.UpstreamPort = upstream.host, upstream.port
	set.Apply([]Listener{cfg})

	set.mu.Lock()
	addr := set.entries[entryKey{port: 9401}].ln.Addr().String()
	set.mu.Unlock()

	for _, host := range []string{"192.168.1.10:9401", "anything.invalid", ""} {
		body, status := getWithHost(t, addr, host)
		if status != 200 || !strings.Contains(body, "jellyfin") {
			t.Errorf("Host %q: status %d body %q, want the bound service", host, status, body)
		}
	}
}

// Shutdown closes live connections once the drain elapses. A relay has no
// natural completion point, so there is nothing to wait for except the clock.
func TestListenerShutdownClosesLiveConnections(t *testing.T) {
	upstream := newFakeTCPUpstream(t)
	set, _ := newTestSet(t)

	cfg := testListener(9501, ListenerTCP)
	cfg.Upstream, cfg.UpstreamPort = upstream.host, upstream.port
	set.Apply([]Listener{cfg})

	set.mu.Lock()
	addr := set.entries[entryKey{port: 9501}].ln.Addr().String()
	set.mu.Unlock()

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	waitFor(t, func() bool { return set.InFlight() == 1 }, "the connection was never relayed")

	set.Shutdown(10 * time.Millisecond)
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("a live connection survived the drain deadline")
	}
}
