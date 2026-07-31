package network

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// testAgent is a stand-in cilium-agent on a unix socket. The socket matters:
// the transport is the part most likely to be wrong, and an httptest server on
// TCP would not exercise it.
func testAgent(t *testing.T, h http.Handler) *client {
	t.Helper()

	// Unix socket paths are capped near 104 bytes on darwin, and a Go test's
	// TempDir is already long — hence the short name rather than t.TempDir().
	dir, err := os.MkdirTemp("", "kn")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	return newClient(sock, 5*time.Second)
}

// testAllocID is the alloc every test in this package attaches. It is long
// enough to satisfy the 5-character CNI floor, which is itself under test.
const testAllocID = "shop-web-0"

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

// endpointJSON builds an agent-shaped endpoint document.
func endpointJSON(allocID string, identity int64, state, ip string, labels []string) map[string]any {
	return map[string]any{
		"id": int64(1234),
		"status": map[string]any{
			"external-identifiers": map[string]any{"container-id": allocID},
			"identity":             map[string]any{"id": identity, "labels": labels},
			"networking": map[string]any{
				"addressing":     []map[string]any{{"ipv4": ip}},
				"interface-name": "lxc1234",
			},
			"state": state,
		},
	}
}

func readyEndpoint(allocID, ip string) map[string]any {
	return endpointJSON(allocID, 1851, endpointStateReady, ip,
		[]string{"k8s:io.kubernetes.pod.namespace=shop", "unspec:kanea=true",
			"unspec:project=shop", "unspec:service=web"})
}

func TestClientEndpointByAlloc(t *testing.T) {
	c := testAgent(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/endpoint/container-id:shop-web-0" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		writeJSON(t, w, readyEndpoint("shop-web-0", "10.200.1.71"))
	}))

	ep, err := c.endpointByAlloc(t.Context(), "shop-web-0")
	if err != nil {
		t.Fatalf("endpointByAlloc: %v", err)
	}
	if ep.ipv4() != "10.200.1.71" {
		t.Errorf("ipv4 = %q, want 10.200.1.71", ep.ipv4())
	}
	if !ep.ready() {
		t.Errorf("endpoint should be ready: %+v", ep.Status)
	}
}

func TestClientEndpointNotFound(t *testing.T) {
	c := testAgent(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	_, err := c.endpointByAlloc(t.Context(), "shop-web-0")
	if !errors.Is(err, ErrEndpointNotFound) {
		t.Fatalf("error = %v, want ErrEndpointNotFound", err)
	}
}

// An endpoint that still carries reserved:init has its traffic denied in both
// directions, so "the agent answered 200" is not the readiness signal.
func TestEndpointReadiness(t *testing.T) {
	tests := []struct {
		name     string
		identity int64
		state    string
		labels   []string
		want     bool
	}{
		{
			name: "resolved identity", identity: 1851, state: endpointStateReady,
			labels: []string{"unspec:project=shop"}, want: true,
		},
		{
			name: "still init", identity: 5, state: endpointStateReady,
			labels: []string{initLabel},
		},
		{
			name: "reserved identity", identity: 4, state: endpointStateReady,
			labels: []string{"reserved:health"},
		},
		{
			name: "regenerating", identity: 1851, state: "waiting-for-identity",
			labels: []string{"unspec:project=shop"},
		},
		{
			// Real identity allocated, but the init label has not been cleared:
			// enforcement follows the labels, so this is not ready.
			name: "identity allocated but init label lingers", identity: 1851,
			state: endpointStateReady, labels: []string{initLabel, "unspec:project=shop"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ep endpoint
			ep.Status.Identity.ID = tc.identity
			ep.Status.Identity.Labels = tc.labels
			ep.Status.State = tc.state
			if got := ep.ready(); got != tc.want {
				t.Fatalf("ready = %v, want %v", got, tc.want)
			}
		})
	}
}

// Roughly one attach in eight hits a 500 because the endpoint is still
// regenerating (spike ①). Treating that as an attach failure would leave allocs
// unlabelled — and therefore cut off — for no reason.
func TestSetIdentityLabelsRetriesServerErrors(t *testing.T) {
	var calls atomic.Int32
	c := testAgent(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(w, "error while regenerating endpoint", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	retry := backoff{Attempts: 6, Step: time.Millisecond}
	if err := c.setIdentityLabels(t.Context(), "shop-web-0", IdentityLabels("shop", "web"), retry); err != nil {
		t.Fatalf("setIdentityLabels: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("agent called %d times, want 3", got)
	}
}

// A 4xx is a malformed request — the classic being a body without `state`,
// which the agent rejects with 422. Retrying that just delays the real error.
func TestSetIdentityLabelsDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	c := testAgent(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "endpoint state is required", http.StatusUnprocessableEntity)
	}))

	retry := backoff{Attempts: 6, Step: time.Millisecond}
	err := c.setIdentityLabels(t.Context(), "shop-web-0", nil, retry)
	if err == nil {
		t.Fatal("setIdentityLabels = nil, want error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("agent called %d times, want 1", got)
	}
}

func TestSetIdentityLabelsSendsState(t *testing.T) {
	var body map[string]any
	c := testAgent(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))

	labels := IdentityLabels("shop", "web")
	if err := c.setIdentityLabels(t.Context(), "shop-web-0", labels, backoff{Attempts: 1, Step: time.Millisecond}); err != nil {
		t.Fatalf("setIdentityLabels: %v", err)
	}
	// Without `state` the agent answers 422/602 and the endpoint keeps
	// reserved:init — silently, from the caller's point of view.
	if body["state"] != "waiting-for-identity" {
		t.Errorf("state = %v, want waiting-for-identity", body["state"])
	}
	if got, ok := body["labels"].([]any); !ok || len(got) != len(labels) {
		t.Errorf("labels = %v, want %d entries", body["labels"], len(labels))
	}
}

func TestSetIdentityLabelsHonoursCancellation(t *testing.T) {
	c := testAgent(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "regenerating", http.StatusInternalServerError)
	}))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := c.setIdentityLabels(ctx, "shop-web-0", nil, backoff{Attempts: 6, Step: time.Hour})
	if err == nil {
		t.Fatal("expected an error from a cancelled context")
	}
}

func TestClientAgentUnavailable(t *testing.T) {
	c := newClient(filepath.Join(t.TempDir(), "absent.sock"), time.Second)

	err := c.health(t.Context())
	if !errors.Is(err, ErrAgentUnavailable) {
		t.Fatalf("error = %v, want ErrAgentUnavailable", err)
	}
}

func TestClientEndpointsEmptyAgent(t *testing.T) {
	// An agent with nothing attached answers 404, not an empty array.
	c := testAgent(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	eps, err := c.endpoints(t.Context())
	if err != nil {
		t.Fatalf("endpoints: %v", err)
	}
	if len(eps) != 0 {
		t.Fatalf("endpoints = %v, want none", eps)
	}
}
