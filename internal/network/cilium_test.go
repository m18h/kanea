package network

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/runtime"
)

// fakeNode records what Attach and Detach do to the node, in order. The order
// is the point: netns → CNI ADD → label PATCH → (caller starts the task) is the
// contract this package exists to keep, and getting it wrong produces a
// workload that runs with its traffic silently denied (M0 spike ①).
type fakeNode struct {
	mu    sync.Mutex
	steps []string

	ns      map[string]bool
	addErr  error
	delErr  error
	addedIP string
}

func newFakeNode() *fakeNode {
	return &fakeNode{ns: map[string]bool{}, addedIP: "10.200.1.71"}
}

func (f *fakeNode) record(step string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps = append(f.steps, step)
}

func (f *fakeNode) taken() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.steps)
}

func (f *fakeNode) add(_ context.Context, allocID, netnsPath string) (string, error) {
	f.record("cni-add")
	if netnsPath == "" {
		return "", errors.New("cni add without a netns")
	}
	f.mu.Lock()
	exists := f.ns[allocID]
	f.mu.Unlock()
	if !exists {
		// CNI ADD against a namespace that does not exist is exactly the bug
		// the ordering rule prevents.
		return "", errors.New("cni add before the netns existed")
	}
	return f.addedIP, f.addErr
}

func (f *fakeNode) del(_ context.Context, allocID, _ string) error {
	f.record("cni-del")
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.ns[allocID] && f.delErr == nil {
		// CNI DEL needs the namespace to still exist in order to clean up
		// (M0 spike ②) — tearing the namespace down first strands the endpoint.
		return errors.New("cni del after the netns was gone")
	}
	return f.delErr
}

func (f *fakeNode) ops() netnsOps {
	return netnsOps{
		create: func(allocID string) (string, error) {
			f.record("netns-create")
			f.mu.Lock()
			defer f.mu.Unlock()
			f.ns[allocID] = true
			return "/run/netns/" + allocID, nil
		},
		path: func(allocID string) string { return "/run/netns/" + allocID },
		delete: func(allocID string) error {
			f.record("netns-delete")
			f.mu.Lock()
			defer f.mu.Unlock()
			delete(f.ns, allocID)
			return nil
		},
		exists: func(allocID string) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.ns[allocID]
		},
	}
}

// testCilium builds a driver whose agent is an httptest server and whose node
// effects are recorded rather than performed.
func testCilium(t *testing.T, node *fakeNode, h http.Handler) *Cilium {
	t.Helper()
	c, err := New(Config{IdentityTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.client = testAgent(t, h)
	c.labelRetry = backoff{Attempts: 2, Step: time.Millisecond}
	c.cni = node
	c.netns = node.ops()
	return c
}

// agentScript answers endpoint lookups with whatever the current phase says,
// and records the PATCH that flips it to ready — a fake agent, not a mock.
type agentScript struct {
	mu       sync.Mutex
	steps    *fakeNode
	attached bool
	labels   []string
	patches  int
}

func (a *agentScript) handler(t *testing.T, ip string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()

		if r.Method == http.MethodPatch {
			a.steps.record("label-patch")
			a.patches++
			a.attached = true
			a.labels = []string{"unspec:kanea=true", "unspec:project=shop", "unspec:service=web"}
			w.WriteHeader(http.StatusOK)
			return
		}
		if !a.attached {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(t, w, endpointJSON(testAllocID, 1851, endpointStateReady, ip, a.labels))
	}
}

func TestAttachOrdering(t *testing.T) {
	node := newFakeNode()
	script := &agentScript{steps: node}
	c := testCilium(t, node, script.handler(t, "10.200.1.71"))

	spec := runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "web"}
	if err := c.Attach(t.Context(), spec); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	want := []string{"netns-create", "cni-add", "label-patch"}
	if got := node.taken(); !slices.Equal(got, want) {
		t.Fatalf("attach steps = %v, want %v", got, want)
	}
}

func TestDetachOrdering(t *testing.T) {
	node := newFakeNode()
	node.ns["shop-web-0"] = true
	c := testCilium(t, node, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	spec := runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "web"}
	if err := c.Detach(t.Context(), spec); err != nil {
		t.Fatalf("Detach: %v", err)
	}

	// CNI DEL first: the plugin enters the namespace to clean up.
	want := []string{"cni-del", "netns-delete"}
	if got := node.taken(); !slices.Equal(got, want) {
		t.Fatalf("detach steps = %v, want %v", got, want)
	}
}

// A failed CNI DEL while the namespace is still there is a real leak — the
// endpoint and its IP allocation stay behind — and must not be swallowed.
func TestDetachReportsRealCleanupFailure(t *testing.T) {
	node := newFakeNode()
	node.ns["shop-web-0"] = true
	node.delErr = errors.New("plugin exploded")
	c := testCilium(t, node, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	err := c.Detach(t.Context(), runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "web"})
	if err == nil {
		t.Fatal("Detach = nil, want the CNI DEL failure")
	}
}

// With the namespace already gone the teardown has effectively happened, and
// failing here would wedge the alloc in a state no retry can leave.
func TestDetachToleratesFailureAfterNetnsIsGone(t *testing.T) {
	node := newFakeNode()
	node.delErr = errors.New("no such netns")
	c := testCilium(t, node, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	if err := c.Detach(t.Context(), runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "web"}); err != nil {
		t.Fatalf("Detach = %v, want nil", err)
	}
}

// The reconciler retries Attach. A second CNI ADD on an attached container
// mints a second endpoint and orphans the first, so an already-ready alloc must
// be a complete no-op.
func TestAttachIsANoOpWhenAlreadyReady(t *testing.T) {
	node := newFakeNode()
	script := &agentScript{steps: node, attached: true, labels: []string{
		"k8s:io.kubernetes.pod.namespace=shop", "unspec:kanea=true",
		"unspec:project=shop", "unspec:service=web",
	}}
	c := testCilium(t, node, script.handler(t, "10.200.1.71"))

	spec := runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "web"}
	if err := c.Attach(t.Context(), spec); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if got := node.taken(); len(got) != 0 {
		t.Fatalf("Attach touched the node for a ready alloc: %v", got)
	}
	if script.patches != 0 {
		t.Errorf("Attach re-patched labels on a ready endpoint")
	}
}

// An attach that got as far as CNI ADD but never landed its labels must resume
// at the PATCH, not start over: the endpoint exists, and re-adding it leaks.
func TestAttachResumesAfterLabelFailure(t *testing.T) {
	node := newFakeNode()
	node.ns["shop-web-0"] = true
	script := &agentScript{steps: node, attached: true, labels: []string{initLabel}}
	c := testCilium(t, node, script.handler(t, "10.200.1.71"))

	spec := runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "web"}
	if err := c.Attach(t.Context(), spec); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	if got := node.taken(); slices.Contains(got, "cni-add") {
		t.Fatalf("Attach re-ran CNI ADD on an existing endpoint: %v", got)
	}
	if script.patches != 1 {
		t.Fatalf("label patches = %d, want 1", script.patches)
	}
}

// The same alloc id under a different service means a stale endpoint survived
// teardown. Identity is what every policy matches on, so accepting it silently
// would be a policy bypass.
func TestAttachRelabelsForeignIdentity(t *testing.T) {
	node := newFakeNode()
	node.ns["shop-web-0"] = true
	script := &agentScript{steps: node, attached: true, labels: []string{
		"unspec:kanea=true", "unspec:project=shop", "unspec:service=api",
	}}
	c := testCilium(t, node, script.handler(t, "10.200.1.71"))

	spec := runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "web"}
	if err := c.Attach(t.Context(), spec); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if script.patches != 1 {
		t.Fatalf("label patches = %d, want the endpoint to be re-labelled once", script.patches)
	}
}

func TestAttachFailsWhenCNIReturnsNoAddress(t *testing.T) {
	node := newFakeNode()
	node.addedIP = ""
	script := &agentScript{steps: node}
	c := testCilium(t, node, script.handler(t, ""))

	err := c.Attach(t.Context(), runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "web"})
	if err == nil || !strings.Contains(err.Error(), "invalid address") {
		t.Fatalf("Attach = %v, want an invalid-address error", err)
	}
}

func TestValidateAttach(t *testing.T) {
	tests := []struct {
		name string
		spec runtime.AllocSpec
		want string
	}{
		{
			name: "valid",
			spec: runtime.AllocSpec{ID: "shop-web-0", Project: "shop", Service: "web"},
		},
		{
			// Cilium builds an interface name from the first 5 characters of
			// "<id>:<ifname>"; a shorter id leaks the ':' and CNI ADD fails with
			// a bare "invalid argument" (spike ①).
			name: "alloc id too short",
			spec: runtime.AllocSpec{ID: "ab", Project: "shop", Service: "web"},
			want: "at least 5",
		},
		{
			name: "empty project",
			spec: runtime.AllocSpec{ID: "shop-web-0", Service: "web"},
			want: "empty project name",
		},
		{
			name: "project would corrupt the label set",
			spec: runtime.AllocSpec{ID: "shop-web-0", Project: "shop=evil", Service: "web"},
			want: "not valid in a label",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAttach(tc.spec)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("validateAttach = %v, want nil", err)
			case tc.want == "":
			case err == nil:
				t.Fatalf("validateAttach = nil, want error containing %q", tc.want)
			case !strings.Contains(err.Error(), tc.want):
				t.Fatalf("validateAttach = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestWaitReadyReportsWhyItFailed(t *testing.T) {
	node := newFakeNode()
	c := testCilium(t, node, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, endpointJSON("shop-web-0", 5, "waiting-for-identity",
			"10.200.1.71", []string{initLabel}))
	}))

	_, err := c.waitReady(t.Context(), "shop-web-0")
	if err == nil {
		t.Fatal("waitReady = nil, want timeout error")
	}
	// "timeout" alone sends an operator to the wrong subsystem; the stuck state
	// and the init label are the actual diagnosis.
	for _, want := range []string{"waiting-for-identity", initLabel} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not mention %q", err, want)
		}
	}
}

func TestWaitReadyReportsMissingEndpoint(t *testing.T) {
	node := newFakeNode()
	c := testCilium(t, node, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	_, err := c.waitReady(t.Context(), "shop-web-0")
	if err == nil || !strings.Contains(err.Error(), "never appeared") {
		t.Fatalf("error = %v, want a 'never appeared' diagnosis", err)
	}
}

func TestAttachments(t *testing.T) {
	node := newFakeNode()
	c := testCilium(t, node, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, []map[string]any{
			readyEndpoint("shop-web-0", "10.200.1.71"),
			readyEndpoint("shop-web-1", "10.200.1.72"),
			// Cilium's own endpoints, and one belonging to something else, must
			// never become LB backends.
			endpointJSON("", 1, endpointStateReady, "10.200.1.1", []string{"reserved:host"}),
			endpointJSON("other-0", 2000, endpointStateReady, "10.200.1.9", []string{"unspec:app=grafana"}),
		})
	}))

	got, err := c.Attachments(t.Context())
	if err != nil {
		t.Fatalf("Attachments: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d attachments, want 2: %+v", len(got), got)
	}
	a, ok := got["shop-web-0"]
	if !ok {
		t.Fatal("shop-web-0 missing")
	}
	if a.IPv4 != "10.200.1.71" || a.Service.String() != "shop/web" || !a.Ready {
		t.Fatalf("attachment = %+v", a)
	}
}

func TestDetachIgnoresEmptyAllocID(t *testing.T) {
	node := newFakeNode()
	c := testCilium(t, node, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	if err := c.Detach(t.Context(), runtime.AllocSpec{}); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if got := node.taken(); len(got) != 0 {
		t.Fatalf("Detach touched the node for an empty alloc id: %v", got)
	}
}
