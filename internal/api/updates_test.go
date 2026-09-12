package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
)

// fakeInspector stands in for the daemon's host probe.
type fakeInspector struct {
	mu       sync.Mutex
	inspects int
}

func (f *fakeInspector) Inspect(context.Context) (api.UpdatesView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inspects++
	pending, security, reboot := 2, 1, true
	return api.UpdatesView{
		OS: api.OSView{
			Name: "Debian GNU/Linux 12 (bookworm)", Kernel: "6.1.0-37-amd64",
			PackageManager: "apt",
			Pending: []api.PackageUpdate{
				{Name: "libssl3", Installed: "1", Candidate: "2", Origin: "stable-security", Security: true},
				{Name: "curl", Installed: "1", Candidate: "2", Origin: "stable"},
			},
			PendingTotal: &pending, SecurityTotal: &security, RebootRequired: &reboot,
		},
		Components: []api.ComponentView{{Name: "containerd", Pinned: "2.3.3", Installed: "2.3.3"}},
	}, nil
}

func (f *fakeInspector) inspectCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inspects
}

func withInspector(f *fakeInspector) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) { cfg.HostInspector = f }
}

func TestUpdatesIs503WithoutAnInspector(t *testing.T) {
	// A daemon that cannot read its host (a dev run, a non-Linux build) is a
	// supported state, and it is different from a failure.
	h := newHarness(t)
	if status, _ := h.raw(t, http.MethodGet, api.PathUpdates); status != http.StatusServiceUnavailable {
		t.Errorf("updates = %d, want 503", status)
	}
}

func TestUpdatesIsAdminOnly(t *testing.T) {
	// What a node is missing is a list of things worth attacking (PRD v1.108).
	fake := &fakeInspector{}
	h := newAuthHarness(t, withInspector(fake))

	req := h.request(t, http.MethodGet, api.PathUpdates, nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("as viewer = %d, want 403: %s", resp.StatusCode, body)
	}
	if fake.inspectCount() != 0 {
		t.Errorf("a viewer's request reached the host probe (%d inspects)", fake.inspectCount())
	}
}

func TestUpdatesCachesTheInspection(t *testing.T) {
	// The probe runs only when an admin's dashboard asks (PRD v1.108), and
	// the cache is what keeps a refetch cadence to one exec per TTL.
	fake := &fakeInspector{}
	clock := struct {
		mu  sync.Mutex
		now time.Time
	}{now: time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)}
	h := newHarness(t, withInspector(fake), func(cfg *api.ServerConfig) {
		cfg.Now = func() time.Time {
			clock.mu.Lock()
			defer clock.mu.Unlock()
			return clock.now
		}
	})

	for i := 0; i < 3; i++ {
		status, body := h.raw(t, http.MethodGet, api.PathUpdates)
		if status != http.StatusOK {
			t.Fatalf("updates %d = %d: %s", i, status, body)
		}
		var view api.UpdatesView
		if err := json.Unmarshal([]byte(body), &view); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if view.OS.PackageManager != "apt" || view.OS.PendingTotal == nil || *view.OS.PendingTotal != 2 {
			t.Fatalf("view %d = %+v, want 2 pending over apt", i, view.OS)
		}
		if len(view.Components) != 1 || view.Components[0].Name != "containerd" {
			t.Fatalf("components %d = %+v", i, view.Components)
		}
		if view.CheckedAt.IsZero() {
			t.Fatalf("view %d has no checked_at; the dashboard cannot say how stale it is", i)
		}
	}
	if fake.inspectCount() != 1 {
		t.Errorf("three fresh reads cost %d probes, want 1", fake.inspectCount())
	}

	clock.mu.Lock()
	clock.now = clock.now.Add(6 * time.Minute)
	clock.mu.Unlock()
	if status, body := h.raw(t, http.MethodGet, api.PathUpdates); status != http.StatusOK {
		t.Fatalf("stale read = %d: %s", status, body)
	}
	if fake.inspectCount() != 2 {
		t.Errorf("a stale cache cost %d probes, want 2", fake.inspectCount())
	}
}
