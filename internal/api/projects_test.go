package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/store"
)

func TestProjectListIsAssembledFromWhatExists(t *testing.T) {
	// There is no project table: a project is the namespace a service declares
	// itself into, so the list has to be derived. This is the test that says so.
	h := newHarness(t)
	h.putService(t, "shop", "web", 2)
	h.putService(t, "shop", "api", 1)
	h.putService(t, "blog", "site", 1)

	status, body := h.raw(t, http.MethodGet, api.PathProjects)
	if status != http.StatusOK {
		t.Fatalf("list projects = %d: %s", status, body)
	}
	var resp api.ProjectsResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Projects) != 2 {
		t.Fatalf("projects = %d, want 2: %s", len(resp.Projects), body)
	}
	// Sorted, so a dashboard and a CLI agree about the order.
	if resp.Projects[0].Name != "blog" || resp.Projects[1].Name != "shop" {
		t.Errorf("projects are not sorted by name: %s", body)
	}
	if resp.Projects[1].Services != 2 {
		t.Errorf("shop has %d services, want 2", resp.Projects[1].Services)
	}
}

func TestGetProjectReports404ForOneThatDoesNotExist(t *testing.T) {
	h := newHarness(t)
	h.putService(t, "shop", "web", 1)

	if status, _ := h.raw(t, http.MethodGet, api.PathProjects+"/shop"); status != http.StatusOK {
		t.Errorf("get shop = %d, want 200", status)
	}
	if status, _ := h.raw(t, http.MethodGet, api.PathProjects+"/nope"); status != http.StatusNotFound {
		t.Errorf("get nope = %d, want 404", status)
	}
}

func TestRestartBumpsTheGenerationRatherThanTouchingContainers(t *testing.T) {
	// A restart is a spec change, so it rolls through the update policy like
	// any other. Nothing here reaches the runtime, which is what keeps the
	// reconciler the only thing that converges state.
	h := newHarness(t)
	h.putService(t, "shop", "web", 2)

	before := desiredFromStore(t, h, "shop/web")
	status, body := h.raw(t, http.MethodPost, api.PathServices+"/shop/web/restart")
	if status != http.StatusOK {
		t.Fatalf("restart = %d: %s", status, body)
	}
	after := desiredFromStore(t, h, "shop/web")

	if after.Generation != before.Generation+1 {
		t.Errorf("generation = %d, want %d", after.Generation, before.Generation+1)
	}
	if reconciler.SpecHash(after) == reconciler.SpecHash(before) {
		t.Error("the spec hash did not change, so nothing would roll")
	}
	// Everything else is untouched: a restart is not a deploy.
	if after.Image != before.Image || after.Count != before.Count {
		t.Error("restart changed something other than the generation")
	}
}

func TestRestartOfAnUnknownServiceIs404(t *testing.T) {
	h := newHarness(t)
	if status, _ := h.raw(t, http.MethodPost, api.PathServices+"/shop/web/restart"); status != http.StatusNotFound {
		t.Errorf("restart of a missing service = %d, want 404", status)
	}
}

func TestApplyPreservesTheRestartGeneration(t *testing.T) {
	// The generation belongs to the running service, not to the file. Without
	// this, the first `kanea run` after a restart would look like another spec
	// change and roll the service a second time.
	ctx := context.Background()
	h := newHarness(t)
	h.putService(t, "shop", "web", 2)

	if status, body := h.raw(t, http.MethodPost, api.PathServices+"/shop/web/restart"); status != http.StatusOK {
		t.Fatalf("restart = %d: %s", status, body)
	}
	generation := desiredFromStore(t, h, "shop/web").Generation

	// An apply from a spec file, which knows nothing about generations.
	fresh := desiredFromStore(t, h, "shop/web")
	fresh.Generation = 0
	if _, err := h.client.Apply(ctx, []reconciler.Desired{fresh}, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if got := desiredFromStore(t, h, "shop/web").Generation; got != generation {
		t.Errorf("generation = %d after an apply, want %d preserved", got, generation)
	}
}

func TestNodeStatsCountsWhatIsRunning(t *testing.T) {
	h := newHarness(t)
	h.putService(t, "shop", "web", 2)

	status, body := h.raw(t, http.MethodGet, api.PathStats)
	if status != http.StatusOK {
		t.Fatalf("node stats = %d: %s", status, body)
	}
	var stats api.NodeStats
	if err := json.Unmarshal([]byte(body), &stats); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if stats.Projects != 1 || stats.Services != 1 {
		t.Errorf("projects/services = %d/%d, want 1/1", stats.Projects, stats.Services)
	}
	// Nothing has been reconciled, so nothing is running — and the field says
	// zero rather than being absent, because zero running is a real answer.
	if stats.Running != 0 {
		t.Errorf("running = %d, want 0", stats.Running)
	}
}

func TestServiceStatsNeedsBothProjectAndService(t *testing.T) {
	h := newHarness(t)
	status, body := h.raw(t, http.MethodGet, api.PathStats+"?project=shop")
	if status != http.StatusBadRequest {
		t.Fatalf("half a service name = %d, want 400: %s", status, body)
	}
	if !strings.Contains(body, "project and service") {
		t.Errorf("the error does not say what is missing: %s", body)
	}
}

func TestNotificationTestIs503WithoutChannels(t *testing.T) {
	// "No channels are configured" and "the test failed" are different answers,
	// and an operator acts differently on each.
	h := newHarness(t)
	status, body := h.raw(t, http.MethodPost, api.PathProjects+"/shop/notifications/test")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("test with no dispatcher = %d, want 503: %s", status, body)
	}
}

// desiredFromStore reads a service straight out of the Store.
func desiredFromStore(t *testing.T, h *harness, key string) reconciler.Desired {
	t.Helper()
	d, _, err := store.GetValue[reconciler.Desired](
		context.Background(), h.store, store.KindService, key)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	return d
}
