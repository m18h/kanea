package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/audit"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/store"
)

// fakeRenderer answers with whatever the test seeded — the handler contract
// is what is under test here; the real renderer has its own tests beside
// toDesired in cmd/kanea.
type fakeRenderer struct {
	result api.RenderResult
	err    error
	hcl    string
	genErr error
}

func (f fakeRenderer) Render(map[string][]byte) (api.RenderResult, error) {
	return f.result, f.err
}

func (f fakeRenderer) Generate([]reconciler.Desired, []gitops.Config) (string, error) {
	return f.hcl, f.genErr
}

func withRenderer(f fakeRenderer) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) { cfg.Spec = f }
}

func specBody(project string) api.SpecRenderRequest {
	return api.SpecRenderRequest{
		Files:   map[string]string{"spec.hcl": `service "web" {}`},
		Project: project,
	}
}

func renderedService(project, service string) api.RenderResult {
	d := testService(service, 1)
	d.Project = project
	return api.RenderResult{Services: []reconciler.Desired{d}, Projects: []string{project}}
}

func (h *authHarness) adminPost(t *testing.T, path string, body any) (*http.Response, string) {
	t.Helper()
	req := h.request(t, http.MethodPost, path, body)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))
	return h.do(t, req)
}

func TestSpecRenderReportsDiagnosticsAsData(t *testing.T) {
	h := newAuthHarness(t, withRenderer(fakeRenderer{result: api.RenderResult{
		Diagnostics: []api.SpecDiagnostic{{
			Severity: "error", Summary: "Missing task", File: "spec.hcl", Line: 3, Column: 1,
		}},
	}}))

	resp, body := h.adminPost(t, api.PathSpecRender, specBody(""))
	// 200, not 4xx: the render ran to completion, and its result is the
	// diagnostic list the editor needs to position.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("render = %d: %s", resp.StatusCode, body)
	}
	var out api.SpecRenderResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Valid || len(out.Diagnostics) != 1 || out.Diagnostics[0].Line != 3 {
		t.Errorf("response = %+v", out)
	}
	if len(out.Services) != 0 {
		t.Error("an invalid spec still returned converted services")
	}
}

func TestSpecRenderRefusesAForeignProject(t *testing.T) {
	h := newAuthHarness(t, withRenderer(fakeRenderer{result: renderedService("other", "web")}))

	resp, body := h.adminPost(t, api.PathSpecRender, specBody("shop"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign project = %d, want 403: %s", resp.StatusCode, body)
	}
}

func TestSpecRenderIsAdminOnly(t *testing.T) {
	h := newAuthHarness(t, withRenderer(fakeRenderer{result: renderedService("shop", "web")}))

	req := h.request(t, http.MethodPost, api.PathSpecRender, specBody(""))
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	resp, _ := h.do(t, req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer render = %d, want 403", resp.StatusCode)
	}
}

func TestSpecApplyWritesThroughTheOneApplyPath(t *testing.T) {
	h := newAuthHarness(t, withRenderer(fakeRenderer{result: renderedService("shop", "web")}))
	ctx := context.Background()

	// Seed a current record with a generation and a pin, as `kanea restart`
	// and the auto-updater would have left them.
	current := testService("web", 1)
	current.Project = "shop"
	current.Generation = 3
	current.Update.Auto = true
	current.PinnedImage = current.Image + "@sha256:feedface"
	mut, err := store.PutMutation(store.KindService, "shop/web", current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Apply(ctx, mut); err != nil {
		t.Fatal(err)
	}

	resp, body := h.adminPost(t, api.PathSpecApply, specBody("shop"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("spec apply = %d: %s", resp.StatusCode, body)
	}

	got, _, err := store.GetValue[reconciler.Desired](ctx, h.store, store.KindService, "shop/web")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	// Generation carry-over is the same code PUT /v1/services runs: an apply
	// that reset it would restart the service a second time.
	if got.Generation != 3 {
		t.Errorf("generation = %d, want 3 (carried over)", got.Generation)
	}
	// The fake's rendered service has Auto=false (the default), which is the
	// operator turning auto off: the pin must drop, handing the spec back the
	// authority (§6.2 R19).
	if got.PinnedImage != "" {
		t.Errorf("pin = %q, want dropped when auto is off", got.PinnedImage)
	}
}

func TestSpecApplyAnswers422WithDiagnostics(t *testing.T) {
	h := newAuthHarness(t, withRenderer(fakeRenderer{result: api.RenderResult{
		Diagnostics: []api.SpecDiagnostic{{Severity: "error", Summary: "broken"}},
	}}))

	resp, body := h.adminPost(t, api.PathSpecApply, specBody(""))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("apply of a broken spec = %d, want 422: %s", resp.StatusCode, body)
	}
	var out api.SpecRenderResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Valid || len(out.Diagnostics) != 1 {
		t.Errorf("response = %+v", out)
	}
}

func TestSpecApplyRequiresCSRFOnACookieSession(t *testing.T) {
	h := newAuthHarness(t, withRenderer(fakeRenderer{result: renderedService("shop", "web")}))
	cookie, _ := h.login(t, adminUser, adminPass)

	req := h.request(t, http.MethodPost, api.PathSpecApply, specBody(""))
	req.AddCookie(cookie)
	// Deliberately no X-Kanea-CSRF header.
	resp, _ := h.do(t, req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("apply without CSRF = %d, want 403", resp.StatusCode)
	}
}

func TestSpecApplyIsAudited(t *testing.T) {
	h := newAuthHarness(t, withRenderer(fakeRenderer{result: renderedService("shop", "web")}))

	if resp, body := h.adminPost(t, api.PathSpecApply, specBody("shop")); resp.StatusCode != http.StatusOK {
		t.Fatalf("apply = %d: %s", resp.StatusCode, body)
	}

	page, err := h.audit.List(context.Background(), audit.Filter{Action: "spec.apply"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range page.Entries {
		if entry.Action == "spec.apply" && entry.Target == "shop/web" {
			found = true
		}
	}
	if !found {
		t.Errorf("no spec.apply audit entry for shop/web in %+v", page.Entries)
	}
}

func TestSpecRoutesAnswer503WithoutARenderer(t *testing.T) {
	h := newAuthHarness(t)
	if resp, _ := h.adminPost(t, api.PathSpecRender, specBody("")); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("render with no renderer = %d, want 503", resp.StatusCode)
	}
}

func TestSpecSourceGeneratesForAProject(t *testing.T) {
	h := newAuthHarness(t, withRenderer(fakeRenderer{hcl: "service \"web\" {}\n"}))
	ctx := context.Background()

	svc := testService("web", 1)
	svc.Project = "shop"
	mut, err := store.PutMutation(store.KindService, "shop/web", svc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Apply(ctx, mut); err != nil {
		t.Fatal(err)
	}

	req := h.request(t, http.MethodGet, api.PathSpecSource+"?project=shop&service=web", nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("source = %d: %s", resp.StatusCode, body)
	}
	var out api.SpecSourceResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Generated || out.HCL == "" {
		t.Errorf("response = %+v", out)
	}
}

func TestSpecSourceRefusesAServiceScopedEditOfAPipelinedProject(t *testing.T) {
	// A one-service spec cannot carry the project's pipeline state; applying
	// it would re-derive the config from that one service and drop every
	// other build block. The refusal points at the whole-project path.
	h := newAuthHarness(t, withRenderer(fakeRenderer{hcl: "service \"web\" {}\n"}))
	ctx := context.Background()

	svc := testService("web", 1)
	svc.Project = "shop"
	svcMut, err := store.PutMutation(store.KindService, "shop/web", svc)
	if err != nil {
		t.Fatal(err)
	}
	cfg := gitops.Config{Project: "shop",
		Source: gitops.Source{URL: "https://git.kanea.test/shop/deploy.git"}}
	cfgMut, err := store.PutMutation(store.KindProject, "shop", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Apply(ctx, svcMut, cfgMut); err != nil {
		t.Fatal(err)
	}

	req := h.request(t, http.MethodGet, api.PathSpecSource+"?project=shop&service=web", nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("service-scoped source of a pipelined project = %d, want 422: %s",
			resp.StatusCode, body)
	}

	// The whole-project form still generates.
	req = h.request(t, http.MethodGet, api.PathSpecSource+"?project=shop", nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))
	resp, body = h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("project-scoped source = %d: %s", resp.StatusCode, body)
	}
}

func TestSpecSourceRefusalNamesTheField(t *testing.T) {
	h := newAuthHarness(t, withRenderer(fakeRenderer{
		genErr: errors.New("cannot generate a spec for shop/web: its volume blocks are not expressible"),
	}))
	ctx := context.Background()

	svc := testService("web", 1)
	svc.Project = "shop"
	mut, err := store.PutMutation(store.KindService, "shop/web", svc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Apply(ctx, mut); err != nil {
		t.Fatal(err)
	}

	req := h.request(t, http.MethodGet, api.PathSpecSource+"?project=shop", nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleAdmin))
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("refused generation = %d, want 422: %s", resp.StatusCode, body)
	}
}
