package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/store"
)

// The spec editor's routes (PRD §12.2, §16.1, v1.38).
//
// Render converts HCL to what the apply route accepts and reports diagnostics
// with file/line positions — it is the editor's "validate" button and has no
// side effects. Apply renders the same bytes and hands the result to the same
// core PUT /v1/services uses, so generation carry-over, pin carry-over and
// the R22 port check are shared by construction rather than replicated.
// Source generates best-effort HCL from the running desired state.
const (
	PathSpecRender = "/v1/spec/render"
	PathSpecApply  = "/v1/spec/apply"
	PathSpecSource = "/v1/spec/source"
)

// SpecRenderer converts HCL job-spec text into what the apply route accepts,
// and back. Implemented in cmd/kanea beside toDesired — the one place that
// knows both vocabularies — and injected, the same seam shape as
// gitops.Applier. Nil means the daemon was built without one: 503.
type SpecRenderer interface {
	// Render parses and validates. Diagnostics are data, not an error: a spec
	// that failed validation is a completed render whose result is the
	// diagnostic list. The error return is for renders that could not run.
	Render(files map[string][]byte) (RenderResult, error)
	// Generate writes HCL for a desired state. A field the generator cannot
	// express is an error naming it — never silently dropped output.
	Generate(services []reconciler.Desired, pipelines []gitops.Config) (string, error)
}

// RenderResult is what a render produced.
type RenderResult struct {
	Services  []reconciler.Desired
	Pipelines []gitops.Config
	// Projects is every project the spec declares, for the boundary check.
	Projects    []string
	Diagnostics []SpecDiagnostic
}

// SpecDiagnostic is one parse or validation finding, positioned for an editor.
type SpecDiagnostic struct {
	Severity string `json:"severity"` // "error" | "warning"
	Summary  string `json:"summary"`
	Detail   string `json:"detail,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}

// HasErrors reports whether any diagnostic is an error.
func hasErrorDiagnostics(diags []SpecDiagnostic) bool {
	for _, d := range diags {
		if d.Severity == "error" {
			return true
		}
	}
	return false
}

// SpecRenderRequest carries the editor's text.
type SpecRenderRequest struct {
	// Files maps a name (for diagnostics) to HCL source.
	Files map[string]string `json:"files"`
	// Project, when set, scopes the spec: declaring any other project is
	// refused — the boundary gitops.parseCheckout draws for a repository
	// (§10), applied to the editor.
	Project string `json:"project,omitempty"`
}

// SpecRenderResponse reports a completed render.
type SpecRenderResponse struct {
	Valid       bool                 `json:"valid"`
	Diagnostics []SpecDiagnostic     `json:"diagnostics,omitempty"`
	Services    []reconciler.Desired `json:"services,omitempty"`
	Pipelines   []gitops.Config      `json:"pipelines,omitempty"`
}

// SpecSourceResponse is generated HCL for the current desired state.
type SpecSourceResponse struct {
	HCL string `json:"hcl"`
	// Generated is always true: this text was derived from the Store, not
	// read from anyone's file. Comments and variable interpolations from the
	// original are gone, and the field says so machine-readably.
	Generated bool `json:"generated"`
}

// renderRequest decodes and renders, refusing a foreign project. Shared by
// the render and apply handlers so they cannot disagree about what a spec
// means.
func (s *Server) renderRequest(r *http.Request) (RenderResult, int, error) {
	if s.spec == nil {
		return RenderResult{}, http.StatusServiceUnavailable,
			errors.New("api: this daemon has no spec renderer")
	}
	var req SpecRenderRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		return RenderResult{}, http.StatusBadRequest, fmt.Errorf("decode request: %w", err)
	}
	if len(req.Files) == 0 {
		return RenderResult{}, http.StatusBadRequest, errors.New("no spec files in request")
	}

	files := make(map[string][]byte, len(req.Files))
	for name, text := range req.Files {
		files[name] = []byte(text)
	}
	result, err := s.spec.Render(files)
	if err != nil {
		return RenderResult{}, http.StatusInternalServerError, err
	}

	// The project boundary: an editor scoped to one project may not redefine
	// another. Same rule as a synced repository (§10), same failure mode
	// prevented — "can edit one project" quietly becoming "owns every service
	// on the node".
	if req.Project != "" && !hasErrorDiagnostics(result.Diagnostics) {
		var foreign []string
		for _, p := range result.Projects {
			if p != req.Project {
				foreign = append(foreign, p)
			}
		}
		for _, svc := range result.Services {
			if svc.Project != req.Project && !sliceContains(foreign, svc.Project) {
				foreign = append(foreign, svc.Project)
			}
		}
		if len(foreign) > 0 {
			sort.Strings(foreign)
			return RenderResult{}, http.StatusForbidden,
				fmt.Errorf("api: a spec for project %s may not declare %s",
					req.Project, strings.Join(foreign, ", "))
		}
	}
	return result, 0, nil
}

// handleSpecRender is the editor's validate: parse, validate, convert —
// nothing written.
func (s *Server) handleSpecRender(w http.ResponseWriter, r *http.Request) {
	result, status, err := s.renderRequest(r)
	if err != nil {
		writeError(w, status, err)
		return
	}
	resp := SpecRenderResponse{Diagnostics: result.Diagnostics}
	if !hasErrorDiagnostics(result.Diagnostics) {
		resp.Valid = true
		resp.Services = result.Services
		resp.Pipelines = result.Pipelines
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSpecApply renders and applies in one request, so validation provably
// ran on the bytes that were applied — there is no window for a client to
// mutate the rendered JSON between validate and apply.
func (s *Server) handleSpecApply(w http.ResponseWriter, r *http.Request) {
	result, status, err := s.renderRequest(r)
	if err != nil {
		writeError(w, status, err)
		return
	}
	if hasErrorDiagnostics(result.Diagnostics) {
		// 422 with the diagnostics as the body: the request was well-formed,
		// the spec was not, and the editor needs the positions.
		writeJSON(w, http.StatusUnprocessableEntity, SpecRenderResponse{
			Valid: false, Diagnostics: result.Diagnostics,
		})
		return
	}

	resp, status, err := s.applyServices(r, ApplyRequest{
		Services: result.Services, Pipelines: result.Pipelines,
	})
	if err != nil {
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSpecSource serves generated HCL for one service or a whole project.
func (s *Server) handleSpecSource(w http.ResponseWriter, r *http.Request) {
	if s.spec == nil {
		writeError(w, http.StatusServiceUnavailable,
			errors.New("api: this daemon has no spec renderer"))
		return
	}
	q := r.URL.Query()
	project, service := q.Get("project"), q.Get("service")
	if project == "" {
		writeError(w, http.StatusBadRequest, errors.New("api: spec source needs a project"))
		return
	}

	all, err := listAll[reconciler.Desired](r.Context(), s.store, store.KindService)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var services []reconciler.Desired
	for _, svc := range all {
		if svc.Project != project {
			continue
		}
		if service != "" && svc.Service != service {
			continue
		}
		services = append(services, svc)
	}
	if len(services) == 0 {
		writeError(w, http.StatusNotFound,
			fmt.Errorf("api: no services in project %s match", project))
		return
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Service < services[j].Service })

	var pipelines []gitops.Config
	if cfg, _, err := store.GetValue[gitops.Config](
		r.Context(), s.store, store.KindProject, project); err == nil {
		configured := cfg.HasSource() || len(cfg.Builds) > 0 || cfg.Notifications != nil
		if service != "" && configured {
			// A one-service spec cannot carry the project's pipeline state:
			// applying it would re-derive the project config from the one
			// service present and silently drop every other service's build
			// block. Refuse rather than generate a spec that applies as less
			// than what is running.
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Errorf("api: project %s has a git or build pipeline; generate the whole "+
					"project (omit service=) or edit the repository's spec instead", project))
			return
		}
		if service == "" && configured {
			pipelines = append(pipelines, cfg)
		}
	}

	hcl, err := s.spec.Generate(services, pipelines)
	if err != nil {
		// A field the generator cannot express refuses by name rather than
		// emitting a spec that would apply as something else (v1.38).
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, SpecSourceResponse{HCL: hcl, Generated: true})
}

func sliceContains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
