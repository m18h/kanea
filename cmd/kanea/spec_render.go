package main

import (
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
)

// specRenderer implements api.SpecRenderer for the dashboard's editor
// (v1.38): the same jobspec.ParseContents the GitOps sync uses, then the same
// toDesired the CLI uses, with the node's own base domain — so a spec means
// exactly one thing whether it arrives from a repository, a terminal or a
// textarea.
type specRenderer struct {
	opts jobspec.Options
}

func (r specRenderer) Render(files map[string][]byte) (api.RenderResult, error) {
	spec, diags := jobspec.ParseContents(r.opts, files)
	out := api.RenderResult{Diagnostics: convertDiagnostics(diags)}
	if diags.HasErrors() || spec == nil {
		return out, nil
	}

	desired, err := toDesired(spec)
	if err != nil {
		// toDesired's refusals are spec problems, not server failures — the
		// editor should see them beside the parser's, just without positions.
		out.Diagnostics = append(out.Diagnostics, api.SpecDiagnostic{
			Severity: "error", Summary: err.Error(),
		})
		return out, nil
	}
	out.Services = desired

	projects := map[string]struct{}{}
	for _, p := range spec.Projects {
		projects[p.Name] = struct{}{}
	}
	for _, svc := range desired {
		projects[svc.Project] = struct{}{}
	}
	for name := range projects {
		out.Projects = append(out.Projects, name)
		if cfg, ok := gitops.ConfigFromSpec(spec, name); ok {
			out.Pipelines = append(out.Pipelines, cfg)
		}
	}
	sort.Strings(out.Projects)
	sort.Slice(out.Pipelines, func(i, j int) bool {
		return out.Pipelines[i].Project < out.Pipelines[j].Project
	})
	return out, nil
}

func (r specRenderer) Generate(
	services []reconciler.Desired, pipelines []gitops.Config,
) (string, error) {
	return toHCL(services, pipelines)
}

// convertDiagnostics turns hcl positions into the editor's shape.
func convertDiagnostics(diags hcl.Diagnostics) []api.SpecDiagnostic {
	out := make([]api.SpecDiagnostic, 0, len(diags))
	for _, d := range diags {
		conv := api.SpecDiagnostic{Summary: d.Summary, Detail: d.Detail, Severity: "warning"}
		if d.Severity == hcl.DiagError {
			conv.Severity = "error"
		}
		if d.Subject != nil {
			conv.File = d.Subject.Filename
			conv.Line = d.Subject.Start.Line
			conv.Column = d.Subject.Start.Column
		}
		out = append(out, conv)
	}
	return out
}
