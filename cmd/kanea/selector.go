package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
)

// selector targets a project, or one service in it, on the plan/run command
// line (PRD §16.2, v1.57): `kanea run app.hcl shop/web` applies one service
// out of the file, `shop` alone a whole project.
type selector struct {
	raw     string // as typed, for error messages
	project string
	service string // empty means the whole project
}

// parseSelector reads "project" or "project/service". It is pure grammar —
// the caller decides first whether the argument was a file.
func parseSelector(arg string) (selector, bool) {
	project, service, hasSlash := strings.Cut(arg, "/")
	if !jobspec.IsName(project) {
		return selector{}, false
	}
	if hasSlash && !jobspec.IsName(service) {
		return selector{}, false
	}
	return selector{raw: arg, project: project, service: service}, true
}

// splitFilesAndSelectors decides, per positional argument, spec file or
// selector. An argument that exists on disk is a file — existence wins (PRD
// v1.57) — and only a non-existent one is read as a selector. Anything that
// is neither is refused by name, which is also what catches a mistyped
// filename: a dot cannot appear in a DNS-1123 label.
func splitFilesAndSelectors(args []string) ([]string, []selector, error) {
	var files []string
	var sels []selector
	for _, arg := range args {
		if _, err := os.Stat(arg); err == nil {
			files = append(files, arg)
			continue
		}
		sel, ok := parseSelector(arg)
		if !ok {
			return nil, nil, fmt.Errorf(
				"%q is not a file and not a selector; a selector is a project or project/service name (DNS-1123 labels)",
				arg)
		}
		sels = append(sels, sel)
	}
	return files, sels, nil
}

// filterDesired keeps the services at least one selector targets, in spec
// order. Every selector must hit something: a selector that matches nothing
// is a typo, and applying past it would deploy more than was asked for
// (`install --only`'s rule). With no selectors it is the identity.
func filterDesired(desired []reconciler.Desired, sels []selector) ([]reconciler.Desired, error) {
	if len(sels) == 0 {
		return desired, nil
	}
	matched := make([]bool, len(sels))
	var kept []reconciler.Desired
	for _, d := range desired {
		keep := false
		for i, sel := range sels {
			if sel.project != d.Project {
				continue
			}
			if sel.service != "" && sel.service != d.Service {
				continue
			}
			matched[i] = true
			keep = true
		}
		if keep {
			kept = append(kept, d)
		}
	}
	for i, sel := range sels {
		if !matched[i] {
			return nil, noMatchError(sel, desired)
		}
	}
	return kept, nil
}

// noMatchError names what the spec does declare, in findService's two shapes:
// the project's services when the project exists, the project list otherwise.
func noMatchError(sel selector, desired []reconciler.Desired) error {
	if sel.service != "" {
		var services []string
		for _, d := range desired {
			if d.Project == sel.project {
				services = append(services, d.Service)
			}
		}
		if len(services) > 0 {
			sort.Strings(services)
			return fmt.Errorf("selector %q matches no service in the spec; project %q declares %s",
				sel.raw, sel.project, strings.Join(services, ", "))
		}
	}
	seen := map[string]bool{}
	var projects []string
	for _, d := range desired {
		if !seen[d.Project] {
			seen[d.Project] = true
			projects = append(projects, d.Project)
		}
	}
	sort.Strings(projects)
	return fmt.Errorf("selector %q matches no service in the spec; the spec declares projects %s",
		sel.raw, strings.Join(projects, ", "))
}

// filterPipelines keeps the configs of projects that kept a service. The
// configs are built from the UNFILTERED spec on purpose: the server replaces
// a project's Builds wholesale on apply, so a config derived from a pruned
// spec would delete the build entries of every unselected sibling — and a
// project none of whose services were selected sends none, because applying
// one project must not rewrite another's sync state.
func filterPipelines(configs []gitops.Config, kept []reconciler.Desired) []gitops.Config {
	keptProjects := map[string]bool{}
	for _, d := range kept {
		keptProjects[d.Project] = true
	}
	var out []gitops.Config
	for _, cfg := range configs {
		if keptProjects[cfg.Project] {
			out = append(out, cfg)
		}
	}
	return out
}
