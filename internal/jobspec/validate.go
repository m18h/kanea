package jobspec

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// SpecVersion is the schema revision this binary speaks (R6, PRD §15.4).
const SpecVersion = 1

// MaxDescription bounds the free-form description field (PRD §4.2).
const MaxDescription = 512

// dns1123Label is the hard naming rule (R1, PRD §4.2): lowercase alphanumeric
// and '-', starting and ending alphanumeric, at most 63 characters. Names are
// composed into DNS, so this is correctness, not style — and it doubles as an
// injection defense (PRD §14, A03).
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// MaxNameLength is the DNS-1123 label limit.
const MaxNameLength = 63

// SecretPrefix marks a secret reference. Secrets are referenced, never inlined
// (R3, PRD §12).
const SecretPrefix = "secret:"

// SharedSecretScope is the one namespace every project may read (R5).
const SharedSecretScope = "shared"

// Validate checks the whole applied set. It is called by the parsers and is
// exported so a stored spec can be re-validated (for example at `kanea plan`
// against the live set).
func Validate(spec *Spec) hcl.Diagnostics {
	var diags hcl.Diagnostics

	diags = append(diags, validateSpecVersion(spec)...)
	diags = append(diags, validateProjects(spec)...)
	diags = append(diags, validateServices(spec)...)
	diags = append(diags, validateDependencies(spec)...)
	return diags
}

func validateSpecVersion(spec *Spec) hcl.Diagnostics {
	switch spec.SpecVersion {
	case SpecVersion:
		return nil
	case 0:
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Missing spec_version",
			Detail: fmt.Sprintf("Job files must declare spec_version = %d at the top level. "+
				"It gates future schema revisions.", SpecVersion),
		}}
	default:
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Unsupported spec_version",
			Detail: fmt.Sprintf("This build understands spec_version %d, the file declares %d. "+
				"Upgrade kanea, or lower the version.", SpecVersion, spec.SpecVersion),
		}}
	}
}

func validateProjects(spec *Spec) hcl.Diagnostics {
	var diags hcl.Diagnostics
	seen := map[string]hcl.Range{}

	for _, p := range spec.Projects {
		diags = append(diags, validateName("Project", p.Name, p.DefRange)...)
		diags = append(diags, validateDescription(p.Description, p.DefRange)...)

		if first, dup := seen[p.Name]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate project",
				Detail: fmt.Sprintf("Project %q is already declared at %s.",
					p.Name, first),
				Subject: p.DefRange.Ptr(),
			})
			continue
		}
		seen[p.Name] = p.DefRange
	}
	return diags
}

func validateServices(spec *Spec) hcl.Diagnostics {
	var diags hcl.Diagnostics
	seen := map[string]hcl.Range{} // project/name -> first declaration

	for _, svc := range spec.Services {
		diags = append(diags, validateName("Service", svc.Name, svc.DefRange)...)
		diags = append(diags, validateDescription(svc.Description, svc.DefRange)...)

		// Every service belongs to a declared project: the project is the
		// isolation boundary, so an implicit one would be a security hole.
		switch {
		case svc.Project == "":
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Service has no project",
				Detail:   fmt.Sprintf("Service %q must set project = \"<name>\".", svc.Name),
				Subject:  svc.DefRange.Ptr(),
			})
		case spec.ProjectByName(svc.Project) == nil:
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unknown project",
				Detail: fmt.Sprintf("Service %q references project %q, which is not declared in this set.",
					svc.Name, svc.Project),
				Subject: svc.DefRange.Ptr(),
			})
		}

		key := svc.Project + "/" + svc.Name
		if first, dup := seen[key]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate service",
				Detail: fmt.Sprintf("Service %q is already declared in project %q at %s.",
					svc.Name, svc.Project, first),
				Subject: svc.DefRange.Ptr(),
			})
		} else {
			seen[key] = svc.DefRange
		}

		if svc.Count < 0 {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid count",
				Detail:   fmt.Sprintf("Service %q has count = %d; it must be zero or more.", svc.Name, svc.Count),
				Subject:  svc.DefRange.Ptr(),
			})
		}

		diags = append(diags, validateTask(svc)...)
		diags = append(diags, validatePorts(svc)...)
		diags = append(diags, validateHealthChecks(svc)...)
		diags = append(diags, validateVolumes(svc)...)
		diags = append(diags, validateScaling(svc)...)
	}
	return diags
}

func validateTask(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if svc.Task == nil {
		return diags // already reported during conversion
	}
	task := svc.Task

	diags = append(diags, validateName("Task", task.Name, task.DefRange)...)

	// R8 — the minimal service is image-only, but something must produce an
	// image: `task.image`, a `build` block, or both (build wins at deploy).
	if task.Image == "" && svc.Build == nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Service has no image",
			Detail: fmt.Sprintf("Service %q must set task.image, declare a build block, or both. "+
				"With both, the pipeline-built image wins and task.image is the pre-first-build value.",
				svc.Name),
			Subject: task.DefRange.Ptr(),
		})
	}

	// R11 — limits are mandatory; the declaration is not. Defaults are already
	// filled in, so a non-positive value here can only be an explicit one.
	if task.Resources.CPU <= 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid CPU limit",
			Detail: fmt.Sprintf("Service %q declares resources.cpu = %d MHz; it must be positive. "+
				"No alloc may run unlimited.", svc.Name, task.Resources.CPU),
			Subject: task.DefRange.Ptr(),
		})
	}
	if task.Resources.Memory <= 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid memory limit",
			Detail: fmt.Sprintf("Service %q declares resources.memory = %d MiB; it must be positive. "+
				"No alloc may run unlimited.", svc.Name, task.Resources.Memory),
			Subject: task.DefRange.Ptr(),
		})
	}

	diags = append(diags, validateSecretRefs(svc)...)
	diags = append(diags, validateCommand(svc)...)
	diags = append(diags, validateCapabilities(svc)...)
	return diags
}

// validateSecretRefs enforces R3 and R5: secrets are referenced by path, and a
// service may only read its own project's namespace or `shared/`. Cross-project
// reads are an IDOR-class exfiltration path (PRD §14, A01).
func validateSecretRefs(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if svc.Task == nil {
		return diags
	}

	for key, value := range svc.Task.Env {
		if !strings.HasPrefix(value, SecretPrefix) {
			continue
		}
		ref := strings.TrimPrefix(value, SecretPrefix)
		scope, rest, found := strings.Cut(ref, "/")
		if !found || scope == "" || rest == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Malformed secret reference",
				Detail: fmt.Sprintf("Environment variable %q in service %q uses %q; "+
					"secret references look like secret:<project>/<name> or secret:shared/<name>.",
					key, svc.Name, value),
				Subject: svc.Task.DefRange.Ptr(),
			})
			continue
		}
		if scope != svc.Project && scope != SharedSecretScope {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Cross-project secret reference",
				Detail: fmt.Sprintf("Service %q (project %q) references %q. A service may only read "+
					"secret:%s/… or secret:%s/….",
					svc.Name, svc.Project, value, svc.Project, SharedSecretScope),
				Subject: svc.Task.DefRange.Ptr(),
			})
		}
	}
	return diags
}

func validatePorts(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if svc.Network == nil {
		return diags
	}
	seen := map[string]hcl.Range{}

	for _, p := range svc.Network.Ports {
		// Port names are referenced as ${service.x.port.<name>} and composed
		// into config, so they follow the same naming rule.
		diags = append(diags, validateName("Port", p.Name, p.DefRange)...)

		if p.Container < 1 || p.Container > 65535 {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid port number",
				Detail: fmt.Sprintf("Port %q of service %q is %d; container ports are 1-65535.",
					p.Name, svc.Name, p.Container),
				Subject: p.DefRange.Ptr(),
			})
		}
		if first, dup := seen[p.Name]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate port name",
				Detail:   fmt.Sprintf("Port %q is already declared at %s.", p.Name, first),
				Subject:  p.DefRange.Ptr(),
			})
			continue
		}
		seen[p.Name] = p.DefRange
	}
	return diags
}

// validateHealthChecks enforces R7. `exec` takes an argument array — a shell
// string would be an injection vector (PRD §14, A03).
func validateHealthChecks(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics

	for _, hc := range svc.HealthChecks {
		switch hc.Type {
		case HealthHTTP:
			if hc.Path == "" {
				diags = append(diags, healthDiag(svc, hc, "An http health check needs path."))
			}
			diags = append(diags, requirePort(svc, hc)...)

		case HealthTCP:
			diags = append(diags, requirePort(svc, hc)...)

		case HealthExec:
			if len(hc.Command) == 0 {
				diags = append(diags, healthDiag(svc, hc,
					"An exec health check needs command = [\"prog\", \"arg\"] — an argument array, never a shell string."))
			}

		case "":
			diags = append(diags, healthDiag(svc, hc,
				fmt.Sprintf("Health check %q has no type; expected %s, %s or %s.",
					hc.Name, HealthHTTP, HealthTCP, HealthExec)))

		default:
			diags = append(diags, healthDiag(svc, hc,
				fmt.Sprintf("Unknown health check type %q; expected %s, %s or %s.",
					hc.Type, HealthHTTP, HealthTCP, HealthExec)))
		}

		if hc.Failures < 0 {
			diags = append(diags, healthDiag(svc, hc, "failures must be zero or more."))
		}
		diags = append(diags, validateDuration("interval", hc.Interval, hc.DefRange)...)
		diags = append(diags, validateDuration("timeout", hc.Timeout, hc.DefRange)...)
	}
	return diags
}

func requirePort(svc *Service, hc *HealthCheck) hcl.Diagnostics {
	if hc.Port == "" {
		return hcl.Diagnostics{healthDiag(svc, hc,
			fmt.Sprintf("A %s health check needs port = \"<port-name>\".", hc.Type))}
	}
	if !hasPort(svc, hc.Port) {
		return hcl.Diagnostics{healthDiag(svc, hc,
			fmt.Sprintf("Health check %q targets port %q, which service %q does not declare. Declared ports: %s.",
				hc.Name, hc.Port, svc.Name, describePorts(svc)))}
	}
	return nil
}

func healthDiag(svc *Service, hc *HealthCheck, detail string) *hcl.Diagnostic {
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  "Invalid health check",
		Detail:   fmt.Sprintf("Service %q, health check %q: %s", svc.Name, hc.Name, detail),
		Subject:  hc.DefRange.Ptr(),
	}
}

func validateVolumes(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	seenName := map[string]hcl.Range{}
	seenPath := map[string]hcl.Range{}

	for _, v := range svc.Volumes {
		diags = append(diags, validateName("Volume", v.Name, v.DefRange)...)

		if !path.IsAbs(v.MountPath) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid mount path",
				Detail: fmt.Sprintf("Volume %q of service %q mounts at %q; mount_path must be absolute.",
					v.Name, svc.Name, v.MountPath),
				Subject: v.DefRange.Ptr(),
			})
		}
		if v.Storage == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Volume has no storage",
				Detail:   fmt.Sprintf("Volume %q of service %q must name a storage resource.", v.Name, svc.Name),
				Subject:  v.DefRange.Ptr(),
			})
		}
		if first, dup := seenName[v.Name]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate volume name",
				Detail:   fmt.Sprintf("Volume %q is already declared at %s.", v.Name, first),
				Subject:  v.DefRange.Ptr(),
			})
		} else {
			seenName[v.Name] = v.DefRange
		}
		// Two volumes on the same path is always a mistake: one silently wins.
		if first, dup := seenPath[v.MountPath]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Conflicting mount path",
				Detail: fmt.Sprintf("Mount path %q is already used by another volume at %s.",
					v.MountPath, first),
				Subject: v.DefRange.Ptr(),
			})
		} else {
			seenPath[v.MountPath] = v.DefRange
		}
	}
	return diags
}

func validateScaling(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	sc := svc.Scaling
	if sc == nil {
		return diags
	}

	if sc.Min < 0 || sc.Max < 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid scaling bounds",
			Detail:   fmt.Sprintf("Service %q: scaling min/max must be zero or more.", svc.Name),
			Subject:  svc.DefRange.Ptr(),
		})
	}
	if sc.Max > 0 && sc.Min > sc.Max {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid scaling bounds",
			Detail: fmt.Sprintf("Service %q: scaling min (%d) exceeds max (%d).",
				svc.Name, sc.Min, sc.Max),
			Subject: svc.DefRange.Ptr(),
		})
	}
	// count outside [min,max] is contradictory: the autoscaler would immediately
	// undo the declared count.
	if sc.Max > 0 && (svc.Count < sc.Min || svc.Count > sc.Max) {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "count outside scaling bounds",
			Detail: fmt.Sprintf("Service %q declares count = %d but scaling allows %d-%d; "+
				"the autoscaler would immediately change it.", svc.Name, svc.Count, sc.Min, sc.Max),
			Subject: svc.DefRange.Ptr(),
		})
	}
	for _, m := range sc.Metrics {
		if m.Target <= 0 {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid scaling metric",
				Detail: fmt.Sprintf("Service %q: metric %q has target %d; it must be positive.",
					svc.Name, m.Name, m.Target),
				Subject: svc.DefRange.Ptr(),
			})
		}
	}
	diags = append(diags, validateDuration("cooldown", sc.Cooldown, svc.DefRange)...)
	return diags
}

// validateDependencies enforces R10: every edge names a service in the same
// project, and the graph is acyclic. Cycles are reported with the path.
func validateDependencies(spec *Spec) hcl.Diagnostics {
	var diags hcl.Diagnostics

	for _, svc := range spec.Services {
		for _, dep := range svc.DependsOn {
			switch {
			case dep == svc.Name:
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Service depends on itself",
					Detail:   fmt.Sprintf("Service %q lists itself in depends_on.", svc.Name),
					Subject:  svc.DefRange.Ptr(),
				})
			case spec.ServiceByName(svc.Project, dep) == nil:
				detail := fmt.Sprintf("Service %q depends on %q, which is not declared in project %q.",
					svc.Name, dep, svc.Project)
				if other := findServiceAnyProject(spec, dep); other != nil {
					detail = fmt.Sprintf("Service %q depends on %q, which belongs to project %q. "+
						"Dependencies are same-project only in v1.", svc.Name, dep, other.Project)
				}
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Unknown dependency",
					Detail:   detail,
					Subject:  svc.DefRange.Ptr(),
				})
			}
		}
	}
	if diags.HasErrors() {
		return diags // cycle detection on a broken graph would mislead
	}
	return append(diags, detectCycles(spec)...)
}

// detectCycles walks each project's dependency graph depth-first and reports
// the first cycle it finds per project, showing the path (R9, R10).
func detectCycles(spec *Spec) hcl.Diagnostics {
	var diags hcl.Diagnostics

	for _, project := range projectsWithServices(spec) {
		services := spec.ServicesInProject(project)
		state := make(map[string]int, len(services)) // 0 unvisited, 1 on stack, 2 done
		var stack []string

		var visit func(svc *Service) []string
		visit = func(svc *Service) []string {
			state[svc.Name] = 1
			stack = append(stack, svc.Name)

			for _, dep := range svc.Dependencies {
				next := spec.ServiceByName(project, dep)
				if next == nil {
					continue // reported by validateDependencies
				}
				switch state[dep] {
				case 1:
					// Found the back edge: cut the stack at its start.
					for i, name := range stack {
						if name == dep {
							return append(append([]string{}, stack[i:]...), dep)
						}
					}
					return []string{dep, dep}
				case 0:
					if cycle := visit(next); cycle != nil {
						return cycle
					}
				}
			}
			stack = stack[:len(stack)-1]
			state[svc.Name] = 2
			return nil
		}

		for _, svc := range services {
			if state[svc.Name] != 0 {
				continue
			}
			stack = stack[:0]
			if cycle := visit(svc); cycle != nil {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Dependency cycle",
					Detail: fmt.Sprintf("Project %q has a dependency cycle: %s. "+
						"Dependencies come from depends_on and from ${service.*} references.",
						project, strings.Join(cycle, " -> ")),
					Subject: svc.DefRange.Ptr(),
				})
				break // one cycle per project is enough to act on
			}
		}
	}
	return diags
}

func projectsWithServices(spec *Spec) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, svc := range spec.Services {
		if _, dup := seen[svc.Project]; dup {
			continue
		}
		seen[svc.Project] = struct{}{}
		out = append(out, svc.Project)
	}
	return out
}

// ---- shared field checks ----

func validateName(what, name string, rng hcl.Range) hcl.Diagnostics {
	if name == "" {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  what + " has no name",
			Detail:   what + " names are required.",
			Subject:  rng.Ptr(),
		}}
	}
	if len(name) > MaxNameLength {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Name too long",
			Detail: fmt.Sprintf("%s name %q is %d characters; DNS-1123 labels are at most %d.",
				what, name, len(name), MaxNameLength),
			Subject: rng.Ptr(),
		}}
	}
	if !dns1123Label.MatchString(name) {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid name",
			Detail: fmt.Sprintf("%s name %q is not a DNS-1123 label: lowercase letters, digits and "+
				"'-', starting and ending with a letter or digit. Names are composed into DNS "+
				"(service.project.%s), so this is enforced at parse time.", what, name, InternalDomain),
			Subject: rng.Ptr(),
		}}
	}
	return nil
}

func validateDescription(desc string, rng hcl.Range) hcl.Diagnostics {
	if len(desc) <= MaxDescription {
		return nil
	}
	return hcl.Diagnostics{{
		Severity: hcl.DiagError,
		Summary:  "Description too long",
		Detail: fmt.Sprintf("description is %d characters; the limit is %d.",
			len(desc), MaxDescription),
		Subject: rng.Ptr(),
	}}
}

// validateDuration checks the Go duration strings used throughout the spec
// ("10s", "2m"). Empty means "use the default" and is always fine.
func validateDuration(field, value string, rng hcl.Range) hcl.Diagnostics {
	if value == "" {
		return nil
	}
	if _, err := ParseDuration(value); err != nil {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid duration",
			Detail:   fmt.Sprintf("%s = %q: %s. Use forms like \"10s\", \"2m\", \"1h30m\".", field, value, err),
			Subject:  rng.Ptr(),
		}}
	}
	return nil
}
