package jobspec

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/reconciler"
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
	diags = append(diags, validateStorages(spec)...)
	diags = append(diags, validateServices(spec)...)
	diags = append(diags, validateExposedDomains(spec)...)
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
		diags = append(diags, validateGit(p)...)
		diags = append(diags, validateNotifications(p)...)
	}
	return diags
}

// validateGit checks a project's GitOps source (PRD §10.1).
//
// The credentials are checked for shape here rather than at sync time for the
// same reason every other reference is: a typo should fail `kanea plan`, in
// front of the person who made it, not sixty seconds later inside a poll loop
// nobody is watching.
func validateGit(p *Project) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if p.Git == nil {
		return diags
	}

	if p.Git.URL == "" {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Git source has no url",
			Detail:   fmt.Sprintf("Project %q declares a git block with no url.", p.Name),
			Subject:  p.DefRange.Ptr(),
		})
	}

	for field, ref := range map[string]string{
		"auth_ref":           p.Git.AuthRef,
		"webhook_secret_ref": p.Git.WebhookSecretRef,
	} {
		if ref == "" {
			continue
		}
		if !strings.HasPrefix(ref, SecretPrefix) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Git credential is not a secret reference",
				Detail: fmt.Sprintf("Project %q sets git.%s = %q. Credentials are referenced, "+
					"never inlined (R3): use secret:%s/<name> or secret:%s/<name>.",
					p.Name, field, ref, p.Name, SharedSecretScope),
				Subject: p.DefRange.Ptr(),
			})
			continue
		}
		scope, rest, found := strings.Cut(strings.TrimPrefix(ref, SecretPrefix), "/")
		if !found || scope == "" || rest == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Malformed secret reference",
				Detail: fmt.Sprintf("Project %q sets git.%s = %q; references look like "+
					"secret:<project>/<name>.", p.Name, field, ref),
				Subject: p.DefRange.Ptr(),
			})
			continue
		}
		// Same scoping rule as a service's (R5): a project may read its own
		// secrets and the shared ones, and nobody else's.
		if scope != p.Name && scope != SharedSecretScope {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Cross-project secret reference",
				Detail: fmt.Sprintf("Project %q sets git.%s = %q. It may only read secret:%s/… "+
					"or secret:%s/….", p.Name, field, ref, p.Name, SharedSecretScope),
				Subject: p.DefRange.Ptr(),
			})
		}
	}

	diags = append(diags, validateDuration("poll_interval", p.Git.PollInterval, p.DefRange)...)
	return diags
}

// validateNotifications checks a project's notification channels (PRD §11).
//
// Every check here exists to fail at `kanea plan` rather than at 3am. A channel
// with a bad filter is silent, and a silent notification channel looks exactly
// like a system with nothing to report — so a pattern matching no known event
// is a spec error, not a warning.
func validateNotifications(p *Project) hcl.Diagnostics {
	var diags hcl.Diagnostics
	n := p.Notifications
	if n == nil {
		return diags
	}
	rng := n.DefRange

	// Credentials are references and are scoped like every other reference
	// (R3, R5). Git, registry, storage and notification credentials all follow
	// the same rule; this is the notification half of it.
	refs := map[string]string{}
	if t := n.Telegram; t != nil {
		if t.ChatID == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Telegram channel has no chat_id",
				Detail:   fmt.Sprintf("Project %q declares a telegram block with no chat_id.", p.Name),
				Subject:  rng.Ptr(),
			})
		}
		refs["telegram.token_ref"] = t.TokenRef
	}
	if w := n.Webhook; w != nil {
		diags = append(diags, validateNotifyURL(p.Name, "webhook.url", w.URL, rng)...)
		if w.SecretRef != "" {
			refs["webhook.secret_ref"] = w.SecretRef
		}
	}
	if s := n.Slack; s != nil {
		refs["slack.url_ref"] = s.URLRef
	}
	if nt := n.Ntfy; nt != nil {
		diags = append(diags, validateNotifyURL(p.Name, "ntfy.url", nt.URL, rng)...)
		if nt.TokenRef != "" {
			refs["ntfy.token_ref"] = nt.TokenRef
		}
	}
	if sm := n.SMTP; sm != nil {
		diags = append(diags, validateSMTP(p.Name, sm, rng)...)
		if sm.PasswordRef != "" {
			refs["smtp.password_ref"] = sm.PasswordRef
		}
	}

	for field, ref := range refs {
		if ref == "" {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Notification channel has no credential reference",
				Detail: fmt.Sprintf("Project %q needs notifications.%s. Credentials are "+
					"referenced, never inlined (R3): use secret:%s/<name>.", p.Name, field, p.Name),
				Subject: rng.Ptr(),
			})
			continue
		}
		diags = append(diags, checkSecretRef(ref, p.Name,
			fmt.Sprintf("notifications.%s in project %q", field, p.Name), rng)...)
	}

	if len(n.On) == 0 && anyChannel(n) {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Notification channel has no event filter",
			Detail: fmt.Sprintf("Project %q declares notification channels but no `on`. "+
				"A channel nobody has told what to send is silent, which is "+
				"indistinguishable from a system with nothing to report. "+
				"Events are: %s.", p.Name, strings.Join(notify.KnownEvents(), ", ")),
			Subject: rng.Ptr(),
		})
	}
	for _, pattern := range n.On {
		if err := notify.ValidatePattern(pattern); err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unknown notification event",
				Detail:   fmt.Sprintf("Project %q: %s", p.Name, err),
				Subject:  rng.Ptr(),
			})
		}
	}
	if _, err := notify.ParseSeverity(n.Severity); n.Severity != "" && err != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Unknown notification severity",
			Detail: fmt.Sprintf("Project %q sets notifications.severity = %q; "+
				"expected info, warning or error.", p.Name, n.Severity),
			Subject: rng.Ptr(),
		})
	}
	return diags
}

// anyChannel reports whether any channel is configured.
func anyChannel(n *Notifications) bool {
	return n.Telegram != nil || n.Webhook != nil || n.Slack != nil ||
		n.Ntfy != nil || n.SMTP != nil
}

// validateNotifyURL enforces https on the targets that carry one literally.
//
// The same rule the egress guard applies at send time, checked here so it fails
// in front of the person who wrote it (§14 A10).
func validateNotifyURL(project, field, raw string, rng hcl.Range) hcl.Diagnostics {
	if raw == "" {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Notification channel has no url",
			Detail:   fmt.Sprintf("Project %q declares %s with no value.", project, field),
			Subject:  rng.Ptr(),
		}}
	}
	if !strings.HasPrefix(raw, "https://") {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Notification target is not https",
			Detail: fmt.Sprintf("Project %q sets notifications.%s = %q. Notification "+
				"targets must use https: a payload over cleartext is one anyone on "+
				"the path can read, and a signature only proves it was not altered.",
				project, field, raw),
			Subject: rng.Ptr(),
		}}
	}
	return nil
}

// validateSMTP checks the mail channel's required fields.
func validateSMTP(project string, sm *SMTPChannel, rng hcl.Range) hcl.Diagnostics {
	var diags hcl.Diagnostics
	missing := func(field string) {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Incomplete smtp channel",
			Detail:   fmt.Sprintf("Project %q declares an smtp block with no %s.", project, field),
			Subject:  rng.Ptr(),
		})
	}
	if sm.Host == "" {
		missing("host")
	}
	if sm.From == "" {
		missing("from")
	}
	if len(sm.To) == 0 {
		missing("to")
	}
	if sm.Username != "" && sm.PasswordRef == "" {
		missing("password_ref (a username needs one)")
	}
	return diags
}

// validateStorages checks the named storage resources (PRD §8): known driver,
// the fields that driver needs, and no duplicates.
func validateStorages(spec *Spec) hcl.Diagnostics {
	var diags hcl.Diagnostics
	seen := map[string]hcl.Range{}

	for _, st := range spec.Storages {
		diags = append(diags, validateName("Storage", st.Name, st.DefRange)...)

		if first, dup := seen[st.Name]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate storage",
				Detail:   fmt.Sprintf("Storage %q is already declared at %s.", st.Name, first),
				Subject:  st.DefRange.Ptr(),
			})
			continue
		}
		seen[st.Name] = st.DefRange

		missing := func(field string) *hcl.Diagnostic {
			return &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Incomplete storage",
				Detail: fmt.Sprintf("Storage %q is type %q and needs %s.",
					st.Name, st.Type, field),
				Subject: st.DefRange.Ptr(),
			}
		}

		switch st.Type {
		case StorageLocal:
			// Nothing to configure: the path is derived under data_dir/volumes.

		case StorageHost:
			diags = append(diags, validateHostPath(st)...)

		case StorageS3:
			if st.Bucket == "" {
				diags = append(diags, missing("bucket"))
			}
			if st.Mode != "" && st.Mode != "ro" && st.Mode != "rw" {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Invalid storage mode",
					Detail: fmt.Sprintf("Storage %q has mode %q; expected \"ro\" (mountpoint-s3, "+
						"the default) or \"rw\" (s3fs).", st.Name, st.Mode),
					Subject: st.DefRange.Ptr(),
				})
			}

		case StorageNFS:
			if st.Server == "" {
				diags = append(diags, missing("server"))
			}
			if st.Export == "" {
				diags = append(diags, missing("export"))
			}

		case StorageSMB:
			if st.Server == "" {
				diags = append(diags, missing("server"))
			}
			if st.Share == "" {
				diags = append(diags, missing("share"))
			}

		case "":
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Storage has no type",
				Detail: fmt.Sprintf("Storage %q must set type = \"%s\" | \"%s\" | \"%s\" | \"%s\".",
					st.Name, StorageLocal, StorageS3, StorageNFS, StorageSMB),
				Subject: st.DefRange.Ptr(),
			})

		default:
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unknown storage type",
				Detail: fmt.Sprintf("Storage %q has type %q; expected %s, %s, %s, %s or %s.",
					st.Name, st.Type, StorageLocal, StorageHost, StorageS3, StorageNFS, StorageSMB),
				Subject: st.DefRange.Ptr(),
			})
		}
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
		diags = append(diags, validateVolumes(spec, svc)...)
		diags = append(diags, validateScaling(svc)...)
		diags = append(diags, validateUpdate(svc)...)
		diags = append(diags, validateExpose(svc)...)
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
	diags = append(diags, validatePassthrough(svc)...)
	diags = append(diags, validateNetworkPolicy(svc)...)
	return diags
}

// validateSecretRefs enforces R3 and R5: secrets are referenced by path, and a
// service may only read its own project's namespace or `shared/`. Cross-project
// reads are an IDOR-class exfiltration path (PRD §14, A01).
func validateSecretRefs(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics

	// The registry push credential is scoped by R5 like everything else. It is
	// checked here rather than in validateTask because a service may have a
	// build block and no task worth validating yet.
	if svc.Build != nil && svc.Build.RegistryAuthRef != "" {
		diags = append(diags, checkSecretRef(
			svc.Build.RegistryAuthRef, svc.Project,
			fmt.Sprintf("build.registry_auth_ref in service %q", svc.Name),
			svc.Build.DefRange)...)
	}

	if svc.Task == nil {
		return diags
	}

	// The pull credential is scoped the same way the push one is (R19, R5).
	if svc.Task.RegistryAuthRef != "" {
		diags = append(diags, checkSecretRef(
			svc.Task.RegistryAuthRef, svc.Project,
			fmt.Sprintf("task.registry_auth_ref in service %q", svc.Name),
			svc.Task.DefRange)...)
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

func validateVolumes(spec *Spec, svc *Service) hcl.Diagnostics {
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
		switch {
		case v.Storage == "":
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Volume has no storage",
				Detail:   fmt.Sprintf("Volume %q of service %q must name a storage resource.", v.Name, svc.Name),
				Subject:  v.DefRange.Ptr(),
			})
		case spec.StorageByName(v.Storage) == nil:
			// Catching this here means a typo fails at `plan`, not at alloc
			// start with a confusing mount error.
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Unknown storage",
				Detail: fmt.Sprintf("Volume %q of service %q references storage %q, which is not "+
					"declared in this set.", v.Name, svc.Name, v.Storage),
				Subject: v.DefRange.Ptr(),
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

// validateUpdate checks the rolling-deploy policy (PRD §4.3, §6.1).
//
// The strategy is checked against a closed set rather than passed through,
// because an unrecognised value has to mean *something* at deploy time, and
// silently falling back to rolling would let `strategy = "canary"` parse, plan,
// apply, and then do something other than what it says — on the one operation
// where being surprised is most expensive.
func validateUpdate(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	up := svc.Update
	if up == nil {
		return diags
	}

	switch up.Strategy {
	case "", reconciler.StrategyRolling, reconciler.StrategyReplace:
	default:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Unknown update strategy",
			Detail: fmt.Sprintf("Service %q has update strategy = %q; it must be %q or %q. "+
				"Canary deployments are a post-v1 feature (PRD §19.3).",
				svc.Name, up.Strategy, reconciler.StrategyRolling, reconciler.StrategyReplace),
			Subject: svc.DefRange.Ptr(),
		})
	}
	if up.MaxParallel < 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid max_parallel",
			Detail: fmt.Sprintf("Service %q has update max_parallel = %d; it must be positive, "+
				"or omitted for one at a time.", svc.Name, up.MaxParallel),
			Subject: svc.DefRange.Ptr(),
		})
	}
	diags = append(diags, validateDuration("min_healthy", up.MinHealthy, svc.DefRange)...)
	diags = append(diags, validateDuration("interval", up.Interval, svc.DefRange)...)
	diags = append(diags, validateDuration("deadline", up.Deadline, svc.DefRange)...)
	diags = append(diags, validateAutoUpdate(svc)...)
	return diags
}

// validateAutoUpdate enforces R19's parse-time half.
//
// What is checked here is whether the request makes sense at all — not whether
// the registry can be reached, which is a node question and a runtime one.
func validateAutoUpdate(svc *Service) hcl.Diagnostics {
	up := svc.Update
	if up == nil || !up.Auto {
		return nil
	}

	reject := func(summary, detail string) hcl.Diagnostics {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  summary,
			Detail:   fmt.Sprintf("Service %q: %s", svc.Name, detail),
			Subject:  svc.DefRange.Ptr(),
		}}
	}

	// A build block already owns this service's image: the pipeline pins the
	// digest it produced. Two writers on one field is a fight in which the
	// loser is whichever ran second, which is not a thing to debug at 3am.
	if svc.Build != nil {
		return reject("Auto-update conflicts with build",
			"update.auto follows a tag in a registry, but this service builds its own image "+
				"and the pipeline pins the digest it produces (§10.2). Remove one of them.")
	}
	if svc.Task == nil || svc.Task.Image == "" {
		return reject("Auto-update needs an image",
			"update.auto re-resolves task.image, and this service does not declare one.")
	}
	// A digest does not move, so following one is a contradiction rather than a
	// no-op — and reading it as a no-op would leave someone believing their
	// service updates when nothing ever will.
	if strings.Contains(svc.Task.Image, "@") {
		return reject("Auto-update needs a tag, not a digest",
			fmt.Sprintf("task.image is %q, which is pinned to a digest. A digest never moves, "+
				"so there is nothing for update.auto to follow — declare a tag instead.",
				svc.Task.Image))
	}

	if up.Interval != "" {
		// Already known to parse: validateDuration ran first.
		if d, err := ParseDuration(up.Interval); err == nil && d < reconciler.MinUpdateInterval {
			return reject("Auto-update interval is too short",
				fmt.Sprintf("update.interval is %s; the minimum is %s. A poll is a request to "+
					"someone else's registry, and a tighter loop earns a rate limit rather than "+
					"a faster deploy.", up.Interval, reconciler.MinUpdateInterval))
		}
	}
	return nil
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

// validateNetworkPolicy enforces R14: the per-service ingress allowlist.
//
// Every entry is checked here rather than when the policy is generated,
// because by then the diagnostic would have no file or line to point at — and
// a network rule that silently fails to match is the exact failure mode this
// whole area is prone to (M0 spike ①).
func validateNetworkPolicy(svc *Service) hcl.Diagnostics {
	if svc.Network == nil || svc.Network.Policy == nil {
		return nil
	}
	policy := svc.Network.Policy

	var diags hcl.Diagnostics
	seen := make(map[string]bool, len(policy.AllowFrom))

	for _, raw := range policy.AllowFrom {
		ref, err := ParsePeerRef(raw)
		if err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid policy peer",
				Detail: fmt.Sprintf("Service %q: %s. Each allow_from entry names one peer as "+
					"\"<project>/<service>\" — for example \"analytics/collector\".", svc.Name, err),
				Subject: policy.DefRange.Ptr(),
			})
			continue
		}
		if seen[ref.String()] {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate policy peer",
				Detail:   fmt.Sprintf("Service %q: %q is listed twice in allow_from.", svc.Name, ref),
				Subject:  policy.DefRange.Ptr(),
			})
			continue
		}
		seen[ref.String()] = true

		// A service naming itself is almost certainly a copy-paste slip, and it
		// is the one entry that can never mean anything: a service already
		// reaches itself.
		if ref.Project == svc.Project && ref.Service == svc.Name {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Service allows itself",
				Detail: fmt.Sprintf("Service %q lists itself in allow_from; a service can always "+
					"reach itself.", svc.Name),
				Subject: policy.DefRange.Ptr(),
			})
		}
	}
	return diags
}

// validateHostPath enforces the parse-time half of R15.
//
// Only the *shape* of the path is decided here. Whether it may actually be
// mounted is a server-config question (§15.1) that a job spec has no business
// answering and this package has no way to answer — it does not know the
// operator's allowlist, and a spec author naming their own permitted paths
// would defeat the point of having one.
func validateHostPath(st *Storage) hcl.Diagnostics {
	reject := func(detail string) hcl.Diagnostics {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid host path",
			Detail:   fmt.Sprintf("Storage %q: %s", st.Name, detail),
			Subject:  st.DefRange.Ptr(),
		}}
	}

	switch {
	case st.Path == "":
		return reject("a host volume needs an absolute `path`.")
	case !filepath.IsAbs(st.Path):
		return reject(fmt.Sprintf("path %q must be absolute.", st.Path))
	case strings.Contains(st.Path, ".."):
		// Refused outright rather than cleaned away: a spec containing ".." is
		// either a mistake or an attempt to walk out of an allowlisted prefix,
		// and silently rewriting it would hide both.
		return reject(fmt.Sprintf("path %q must not contain \"..\".", st.Path))
	case filepath.Clean(st.Path) != st.Path:
		return reject(fmt.Sprintf("path %q is not in its simplest form; write %q.",
			st.Path, filepath.Clean(st.Path)))
	case st.Path == "/":
		return reject("mounting the whole root filesystem is never permitted.")
	}
	return nil
}

// systemMountPaths are the trees a passthrough may not be mounted over.
//
// Each is load-bearing for the sandbox itself: /dev is the tmpfs a granted
// device is mknod'd into, /proc and /sys are what the masked-path list applies
// to. Something bound over one of them is either a mistake or an attempt to
// undo a hardening default from inside the spec that the default constrains.
var systemMountPaths = []string{"/dev", "/proc", "/sys"}

// validatePassthrough enforces the parse-time half of R17 and R18.
//
// Shape only, and less of it than R15 needs: a device or socket block carries a
// *grant name*, not a path, so there is no host path here to validate. Whether
// the node has that grant, and whether this project may claim it, is a
// server-config question (§15.1) this package cannot answer and should not try
// to — a spec that named its own permitted devices would be the escape hatch
// the grant model exists to avoid.
func validatePassthrough(svc *Service) hcl.Diagnostics {
	task := svc.Task
	var diags hcl.Diagnostics

	// Sockets and volumes share one namespace of mount paths: two things on one
	// path means one of them silently wins, whichever kind they are.
	seenPath := map[string]hcl.Range{}
	for _, v := range svc.Volumes {
		if _, dup := seenPath[v.MountPath]; !dup {
			seenPath[v.MountPath] = v.DefRange
		}
	}

	// Devices and sockets share one namespace too, so that a diagnostic about a
	// duplicate name never depends on which kind of block it came from.
	seenName := map[string]hcl.Range{}
	claimName := func(kind, name string, rng hcl.Range) {
		if first, dup := seenName[name]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate " + strings.ToLower(kind) + " name",
				Detail:   fmt.Sprintf("%s %q is already declared at %s.", kind, name, first),
				Subject:  rng.Ptr(),
			})
			return
		}
		seenName[name] = rng
	}

	for _, d := range task.Devices {
		diags = append(diags, validateName("Device", d.Name, d.DefRange)...)
		diags = append(diags, validateGrant("Device", svc.Name, d.Name, d.Grant, d.DefRange)...)
		claimName("Device", d.Name, d.DefRange)
	}

	for _, s := range task.Sockets {
		diags = append(diags, validateName("Socket", s.Name, s.DefRange)...)
		diags = append(diags, validateGrant("Socket", svc.Name, s.Name, s.Grant, s.DefRange)...)
		claimName("Socket", s.Name, s.DefRange)

		reject := func(detail string) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid socket mount path",
				Detail:   fmt.Sprintf("Socket %q of service %q: %s", s.Name, svc.Name, detail),
				Subject:  s.DefRange.Ptr(),
			})
		}
		switch {
		case s.MountPath == "":
			reject("a socket needs an absolute `mount_path`.")
			continue
		case !path.IsAbs(s.MountPath):
			reject(fmt.Sprintf("mount_path %q must be absolute.", s.MountPath))
			continue
		case strings.Contains(s.MountPath, ".."):
			reject(fmt.Sprintf("mount_path %q must not contain \"..\".", s.MountPath))
			continue
		case path.Clean(s.MountPath) != s.MountPath:
			reject(fmt.Sprintf("mount_path %q is not in its simplest form; write %q.",
				s.MountPath, path.Clean(s.MountPath)))
			continue
		case s.MountPath == "/":
			reject("a socket cannot be mounted over the root filesystem.")
			continue
		}
		if under := systemPathFor(s.MountPath); under != "" {
			reject(fmt.Sprintf("mount_path %q is under %s, which the sandbox owns.",
				s.MountPath, under))
			continue
		}
		if first, dup := seenPath[s.MountPath]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Conflicting mount path",
				Detail: fmt.Sprintf("Mount path %q is already used at %s.",
					s.MountPath, first),
				Subject: s.DefRange.Ptr(),
			})
			continue
		}
		seenPath[s.MountPath] = s.DefRange
	}
	return diags
}

// validateGrant checks that a grant reference is shaped like one a node config
// could define (R17, R18). It says nothing about whether the grant exists.
func validateGrant(kind, service, name, grant string, rng hcl.Range) hcl.Diagnostics {
	if grant == "" {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Missing grant",
			Detail: fmt.Sprintf("%s %q of service %q must name a `grant` the operator has "+
				"defined on the node (§15.1).", kind, name, service),
			Subject: rng.Ptr(),
		}}
	}
	if !dns1123Label.MatchString(grant) {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid grant name",
			Detail: fmt.Sprintf("%s %q of service %q requests grant %q, which is not a DNS-1123 "+
				"label; no node config could define it.", kind, name, service, grant),
			Subject: rng.Ptr(),
		}}
	}
	return nil
}

// systemPathFor returns the system tree p sits under, or "".
func systemPathFor(p string) string {
	for _, sys := range systemMountPaths {
		if p == sys || strings.HasPrefix(p, sys+"/") {
			return sys
		}
	}
	return ""
}

// checkSecretRef enforces R3 (referenced, never inlined) and R5 (project-scoped)
// on one reference.
//
// `where` names the field in a way that reads in a diagnostic — the operator
// needs to know which of several references in a spec is the wrong one.
func checkSecretRef(ref, project, where string, rng hcl.Range) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if !strings.HasPrefix(ref, SecretPrefix) {
		return append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Credential is not a secret reference",
			Detail: fmt.Sprintf("%s is %q. Credentials are referenced, never inlined (R3): "+
				"use secret:%s/<name> or secret:%s/<name>.",
				where, ref, project, SharedSecretScope),
			Subject: rng.Ptr(),
		})
	}
	scope, rest, found := strings.Cut(strings.TrimPrefix(ref, SecretPrefix), "/")
	if !found || scope == "" || rest == "" {
		return append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Malformed secret reference",
			Detail: fmt.Sprintf("%s is %q; references look like secret:<project>/<name>.",
				where, ref),
			Subject: rng.Ptr(),
		})
	}
	if scope != project && scope != SharedSecretScope {
		return append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Cross-project secret reference",
			Detail: fmt.Sprintf("%s references %q, which belongs to another project. "+
				"Only secret:%s/… or secret:%s/… may be read here (R5).",
				where, ref, project, SharedSecretScope),
			Subject: rng.Ptr(),
		})
	}
	return diags
}
