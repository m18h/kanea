package jobspec

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/secrets"
)

// MaxContainerID is containerd's identifier ceiling. An init container's id is
// composed from the alloc id, the step's ordinal and the step's name (see
// runtime.InitID), so the three share one budget and a long project name
// spends part of a step's.
//
// Note this bounds the *init* id only. An alloc id alone can already exceed
// the ceiling on a node whose project and service names are both near the
// DNS-1123 maximum; that is older than R32 and is not made better by pretending
// this check fixes it, so the message names the budget rather than the rule.
const MaxContainerID = 76

// maxAllocIndexDigits is the index allowance in the id-budget check: enough for
// 9 999 allocs of one service, which is four orders of magnitude past anything
// a single node runs.
const maxAllocIndexDigits = 4

// pullPolicies is R33's closed set. Empty is not in it and is not an error:
// empty means "the node decides" (§15.1's images stanza), the shape
// expose.tls.mode has, because a spec is parsed client-side and a node default
// resolved there would make one spec mean different things on two machines.
var pullPolicies = map[string]bool{
	runtime.PullIfNotPresent: true,
	runtime.PullNever:        true,
	runtime.PullAlways:       true,
}

// CheckPullPolicy validates one declared policy against R33 and returns the
// first problem, or nil.
//
// allowAlways is false for an init container, and the refusal is the rule
// rather than an omission: "always" lowers to R19 auto-update, which writes a
// pinned image, and there is exactly one pinned-image field on a record and it
// belongs to the task. Honouring it on a step could only mean re-pulling per
// alloc create, which is the drift the policy refuses one level up.
//
// It is the shared core of the plan-time and apply-time checks, like
// CheckCapabilities and CheckSecretRefScope, so the two paths cannot drift.
func CheckPullPolicy(policy string, allowAlways bool) error {
	if policy == "" {
		return nil
	}
	if !pullPolicies[policy] {
		return fmt.Errorf("pull_policy %q is not a policy; it must be %q, %q or %q, "+
			"or omitted to take the node's default (PRD §6.2 R33)",
			policy, runtime.PullIfNotPresent, runtime.PullNever, runtime.PullAlways)
	}
	if policy == runtime.PullAlways && !allowAlways {
		return fmt.Errorf("pull_policy %q is not available on an init container: it lowers to "+
			"update { auto = true }, which pins a digest, and the pinned image belongs to the "+
			"task. Declare it on the task instead (PRD §6.2 R33)", runtime.PullAlways)
	}
	return nil
}

// validateInits enforces R32 over a service's init blocks.
//
// Everything an init block can get wrong that the task can get wrong is checked
// by the same core the task's rule uses (checkCapability, checkSecretRef,
// checkContainerID, ParseDuration); what is new here is the name uniqueness and
// the id budget, both of which exist because a step's name composes into a
// containerd id and a log file rather than staying inside the spec.
func validateInits(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if len(svc.Inits) == 0 {
		return diags
	}

	// R25: the wasm sandbox holds one module, so there is no second container
	// to run. The function block has no `init` field, so this can only be
	// reached by a spec that declared both blocks on one service.
	if svc.Function != nil {
		return append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Function declares init containers",
			Detail: fmt.Sprintf("Function %q declares %d init block(s); the wasm runtime runs one "+
				"module and has no second container to run (PRD §6.2 R25). Use an ordinary service.",
				svc.Name, len(svc.Inits)),
			Subject: svc.Inits[0].DefRange.Ptr(),
		})
	}

	seen := map[string]bool{}
	for ordinal, init := range svc.Inits {
		diags = append(diags, validateName("Init container", init.Name, init.DefRange)...)

		if seen[init.Name] {
			diags = append(diags, initDiag(init, "Duplicate init container",
				fmt.Sprintf("Service %q declares init %q more than once. Names compose into a "+
					"container id and a log file, so they must be unique within a service.",
					svc.Name, init.Name)))
		}
		seen[init.Name] = true

		// The id budget. Checked at plan because the alternative is a container
		// create that fails on every alloc with an identifier error nobody can
		// attribute to a name in the spec.
		if id := len(runtime.InitID(
			svc.Project+"-"+svc.Name, ordinal, init.Name,
		)) + maxAllocIndexDigits; id > MaxContainerID {
			diags = append(diags, initDiag(init, "Init container name is too long",
				fmt.Sprintf("Init %q of service %q composes into a container id of about %d "+
					"characters; the runtime's limit is %d. The project name, the service name "+
					"and this one share that budget, so shorten whichever you can.",
					init.Name, svc.Name, id, MaxContainerID)))
		}

		// R32: an init container has no build block, so R8's
		// wait-for-the-first-build has nothing to wait for.
		if init.Image == "" {
			diags = append(diags, initDiag(init, "Init container has no image",
				fmt.Sprintf("Init %q of service %q must set image. Unlike a task it has no build "+
					"block, so there is no pipeline to produce one.", init.Name, svc.Name)))
		}

		// R12's rule, unchanged: the first element is the program, later
		// arguments may be empty because some programs use that meaningfully.
		if len(init.Command) > 0 && strings.TrimSpace(init.Command[0]) == "" {
			diags = append(diags, initDiag(init, "Empty command",
				fmt.Sprintf("Init %q of service %q declares a command whose first element is empty; "+
					"it names the program to run (PRD §6.2 R12).", init.Name, svc.Name)))
		}

		// R11 (v1.58): zero is unbounded, so only a negative is malformed.
		if init.Resources.CPU < 0 {
			diags = append(diags, initDiag(init, "Invalid CPU limit",
				fmt.Sprintf("Init %q of service %q declares resources.cpu = %d MHz; it cannot be "+
					"negative. Omit the field for all cores.", init.Name, svc.Name, init.Resources.CPU)))
		}
		if init.Resources.Memory < 0 {
			diags = append(diags, initDiag(init, "Invalid memory limit",
				fmt.Sprintf("Init %q of service %q declares resources.memory = %d MiB; it cannot be "+
					"negative. Omit the field for all allocatable memory.",
					init.Name, svc.Name, init.Resources.Memory)))
		}

		// R13, through the same per-entry core the task's list goes through.
		capsSeen := map[string]bool{}
		for _, capability := range init.Capabilities {
			if err := checkCapability(capability, capsSeen); err != nil {
				diags = append(diags, initDiag(init, "Invalid capability",
					fmt.Sprintf("Init %q of service %q: %s", init.Name, svc.Name, err)))
			}
		}

		// R23, numeric and range-checked exactly as the task's is.
		diags = append(diags, validateUserBlock(
			fmt.Sprintf("Init container %q", init.Name), svc.Name, init.User)...)

		// R33.
		if err := CheckPullPolicy(init.PullPolicy, false); err != nil {
			diags = append(diags, initDiag(init, "Invalid pull policy",
				fmt.Sprintf("Init %q of service %q: %s", init.Name, svc.Name, err)))
		}

		// R32: absent or zero is no timeout (R11's rule); a negative one is
		// neither a bound nor an absence, so it is refused rather than read as
		// either.
		diags = append(diags, validateDuration(
			fmt.Sprintf("init %q timeout", init.Name), init.Timeout, init.DefRange)...)
		if d, err := ParseDuration(init.Timeout); init.Timeout != "" && err == nil && d < 0 {
			diags = append(diags, initDiag(init, "Invalid timeout",
				fmt.Sprintf("Init %q of service %q declares timeout = %q; it cannot be negative. "+
					"Omit it for no timeout at all.", init.Name, svc.Name, init.Timeout)))
		}

		// R5, through checkSecretRef, so the scoping rule has one
		// implementation across the task and every step.
		if init.RegistryAuthRef != "" {
			diags = append(diags, checkSecretRef(
				init.RegistryAuthRef, svc.Project,
				fmt.Sprintf("init %q registry_auth_ref in service %q", init.Name, svc.Name),
				init.DefRange)...)
		}
		for key, value := range init.Env {
			ref, _, ok := secrets.ParseEnvRef(value)
			if !ok {
				continue
			}
			diags = append(diags, checkSecretRef(
				ref, svc.Project,
				fmt.Sprintf("environment variable %q of init %q in service %q", key, init.Name, svc.Name),
				init.DefRange)...)
		}
	}
	return diags
}

func initDiag(init *InitContainer, summary, detail string) *hcl.Diagnostic {
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  summary,
		Detail:   detail,
		Subject:  init.DefRange.Ptr(),
	}
}
