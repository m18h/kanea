package jobspec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// The hardening posture (R13, v1.105): the strong profile as one named word,
// beside the compatible default v1.56 chose.
//
// Restricted restricts the *task*. Init blocks keep their own rules on
// purpose: the recommended shape for a volume-owning image is an init step
// that runs as root, chowns, exits, and a task that runs restricted (R32's
// canonical step, R23/R24's model). A function refuses the field
// structurally: hclFunction has no hardening attribute, R25's pattern where
// the absence is the refusal.

// Hardening postures. HardeningCompatible is the default's explicit spelling
// and canonicalises to "" at parse, so it never reaches a record and is never
// SpecHash material; HardeningRestricted survives into the record and IS hash
// material, because declaring it changes what the container runs with.
const (
	HardeningCompatible = "compatible"
	HardeningRestricted = "restricted"
)

// canonicalHardening folds the default's explicit spelling to the empty
// string. Unknown values pass through for validation to refuse with a
// position; case and whitespace are forgiven, typos are not.
func canonicalHardening(s string) string {
	folded := strings.ToLower(strings.TrimSpace(s))
	if folded == HardeningCompatible {
		return ""
	}
	if folded == HardeningRestricted {
		return HardeningRestricted
	}
	return s
}

// CheckHardening validates a posture against the fields it constrains and
// returns the first problem, or nil. It is the shared core of the parse-time
// half (validateHardening) and the apply seam (the API's validateDesired), so
// the two paths cannot drift. hardening arrives canonical: "" or
// "restricted"; a stored record carrying "compatible" is refused, because the
// canonical spelling of the default is omission and a record is the
// serialized form.
func CheckHardening(hardening string, capabilities []string, hasUser, rootUser, function bool) error {
	switch hardening {
	case "":
		return nil
	case HardeningRestricted:
	default:
		return fmt.Errorf(
			"unknown hardening %q; it is %q (the default) or %q",
			hardening, HardeningCompatible, HardeningRestricted)
	}

	if function {
		return errors.New(
			`a function cannot declare hardening: the wasm sandbox has no capability or uid concept to restrict`)
	}
	if !hasUser {
		return fmt.Errorf(
			`hardening = %q requires a user block: declare user { uid, gid } with a non-zero uid, `+
				`and use an init step for any setup that genuinely needs root`, HardeningRestricted)
	}
	if rootUser {
		return fmt.Errorf(
			`hardening = %q refuses uid 0: the posture is a non-root task with no capabilities, `+
				`and root without capabilities is a promise most images break at the first chown. `+
				`Run setup that needs root in an init step`, HardeningRestricted)
	}
	for _, capability := range capabilities {
		// "none" is redundant under restricted (drop-ALL is already the
		// posture) and allowed: a spec saying the same thing twice is not
		// wrong. A real grant is a contradiction, refused by name.
		if strings.ToUpper(strings.TrimSpace(capability)) == capabilityNoneUpper {
			continue
		}
		return fmt.Errorf(
			"hardening = %q grants no capabilities, and the spec declares %s; "+
				"remove the grant, or drop the posture to declare it",
			HardeningRestricted, capability)
	}
	return nil
}

// validateHardening is CheckHardening's parse-time half: the same core,
// wrapped in diagnostics that point at the service.
func validateHardening(svc *Service) hcl.Diagnostics {
	var (
		caps    []string
		hasUser bool
		root    bool
	)
	if svc.Task != nil {
		caps = svc.Task.Capabilities
		if svc.Task.User != nil {
			hasUser = true
			root = svc.Task.User.UID == 0
		}
	}
	if err := CheckHardening(svc.Hardening, caps, hasUser, root, svc.Function != nil); err != nil {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid hardening",
			Detail:   fmt.Sprintf("Service %q: %s.", svc.Name, err),
			Subject:  svc.DefRange.Ptr(),
		}}
	}
	return nil
}

// warnHardening names the weak defaults an operator should see at plan
// (v1.105). Warnings, never errors: the compatible default is a contract, and
// a stock image's spec keeps planning clean aside from these lines.
//
// Functions are skipped except for the tag warning: a wasm module has no uid
// and no rootfs, but its module reference is an OCI image and a moving tag
// moves either way.
func warnHardening(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if svc.Task == nil {
		return diags
	}
	warn := func(summary, detail string, rng hcl.Range) {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagWarning,
			Summary:  summary,
			Detail:   detail,
			Subject:  rng.Ptr(),
		})
	}

	// A moving tag deploys whatever it points at on the day. Auto-update is
	// the one deliberate way to follow one (the tag is resolved and pinned, so
	// every replica rolls together); a build block's pipeline pins the digest
	// it produces; an empty image is waiting for its first build; and a digest
	// does not move. Everything else earns the line.
	image := svc.Task.Image
	auto := svc.Update != nil && svc.Update.Auto
	if image != "" && !strings.Contains(image, "@") && !auto && svc.Build == nil {
		warn("Image follows a moving tag",
			fmt.Sprintf("Service %q pulls %q, a tag with no digest: a deploy runs whatever the "+
				"tag points at that day. Pin it (image@sha256:…), or opt into update.auto to "+
				"follow the tag deliberately.", svc.Name, image),
			svc.Task.DefRange)
	}

	if svc.Function != nil {
		return diags
	}

	// Restricted already *requires* a non-root user, so the uid warning would
	// only ever double an error.
	if svc.Hardening != HardeningRestricted {
		switch {
		case svc.Task.User == nil:
			warn("Task runs as the image's own user",
				fmt.Sprintf("Service %q declares no user block, so the image decides the uid - "+
					"often root, with the baseline capabilities on. Declare user { uid, gid }, "+
					"or name the strong posture with hardening = %q.",
					svc.Name, HardeningRestricted),
				svc.Task.DefRange)
		case svc.Task.User.UID == 0:
			warn("Task runs as root",
				fmt.Sprintf("Service %q declares uid 0 with the baseline capabilities on. If the "+
					"root work is startup-only, move it to an init step and run the task as a "+
					"non-zero uid with hardening = %q.", svc.Name, HardeningRestricted),
				svc.Task.User.DefRange)
		}
	}

	if !svc.Task.ReadOnlyRootfs {
		warn("Root filesystem is writable",
			fmt.Sprintf("Service %q leaves its root filesystem writable. Set "+
				"read_only_rootfs = true and mount a volume where the workload genuinely "+
				"writes; a compromised process then cannot rewrite the image's own files.",
				svc.Name),
			svc.Task.DefRange)
	}
	return diags
}
