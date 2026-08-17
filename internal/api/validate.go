package api

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/secrets"
)

// validateDesired re-enforces at the apply seam the invariants jobspec
// enforces at parse time. The parser is one way a record reaches the Store;
// PUT /v1/services is another, and R22's port policy has always been checked
// at this layer for exactly that reason ("the boundary rather than a second
// opinion"). This is the rest of the list, and the order is the order an
// operator would meet them.
//
// Everything here mirrors a parse-time rule with its own message; nothing here
// is a new rule. A record that passes this function is one a spec could have
// declared - which is the whole claim the passthrough/grant design rests on.
func validateDesired(svc reconciler.Desired) error {
	key := svc.Project + "/" + svc.Service

	// R1/§4.2: names compose into DNS and into host paths the reconciler
	// builds as root - volume directories, resolv.conf, log files. The
	// parser refuses anything that is not a DNS-1123 label; a record that
	// never saw the parser is refused again here.
	if !jobspec.IsName(svc.Project) || !jobspec.IsName(svc.Service) {
		return fmt.Errorf("service %s: project and service names must be DNS-1123 labels "+
			"(a lowercase letter or digit, dashes inside, 63 chars max)", key)
	}

	// R13: capabilities are an allowlist, not a prefix check.
	if err := jobspec.CheckCapabilities(svc.Capabilities); err != nil {
		return fmt.Errorf("service %s: %w", key, err)
	}

	for _, v := range svc.Volumes {
		if !jobspec.IsName(v.Name) {
			return fmt.Errorf("service %s: volume name %q is not a DNS-1123 label", key, v.Name)
		}
		// R5 (v1.72's rule, applied to an inline resource the parser never
		// saw): mounting is reading, so the credential must name this
		// service's own project or shared/.
		if ref := v.Resource.AuthRef; ref != "" {
			if err := jobspec.CheckSecretRefScope(ref, svc.Project,
				fmt.Sprintf("volume %q's storage auth_ref", v.Name)); err != nil {
				return fmt.Errorf("service %s: %w", key, err)
			}
		}
		// The endpoint half of the same rule: the mount helper sends the
		// resolved credential to this address on every request.
		if ep := v.Resource.Endpoint; ep != "" && !strings.HasPrefix(ep, "https://") {
			return fmt.Errorf("service %s: storage %q sets endpoint %q; endpoints must use https",
				key, v.Resource.Name, ep)
		}
	}

	// R5 again, for env references: the parser scopes them (validateSecretRefs);
	// a record written directly is checked here. Both delivery forms (file and
	// inline, v1.76) scope identically.
	for name, value := range svc.Env {
		ref, _, ok := secrets.ParseEnvRef(value)
		if !ok {
			continue
		}
		if err := jobspec.CheckSecretRefScope(ref, svc.Project,
			fmt.Sprintf("env %s", name)); err != nil {
			return fmt.Errorf("service %s: %w", key, err)
		}
	}

	// R25: a non-default runtime gets the whole refusal list, not two of
	// seven. A record carrying Runtime beside any of these reached the Store
	// without the parser's function lowering, and the runtime's own guarantees
	// (no volumes, no devices, no way to grant) depend on the list being
	// complete. The runtime name itself and the exec-probe refusal stay in
	// applyServices, next to the closed set.
	if svc.Runtime != "" {
		switch {
		case len(svc.Volumes) > 0:
			return fmt.Errorf("service %s names runtime %q and declares volumes; the wasm runtime "+
				"has no mount primitive (PRD §6.2 R25)", key, svc.Runtime)
		case len(svc.Devices) > 0:
			return fmt.Errorf("service %s names runtime %q and declares devices; the wasm runtime "+
				"has no device passthrough (PRD §6.2 R25)", key, svc.Runtime)
		case len(svc.Sockets) > 0:
			return fmt.Errorf("service %s names runtime %q and declares sockets; the wasm runtime "+
				"has no socket passthrough (PRD §6.2 R25)", key, svc.Runtime)
		case len(svc.Capabilities) > 0:
			return fmt.Errorf("service %s names runtime %q and declares capabilities; the wasm "+
				"runtime grants none (PRD §6.2 R25)", key, svc.Runtime)
		case svc.User != nil:
			return fmt.Errorf("service %s names runtime %q and declares a user; the wasm runtime "+
				"has no uid concept (PRD §6.2 R25)", key, svc.Runtime)
		case svc.Scaling != nil:
			return fmt.Errorf("service %s names runtime %q and declares scaling; function scaling "+
				"is event-driven, not replica-count (PRD §6.2 R25)", key, svc.Runtime)
		}
	}

	// R16 (v1.50): every route that authenticates must authenticate the same
	// way - the verifier bundle is keyed per service (v1.40's invariant), and
	// the projection takes the first route's auth and stands it for all of
	// them, so a disagreeing second block would silently serve unauthenticated.
	var first *reconciler.AuthPolicy
	for _, e := range svc.AllExposes() {
		if e.Auth == nil {
			continue
		}
		if first == nil {
			first = e.Auth
			continue
		}
		if !reflect.DeepEqual(first, e.Auth) {
			return fmt.Errorf("service %s declares different auth configurations on different "+
				"expose blocks (PRD §6.2 R16); every block that declares auth must declare "+
				"the same auth", key)
		}
	}

	return nil
}

// logPathFor joins an alloc's log path, verifying the result stays under
// logDir. Alloc IDs come from Store records whose names were DNS-1123 labels
// at both boundaries (jobspec R1 at parse, validateDesired at the apply seam);
// this is the assertion at the point of the read, the same shape withinBase
// gives the reconciler at the point of the write.
func logPathFor(logDir, allocID string) (string, error) {
	path := filepath.Join(logDir, allocID+".log")
	rel, err := filepath.Rel(logDir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("alloc id %q escapes the log directory", allocID)
	}
	return path, nil
}
