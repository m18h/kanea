package api

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
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

	// R33: the policy vocabulary is closed, and "always" is a task-only word
	// (there is one pinned-image field and it belongs to the task).
	if err := jobspec.CheckPullPolicy(svc.PullPolicy, true); err != nil {
		return fmt.Errorf("service %s: %w", key, err)
	}

	// R32: every rule validateInits applies at plan, applied again here for a
	// record that never met the parser. Each goes through the same exported
	// core as its parse-time half, so the two cannot drift.
	initNames := make(map[string]struct{}, len(svc.Init))
	for _, step := range svc.Init {
		if !jobspec.IsName(step.Name) {
			return fmt.Errorf("service %s: init container name %q is not a DNS-1123 label; "+
				"it composes into a container id and a log file name", key, step.Name)
		}
		if _, dup := initNames[step.Name]; dup {
			return fmt.Errorf("service %s: init container %q is declared more than once", key, step.Name)
		}
		initNames[step.Name] = struct{}{}
		if step.Image == "" {
			return fmt.Errorf("service %s: init container %q has no image; unlike a task it has "+
				"no build block (PRD §6.2 R32)", key, step.Name)
		}
		if err := jobspec.CheckCapabilities(step.Capabilities); err != nil {
			return fmt.Errorf("service %s: init container %q: %w", key, step.Name, err)
		}
		if err := jobspec.CheckPullPolicy(step.PullPolicy, false); err != nil {
			return fmt.Errorf("service %s: init container %q: %w", key, step.Name, err)
		}
		if step.Timeout < 0 {
			return fmt.Errorf("service %s: init container %q declares a negative timeout; omit it "+
				"for no timeout at all (PRD §6.2 R32)", key, step.Name)
		}
		if ref := step.RegistryAuthRef; ref != "" {
			if err := jobspec.CheckSecretRefScope(ref, svc.Project,
				fmt.Sprintf("init %q registry_auth_ref", step.Name)); err != nil {
				return fmt.Errorf("service %s: %w", key, err)
			}
		}
		for name, value := range step.Env {
			ref, _, ok := secrets.ParseEnvRef(value)
			if !ok {
				continue
			}
			if err := jobspec.CheckSecretRefScope(ref, svc.Project,
				fmt.Sprintf("env %s of init %q", name, step.Name)); err != nil {
				return fmt.Errorf("service %s: %w", key, err)
			}
		}
	}

	// R35: every rule validateFiles applies at parse, applied again here for a
	// record that never met the parser. The NUL check matters more at this seam
	// than at the other one: content arrives base64-encoded here, so a NUL is
	// perfectly expressible, and it is what keeps a secret placeholder
	// inexpressible by anything but the parser.
	seenFile := map[string]struct{}{}
	seenPath := map[string]struct{}{}
	for _, v := range svc.Volumes {
		seenPath[v.MountPath] = struct{}{}
	}
	for _, sock := range svc.Sockets {
		seenPath[sock.MountPath] = struct{}{}
	}
	totalFiles := 0
	for _, f := range svc.Files {
		if !jobspec.IsName(f.Name) {
			return fmt.Errorf("service %s: file name %q is not a DNS-1123 label", key, f.Name)
		}
		if _, dup := seenFile[f.Name]; dup {
			return fmt.Errorf("service %s: file %q is declared more than once", key, f.Name)
		}
		seenFile[f.Name] = struct{}{}
		if err := jobspec.CheckFilePath(f.Name, f.Path); err != nil {
			return fmt.Errorf("service %s: %w", key, err)
		}
		if _, dup := seenPath[f.Path]; dup {
			return fmt.Errorf("service %s: file %q mounts at %q, which is already mounted",
				key, f.Name, f.Path)
		}
		seenPath[f.Path] = struct{}{}
		if err := jobspec.CheckFileContent(f.Name, f.Content, f.Nonce, len(f.SecretRefs)); err != nil {
			return fmt.Errorf("service %s: %w", key, err)
		}
		if err := jobspec.CheckFileMode(f.Name, f.Mode, len(f.SecretRefs) > 0); err != nil {
			return fmt.Errorf("service %s: %w", key, err)
		}
		// R5 over every reference a placeholder can index into. A forged
		// placeholder could only ever select one of these, which is why the
		// table is the authority and the bytes are inert.
		for _, ref := range f.SecretRefs {
			if err := jobspec.CheckSecretRefScope(ref, svc.Project,
				fmt.Sprintf("file %q", f.Name)); err != nil {
				return fmt.Errorf("service %s: %w", key, err)
			}
		}
		if f.Nonce == "" && len(f.SecretRefs) > 0 {
			return fmt.Errorf("service %s: file %q names secret references with no nonce; "+
				"its placeholders could not be substituted", key, f.Name)
		}
		totalFiles += len(f.Content)
	}
	if totalFiles > jobspec.MaxServiceFileBytes {
		return fmt.Errorf("service %s declares %d bytes of file content; the limit is %d (PRD §21)",
			key, totalFiles, jobspec.MaxServiceFileBytes)
	}

	// R11 (v1.89) on the pids cap: the parser refuses a negative one; the
	// same refusal lands here for records that never saw the parser.
	if svc.Resources.PidsLimit < 0 {
		return fmt.Errorf("service %s: resources.pids cannot be negative; "+
			"omitted (or 0) takes the default cap", key)
	}
	for _, step := range svc.Init {
		if step.Resources.PidsLimit != 0 && step.Resources.PidsLimit != runtime.DefaultPidsLimit {
			return fmt.Errorf("service %s: init step %q declares a pids cap; a step inherits "+
				"the alloc's cap (PRD §6.2 R32)", key, step.Name)
		}
	}

	// R25: a non-default runtime gets the whole refusal list, not two of
	// seven - it is the whole list, and init containers and files make it
	// nine. A record carrying Runtime beside any of these reached the Store
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
		case len(svc.Init) > 0:
			return fmt.Errorf("service %s names runtime %q and declares init containers; the wasm "+
				"runtime runs one module and has no second container to run (PRD §6.2 R25)",
				key, svc.Runtime)
		case len(svc.Files) > 0:
			return fmt.Errorf("service %s names runtime %q and declares files; the wasm runtime "+
				"has no mount primitive (PRD §6.2 R25)", key, svc.Runtime)
		case svc.Resources.PidsLimit != 0 && svc.Resources.PidsLimit != runtime.DefaultPidsLimit:
			return fmt.Errorf("service %s names runtime %q and declares a pids cap; the wasm "+
				"sandbox's caps are fixed (PRD §6.2 R25)", key, svc.Runtime)
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

// initLogPathFor is logPathFor for one of an alloc's init containers (R32).
//
// The step is named rather than passed as an id: the caller supplies a name it
// found in the *record's own* Desired.Init, and the id is composed here, so a
// query string can never name a container directly. The containment assertion
// then runs on the composed result, which is what it is for.
func initLogPathFor(logDir, allocID string, ordinal int, name string) (string, error) {
	id := runtime.InitID(allocID, ordinal, name)
	path := filepath.Join(logDir, id+".log")
	rel, err := filepath.Rel(logDir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("init container id %q escapes the log directory", id)
	}
	return path, nil
}

// resolveInitStep finds a named step in a service's declared sequence. The
// name comes from a client; the ordinal and the id do not.
func resolveInitStep(svc reconciler.Desired, name string) (int, bool) {
	for i := range svc.Init {
		if svc.Init[i].Name == name {
			return i, true
		}
	}
	return 0, false
}
