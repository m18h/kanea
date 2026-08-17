package reconciler_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
)

// The two halves of v1.56's invariant, asserted together: a spec that declares
// no capabilities still hashes to the pre-feature digest (so upgrading kanead
// re-hashes nothing and rolls nothing) while its projection carries the
// baseline. The hash and the projection diverged on purpose; this test is what
// keeps anyone from "fixing" that by writing the baseline into the record.
func TestTheCapabilityBaselineNeverEntersTheSpecHash(t *testing.T) {
	d := desired(3)
	d.Volumes = []reconciler.Volume{{Name: "data", MountPath: "/data"}}

	// The same digest TestSpecHashIsUnchangedForASpecWithNoUserOrOwnership
	// pins: the exact bytes this Desired hashed to before the baseline (and
	// before R23) existed.
	const preBaseline = "df0877104f33e69e9cebc6f3d05a5975"
	if got := reconciler.SpecHash(d); got != preBaseline {
		t.Errorf("spec hash = %s, want %s\n"+
			"A spec with no capabilities line must hash as it did before the baseline "+
			"existed. If it does not, upgrading kanead rolls every alloc on the node.",
			got, preBaseline)
	}

	spec := reconciler.AllocSpecFor(d, 0, "", "/vol")
	if !reflect.DeepEqual(spec.Capabilities, reconciler.BaselineCapabilities) {
		t.Errorf("projected capabilities = %v, want the baseline %v",
			spec.Capabilities, reconciler.BaselineCapabilities)
	}
}

// "none" starts from nothing: alone it is the pre-v1.56 drop-ALL posture, and
// beside a grant it means exactly that grant. The token itself must never
// survive into the projection: runc refuses unknown capability names, so a
// leaked token would fail every alloc of the service.
func TestNoneMeansNoCapabilities(t *testing.T) {
	d := desired(1)
	d.Capabilities = []string{"none"}
	if got := reconciler.AllocSpecFor(d, 0, "", "/vol").Capabilities; len(got) != 0 {
		t.Errorf("[\"none\"] projected to %v, want nothing", got)
	}

	d.Capabilities = []string{"CAP_NET_RAW", "none"}
	got := reconciler.AllocSpecFor(d, 0, "", "/vol").Capabilities
	if !reflect.DeepEqual(got, []string{"CAP_NET_RAW"}) {
		t.Errorf("[\"none\", CAP_NET_RAW] projected to %v, want exactly [CAP_NET_RAW]", got)
	}
}

// A declared grant adds to the baseline rather than replacing it: otherwise
// granting ping would silently take away the uid-switching set, which is the
// exact confusion the baseline exists to end.
func TestDeclaredCapabilitiesMergeWithTheBaseline(t *testing.T) {
	d := desired(1)
	d.Capabilities = []string{"CAP_NET_RAW", "CAP_CHOWN"} // CHOWN is already baseline
	got := reconciler.AllocSpecFor(d, 0, "", "/vol").Capabilities

	want := append([]string{"CAP_NET_RAW"}, reconciler.BaselineCapabilities...)
	if len(got) != len(want) {
		t.Fatalf("projected %d capabilities %v, want %d (baseline ∪ declared, deduplicated)",
			len(got), got, len(want))
	}
	for _, c := range want {
		if !slices.Contains(got, c) {
			t.Errorf("projected set %v is missing %s", got, c)
		}
	}
}

// Declaring "none" (or spelling the baseline out) is a spec change and must
// roll: what the container runs with genuinely changes. The second half pins
// the other direction: the declared list is what hashes, so an explicit
// baseline is a different record than an implied one, and nobody gets to
// "optimize" the union back into the store.
func TestDeclaringNoneRollsTheService(t *testing.T) {
	base := desired(1)

	none := base
	none.Capabilities = []string{"none"}
	if reconciler.SpecHash(none) == reconciler.SpecHash(base) {
		t.Error("declaring [\"none\"] did not change the spec hash; the opt-out would never deploy")
	}

	explicit := base
	explicit.Capabilities = append([]string(nil), reconciler.BaselineCapabilities...)
	if reconciler.SpecHash(explicit) == reconciler.SpecHash(base) {
		t.Error("an explicitly declared baseline hashes like an implied one; the declared list is what hashes")
	}
}

// R25 gives a function's spec no way to declare capabilities, and the
// projection must not hand it the runc baseline either: a non-default runtime
// passes through verbatim, so upgrading kanead changes nothing about what a
// function alloc gets.
func TestAFunctionGetsNoCapabilityBaseline(t *testing.T) {
	d := desired(1)
	d.Runtime = runtime.RuntimeWasmtime
	if got := reconciler.AllocSpecFor(d, 0, "", "/vol").Capabilities; len(got) != 0 {
		t.Errorf("a wasm alloc was projected capabilities %v, want none", got)
	}
}

// Capabilities are spec-hash material, so a capability edit rolls every alloc,
// and a plan that did not mention it would show a redeploy with no visible
// cause (the runtime/ports rule, applied to R13).
func TestDiffNamesACapabilityChange(t *testing.T) {
	have := desired(1)
	want := have
	want.Capabilities = []string{"none"}

	lines := reconciler.Diff([]reconciler.Desired{have}, []reconciler.Desired{want})
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "capabilities baseline (default) -> [none]") {
		t.Fatalf("plan lines %q do not name the capability change", joined)
	}
}
