//go:build linux && bpfload

// The kernel-floor gate (PRD §21: "kernel ≥ 5.10; the floor is spike-validated,
// not inherited").
//
// Nothing else in CI ever loads a BPF program. `bpf-verify` regenerates the
// committed artifacts and diffs the bytes, which asks whether they still come
// from the committed sources, not whether any kernel will accept them. So a
// change to kanea.c that needs a helper, a map type or an instruction added
// after 5.10 would raise the real floor silently, and the first person to find
// out would be an operator on a Debian 11 node whose datapath does not come up.
//
// This test answers only the question a VM can answer cheaply: does the kernel
// running it accept the shipping object? It loads and verifies, and deliberately
// does NOT attach: attachment needs cgroup and netlink state that belongs to the
// spike harness (spikes/ebpf-datapath), which is the full-fidelity run on real
// hardware. The two are complementary: run this one first, because it is the
// cheapest question and it fails fast if the object will not verify at all.
//
// CI does not run it. Booting a 5.10 kernel there was tried through
// cilium/little-vm-helper and abandoned: the action fetches the image and then
// hands lvh the qcow2 path where it expects a registry reference. A check that
// always fails is worse than one that does not exist, so this runs by hand on
// the floor node instead (docs/VALIDATION.md §3).
//
// Behind a build tag because it needs root and a bpffs-capable kernel, which the
// ordinary `go test ./...` has neither of:
//
//	sudo -E go test -tags bpfload -run Floor -v ./internal/datapath/
package datapath

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/m18h/kanea/internal/datapath/bpf"
	"github.com/m18h/kanea/internal/datapath/dpmap"
)

// everyProgram is the four the loader looks up by name; a miss is a hard error
// in openObjects, so the floor has to clear all of them.
var everyProgram = []string{
	bpf.ProgConnect4,
	bpf.ProgConnect6,
	bpf.ProgToContainer,
	bpf.ProgFromContainer,
}

// everyMap is every map the object declares. The v6 entries matter most here:
// their 20-byte keys are the widest the datapath has, and a key width the
// verifier will not take is the failure this gate exists to find early.
var everyMap = []string{
	dpmap.MapSvcV4, dpmap.MapSvcBackends, dpmap.MapIdentityV4, dpmap.MapAllowV4,
	dpmap.MapStatsSvc, dpmap.MapStatsEp, dpmap.MapStatsDrops, dpmap.MapConfig,
	dpmap.MapSvcV6, dpmap.MapSvcBackends6, dpmap.MapIdentityV6,
	dpmap.MapStatsEp6, dpmap.MapStatsDrops6, dpmap.MapConfig6,
	dpmap.MapClusterV4, dpmap.MapClusterV6,
}

func TestFloorTheShippingObjectVerifies(t *testing.T) {
	// The same call loadPinned makes, for the same reason: below 5.11 the
	// kernel charges maps and programs against RLIMIT_MEMLOCK, and the five
	// PERCPU_HASH stats maps cost ~360 KiB per CPU. Without this the test
	// would fail on a big-core 5.10 box for a reason that has nothing to do
	// with the verifier, which is exactly the misdiagnosis to avoid.
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("raise RLIMIT_MEMLOCK: %v", err)
	}

	spec, err := bpf.LoadSpec()
	if err != nil {
		t.Fatalf("load the embedded spec: %v", err)
	}

	// Named before loading: a program missing from the object is a build
	// problem, and reporting it as a verifier rejection would send the reader
	// to the kernel instead of to bpf2go.
	for _, name := range everyProgram {
		if _, ok := spec.Programs[name]; !ok {
			t.Errorf("program %q is not in the shipping object", name)
		}
	}
	for _, name := range everyMap {
		if _, ok := spec.Maps[name]; !ok {
			t.Errorf("map %q is not in the shipping object", name)
		}
	}
	if t.Failed() {
		return
	}

	// No PinPath: this creates maps and loads programs into the kernel, runs
	// the verifier over each, and touches nothing on the filesystem. A node's
	// pins are not this test's business.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// %+v is the full verifier log. Truncated, it names an
			// instruction nobody can act on.
			t.Fatalf("this kernel's verifier rejected the shipping object.\n"+
				"That is the kernel floor moving: PRD §21 claims ≥ 5.10, and "+
				"either the claim or the program has to change.\n%+v", ve)
		}
		t.Fatalf("load the collection: %v", err)
	}
	defer coll.Close()

	// Loaded, not merely present in the spec.
	for _, name := range everyProgram {
		if coll.Programs[name] == nil {
			t.Errorf("program %q did not load", name)
		}
	}
	for _, name := range everyMap {
		if coll.Maps[name] == nil {
			t.Errorf("map %q was not created", name)
		}
	}
}
