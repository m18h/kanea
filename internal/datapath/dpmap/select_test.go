package dpmap

import (
	"fmt"
	"math/rand/v2"
	"testing"
)

func TestPickOfOneIsAlwaysZero(t *testing.T) {
	for _, r := range []uint32{0, 1, 42, 0xFFFFFFFF} {
		if got := Pick(1, r); got != 0 {
			t.Errorf("Pick(1, %d) = %d, want 0", r, got)
		}
	}
}

func TestPickMirrorsTheModulo(t *testing.T) {
	cases := []struct {
		count int
		rand  uint32
		want  uint16
	}{
		{4, 0, 0},
		{4, 5, 1},
		{4, 0xFFFFFFFF, 3}, // 4294967295 % 4
		{3, 10, 1},
		{7, 100, 2},
	}
	for _, tc := range cases {
		if got := Pick(tc.count, tc.rand); got != tc.want {
			t.Errorf("Pick(%d, %d) = %d, want %d", tc.count, tc.rand, got, tc.want)
		}
	}
}

// TestPickIsLooselyUniform: 100k draws over 4 backends land each backend
// near 25k. The tolerance is ±4% of the total per bucket — ~7σ, loose on
// purpose: this pins "the selection is a modulo over the whole set", not
// the PRNG's quality (the kernel's prandom is not ours to test).
func TestPickIsLooselyUniform(t *testing.T) {
	const (
		backends = 4
		draws    = 100_000
	)
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic test PRNG, not crypto
	var buckets [backends]int
	for i := 0; i < draws; i++ {
		buckets[Pick(backends, rng.Uint32())]++
	}
	const want = draws / backends
	const slack = draws / 100 // 1 000 per bucket
	for i, n := range buckets {
		if n < want-slack || n > want+slack {
			t.Errorf("backend %d picked %d times, want %d±%d", i, n, want, slack)
		}
	}
}

func backendsOf(ips ...byte) []Backend {
	out := make([]Backend, len(ips))
	for i, ip := range ips {
		out[i] = Backend{IP: [4]byte{10, 0, 0, ip}, Port: 8080}
	}
	return out
}

// TestFlipPlanOrdering: every put of the new generation strictly before
// the one commit, every delete of the old generation strictly after. That
// order IS the atomicity — reordering it is the torn-set bug.
func TestFlipPlanOrdering(t *testing.T) {
	const oldGen = 7
	current := backendsOf(1, 2, 3)
	next := backendsOf(4, 5)

	ops := FlipPlan(9, current, next, oldGen)

	if want := len(next) + 1 + len(current); len(ops) != want {
		t.Fatalf("plan has %d ops, want %d", len(ops), want)
	}

	commitAt := -1
	for i, op := range ops {
		switch op.Kind {
		case OpCommitService:
			if commitAt != -1 {
				t.Fatalf("two commits, at %d and %d", commitAt, i)
			}
			commitAt = i
			if op.Svc != (SvcVal{SvcID: 9, Count: 2, Gen: oldGen + 1}) {
				t.Errorf("commit writes %+v, want svc 9, count 2, gen %d", op.Svc, oldGen+1)
			}
		case OpPutBackend:
			if commitAt != -1 {
				t.Errorf("put at %d after the commit at %d", i, commitAt)
			}
			if op.Key.Gen != oldGen+1 {
				t.Errorf("put at %d writes gen %d, want %d", i, op.Key.Gen, oldGen+1)
			}
		case OpDeleteBackend:
			if commitAt == -1 {
				t.Errorf("delete at %d before the commit", i)
			}
			if op.Key.Gen != oldGen {
				t.Errorf("delete at %d removes gen %d, want %d", i, op.Key.Gen, oldGen)
			}
		default:
			t.Fatalf("op %d has unknown kind %d", i, op.Kind)
		}
	}
	if commitAt == -1 {
		t.Fatal("plan has no commit")
	}
}

// flipModel executes ops against an in-memory model of svc_v4 (one entry)
// and svc_backends, the way the linux writer will against the kernel maps.
type flipModel struct {
	svc      SvcVal
	backends map[BackendKey]BackendVal
}

func (m *flipModel) apply(op Op) {
	switch op.Kind {
	case OpPutBackend:
		m.backends[op.Key] = op.Val
	case OpCommitService:
		m.svc = op.Svc
	case OpDeleteBackend:
		delete(m.backends, op.Key)
	}
}

// read is the datapath's view: resolve the committed generation, then look
// up every index the committed count names — exactly what kanea_connect4
// does for the one index it draws.
func (m *flipModel) read() ([]BackendVal, error) {
	out := make([]BackendVal, 0, m.svc.Count)
	for i := uint16(0); i < m.svc.Count; i++ {
		v, ok := m.backends[BackendKey{SvcID: m.svc.SvcID, Index: i, Gen: m.svc.Gen}]
		if !ok {
			return nil, fmt.Errorf("svc %d gen %d index %d: no backend (torn set)", m.svc.SvcID, m.svc.Gen, i)
		}
		out = append(out, v)
	}
	return out, nil
}

func valsOf(bs []Backend) []BackendVal {
	out := make([]BackendVal, len(bs))
	for i, b := range bs {
		out[i] = BackendVal(b)
	}
	return out
}

func sameSet(got, want []BackendVal) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestFlipPlanIsAtomicAtEveryBoundary interleaves a reader at every op
// boundary of the plan — before the first op, between every pair, after
// the last — and requires it to see the complete old set or the complete
// new set, never a mixture and never a miss. This is the property the
// generation flip exists for: a connect during a backend change must not
// observe a torn set.
func TestFlipPlanIsAtomicAtEveryBoundary(t *testing.T) {
	const (
		svcID  = 3
		oldGen = 41
	)
	cases := []struct {
		name          string
		current, next []Backend
	}{
		{"replace", backendsOf(1, 2, 3), backendsOf(4, 5)},
		{"grow", backendsOf(1), backendsOf(1, 2, 3, 4)},
		{"scale to zero", backendsOf(1, 2), nil},
		{"from zero", nil, backendsOf(9)},
		{"same set rewritten", backendsOf(1, 2), backendsOf(1, 2)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := FlipPlan(svcID, tc.current, tc.next, oldGen)

			model := &flipModel{
				svc:      SvcVal{SvcID: svcID, Count: uint16(len(tc.current)), Gen: oldGen},
				backends: make(map[BackendKey]BackendVal),
			}
			for i, b := range tc.current {
				model.backends[BackendKey{SvcID: svcID, Index: uint16(i), Gen: oldGen}] = BackendVal(b)
			}

			oldSet := valsOf(tc.current)
			newSet := valsOf(tc.next)

			// Boundary 0 is before any op; boundary i is after ops[i-1].
			for boundary := 0; boundary <= len(ops); boundary++ {
				if boundary > 0 {
					model.apply(ops[boundary-1])
				}
				got, err := model.read()
				if err != nil {
					t.Fatalf("boundary %d: %v", boundary, err)
				}
				switch model.svc.Gen {
				case oldGen:
					if !sameSet(got, oldSet) {
						t.Fatalf("boundary %d: gen %d sees %v, want the complete old set %v", boundary, oldGen, got, oldSet)
					}
				case oldGen + 1:
					if !sameSet(got, newSet) {
						t.Fatalf("boundary %d: gen %d sees %v, want the complete new set %v", boundary, oldGen+1, got, newSet)
					}
				default:
					t.Fatalf("boundary %d: svc entry names gen %d, which no op wrote", boundary, model.svc.Gen)
				}
			}

			// After the full plan the old generation is gone: nothing keyed
			// under oldGen survives to be resurrected by a later flip back
			// to the same number.
			for k := range model.backends {
				if k.Gen == oldGen {
					t.Errorf("old-generation entry %+v survived the flip", k)
				}
			}
		})
	}
}
