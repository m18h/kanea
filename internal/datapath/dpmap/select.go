package dpmap

// Backend is one member of a service's backend set, in the order the flip
// writes it: index i of generation g lands at backend_key{svc, i, g}.
type Backend struct {
	IP   [4]byte // network order
	Port uint16  // host value; encoded big-endian on the wire
}

// Pick is the userspace reference of the datapath's backend selection:
// kanea_connect4 computes bpf_get_prandom_u32() % count. count must be in
// [1, 65535] — svc_val.count is a __u16, and the program checks count == 0
// (and refuses the connect) before selecting. Pick mirrors that by
// returning 0 outside the range, which the caller must never reach.
func Pick(count int, rand uint32) uint16 {
	if count <= 0 || count > 0xFFFF {
		return 0
	}
	// #nosec G115 — count is bounded to the uint16 range above, and the
	// modulo bounds the result below it.
	return uint16(rand % uint32(count))
}

// OpKind names one step of a generation flip.
type OpKind uint8

// The three op kinds, in the only order a flip may execute them.
const (
	// OpPutBackend writes svc_backends[Key] = Val. Every put of the new
	// generation happens strictly before the commit.
	OpPutBackend OpKind = iota + 1
	// OpCommitService atomically updates the service's svc_v4 value to
	// Svc — the one write that makes the new generation visible. The
	// svc_v4 key (VIP/port/proto) is the executor's to supply; the plan
	// carries the value.
	OpCommitService
	// OpDeleteBackend deletes svc_backends[Key] — the old generation's
	// entries, strictly after the commit.
	OpDeleteBackend
)

// Op is one map operation of a generation flip, in a form neutral enough
// for the linux writer to execute against the kernel maps and for tests to
// execute against a model.
type Op struct {
	Kind OpKind
	Key  BackendKey // put and delete
	Val  BackendVal // put only
	Svc  SvcVal     // commit only
}

// FlipPlan returns the ordered map operations that replace a service's
// backend set: puts of every next backend under oldGen+1, then the one
// commit that flips svc_v4 to the new generation, then deletes of the old
// generation's entries.
//
// The order is the atomicity: a connect that lands before the commit
// resolves oldGen and finds the old set complete (nothing of it has been
// touched); one that lands after resolves oldGen+1 and finds the new set
// complete (all of it was written first). Half-updating svc_backends
// without flipping svc_v4 is the torn-set bug this pattern exists to
// prevent — which is why the writer executes a plan instead of improvising.
//
// An empty next set is a valid plan: the commit writes Count 0 and the
// datapath refuses connects with DROP_NO_BACKEND until the next flip.
func FlipPlan(svcID uint16, current, next []Backend, oldGen uint32) []Op {
	newGen := oldGen + 1
	ops := make([]Op, 0, len(next)+1+len(current))

	// #nosec G115 — backend counts fit a __u16 by construction: svc_backends
	// holds at most 16384 entries, and jobspec caps replicas far below that.
	for i, b := range next {
		ops = append(ops, Op{
			Kind: OpPutBackend,
			Key:  BackendKey{SvcID: svcID, Index: uint16(i), Gen: newGen}, // #nosec G115 — bounded as above
			Val:  BackendVal(b),
		})
	}

	ops = append(ops, Op{
		Kind: OpCommitService,
		Svc:  SvcVal{SvcID: svcID, Count: uint16(len(next)), Gen: newGen}, // #nosec G115 — bounded as above
	})

	for i := range current {
		ops = append(ops, Op{
			Kind: OpDeleteBackend,
			Key:  BackendKey{SvcID: svcID, Index: uint16(i), Gen: oldGen}, // #nosec G115 — bounded as above
		})
	}

	return ops
}
