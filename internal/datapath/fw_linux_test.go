//go:build linux

package datapath

import (
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func TestBuildEgressExprs(t *testing.T) {
	// The rule is the whole control: repo-controlled build code, host
	// networking, and the one destination it must never reach. Assert the
	// shape rather than the table, because the table needs a live netlink.
	exprs := buildEgressExprs(900)
	if len(exprs) != 6 {
		t.Fatalf("buildEgressExprs = %d expressions, want 6", len(exprs))
	}

	// meta skuid == 900
	meta, ok := exprs[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeySKUID {
		t.Fatalf("exprs[0] = %#v, want the skuid meta load", exprs[0])
	}
	uidCmp, ok := exprs[1].(*expr.Cmp)
	if !ok || uidCmp.Op != expr.CmpOpEq {
		t.Fatalf("exprs[1] = %#v, want the uid comparison", exprs[1])
	}
	wantUID := binaryutil.NativeEndian.PutUint32(900)
	if string(uidCmp.Data) != string(wantUID) {
		t.Errorf("uid comparison data = %v, want %v", uidCmp.Data, wantUID)
	}

	// ip daddr & 255.255.0.0 == 169.254.0.0
	if _, ok := exprs[2].(*expr.Payload); !ok {
		t.Fatalf("exprs[2] = %#v, want the daddr payload load", exprs[2])
	}
	mask, ok := exprs[3].(*expr.Bitwise)
	if !ok || string(mask.Mask) != string([]byte{0xff, 0xff, 0x00, 0x00}) {
		t.Fatalf("exprs[3] = %#v, want the /16 mask", exprs[3])
	}
	dstCmp, ok := exprs[4].(*expr.Cmp)
	if !ok || dstCmp.Op != expr.CmpOpEq || string(dstCmp.Data) != string([]byte{169, 254, 0, 0}) {
		t.Fatalf("exprs[4] = %#v, want the 169.254.0.0 comparison", exprs[4])
	}

	// drop
	verdict, ok := exprs[5].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictDrop {
		t.Fatalf("exprs[5] = %#v, want the drop verdict", exprs[5])
	}
}
