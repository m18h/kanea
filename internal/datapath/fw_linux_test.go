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

func TestBuildEgressRangeExprs(t *testing.T) {
	// The subuid half (v1.105): a Dockerfile USER step runs as a subuid, so
	// the same metadata drop must cover the whole /etc/subuid range. Shape
	// again, for the reason above.
	exprs := buildEgressRangeExprs(200000, 65536)
	if len(exprs) != 8 {
		t.Fatalf("buildEgressRangeExprs = %d expressions, want 8", len(exprs))
	}

	meta, ok := exprs[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeySKUID {
		t.Fatalf("exprs[0] = %#v, want the skuid meta load", exprs[0])
	}
	// The swap to big-endian is what makes the range numeric: nft_cmp
	// compares bytes lexicographically, and a native-endian >= on a
	// little-endian kernel would order 256 below 1.
	swap, ok := exprs[1].(*expr.Byteorder)
	if !ok || swap.Op != expr.ByteorderHton || swap.Len != 4 {
		t.Fatalf("exprs[1] = %#v, want the hton byteorder swap", exprs[1])
	}

	// 200000 <= skuid < 265536, half-open exactly as /etc/subuid means it.
	from, ok := exprs[2].(*expr.Cmp)
	if !ok || from.Op != expr.CmpOpGte ||
		string(from.Data) != string(binaryutil.BigEndian.PutUint32(200000)) {
		t.Fatalf("exprs[2] = %#v, want skuid >= 200000 big-endian", exprs[2])
	}
	to, ok := exprs[3].(*expr.Cmp)
	if !ok || to.Op != expr.CmpOpLt ||
		string(to.Data) != string(binaryutil.BigEndian.PutUint32(265536)) {
		t.Fatalf("exprs[3] = %#v, want skuid < 265536 big-endian", exprs[3])
	}

	// The destination half and the verdict are the uid rule's, verbatim.
	if _, ok := exprs[4].(*expr.Payload); !ok {
		t.Fatalf("exprs[4] = %#v, want the daddr payload load", exprs[4])
	}
	mask, ok := exprs[5].(*expr.Bitwise)
	if !ok || string(mask.Mask) != string([]byte{0xff, 0xff, 0x00, 0x00}) {
		t.Fatalf("exprs[5] = %#v, want the /16 mask", exprs[5])
	}
	dstCmp, ok := exprs[6].(*expr.Cmp)
	if !ok || dstCmp.Op != expr.CmpOpEq || string(dstCmp.Data) != string([]byte{169, 254, 0, 0}) {
		t.Fatalf("exprs[6] = %#v, want the 169.254.0.0 comparison", exprs[6])
	}
	verdict, ok := exprs[7].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictDrop {
		t.Fatalf("exprs[7] = %#v, want the drop verdict", exprs[7])
	}
}
