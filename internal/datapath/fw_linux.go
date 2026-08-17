//go:build linux

package datapath

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// nftTable is the one table Kanea owns. Everything in it is ours to flush;
// nothing outside it is ever touched: a foreign FORWARD-drop policy (docker,
// ufw) is a `kanea doctor` finding, not something the datapath fights.
const nftTable = NFTableName

// nftFirewall is the real Firewall over google/nftables.
//
// buildUID is the kanea-buildkit account's uid, or 0 when there is no build
// daemon on the node. It keys the build-egress rule below; the account is
// resolved once by the caller, because a uid is what the kernel matches on.
type nftFirewall struct{ buildUID int }

// EnsureMasquerade installs the single NAT rule the datapath needs: traffic
// from the cluster CIDR to anywhere outside it is masqueraded on the way out.
// Kernel conntrack does the NAT; the rule is idempotent because the owned
// table is flushed and rewritten in one transaction.
//
// It also asserts net.ipv4.ip_forward (v1.65): masquerade without forwarding
// is a rule that matches nothing, and the pre-v1.65 datapath inherited the
// sysctl from "the node's existing configuration"; usually docker's, which
// is exactly the dependency that broke the first node to drop docker.
func (fw nftFirewall) EnsureMasquerade(clusterCIDR netip.Prefix, _ string) error {
	if err := writeSysctl("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
		return fmt.Errorf("ip_forward: %w", err)
	}
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftTable})
	conn.FlushTable(table)
	chain := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	network := clusterCIDR.Masked().Addr().As4()
	mask := maskFor(clusterCIDR)
	zero := []byte{0, 0, 0, 0}
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// ip saddr & mask == cluster network
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask[:], Xor: zero},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network[:]},
			// ip daddr & mask != cluster network
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask[:], Xor: zero},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: network[:]},
			&expr.Masq{},
		},
	})

	// The build-egress rule (v1.75): a Dockerfile RUN step is repo-controlled
	// code, and it runs with host networking (rootlesskit --net=host), so the
	// alloc-veth egress guard never sees it. The one destination a build must
	// never reach is the link-local range the guard drops for allocs (§14
	// A10): the cloud metadata service, first of all. The build daemon and
	// its workers all run as this one uid on the host (rootless uid-mapping
	// puts container root there), so the account is the match.
	//
	// Deliberately in the owned table's one rewrite: a second writer would
	// flush this rule away on the next ensure, and a rule in someone else's
	// table is the foreign-firewall fight the datapath refuses to have.
	if fw.buildUID > 0 {
		out := conn.AddChain(&nftables.Chain{
			Name:     "output",
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookOutput,
			Priority: nftables.ChainPriorityFilter,
		})
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: out,
			Exprs: buildEgressExprs(fw.buildUID),
		})
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables: install masquerade: %w", err)
	}
	return nil
}

// buildEgressExprs renders the build-egress drop: meta skuid == uid, ip daddr
// & 255.255.0.0 == 169.254.0.0, drop. Link-local v6 has no rule here: a
// link-local destination from the host is already unroutable off-link, and
// the AWS v6 metadata address (fd00:ec2::254) sits in a ULA range a build has
// no route to on a v4-only node; the v4 /16 is the one that is routable
// everywhere it matters.
func buildEgressExprs(uid int) []expr.Any {
	uidBytes := binaryutil.NativeEndian.PutUint32(uint32(uid))
	return []expr.Any{
		// meta skuid == uid
		&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: uidBytes},
		// ip daddr & 255.255.0.0 == 169.254.0.0
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: []byte{0xff, 0xff, 0x00, 0x00}, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{169, 254, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// Teardown removes the owned table. Absent is success.
func (nftFirewall) Teardown() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftTable})
	if err := conn.Flush(); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("nftables: remove table %s: %w", nftTable, err)
	}
	return nil
}
