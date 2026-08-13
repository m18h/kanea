//go:build linux

package datapath

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// nftTable is the one table Kanea owns. Everything in it is ours to flush;
// nothing outside it is ever touched — a foreign FORWARD-drop policy (docker,
// ufw) is a `kanea doctor` finding, not something the datapath fights.
const nftTable = NFTableName

// nftFirewall is the real Firewall over google/nftables.
type nftFirewall struct{}

// EnsureMasquerade installs the single NAT rule the datapath needs: traffic
// from the cluster CIDR to anywhere outside it is masqueraded on the way out.
// Kernel conntrack does the NAT; the rule is idempotent because the owned
// table is flushed and rewritten in one transaction.
//
// It also asserts net.ipv4.ip_forward (v1.65): masquerade without forwarding
// is a rule that matches nothing, and the pre-v1.65 datapath inherited the
// sysctl from "the node's existing configuration" — usually docker's, which
// is exactly the dependency that broke the first node to drop docker.
func (nftFirewall) EnsureMasquerade(clusterCIDR netip.Prefix, _ string) error {
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
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("nftables: install masquerade: %w", err)
	}
	return nil
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
