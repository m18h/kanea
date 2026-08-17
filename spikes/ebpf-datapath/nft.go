//go:build linux

package main

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	nftTable    = "kanea-spike"
	nftSimTable = "kanea-spike-sim" // check 6's docker/ufw stand-in
)

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

// saddrMatch / daddrMatch: `ip {s,d}addr 10.244.0.0/16` as raw exprs.
func addrMatch(offset uint32) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  1,
			Base:          expr.PayloadBaseNetworkHeader,
			Offset:        offset, // 12 = saddr, 16 = daddr
			Len:           4,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{0xff, 0xff, 0x00, 0x00},
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 244, 0, 0}},
	}
}

// nftSetup programs the spike's own table: postrouting masquerade for pod
// traffic leaving the uplink (with a counter so the harness can prove the
// rule matched even without internet reachability), plus a FORWARD accept
// chain for the pod CIDR in both directions.
func nftSetup(e *env) error {
	c, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	e.nft = c

	tbl := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftTable})

	post := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    tbl,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	masqExprs := addrMatch(12)
	masqExprs = append(masqExprs,
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(e.uplinkName)},
		&expr.Counter{},
		&expr.Masq{},
	)
	c.AddRule(&nftables.Rule{Table: tbl, Chain: post, Exprs: masqExprs})

	fwd := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})
	for _, off := range []uint32{12, 16} {
		exprs := addrMatch(off)
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
		c.AddRule(&nftables.Rule{Table: tbl, Chain: fwd, Exprs: exprs})
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nft flush: %w", err)
	}
	return nil
}

func nftTeardown(e *env) {
	if e.nft == nil {
		return
	}
	for _, name := range []string{nftTable, nftSimTable} {
		e.nft.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: name})
		_ = e.nft.Flush() // per table: deleting an absent one must not veto the other
	}
}

func nftPurge() {
	c, err := nftables.New()
	if err != nil {
		return
	}
	for _, name := range []string{nftTable, nftSimTable} {
		c.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: name})
		_ = c.Flush()
	}
}

// masqCounter reads packets/bytes from the masquerade rule's counter.
func masqCounter(e *env) (packets, bytes uint64, err error) {
	tbl := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftTable}
	chain := &nftables.Chain{Name: "postrouting", Table: tbl}
	rules, err := e.nft.GetRules(tbl, chain)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range rules {
		var counter *expr.Counter
		var isMasq bool
		for _, ex := range r.Exprs {
			switch v := ex.(type) {
			case *expr.Counter:
				counter = v
			case *expr.Masq:
				isMasq = true
			}
		}
		if isMasq && counter != nil {
			return counter.Packets, counter.Bytes, nil
		}
	}
	return 0, 0, fmt.Errorf("masquerade rule not found")
}

// simDropInstall creates a second table whose FORWARD chain has policy drop
// and no rules: what a docker or ufw install effectively does to routed
// traffic. Returns the objects so the check can add "rescue" rules into it.
func simDropInstall(e *env) (*nftables.Table, *nftables.Chain, error) {
	drop := nftables.ChainPolicyDrop
	tbl := e.nft.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftSimTable})
	chain := e.nft.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityRef(10), // after our accept chain
		Policy:   &drop,
	})
	if err := e.nft.Flush(); err != nil {
		return nil, nil, err
	}
	return tbl, chain, nil
}

// simDropRescue inserts pod-CIDR accepts into the simulated chain itself:
// the "insert into DOCKER-USER/ufw's chain" move an operator would make.
func simDropRescue(e *env, tbl *nftables.Table, chain *nftables.Chain) error {
	for _, off := range []uint32{12, 16} {
		exprs := addrMatch(off)
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
		e.nft.InsertRule(&nftables.Rule{Table: tbl, Chain: chain, Exprs: exprs})
	}
	return e.nft.Flush()
}

func simDropRemove(e *env) error {
	e.nft.DelTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: nftSimTable})
	return e.nft.Flush()
}
