//go:build linux

package main

import (
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// The host-firewall finding (PRD v1.86).
//
// The defect this replaces looked at the forward hook only, so a node whose
// input hook dropped the query to the internal resolver got a clean bill of
// health and no DNS. The second half - looking for an accept that names the
// cluster CIDR - is what stops the replacement from warning forever on every
// correctly configured node, and it is tested here because "self-clearing" is
// the property that decides whether anyone reads the finding at all.

const (
	testCluster  = "10.244.0.0/16"
	testResolver = "10.244.0.1:53"
)

// dropChain builds a base chain with a drop policy on the given hook.
func dropChain(t *testing.T, table, name string, hook *nftables.ChainHook) *nftables.Chain {
	t.Helper()
	policy := nftables.ChainPolicyDrop
	return &nftables.Chain{
		Name:    name,
		Table:   &nftables.Table{Name: table, Family: nftables.TableFamilyIPv4},
		Hooknum: hook,
		Policy:  &policy,
	}
}

// acceptChain is a regular chain a manager hangs its user rules off.
func acceptChain() *nftables.Chain {
	return &nftables.Chain{
		Name:  "ufw-user-input",
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
	}
}

// sourceAcceptRule is what `ufw allow from 10.244.0.0/16` renders as: load the
// source address, mask it, compare, accept.
func sourceAcceptRule(network [4]byte, verdict expr.VerdictKind) *nftables.Rule {
	return &nftables.Rule{
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: []byte{0xff, 0xff, 0, 0}, Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network[:]},
			&expr.Verdict{Kind: verdict},
		},
	}
}

func noRules(*nftables.Chain) []*nftables.Rule { return nil }

func TestTheHostFirewallFinding(t *testing.T) {
	network := [4]byte{10, 244, 0, 0}

	tests := []struct {
		name     string
		chains   []*nftables.Chain
		rules    func(*nftables.Chain) []*nftables.Rule
		wantOK   bool
		wantWarn bool
		contains string
	}{
		{
			name:     "an open node passes",
			chains:   nil,
			rules:    noRules,
			wantOK:   true,
			contains: "no drop policy",
		},
		{
			// The regression: the forward hook is fine and DNS is dead, which
			// is the exact node this finding was rewritten for.
			name:     "an input drop alone is a finding",
			chains:   []*nftables.Chain{dropChain(t, "filter", "INPUT", nftables.ChainHookInput)},
			rules:    noRules,
			wantOK:   true,
			wantWarn: true,
			contains: "input",
		},
		{
			name:     "a forward drop alone is a finding",
			chains:   []*nftables.Chain{dropChain(t, "filter", "FORWARD", nftables.ChainHookForward)},
			rules:    noRules,
			wantOK:   true,
			wantWarn: true,
			contains: "forward",
		},
		{
			// Self-clearing: the same ruleset, plus the rule `kanea firewall`
			// tells the operator to add.
			name: "an accept for the cluster clears it",
			chains: []*nftables.Chain{
				dropChain(t, "filter", "INPUT", nftables.ChainHookInput),
				dropChain(t, "filter", "FORWARD", nftables.ChainHookForward),
				acceptChain(),
			},
			rules: func(c *nftables.Chain) []*nftables.Rule {
				if c.Name != "ufw-user-input" {
					return nil
				}
				return []*nftables.Rule{sourceAcceptRule(network, expr.VerdictAccept)}
			},
			wantOK:   true,
			contains: "accept for " + testCluster,
		},
		{
			// A rule that merely *matches* the CIDR is not an allowance, and
			// treating one as such would clear the finding on a node that logs
			// pod traffic before dropping it.
			name: "a rule that matches but does not accept does not clear it",
			chains: []*nftables.Chain{
				dropChain(t, "filter", "INPUT", nftables.ChainHookInput),
				acceptChain(),
			},
			rules: func(c *nftables.Chain) []*nftables.Rule {
				if c.Name != "ufw-user-input" {
					return nil
				}
				return []*nftables.Rule{sourceAcceptRule(network, expr.VerdictDrop)}
			},
			wantOK:   true,
			wantWarn: true,
			contains: "no rule accepts",
		},
		{
			// Someone else's CIDR: this is the k3s leftover that made the
			// original node look configured.
			name: "an accept for another cluster does not clear it",
			chains: []*nftables.Chain{
				dropChain(t, "filter", "INPUT", nftables.ChainHookInput),
				acceptChain(),
			},
			rules: func(c *nftables.Chain) []*nftables.Rule {
				if c.Name != "ufw-user-input" {
					return nil
				}
				return []*nftables.Rule{sourceAcceptRule([4]byte{10, 42, 0, 0}, expr.VerdictAccept)}
			},
			wantOK:   true,
			wantWarn: true,
			contains: "no rule accepts",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := nftFirewallFinding(tc.chains, tc.rules, "host firewall", testCluster, testResolver)
			if got.OK != tc.wantOK || got.Warn != tc.wantWarn {
				t.Fatalf("OK = %v, Warn = %v; want %v/%v (detail: %s)",
					got.OK, got.Warn, tc.wantOK, tc.wantWarn, got.Detail)
			}
			if !strings.Contains(got.Detail, tc.contains) {
				t.Fatalf("detail = %q, want it to mention %q", got.Detail, tc.contains)
			}
		})
	}
}

// The fix line has to name what stopped working, not what the chain is. An
// operator meeting this warning is trying to find out why DNS died, and
// "pod traffic dies at this chain" - the old wording - does not tell them.
func TestTheFirewallFixNamesTheResolverAndTheCommand(t *testing.T) {
	fix := firewallFix(testCluster, testResolver)
	for _, want := range []string{testResolver, "internet", "kanea firewall", testCluster} {
		if !strings.Contains(fix, want) {
			t.Errorf("fix = %q, want it to mention %q", fix, want)
		}
	}
}

// A drop on some other hook (prerouting, output) is not this finding's
// business: it would be a warning nobody could act on from here.
func TestOnlyTheHooksAllocTrafficCrossesCount(t *testing.T) {
	got := nftFirewallFinding(
		[]*nftables.Chain{dropChain(t, "filter", "OUTPUT", nftables.ChainHookOutput)},
		noRules, "host firewall", testCluster, testResolver)
	if got.Warn {
		t.Fatalf("an output-hook drop produced a finding: %s", got.Detail)
	}
}
