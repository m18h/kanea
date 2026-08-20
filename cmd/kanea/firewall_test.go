package main

import (
	"strings"
	"testing"
)

// `kanea firewall` (PRD v1.86).
//
// The rules have to carry *this node's* values. The node that prompted the
// command had ufw rules for 10.42.0.0/16 and 10.43.0.0/16 - k3s's defaults,
// left over from a previous install - and they looked like a configured
// firewall while allowing nothing Kanea uses. A command that printed a
// documented example would reproduce that failure with more steps.

func renderManager(t *testing.T, name string, f firewallFacts) string {
	t.Helper()
	blocks, err := selectFirewallBlocks(name, false)
	if err != nil {
		t.Fatalf("selectFirewallBlocks(%q): %v", name, err)
	}
	if len(blocks) != 1 {
		t.Fatalf("got %d blocks, want exactly the one named", len(blocks))
	}
	return strings.Join(blocks[0].render(f), "\n")
}

func testFacts() firewallFacts {
	return firewallFacts{
		cluster:      "10.99.0.0/16",
		resolver:     "10.99.0.1:53",
		resolverIP:   "10.99.0.1",
		resolverPort: "53",
	}
}

func TestEveryManagerCoversBothHooksWithThisNodesValues(t *testing.T) {
	f := testFacts()
	for _, manager := range []string{"ufw", "firewalld", "nft", "iptables"} {
		t.Run(manager, func(t *testing.T) {
			got := renderManager(t, manager, f)
			if !strings.Contains(got, f.cluster) {
				t.Errorf("rules do not mention this node's cluster CIDR %s:\n%s", f.cluster, got)
			}
			// firewalld's trusted zone covers the input hook by source, so it
			// has no resolver-specific line; everyone else names the address
			// the workload actually dials.
			if manager != "firewalld" && !strings.Contains(got, f.resolverIP) {
				t.Errorf("rules do not mention the resolver %s:\n%s", f.resolverIP, got)
			}
			// The forward half is the one people miss, because on ufw the
			// obvious `ufw allow` does not reach it at all.
			forward := map[string]string{
				"ufw":       "route allow",
				"firewalld": "FORWARD",
				"nft":       "forward",
				"iptables":  "FORWARD",
			}[manager]
			if !strings.Contains(got, forward) {
				t.Errorf("rules do not cover the forward hook (%q):\n%s", forward, got)
			}
		})
	}
}

// UDP is what a resolver is asked over and TCP is what a truncated answer is
// retried over (v1.86), so a rule set that allows only one of them fails on
// exactly the large answers TCP exists for.
func TestTheDNSRulesCoverBothTransports(t *testing.T) {
	got := renderManager(t, "ufw", testFacts())
	if !strings.Contains(got, "proto udp") || !strings.Contains(got, "proto tcp") {
		t.Fatalf("the DNS rules do not cover both transports:\n%s", got)
	}
}

// With no internal resolver there is nothing on the input hook to allow, and
// inventing a rule for an address nothing binds would be advice that quietly
// does nothing.
func TestNoResolverMeansNoInputRule(t *testing.T) {
	got := renderManager(t, "ufw", firewallFacts{cluster: "10.99.0.0/16", dnsOff: true})
	if strings.Contains(got, "port ") {
		t.Fatalf("a port rule was printed for a node with no resolver:\n%s", got)
	}
	if !strings.Contains(got, "route allow") {
		t.Fatalf("the egress rule is still needed without a resolver:\n%s", got)
	}
}

func TestAnUnknownManagerIsRefusedByName(t *testing.T) {
	_, err := selectFirewallBlocks("iptables-nft", false)
	if err == nil {
		t.Fatal("an unknown manager was accepted")
	}
	for _, want := range []string{"iptables-nft", "ufw", "firewalld"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

// --all is the escape hatch for a node whose manager is not detected, and the
// undetected case falls back to the same thing rather than printing nothing.
func TestAllPrintsEveryManager(t *testing.T) {
	blocks, err := selectFirewallBlocks("", true)
	if err != nil {
		t.Fatalf("selectFirewallBlocks: %v", err)
	}
	if len(blocks) != len(firewallBlocks()) {
		t.Fatalf("got %d blocks, want all %d", len(blocks), len(firewallBlocks()))
	}
}

// nft and iptables are the fallbacks rather than owners: auto-detecting them
// would tell an operator running ufw to write rules underneath it, which ufw
// then reorders around on its next reload.
func TestOnlyRulesetOwnersAreAutoDetected(t *testing.T) {
	for _, b := range firewallBlocks() {
		switch b.manager {
		case "ufw", "firewalld":
			if b.detect == nil {
				t.Errorf("%s owns a ruleset and should be detectable", b.manager)
			}
		default:
			if b.detect != nil {
				t.Errorf("%s is a fallback and must not be auto-detected", b.manager)
			}
		}
	}
}
