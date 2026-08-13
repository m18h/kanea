//go:build linux

package main

import (
	"os"
	"os/exec"
	"strings"

	"github.com/google/nftables"

	"github.com/m18h/kanea/internal/datapath"
)

// The network egress findings (PRD v1.65) — promised by v1.36's text and
// implemented here. Each is a warning, never a failure: kanead asserts all
// of this itself at startup and re-ensures it while running, so a finding
// means either "kanead has not run yet" (fine) or "something on this node
// keeps undoing it" (the thing worth naming).

// networkEgressChecks are the ebpf-mode egress findings.
func networkEgressChecks() []checkResult {
	return []checkResult{
		checkIPForward(),
		checkForwardPolicy(),
		checkKaneaTable(),
	}
}

// checkIPForward reports v4 forwarding. kanead sets it at startup (v1.65);
// before that it was inherited from "the node's existing configuration",
// which usually meant docker's — and broke on the first node to drop docker.
func checkIPForward() checkResult {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return warn("ip_forward", "cannot read /proc/sys/net/ipv4/ip_forward: "+err.Error(), "")
	}
	if strings.TrimSpace(string(raw)) == "1" {
		return pass("ip_forward", "net.ipv4.ip_forward is on")
	}
	return warn("ip_forward", "net.ipv4.ip_forward is 0 — container egress cannot be routed",
		"kanead sets this at startup; if it reads 0 while kanead runs, something on the "+
			"node keeps resetting it (check sysctl.d)")
}

// checkForwardPolicy looks for a foreign drop policy on the forward hook —
// docker's and ufw's default posture, and the one thing the spike measured
// killing pod traffic that the datapath deliberately does not fight.
func checkForwardPolicy() checkResult {
	// nftables chains cover both native nft rules and iptables-nft, which is
	// what every current distribution ships.
	if conn, err := nftables.New(); err == nil {
		chains, err := conn.ListChains()
		if err == nil {
			for _, c := range chains {
				if c.Hooknum == nil || c.Policy == nil || c.Table == nil {
					continue
				}
				if *c.Hooknum == *nftables.ChainHookForward && *c.Policy == nftables.ChainPolicyDrop {
					return warn("forward policy",
						"table "+c.Table.Name+" chain "+c.Name+" drops on the forward hook",
						"a firewall manager (docker, ufw, firewalld) owns it; allow forwarding for "+
							"the cluster CIDR there, or accept that pod traffic dies at this chain")
				}
			}
			return pass("forward policy", "no drop policy on the forward hook")
		}
	}
	// Legacy x_tables does not surface through nftables netlink; ask the
	// binary when one exists.
	if path, err := exec.LookPath("iptables"); err == nil {
		out, err := exec.Command(path, "-S", "FORWARD", "-w").Output() // #nosec G204 — a fixed argv on a resolved binary
		if err == nil {
			if strings.HasPrefix(strings.TrimSpace(string(out)), "-P FORWARD DROP") {
				return warn("forward policy", "iptables FORWARD policy is DROP",
					"a firewall manager owns it; allow forwarding for the cluster CIDR")
			}
			return pass("forward policy", "iptables FORWARD policy is not DROP")
		}
	}
	return warn("forward policy", "cannot inspect the forward hook (not root, or no netlink)", "")
}

// checkKaneaTable reports whether the owned nftables table exists. kanead
// installs it at startup and, since v1.65, re-ensures it every 30 seconds —
// so a missing table beside a running kanead means a firewall manager is
// flushing the ruleset faster than that, and egress NAT dies with it.
func checkKaneaTable() checkResult {
	conn, err := nftables.New()
	if err != nil {
		return warn("nft table", "cannot open netlink: "+err.Error(), "run doctor as root")
	}
	tables, err := conn.ListTables()
	if err != nil {
		return warn("nft table", "cannot list nftables: "+err.Error(), "run doctor as root")
	}
	for _, t := range tables {
		if t.Name == datapath.NFTableName && t.Family == nftables.TableFamilyIPv4 {
			return pass("nft table", "the "+datapath.NFTableName+" table is installed (masquerade lives here)")
		}
	}
	return warn("nft table", "the "+datapath.NFTableName+" nftables table is absent — egress NAT is not installed",
		"kanead installs and re-ensures it while running; absent beside a running kanead "+
			"means a firewall manager keeps flushing the ruleset")
}
