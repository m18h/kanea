//go:build linux

package main

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/m18h/kanea/internal/datapath"
)

// The network egress findings (PRD v1.65): promised by v1.36's text and
// implemented here. Each is a warning, never a failure: kanead asserts all
// of this itself at startup and re-ensures it while running, so a finding
// means either "kanead has not run yet" (fine) or "something on this node
// keeps undoing it" (the thing worth naming).

// networkEgressChecks are the ebpf-mode egress findings.
func networkEgressChecks(opts preflightOptions) []checkResult {
	return []checkResult{
		checkIPForward(),
		checkHostFirewall(opts),
		checkKaneaTable(),
	}
}

// checkIPForward reports v4 forwarding. kanead sets it at startup (v1.65);
// before that it was inherited from "the node's existing configuration",
// which usually meant docker's, and broke on the first node to drop docker.
func checkIPForward() checkResult {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return warn("ip_forward", "cannot read /proc/sys/net/ipv4/ip_forward: "+err.Error(), "")
	}
	if strings.TrimSpace(string(raw)) == "1" {
		return pass("ip_forward", "net.ipv4.ip_forward is on")
	}
	return warn("ip_forward", "net.ipv4.ip_forward is 0; container egress cannot be routed",
		"kanead sets this at startup; if it reads 0 while kanead runs, something on the "+
			"node keeps resetting it (check sysctl.d)")
}

// nftConn is the netlink seam, so the firewall findings can be driven from a
// test rather than only from a root shell on a real node. Consumer-side and a
// package var for the same reason internalErrorLog is one: the call sites are
// few and the alternative is threading a connection through every check.
var nftConn = func() (*nftables.Conn, error) { return nftables.New() }

// checkHostFirewall looks for a foreign drop policy on the hooks alloc traffic
// crosses, which is two hooks and not one (v1.86).
//
// *forward* is where egress dies, and is the one this check has always
// covered. *input* is where the query to the internal resolver dies, and was
// missed for a year: an alloc asking `10.244.0.1:53` is opening a new inbound
// connection to the host on a veth, so it traverses INPUT like any other
// arrival, and ufw's default `deny (incoming)` eats it. The host's own `dig`
// keeps working throughout, because every firewall manager accepts `lo`
// unconditionally, which is exactly what makes the failure read as "Kanea's
// DNS is broken".
//
// The policy alone cannot decide the finding, and that is the important half.
// A correctly configured ufw and a fatal one both read `policy drop`, so a
// check that stopped there would warn forever on every firewalled node and
// become something operators learn to ignore. So it also looks for an accept
// rule naming the cluster CIDR as a source: `ufw allow from 10.244.0.0/16`
// renders as exactly that. Heuristic, deliberately - it does not evaluate the
// ruleset, and a rule buried under an earlier drop would fool it - but it
// makes the finding self-clearing, which is worth more here than a precision
// nothing short of a live probe can deliver.
func checkHostFirewall(opts preflightOptions) checkResult {
	const name = "host firewall"
	// Networking() resolves the compiled defaults, so the finding names the
	// CIDR this node actually uses rather than an empty flag.
	node, cluster := opts.layout.Networking()
	resolver := dnsAddrFor(opts.networkMode, node)
	if resolver == "" {
		resolver = "the node CIDR's .1 on port 53"
	}

	conn, err := nftConn()
	if err == nil {
		// The socket opens for anyone; it is the read that needs privilege, so
		// an ordinary user gets here and fails one line down.
		if chains, listErr := conn.ListChains(); listErr == nil {
			rules := func(c *nftables.Chain) []*nftables.Rule {
				got, err := conn.GetRules(c.Table, c)
				if err != nil {
					return nil
				}
				return got
			}
			return nftFirewallFinding(chains, rules, name, cluster, resolver)
		}
	}

	// Legacy x_tables does not surface through nftables netlink; ask the
	// binary when one exists.
	if path, lookErr := exec.LookPath("iptables"); lookErr == nil {
		var dropped []string
		for _, chain := range []string{"INPUT", "FORWARD"} {
			out, runErr := exec.Command(path, "-S", chain, "-w").Output() // #nosec G204: a fixed argv on a resolved binary
			if runErr != nil {
				dropped = nil
				break
			}
			if strings.HasPrefix(strings.TrimSpace(string(out)), "-P "+chain+" DROP") {
				dropped = append(dropped, chain)
			}
		}
		if len(dropped) > 0 {
			return warn(name, "iptables policy is DROP on "+strings.Join(dropped, " and "),
				firewallFix(cluster, resolver))
		}
		if _, runErr := exec.Command(path, "-S", "INPUT", "-w").Output(); runErr == nil { // #nosec G204: a fixed argv on a resolved binary
			return pass(name, "no drop policy on the input or forward hook")
		}
	}
	// One message for every way of not having looked. The netlink libraries
	// render a denial as text rather than a wrapped errno on some paths, so
	// claiming *which* way it failed would sometimes be wrong; that the
	// ruleset was not read is true in all of them.
	return skip(name, "not checked: the ruleset could not be read (needs root)")
}

// nftFirewallFinding decides the finding from a ruleset.
//
// It takes the chains and a rule lookup rather than a connection, so the
// decision is a pure function of what the ruleset says: nftables.Chain and
// nftables.Rule are plain structs a test can build, and *nftables.Conn is a
// netlink socket that only exists as root on a real node.
func nftFirewallFinding(
	chains []*nftables.Chain,
	rules func(*nftables.Chain) []*nftables.Rule,
	name, cluster, resolver string,
) checkResult {
	var dropped []string
	seen := map[string]bool{}
	for _, c := range chains {
		if c.Hooknum == nil || c.Policy == nil || c.Table == nil {
			continue
		}
		if *c.Policy != nftables.ChainPolicyDrop {
			continue
		}
		var hook string
		switch *c.Hooknum {
		case *nftables.ChainHookInput:
			hook = "input"
		case *nftables.ChainHookForward:
			hook = "forward"
		default:
			continue
		}
		label := "table " + c.Table.Name + " chain " + c.Name + " (" + hook + ")"
		if !seen[label] {
			seen[label] = true
			dropped = append(dropped, label)
		}
	}
	if len(dropped) == 0 {
		return pass(name, "no drop policy on the input or forward hook")
	}

	if allowsCluster(chains, rules, cluster) {
		return pass(name, "a firewall owns "+strings.Join(dropped, ", ")+
			", and the ruleset has an accept for "+cluster)
	}
	return warn(name, strings.Join(dropped, ", ")+" drops, and no rule accepts "+cluster,
		firewallFix(cluster, resolver))
}

// firewallFix is the one sentence worth printing here, and it names both
// consequences rather than describing the chain: "pod traffic dies at this
// chain" is true and abstract, and the operator reading it is trying to work
// out why DNS stopped.
func firewallFix(cluster, resolver string) string {
	return "workloads cannot reach the internal resolver at " + resolver +
		" or the internet; run `kanea firewall` for the rules this node needs " +
		"(they allow " + cluster + " in and routed)"
}

// allowsCluster reports whether any rule in the ip/inet filter tables accepts
// traffic whose source is the cluster CIDR.
//
// It matches on the shape a manager actually emits: load the source address,
// mask it, compare it to the network, and accept. `ufw allow from
// 10.244.0.0/16` produces precisely that, and so does the hand-written nft
// rule `kanea firewall` prints.
func allowsCluster(chains []*nftables.Chain, rules func(*nftables.Chain) []*nftables.Rule, cluster string) bool {
	prefix, err := netip.ParsePrefix(cluster)
	if err != nil || !prefix.Addr().Is4() {
		return false
	}
	network := prefix.Masked().Addr().As4()

	for _, c := range chains {
		if c.Table == nil {
			continue
		}
		if c.Table.Family != nftables.TableFamilyIPv4 && c.Table.Family != nftables.TableFamilyINet {
			continue
		}
		for _, r := range rules(c) {
			if ruleAcceptsSource(r, network) {
				return true
			}
		}
	}
	return false
}

// ruleAcceptsSource reports whether one rule compares the IPv4 source address
// against network and then accepts.
//
// Offset 12 is the source address in an IPv4 header; a Cmp carrying the
// network's four bytes is the comparison, whether or not a Bitwise masked it
// first (a /32 rule carries no mask). The verdict has to be an accept, or a
// logging rule that merely *matches* the CIDR would read as an allowance.
func ruleAcceptsSource(r *nftables.Rule, network [4]byte) bool {
	matched := false
	sourceLoaded := false
	for _, e := range r.Exprs {
		switch v := e.(type) {
		case *expr.Payload:
			sourceLoaded = v.Base == expr.PayloadBaseNetworkHeader && v.Offset == 12 && v.Len == 4
		case *expr.Cmp:
			if sourceLoaded && v.Op == expr.CmpOpEq && len(v.Data) == 4 &&
				[4]byte(v.Data) == network {
				matched = true
			}
		case *expr.Verdict:
			if matched && v.Kind == expr.VerdictAccept {
				return true
			}
		}
	}
	return false
}

// checkKaneaTable reports whether the owned nftables table exists. kanead
// installs it at startup and, since v1.65, re-ensures it every 30 seconds:
// so a missing table beside a running kanead means a firewall manager is
// flushing the ruleset faster than that, and egress NAT dies with it.
func checkKaneaTable() checkResult {
	conn, err := nftConn()
	if err != nil {
		return skip("nft table", "not checked: cannot open netlink ("+err.Error()+")")
	}
	tables, err := conn.ListTables()
	if err != nil {
		return skip("nft table", "not checked: the ruleset could not be read (needs root)")
	}
	for _, t := range tables {
		if t.Name == datapath.NFTableName && t.Family == nftables.TableFamilyIPv4 {
			return pass("nft table", "the "+datapath.NFTableName+" table is installed (masquerade lives here)")
		}
	}
	return warn("nft table", "the "+datapath.NFTableName+" nftables table is absent; egress NAT is not installed",
		"kanead installs and re-ensures it while running; absent beside a running kanead "+
			"means a firewall manager keeps flushing the ruleset")
}
