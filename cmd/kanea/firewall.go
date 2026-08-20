package main

import (
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/m18h/kanea/internal/provision"
)

// `kanea firewall` prints the rules a host firewall needs for this node's
// workloads to work (PRD v1.86, §16.2).
//
// It exists because `kanea doctor` can say a firewall owns the input and
// forward hooks and cannot say what to type: the answer depends on this node's
// cluster CIDR, its resolver address and which manager owns the ruleset, and an
// operator holding a warning with no rules in it goes to a search engine and
// comes back with something written for docker.
//
// It never applies anything, and that is the same decision §5.2.5 makes for the
// datapath: Kanea owns exactly the `kanea` nftables table, and a rule written
// into someone else's ruleset is flushed away by its owner on the next reload.
// A fix that silently stops being applied is worse than one an operator ran
// themselves and can see in `ufw status`.

// firewallRules is one manager's block.
type firewallRules struct {
	// manager is the flag value and the heading.
	manager string
	// title is what it is called in prose.
	title string
	// detect reports whether this manager appears to own the node's ruleset.
	detect func() bool
	// render returns the commands, one per line, for the given node values.
	render func(f firewallFacts) []string
	// note is printed under the block when there is something the commands
	// cannot express.
	note string
}

// firewallFacts is what the rules are derived from: this node's real values,
// never a documented example, because the whole failure this command addresses
// was allow rules written for a different platform's CIDRs.
type firewallFacts struct {
	cluster  string
	resolver string
	// resolverIP and resolverPort are the resolver split for managers whose
	// syntax wants them apart.
	resolverIP   string
	resolverPort string
	// dnsOff is true when this node runs no internal resolver, in which case
	// the input rule has nothing to allow and is omitted rather than invented.
	dnsOff bool
}

func runFirewall(args []string) error {
	fset := flag.NewFlagSet("firewall", flag.ContinueOnError)
	prefix := fset.String("prefix", provision.DefaultPrefix, "component install prefix")
	nodeCIDR := fset.String("node-cidr", provision.DefaultNodeCIDR, "this node's container subnet")
	clusterCIDR := fset.String("cluster-cidr", provision.DefaultClusterCIDR, "the native routing CIDR")
	networkMode := fset.String("network", networkEBPF, "network mode: ebpf or netns")
	manager := fset.String("manager", "", "print rules for one manager: ufw, firewalld, nft, iptables")
	all := fset.Bool("all", false, "print every manager's rules, not just the detected one")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if err := validNetworkMode(*networkMode); err != nil {
		return err
	}

	layout := componentLayout(*prefix, *nodeCIDR, *clusterCIDR)
	if err := layout.ValidateNetworking(); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	node, cluster := layout.Networking()

	facts := firewallFacts{cluster: cluster, resolver: dnsAddrFor(*networkMode, node)}
	if facts.resolver == "" {
		facts.dnsOff = true
	} else if ip, port, err := splitHostPortLoose(facts.resolver); err == nil {
		facts.resolverIP, facts.resolverPort = ip, port
	}

	blocks, err := selectFirewallBlocks(*manager, *all)
	if err != nil {
		return err
	}

	o := newOut()
	o.printf("kanea firewall: %s\n\n", version)
	o.printf("Workload traffic crosses two hooks a host firewall owns, and both are\n")
	o.printf("refused by a default-deny posture:\n\n")
	if facts.dnsOff {
		o.printf("  forward   %s reaching anything off this node\n", cluster)
		o.printf("  input     (no internal resolver on this node: --network netns or --dns-listen off)\n\n")
	} else {
		o.printf("  input     %s reaching the internal resolver at %s\n", cluster, facts.resolver)
		o.printf("  forward   %s reaching anything off this node\n\n", cluster)
	}

	for _, b := range blocks {
		o.printf("# %s\n", b.title)
		for _, line := range b.render(facts) {
			o.printf("%s\n", line)
		}
		if b.note != "" {
			o.printf("# %s\n", b.note)
		}
		o.println()
	}

	o.printf("These are printed, never applied: Kanea owns one nftables table (%q) and\n", "kanea")
	o.printf("writes nothing outside it, because a rule in a manager's ruleset is flushed\n")
	o.printf("away by that manager on its next reload.\n")
	o.printf("A published port (PRD §7.2.2) needs its own inbound allow; this command\n")
	o.printf("cannot know which ports are published without asking the daemon.\n")
	return o.Err()
}

// selectFirewallBlocks resolves which managers to print for: the named one, all
// of them, or the one that appears to own this node's ruleset.
//
// Detection failing is not an error; it falls back to printing everything,
// because a list an operator has to pick from is still an answer and refusing
// to print would leave them exactly where the warning did.
func selectFirewallBlocks(manager string, all bool) ([]firewallRules, error) {
	blocks := firewallBlocks()
	if manager != "" {
		for _, b := range blocks {
			if strings.EqualFold(b.manager, manager) {
				return []firewallRules{b}, nil
			}
		}
		names := make([]string, 0, len(blocks))
		for _, b := range blocks {
			names = append(names, b.manager)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("firewall: unknown --manager %q: want one of %s",
			manager, strings.Join(names, ", "))
	}
	if all {
		return blocks, nil
	}
	for _, b := range blocks {
		if b.detect != nil && b.detect() {
			return []firewallRules{b}, nil
		}
	}
	return blocks, nil
}

// firewallBlocks is the rule set per manager, in detection order: the two that
// own a ruleset wholesale come first, so a node running ufw is not told to
// write raw nft rules underneath it.
func firewallBlocks() []firewallRules {
	return []firewallRules{
		{
			manager: "ufw",
			title:   "ufw",
			detect:  func() bool { return managerActive("ufw", []string{"status"}, "Status: active") },
			render: func(f firewallFacts) []string {
				var out []string
				if !f.dnsOff {
					out = append(out,
						fmt.Sprintf("ufw allow in from %s to %s port %s proto udp comment 'kanea internal DNS'",
							f.cluster, f.resolverIP, f.resolverPort),
						fmt.Sprintf("ufw allow in from %s to %s port %s proto tcp comment 'kanea internal DNS'",
							f.cluster, f.resolverIP, f.resolverPort),
					)
				}
				return append(out,
					fmt.Sprintf("ufw route allow from %s to any comment 'kanea workload egress'", f.cluster))
			},
			note: "`ufw route allow` is the forward hook; a plain `ufw allow` does not reach it.",
		},
		{
			manager: "firewalld",
			title:   "firewalld",
			detect:  func() bool { return managerActive("firewall-cmd", []string{"--state"}, "running") },
			render: func(f firewallFacts) []string {
				return []string{
					fmt.Sprintf("firewall-cmd --permanent --zone=trusted --add-source=%s", f.cluster),
					fmt.Sprintf("firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -s %s -j ACCEPT", f.cluster),
					"firewall-cmd --reload",
				}
			},
			note: "the trusted zone covers the input hook; the direct rule covers forward.",
		},
		{
			manager: "nft",
			title:   "nftables (no manager: adjust the table and chain names to yours)",
			detect:  nil, // never auto-detected: it is the fallback, not an owner
			render: func(f firewallFacts) []string {
				var out []string
				if !f.dnsOff {
					out = append(out,
						fmt.Sprintf("nft add rule inet filter input ip saddr %s ip daddr %s udp dport %s accept",
							f.cluster, f.resolverIP, f.resolverPort),
						fmt.Sprintf("nft add rule inet filter input ip saddr %s ip daddr %s tcp dport %s accept",
							f.cluster, f.resolverIP, f.resolverPort),
					)
				}
				return append(out,
					fmt.Sprintf("nft add rule inet filter forward ip saddr %s accept", f.cluster),
					fmt.Sprintf("nft add rule inet filter forward ip daddr %s ct state related,established accept", f.cluster))
			},
			note: "the return rule is needed only where the forward chain has no established accept.",
		},
		{
			manager: "iptables",
			title:   "iptables (legacy)",
			detect:  nil, // the nft path covers iptables-nft; this is for x_tables
			render: func(f firewallFacts) []string {
				var out []string
				if !f.dnsOff {
					out = append(out,
						fmt.Sprintf("iptables -A INPUT -s %s -d %s -p udp --dport %s -j ACCEPT",
							f.cluster, f.resolverIP, f.resolverPort),
						fmt.Sprintf("iptables -A INPUT -s %s -d %s -p tcp --dport %s -j ACCEPT",
							f.cluster, f.resolverIP, f.resolverPort),
					)
				}
				return append(out,
					fmt.Sprintf("iptables -A FORWARD -s %s -j ACCEPT", f.cluster),
					fmt.Sprintf("iptables -A FORWARD -d %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", f.cluster))
			},
			note: "these do not survive a reboot on their own; persist them the way your distribution does.",
		},
	}
}

// managerActive reports whether a manager's own status command says it is
// running. Asking the tool rather than looking for its binary: ufw is installed
// and inactive on a great many nodes, and printing its rules there would be
// telling an operator to configure something that is not in the path.
func managerActive(binary string, args []string, want string) bool {
	path, err := exec.LookPath(binary)
	if err != nil {
		return false
	}
	out, err := exec.Command(path, args...).Output() // #nosec G204: a fixed argv on a resolved binary
	if err != nil {
		// firewall-cmd --state exits non-zero when not running, which is the
		// answer rather than a failure to read it.
		return false
	}
	return strings.Contains(string(out), want)
}

// splitHostPortLoose splits an address that is known to carry a port.
func splitHostPortLoose(addr string) (string, string, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", "", errors.New("no port")
	}
	host := strings.TrimSuffix(strings.TrimPrefix(addr[:i], "["), "]")
	return host, addr[i+1:], nil
}
