package main

// The end of `kanea init` (PRD v1.45): start the daemon, create the first
// admin, and summarise what was built. §13.1 has promised since v1.18 that
// init creates the first account "through the same API everything else uses —
// over the local unix socket"; this is that promise kept, instead of printed.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/network"
)

// adminAPI is the slice of the API client the bootstrap needs — a seam so the
// flow is testable without a daemon on the other end of a socket.
type adminAPI interface {
	Health(ctx context.Context) (api.Health, error)
	Users(ctx context.Context) ([]auth.User, error)
	PutUser(ctx context.Context, name, password string, role auth.Role) error
}

// systemdAvailable reports whether this host can be asked to start units at
// all. Not a check that systemd is pid 1 — LookPath is as far as a CLI can
// honestly see — but it cleanly excludes macOS builds and containers.
func systemdAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
}

// systemctl runs one systemctl verb with a bounded context, passing output
// through so the operator sees what systemd said.
func systemctl(ctx context.Context, timeout time.Duration, args ...string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("systemd is Linux-only (this is %s)", runtime.GOOS)
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl not found")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", args...) // #nosec G204 — every call site passes literals
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// resolveListen settles the API/dashboard listen address before anything else
// runs, so a refusal costs nothing. Prompted only on a terminal and only when
// the flag was not given: a script that passes --listen consumes no stdin, and
// a piped init with no flag gets the loopback default rather than a prompt
// that would eat a line meant for the key ceremony.
func resolveListen(o *out, reader *bufio.Reader, explicit bool, value, cert, key string) (string, error) {
	addr := value
	if !explicit && term.IsTerminal(int(os.Stdin.Fd())) {
		o.printf("API/dashboard listen address [%s] (\"none\" for socket-only): ", api.DefaultListenAddr)
		if err := o.Err(); err != nil {
			return "", err
		}
		line, err := reader.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			return "", fmt.Errorf("read listen address: %w", err)
		}
		if answer := strings.TrimSpace(line); answer != "" {
			addr = answer
		}
	}
	if addr == "none" || addr == "off" {
		return "", nil
	}

	if (cert == "") != (key == "") {
		return "", errors.New("--listen-cert and --listen-key go together")
	}
	public, err := api.IsPublicAddr(addr)
	if err != nil {
		return "", err
	}
	if public && cert == "" {
		// The same refusal listenNetwork makes at startup (§13.1, §14 A05),
		// moved in front of whoever typed the address — a unit that fails on
		// its first boot is a refusal in a journal nobody is watching yet.
		return "", fmt.Errorf("%s is beyond loopback and would carry credentials in clear text; "+
			"pass --listen-cert/--listen-key, bind loopback, or answer none", addr)
	}
	return addr, nil
}

// printManualNext is the pre-v1.45 ending: the steps init could not run, on
// nodes where it cannot run them (--skip-units, --no-start, no systemd) or
// when a bootstrap step failed partway and the operator has to finish by hand.
func printManualNext(o *out) {
	o.println()
	o.println("Next:")
	o.println("  1. systemctl daemon-reload && systemctl enable --now kanead")
	o.println("  2. kanea user add <name> --role admin        # the first account")
	o.println("  3. kanea run <spec.hcl>                      # deploy something")
	o.println()
	o.println("Configure a backup destination before you need one — see docs/DR_RUNBOOK.md.")
}

// bootstrapOptions is everything bootstrapDaemon needs, with the two effects —
// the API and systemctl — injected so the flow is testable.
type bootstrapOptions struct {
	listen                                string // the effective listen address; "" is socket-only
	adminUser                             string // --admin-user; empty means prompt
	timeout                               time.Duration
	network                               string // kanead's network mode; netns has no internal DNS
	nodeCIDR                              string
	clusterCIDR, serviceCIDR              string
	nodeCIDR6, clusterCIDR6, serviceCIDR6 string
	client                                adminAPI
	run                                   func(ctx context.Context, args ...string) error
}

// bootstrapDaemon starts kanead, creates the first admin over the socket, and
// prints the summary. Every failure path prints the manual steps first: an
// operator whose init died halfway still has the recipe the old init printed.
func bootstrapDaemon(o *out, reader *bufio.Reader, opts bootstrapOptions) error {
	ctx := context.Background()

	o.println("Starting kanead:")
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "kanead"}} {
		if err := opts.run(ctx, args...); err != nil {
			printManualNext(o)
			return fmt.Errorf("start kanead: %w", err)
		}
	}
	o.println("  waiting for the control plane…")
	health, err := waitForDaemon(ctx, opts.client, opts.timeout)
	if err != nil {
		o.println("  kanead did not answer — check `journalctl -u kanead`.")
		printManualNext(o)
		return err
	}

	// The first admin, idempotently: an account that exists is skipped, never
	// re-prompted — PutUser is an upsert, and a re-run of init must not
	// replace a password nobody asked it to.
	users, err := opts.client.Users(ctx)
	if err != nil {
		printManualNext(o)
		return fmt.Errorf("list accounts: %w", err)
	}
	created := false
	adminName := ""
	if len(users) > 0 {
		o.println("An account already exists — skipping the first-admin step.")
	} else {
		adminName = opts.adminUser
		if adminName == "" {
			o.printf("First admin username: ")
			if err := o.Err(); err != nil {
				return err
			}
			line, err := reader.ReadString('\n')
			if err != nil && strings.TrimSpace(line) == "" {
				printManualNext(o)
				return fmt.Errorf("read username: %w", err)
			}
			adminName = strings.TrimSpace(line)
		}
		if adminName == "" {
			printManualNext(o)
			return errors.New("an admin username is required (or pass --admin-user)")
		}
		password, err := readPasswordFrom(reader, fmt.Sprintf("password for %s: ", adminName))
		if err != nil {
			printManualNext(o)
			return err
		}
		// Name and password rules are the server's; its refusal comes back
		// with the reason and is not duplicated here.
		if err := opts.client.PutUser(ctx, adminName, password, auth.RoleAdmin); err != nil {
			printManualNext(o)
			return fmt.Errorf("create account %s: %w", adminName, err)
		}
		o.printf("Created admin account %q.\n", adminName)
		created = true
	}

	// §13.1 refuses a network listener on a daemon that booted with no
	// account, and its refusal message prescribes exactly this: create the
	// account, then restart. The health.Listen check also covers a re-run
	// whose only change was --listen — `enable --now` does not re-exec a
	// running unit, so without a restart the new address would never bind.
	if opts.listen != "" && (created || health.Listen == "") {
		o.println("Restarting kanead so the network listener opens…")
		if err := opts.run(ctx, "restart", "kanead"); err != nil {
			printManualNext(o)
			return fmt.Errorf("restart kanead: %w", err)
		}
		health, err = waitForDaemon(ctx, opts.client, opts.timeout)
		if err != nil {
			printManualNext(o)
			return err
		}
		if health.Listen == "" {
			// A warning, not a failure: the node works over the socket, and
			// the journal has the listener's own refusal with its reason.
			o.println("Warning: the network listener did not open — check `journalctl -u kanead`.")
			o.println("The API still answers on the local socket.")
		}
	}

	initSummary(o, summaryInfo{
		dashboard:       dashboardFor(health),
		admin:           adminName,
		accountsExisted: !created,
		dnsAddr:         dnsAddrFor(opts.network, opts.nodeCIDR),
		nodeCIDR:        opts.nodeCIDR, clusterCIDR: opts.clusterCIDR, serviceCIDR: opts.serviceCIDR,
		nodeCIDR6: opts.nodeCIDR6, clusterCIDR6: opts.clusterCIDR6, serviceCIDR6: opts.serviceCIDR6,
	})
	return o.Err()
}

// dashboardFor derives the summary's URL from what the daemon actually bound —
// never from what init asked for, because those differing is the failure the
// summary must not paper over.
func dashboardFor(health api.Health) string {
	if health.Listen == "" {
		return ""
	}
	return dashboardURL(health.Listen, health.TLS)
}

// dnsAddrFor is the internal resolver's address: the node CIDR's .1, exactly
// as kanead's buildDNS derives it. Empty under netns, which has no datapath
// and no service frontends for a resolver to answer for.
func dnsAddrFor(networkMode, nodeCIDR string) string {
	if networkMode == networkNetns {
		return ""
	}
	prefix, err := netip.ParsePrefix(nodeCIDR)
	if err != nil {
		return ""
	}
	host := prefix.Masked().Addr().Next()
	return net.JoinHostPort(host.String(), strconv.Itoa(network.DefaultDNSPort))
}

// summaryInfo is what the end-of-init summary renders. It deliberately has no
// field a password could travel in.
type summaryInfo struct {
	dashboard                             string // URL, or "" when the API is socket-only
	admin                                 string // the account created this run, or ""
	accountsExisted                       bool
	dnsAddr                               string // "" when the internal DNS is not running
	nodeCIDR, clusterCIDR, serviceCIDR    string
	nodeCIDR6, clusterCIDR6, serviceCIDR6 string
}

// initSummary is a pure renderer over summaryInfo, so a test can pin every
// variant without a daemon.
func initSummary(o *out, s summaryInfo) {
	o.println()
	o.println("───────────────────────────────────────────────────────────────")
	o.println("Kanea is running.")
	o.println()
	switch {
	case s.dashboard != "" && s.admin != "":
		o.printf("  Dashboard      %s   (log in as %q)\n", s.dashboard, s.admin)
	case s.dashboard != "" && s.accountsExisted:
		o.printf("  Dashboard      %s   (accounts already existed)\n", s.dashboard)
	case s.dashboard != "":
		o.printf("  Dashboard      %s\n", s.dashboard)
	default:
		o.printf("  Dashboard      not exposed — the API answers only on %s\n", api.DefaultSocket)
		o.println("                 (re-run kanead with --listen to serve it)")
	}
	if s.dnsAddr != "" {
		o.printf("  Internal DNS   %s   (allocs resolve <service>.<project> here)\n", s.dnsAddr)
	} else {
		o.println("  Internal DNS   off (netns mode has no service frontends)")
	}
	o.println()
	o.println("  Addressing")
	o.printf("    node CIDR      %-18s this node's allocs\n", s.nodeCIDR)
	o.printf("    cluster CIDR   %-18s routed, masqueraded as internal\n", s.clusterCIDR)
	o.printf("    service CIDR   %-18s service VIPs\n", s.serviceCIDR)
	if s.nodeCIDR6 != "" {
		o.printf("    node CIDR v6      %s\n", s.nodeCIDR6)
		o.printf("    cluster CIDR v6   %s\n", s.clusterCIDR6)
		o.printf("    service CIDR v6   %s\n", s.serviceCIDR6)
	}
	o.println()
	o.println("Deploy something:  kanea run <spec.hcl>")
	o.println("Configure a backup destination before you need one — see docs/DR_RUNBOOK.md.")
}
