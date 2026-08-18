package main

// The end of `kanea init` (PRD v1.45): start the daemon, create the first
// admin, and summarise what was built. §13.1 has promised since v1.18 that
// init creates the first account "through the same API everything else uses:
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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/certsource"
	"github.com/m18h/kanea/internal/network"
	"github.com/m18h/kanea/internal/nodeconfig"
	"github.com/m18h/kanea/internal/provision"
)

// adminAPI is the slice of the API client the bootstrap needs: a seam so the
// flow is testable without a daemon on the other end of a socket.
type adminAPI interface {
	Health(ctx context.Context) (api.Health, error)
	Users(ctx context.Context) ([]auth.User, error)
	PutUser(ctx context.Context, name, password string, role auth.Role) error
}

// systemdAvailable reports whether this host can be asked to start units at
// all. Not a check that systemd is pid 1 (LookPath is as far as a CLI can
// honestly see) but it cleanly excludes macOS builds and containers.
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
	cmd := exec.CommandContext(ctx, "systemctl", args...) // #nosec G204; every call site passes literals
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// listenDecision is resolveListen's answer: where the API/dashboard binds,
// and which certificate secures it.
type listenDecision struct {
	addr string // the effective address; "" is socket-only
	// cert/key are the explicit --listen-cert/--listen-key pair, or empty.
	cert, key string
	// provisionPair means the address is public and no explicit pair was
	// given: init provisions the default 10-year self-signed pair (PRD v1.80)
	// and the unit points --listen-cert/--listen-key at it. The override
	// chain is unchanged: kanea.hcl's bind stanza owns the listener when
	// present (no listen flags are rendered at all), and explicit flags win.
	provisionPair bool
}

// resolveListen settles the API/dashboard listen address before anything else
// runs, so a refusal costs nothing. Prompted only on a terminal and only when
// the flag was not given: a script that passes --listen consumes no stdin, and
// a piped init with no flag gets the loopback default rather than a prompt
// that would eat a line meant for the key ceremony.
//
// A public address with no certificate pair is no longer refused (v1.80):
// init provisions a default self-signed pair instead of demanding one
// (§13.1/§14 A05's rule is "TLS beyond loopback", and the provisioned pair
// satisfies it). The one refusal left is the unspecified host, because a SAN
// needs something to name.
func resolveListen(o *out, reader *bufio.Reader, explicit bool, value, cert, key string) (listenDecision, error) {
	addr := value
	if !explicit && term.IsTerminal(int(os.Stdin.Fd())) {
		var err error
		addr, err = askListenAddress(o, reader)
		if err != nil {
			return listenDecision{}, err
		}
	}
	if addr == "none" || addr == "off" {
		return listenDecision{}, nil
	}

	if (cert == "") != (key == "") {
		return listenDecision{}, errors.New("--listen-cert and --listen-key go together")
	}
	public, err := api.IsPublicAddr(addr)
	if err != nil {
		return listenDecision{}, err
	}
	if !public || cert != "" {
		return listenDecision{addr: addr, cert: cert, key: key}, nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return listenDecision{}, fmt.Errorf("bad listen address %q: %w", addr, err)
	}
	if unspecifiedListenHost(host) {
		// validateBind's v1.61 rule, applied to the provisioned pair: a
		// certificate needs a name, and every-interface has none.
		return listenDecision{}, fmt.Errorf("%s binds every interface, and a certificate's SAN needs a "+
			"host to name; bind a specific address, or set bind.api_tls and bind.api_domain in %s",
			addr, nodeconfig.DefaultPath)
	}
	return listenDecision{addr: addr, provisionPair: true}, nil
}

// askListenAddress is the prompt itself. An empty answer keeps loopback.
func askListenAddress(o *out, reader *bufio.Reader) (string, error) {
	o.printf("API/dashboard listen address [%s] (\"none\" for socket-only): ", api.DefaultListenAddr)
	if err := o.Err(); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return "", fmt.Errorf("read listen address: %w", err)
	}
	if answer := strings.TrimSpace(line); answer != "" {
		return answer, nil
	}
	return api.DefaultListenAddr, nil
}

// The static pair init provisions as the default listener certificate
// (PRD v1.80): a public listen address gets HTTPS with a SAN matching its
// host, and kanea.hcl's bind stanza (or explicit --listen-cert/--listen-key)
// is the override.
var (
	provisionedAPICertPath = filepath.Join(provision.DefaultConfDir, "api.crt")
	provisionedAPIKeyPath  = filepath.Join(provision.DefaultConfDir, "api.key")
)

// unspecifiedListenHost reports whether host names every interface: the empty
// host (":8600") or the unspecified address of either family. Mirrors
// nodeconfig's unexported check (the deliberate-duplication precedent): the
// daemon's parser stays the authority; this is init's early refusal.
func unspecifiedListenHost(host string) bool {
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// ensureAPIPair provisions the default listener certificate (PRD v1.80): a
// static, ten-year self-signed pair minted once, which the unit points
// --listen-cert/--listen-key at. Existing files are left alone: re-minting
// would flip the fingerprint operators have already accepted, which is the
// master key's "never regenerated" rule at a smaller stake. Half a pair is an
// error, never a guess: something edited these files by hand, and init does
// not overwrite what it cannot explain.
func ensureAPIPair(o *out, addr, certPath, keyPath string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("bad listen address %q: %w", addr, err)
	}
	if unspecifiedListenHost(host) {
		return fmt.Errorf("%s binds every interface, and a certificate's SAN needs a "+
			"host to name; bind a specific address, or set bind.api_tls and bind.api_domain in %s",
			addr, nodeconfig.DefaultPath)
	}

	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	certExists, keyExists := certErr == nil, keyErr == nil
	switch {
	case certExists && keyExists:
		o.printf("Listener certificate already present at %s; leaving it alone.\n", certPath)
		return nil
	case certExists != keyExists:
		return fmt.Errorf("half a certificate pair at %s and %s; remove or complete it", certPath, keyPath)
	}

	certPEM, keyPEM, err := certsource.StandalonePairPEM(host, time.Now())
	if err != nil {
		return err
	}
	// #nosec G301; createLayout's mode for the same directory: /etc/kanea is
	// policy, not a secret, and the key beside the certificate is 0600.
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(certPath), err)
	}
	// Cert 0644 (public material), key 0600: certsource's own warning for
	// provided keys fires on anything wider, and the key is a credential.
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil { // #nosec G306; a public certificate
		return fmt.Errorf("write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", keyPath, err)
	}
	o.printf("Provisioned a 10-year self-signed listener certificate for %s:\n", host)
	o.printf("  %s\n", certPath)
	o.println("  Override it any time: /etc/kanea/kanea.hcl's bind stanza (acme,")
	o.println("  self-signed, provided, plaintext) or --listen-cert/--listen-key.")
	return o.Err()
}

// listenFromServerConfig decides whether kanea.hcl owns the API listener for
// this init run (PRD §15.1, v1.61): a bind.api_addr with no explicit --listen.
// When it does, init skips the prompt and renders no listen flags into the
// unit: a unit that repeated the file's answer would turn the file off. The
// beyond-loopback refusal is resolveListen's, made at the file's coordinates:
// a unit that fails on its first boot is a refusal in a journal nobody is
// watching yet.
func listenFromServerConfig(cfg *nodeconfig.Config, explicitListen bool) (addr string, owned bool, err error) {
	if explicitListen || cfg.Bind == nil || cfg.Bind.APIAddr == "" {
		return "", false, nil
	}
	public, err := api.IsPublicAddr(cfg.Bind.APIAddr)
	if err != nil {
		return "", false, fmt.Errorf("%s: bind.api_addr: %w", cfg.Path, err)
	}
	// A declared api_tls mode is a TLS story (or, for plaintext, a typed
	// decision); parse already refused its contradictions. Only the unset
	// mode with no pair meets the beyond-loopback refusal, exactly as the
	// bare flags would.
	if public && cfg.Bind.APITLS == "" && cfg.Bind.APICert == "" {
		return "", false, fmt.Errorf("%s: bind.api_addr %s is beyond loopback and would carry "+
			"credentials in clear text; set bind.api_tls (acme, self-signed, provided or "+
			"plaintext), bind loopback, or remove the stanza", cfg.Path, cfg.Bind.APIAddr)
	}
	return cfg.Bind.APIAddr, true, nil
}

// printManualNext is the pre-v1.45 ending: the steps init could not run, on
// nodes where it cannot run them (--skip-units, --no-start, no systemd) or
// when a bootstrap step failed partway and the operator has to finish by hand.
func printManualNext(o *out) {
	o.println()
	o.println("Next:")
	o.println("  1. sudo systemctl daemon-reload && sudo systemctl enable --now kanead")
	o.println("  2. sudo kanea user add --role admin <name>   # the first account")
	o.println("  3. kanea run <spec.hcl>                      # deploy something")
	o.println()
	o.println("Configure a backup destination before you need one: see docs/DR_RUNBOOK.md.")
}

// bootstrapOptions is everything bootstrapDaemon needs, with the two effects
// (the API and systemctl) injected so the flow is testable.
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
		o.println("  kanead did not answer; check `journalctl -u kanead`.")
		printManualNext(o)
		return err
	}

	// The first admin, idempotently: an account that exists is skipped, never
	// re-prompted; PutUser is an upsert, and a re-run of init must not
	// replace a password nobody asked it to.
	users, err := opts.client.Users(ctx)
	if err != nil {
		printManualNext(o)
		return fmt.Errorf("list accounts: %w", err)
	}
	created := false
	adminName := ""
	if len(users) > 0 {
		o.println("An account already exists; skipping the first-admin step.")
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
	// account, then restart. The comparison beside it covers a re-run whose
	// listener changed in either direction — a new --listen, a new bind
	// stanza (v1.80), or a "none" that retires one: `enable --now` does not
	// re-exec a running unit, so without the restart the daemon keeps serving
	// whatever the previous run settled. health.Listen is the daemon's
	// *configured* address, reported verbatim, so an unchanged re-run
	// compares equal and nothing restarts.
	if (created && opts.listen != "") || opts.listen != health.Listen {
		o.println("Restarting kanead so the settled listener takes effect…")
		if err := opts.run(ctx, "restart", "kanead"); err != nil {
			printManualNext(o)
			return fmt.Errorf("restart kanead: %w", err)
		}
		health, err = waitForDaemon(ctx, opts.client, opts.timeout)
		if err != nil {
			printManualNext(o)
			return err
		}
		if opts.listen != "" && health.Listen != opts.listen {
			// A warning, not a failure: the node works over the socket, and
			// the journal has the listener's own refusal with its reason.
			o.println("Warning: the network listener did not open; check `journalctl -u kanead`.")
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

// dashboardFor derives the summary's URL from what the daemon actually bound:
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
		o.printf("  Dashboard      not exposed; the API answers only on %s\n", api.DefaultSocket)
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
	o.println("CLI without sudo:  sudo usermod -aG kanea <user>   # root-equivalent; log in again")
	o.println("Configure a backup destination before you need one; see docs/DR_RUNBOOK.md.")
}
