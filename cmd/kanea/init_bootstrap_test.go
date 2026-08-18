package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
)

// fakeAdminAPI is the bootstrap's client seam, recording what was asked of it.
type fakeAdminAPI struct {
	health   api.Health
	users    []auth.User
	putCalls []string
	putPass  string
	putRole  auth.Role
	// listenAfterRestart is what Health reports once a restart ran.
	listenAfterRestart string
	// healthAfterRestart, when set, replaces the reported health wholesale
	// once a restart ran: a listener can close, not only open.
	healthAfterRestart *api.Health
	restarted          bool
}

func (f *fakeAdminAPI) Health(context.Context) (api.Health, error) {
	if f.restarted && f.healthAfterRestart != nil {
		return *f.healthAfterRestart, nil
	}
	h := f.health
	if f.restarted && f.listenAfterRestart != "" {
		h.Listen = f.listenAfterRestart
	}
	return h, nil
}

func (f *fakeAdminAPI) Users(context.Context) ([]auth.User, error) { return f.users, nil }

func (f *fakeAdminAPI) PutUser(_ context.Context, name, password string, role auth.Role) error {
	f.putCalls = append(f.putCalls, name)
	f.putPass, f.putRole = password, role
	return nil
}

// recordingRunner is the systemctl seam.
type recordingRunner struct {
	calls [][]string
	fake  *fakeAdminAPI
}

func (r *recordingRunner) run(_ context.Context, args ...string) error {
	r.calls = append(r.calls, args)
	if len(args) > 0 && args[0] == "restart" && r.fake != nil {
		r.fake.restarted = true
	}
	return nil
}

func (r *recordingRunner) restarts() int {
	n := 0
	for _, call := range r.calls {
		if len(call) > 0 && call[0] == "restart" {
			n++
		}
	}
	return n
}

func testBootstrapOptions(fake *fakeAdminAPI, runner *recordingRunner) bootstrapOptions {
	runner.fake = fake
	return bootstrapOptions{
		listen: "127.0.0.1:8600", timeout: time.Second,
		network:  networkEBPF,
		nodeCIDR: "10.244.0.0/24", clusterCIDR: "10.244.0.0/16", serviceCIDR: "10.201.0.0/16",
		client: fake, run: runner.run,
	}
}

func TestBootstrapCreatesTheFirstAdminAndRestartsOnce(t *testing.T) {
	fake := &fakeAdminAPI{listenAfterRestart: "127.0.0.1:8600"}
	runner := &recordingRunner{}
	var buf bytes.Buffer
	reader := bufio.NewReader(strings.NewReader("michael\nsw0rdfish-passw0rd\n"))

	if err := bootstrapDaemon(&out{w: &buf}, reader, testBootstrapOptions(fake, runner)); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	if len(fake.putCalls) != 1 || fake.putCalls[0] != "michael" {
		t.Errorf("PutUser calls = %v, want exactly [michael]", fake.putCalls)
	}
	if fake.putRole != auth.RoleAdmin {
		t.Errorf("role = %q, want admin", fake.putRole)
	}
	if fake.putPass != "sw0rdfish-passw0rd" {
		t.Errorf("password did not survive the piped read: %q", fake.putPass)
	}
	if got := runner.restarts(); got != 1 {
		t.Errorf("restarts = %d, want exactly 1 (the §13.1 listener restart)", got)
	}
	if !strings.Contains(buf.String(), "http://127.0.0.1:8600") {
		t.Errorf("summary is missing the dashboard URL:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "sw0rdfish-passw0rd") {
		t.Errorf("the password leaked into the output:\n%s", buf.String())
	}
}

func TestBootstrapSkipsAnExistingAccountAndDoesNotRestart(t *testing.T) {
	// Idempotency: PutUser is an upsert, so a re-run must never reach it; a
	// prompt on a re-run would replace a password nobody asked to change. And
	// with the listener already open, there is nothing to restart for.
	fake := &fakeAdminAPI{
		health: api.Health{Listen: "127.0.0.1:8600"},
		users:  []auth.User{{Name: "michael", Role: auth.RoleAdmin}},
	}
	runner := &recordingRunner{}
	var buf bytes.Buffer
	// An empty reader: any prompt would fail the read, failing the test.
	reader := bufio.NewReader(strings.NewReader(""))

	if err := bootstrapDaemon(&out{w: &buf}, reader, testBootstrapOptions(fake, runner)); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if len(fake.putCalls) != 0 {
		t.Errorf("PutUser was called on a node with accounts: %v", fake.putCalls)
	}
	if got := runner.restarts(); got != 0 {
		t.Errorf("restarts = %d, want 0 when the listener is already open", got)
	}
	if !strings.Contains(buf.String(), "accounts already existed") {
		t.Errorf("summary does not say accounts existed:\n%s", buf.String())
	}
}

func TestBootstrapRestartsWhenTheListenerIsNotOpen(t *testing.T) {
	// The changed-flag re-run: accounts exist, but the running daemon reports
	// no listener; `enable --now` does not re-exec a running unit, so the
	// restart is the only way the new --listen ever binds.
	fake := &fakeAdminAPI{
		users:              []auth.User{{Name: "michael", Role: auth.RoleAdmin}},
		listenAfterRestart: "127.0.0.1:8600",
	}
	runner := &recordingRunner{}
	var buf bytes.Buffer

	opts := testBootstrapOptions(fake, runner)
	if err := bootstrapDaemon(&out{w: &buf}, bufio.NewReader(strings.NewReader("")), opts); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got := runner.restarts(); got != 1 {
		t.Errorf("restarts = %d, want 1 to pick up the configured listener", got)
	}
}

func TestBootstrapRestartsWhenTheListenAddressChanged(t *testing.T) {
	// The re-run that moves the listener: accounts exist and the daemon is
	// already serving the old address, so neither half of the pre-v1.80
	// condition (created, or no listener configured) fires. Only comparing
	// the settled address against the daemon's configured one picks the new
	// unit's argv up.
	fake := &fakeAdminAPI{
		health:             api.Health{Listen: "127.0.0.1:8600"},
		users:              []auth.User{{Name: "michael", Role: auth.RoleAdmin}},
		listenAfterRestart: "10.0.0.5:8600",
	}
	runner := &recordingRunner{}
	var buf bytes.Buffer

	opts := testBootstrapOptions(fake, runner)
	opts.listen = "10.0.0.5:8600"
	if err := bootstrapDaemon(&out{w: &buf}, bufio.NewReader(strings.NewReader("")), opts); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got := runner.restarts(); got != 1 {
		t.Errorf("restarts = %d, want 1: a changed --listen never binds without it", got)
	}
	if !strings.Contains(buf.String(), "10.0.0.5:8600") {
		t.Errorf("summary must report the new address:\n%s", buf.String())
	}
}

func TestBootstrapRestartsWhenTheListenerIsRetired(t *testing.T) {
	// listen → none: the running daemon is still holding the old listener,
	// and only a restart closes it. The "did not open" warning must NOT fire
	// afterwards: a socket-only outcome is exactly what was asked for.
	fake := &fakeAdminAPI{
		health:             api.Health{Listen: "127.0.0.1:8600"},
		users:              []auth.User{{Name: "michael", Role: auth.RoleAdmin}},
		healthAfterRestart: &api.Health{},
	}
	runner := &recordingRunner{}
	var buf bytes.Buffer

	opts := testBootstrapOptions(fake, runner)
	opts.listen = ""
	if err := bootstrapDaemon(&out{w: &buf}, bufio.NewReader(strings.NewReader("")), opts); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got := runner.restarts(); got != 1 {
		t.Errorf("restarts = %d, want 1: retiring a listener takes a restart", got)
	}
	if strings.Contains(buf.String(), "did not open") {
		t.Errorf("a retired listener must not warn as a failed one:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), api.DefaultSocket) {
		t.Errorf("a socket-only summary names the socket:\n%s", buf.String())
	}
}

func TestBootstrapDoesNotRestartAFreshSocketOnlyNode(t *testing.T) {
	// Fresh init, socket-only: the account is created over the socket and
	// there is no listener to open, so there is nothing to restart for.
	fake := &fakeAdminAPI{}
	runner := &recordingRunner{}
	var buf bytes.Buffer

	opts := testBootstrapOptions(fake, runner)
	opts.listen = ""
	reader := bufio.NewReader(strings.NewReader("michael\nsw0rdfish-passw0rd\n"))
	if err := bootstrapDaemon(&out{w: &buf}, reader, opts); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if len(fake.putCalls) != 1 {
		t.Errorf("PutUser calls = %v, want [michael]", fake.putCalls)
	}
	if got := runner.restarts(); got != 0 {
		t.Errorf("restarts = %d, want 0: a socket-only node has no listener to open", got)
	}
}

func TestBootstrapWithAdminUserFlagPromptsOnlyForThePassword(t *testing.T) {
	fake := &fakeAdminAPI{listenAfterRestart: "127.0.0.1:8600"}
	runner := &recordingRunner{}
	opts := testBootstrapOptions(fake, runner)
	opts.adminUser = "ci"
	reader := bufio.NewReader(strings.NewReader("pipeline-secret-pw\n"))

	var buf bytes.Buffer
	if err := bootstrapDaemon(&out{w: &buf}, reader, opts); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if len(fake.putCalls) != 1 || fake.putCalls[0] != "ci" {
		t.Errorf("PutUser calls = %v, want [ci]", fake.putCalls)
	}
	if fake.putPass != "pipeline-secret-pw" {
		t.Errorf("password = %q; the username prompt consumed the wrong line", fake.putPass)
	}
}

func TestInitSummaryVariants(t *testing.T) {
	render := func(s summaryInfo) string {
		var buf bytes.Buffer
		initSummary(&out{w: &buf}, s)
		return buf.String()
	}
	base := summaryInfo{
		dashboard: "http://localhost:8600", admin: "michael",
		dnsAddr:  "10.244.0.1:53",
		nodeCIDR: "10.244.0.0/24", clusterCIDR: "10.244.0.0/16", serviceCIDR: "10.201.0.0/16",
	}

	full := render(base)
	for _, want := range []string{
		"http://localhost:8600", `"michael"`, "10.244.0.1:53",
		"10.244.0.0/24", "10.244.0.0/16", "10.201.0.0/16",
	} {
		if !strings.Contains(full, want) {
			t.Errorf("summary is missing %q:\n%s", want, full)
		}
	}
	if strings.Contains(full, "cidr6") || strings.Contains(full, "CIDR v6") {
		t.Errorf("a v4-only summary mentions v6:\n%s", full)
	}

	dual := base
	dual.nodeCIDR6, dual.clusterCIDR6, dual.serviceCIDR6 = "fd10:244::/64", "fd10:244::/56", "fd10:245::/64"
	if got := render(dual); !strings.Contains(got, "fd10:244::/64") {
		t.Errorf("dual-stack summary is missing the v6 trio:\n%s", got)
	}

	socketOnly := base
	socketOnly.dashboard, socketOnly.admin = "", ""
	if got := render(socketOnly); !strings.Contains(got, api.DefaultSocket) {
		t.Errorf("socket-only summary does not name the socket:\n%s", got)
	}

	netns := base
	netns.dnsAddr = ""
	if got := render(netns); !strings.Contains(got, "netns mode has no service frontends") {
		t.Errorf("netns summary does not explain the missing DNS:\n%s", got)
	}
}

func TestDNSAddrForDerivesTheNodeCIDRsDotOne(t *testing.T) {
	if got := dnsAddrFor(networkEBPF, "10.9.4.0/24"); got != "10.9.4.1:53" {
		t.Errorf("dnsAddrFor = %q, want 10.9.4.1:53", got)
	}
	if got := dnsAddrFor(networkNetns, "10.9.4.0/24"); got != "" {
		t.Errorf("netns mode derived a DNS address: %q", got)
	}
}

func TestResolveListenValidatesWithoutPrompting(t *testing.T) {
	// Under `go test` stdin is not a terminal, so an explicit=false call must
	// not consume the reader: the piped-init contract.
	cases := []struct {
		name     string
		explicit bool
		value    string
		cert     string
		key      string
		want     string
		wantPair bool
		wantErr  bool
	}{
		{name: "default loopback", value: api.DefaultListenAddr, want: "127.0.0.1:8600"},
		{name: "none means socket-only", explicit: true, value: "none", want: ""},
		{name: "off is an alias", explicit: true, value: "off", want: ""},
		{name: "public without a pair gets the default pair", explicit: true, value: "198.100.154.249:8600",
			want: "198.100.154.249:8600", wantPair: true},
		{name: "public with TLS", explicit: true, value: "10.0.0.5:8600",
			cert: "/etc/kanea/api.crt", key: "/etc/kanea/api.key", want: "10.0.0.5:8600"},
		{name: "a LAN address is beyond loopback and gets the pair", explicit: true, value: "192.168.1.10:8600", wantPair: true,
			want: "192.168.1.10:8600"},
		{name: "half a keypair refused", explicit: true, value: "127.0.0.1:8600",
			cert: "/etc/kanea/api.crt", wantErr: true},
		{name: "garbage refused", explicit: true, value: "not an address", wantErr: true},
		{name: "unspecified host has no name to certify", explicit: true, value: "0.0.0.0:8600", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader("this line must not be consumed\n"))
			decision, err := resolveListen(newOut(), reader, tc.explicit, tc.value, tc.cert, tc.key)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("accepted %q", tc.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused %q: %v", tc.value, err)
			}
			if decision.addr != tc.want {
				t.Errorf("got %q, want %q", decision.addr, tc.want)
			}
			if decision.provisionPair != tc.wantPair {
				t.Errorf("provisionPair = %v, want %v", decision.provisionPair, tc.wantPair)
			}
			if line, _ := reader.ReadString('\n'); line != "this line must not be consumed\n" {
				t.Errorf("resolveListen consumed stdin it was not offered; next read got %q", line)
			}
		})
	}
}

// The default listener pair (PRD v1.80): minted once, left alone on re-runs,
// and refused when only half a pair exists.
func TestEnsureAPIPair(t *testing.T) {
	t.Run("mints a usable 10-year pair once, then leaves it alone", func(t *testing.T) {
		certPath := filepath.Join(t.TempDir(), "api.crt")
		keyPath := filepath.Join(t.TempDir(), "api.key")
		var buf bytes.Buffer
		if err := ensureAPIPair(&out{w: &buf}, "198.100.154.249:8600", certPath, keyPath); err != nil {
			t.Fatalf("ensureAPIPair: %v", err)
		}
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			t.Fatalf("the written pair must load: %v", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("198.100.154.249")) {
			t.Errorf("IP SANs = %v, want the listen address's IP", leaf.IPAddresses)
		}
		if got := time.Until(leaf.NotAfter); got < 9*365*24*time.Hour {
			t.Errorf("validity = %v, want the 10-year default", got)
		}
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("key mode = %04o, want 0600 (certsource's own provided-key rule)", perm)
		}

		// A re-run must not re-mint: the fingerprint operators accepted is
		// the one that stays.
		before, _ := os.ReadFile(certPath)
		if err := ensureAPIPair(&out{w: &buf}, "198.100.154.249:8600", certPath, keyPath); err != nil {
			t.Fatalf("ensureAPIPair re-run: %v", err)
		}
		after, _ := os.ReadFile(certPath)
		if !bytes.Equal(before, after) {
			t.Error("a re-run re-minted the certificate; existing material is left alone")
		}
		if !strings.Contains(buf.String(), "leaving it alone") {
			t.Errorf("the re-run must say it left the pair alone:\n%s", buf.String())
		}
	})

	t.Run("half a pair is an error, never a guess", func(t *testing.T) {
		dir := t.TempDir()
		certPath := filepath.Join(dir, "api.crt")
		keyPath := filepath.Join(dir, "api.key")
		if err := os.WriteFile(certPath, []byte("some cert"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ensureAPIPair(newOut(), "198.100.154.249:8600", certPath, keyPath); err == nil {
			t.Fatal("a cert with no key must not be completed silently")
		}
	})

	t.Run("an unspecified host is refused before anything is written", func(t *testing.T) {
		dir := t.TempDir()
		certPath := filepath.Join(dir, "api.crt")
		err := ensureAPIPair(newOut(), "0.0.0.0:8600", certPath, filepath.Join(dir, "api.key"))
		if err == nil || !strings.Contains(err.Error(), "api_domain") {
			t.Fatalf("the refusal must name the api_domain route, got: %v", err)
		}
		if _, statErr := os.Stat(certPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Error("the refusal wrote a certificate")
		}
	})
}
