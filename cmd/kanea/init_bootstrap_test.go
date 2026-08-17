package main

import (
	"bufio"
	"bytes"
	"context"
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
	restarted          bool
}

func (f *fakeAdminAPI) Health(context.Context) (api.Health, error) {
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
		wantErr  bool
	}{
		{name: "default loopback", value: api.DefaultListenAddr, want: "127.0.0.1:8600"},
		{name: "none means socket-only", explicit: true, value: "none", want: ""},
		{name: "off is an alias", explicit: true, value: "off", want: ""},
		{name: "public without TLS refused", explicit: true, value: "0.0.0.0:8600", wantErr: true},
		{name: "public with TLS", explicit: true, value: "10.0.0.5:8600",
			cert: "/etc/kanea/api.crt", key: "/etc/kanea/api.key", want: "10.0.0.5:8600"},
		{name: "half a keypair refused", explicit: true, value: "127.0.0.1:8600",
			cert: "/etc/kanea/api.crt", wantErr: true},
		{name: "garbage refused", explicit: true, value: "not an address", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader("this line must not be consumed\n"))
			got, err := resolveListen(newOut(), reader, tc.explicit, tc.value, tc.cert, tc.key)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("accepted %q", tc.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused %q: %v", tc.value, err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if line, _ := reader.ReadString('\n'); line != "this line must not be consumed\n" {
				t.Errorf("resolveListen consumed stdin it was not offered; next read got %q", line)
			}
		})
	}
}
