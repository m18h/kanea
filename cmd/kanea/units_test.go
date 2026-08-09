package main

import (
	"errors"
	"flag"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/api"
)

func TestUnitsCarryTheCgroupGuarantees(t *testing.T) {
	// Constraint #11 is not something Go can arrange for itself: memory.min and
	// OOMScoreAdjust are systemd's to set, and a Kanea installed without these
	// lines runs until the node is under memory pressure and the OOM killer
	// picks the largest process, which is usually kanead.
	dir := t.TempDir()
	o := newOut()
	if err := writeUnits(o, unitOptions{
		dir: dir, dataDir: "/var/lib/kanea", logDir: "/var/log/kanea/allocs",
		reserve: "2G", binary: "/usr/local/bin/kanea",
	}); err != nil {
		t.Fatalf("write units: %v", err)
	}

	read := func(name string) string {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 — a test path
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(body)
	}

	slice := read("kanea.slice")
	if !strings.Contains(slice, "MemoryMin=2G") {
		t.Errorf("the control-plane slice has no memory floor:\n%s", slice)
	}

	service := read("kanead.service")
	for _, want := range []string{
		"OOMScoreAdjust=-900",
		"Slice=kanea.slice",
		"ExecStart=/usr/local/bin/kanea agent",
		// A control-plane restart must not take the workloads with it.
		"KillMode=process",
		// Not Type=notify: nothing in kanead sends sd_notify, and systemd would
		// wait for a readiness message that never arrives and then kill it.
		"Type=exec",
	} {
		if !strings.Contains(service, want) {
			t.Errorf("kanead.service is missing %q:\n%s", want, service)
		}
	}

	// The edge is a separate process from day one (§18 rule 8), and must not
	// wait on the control plane — that separation is the whole reason it exists.
	edge := read("kanea-edge.service")
	for _, line := range strings.Split(edge, "\n") {
		// A directive, not the comment that explains why there isn't one.
		if strings.HasPrefix(line, "After=kanead") || strings.HasPrefix(line, "Requires=kanead") {
			t.Errorf("the edge unit orders itself after kanead (%q); north-south "+
				"traffic would then depend on the control plane being up", line)
		}
	}
	if !strings.Contains(edge, "AmbientCapabilities=CAP_NET_BIND_SERVICE") {
		t.Error("the edge unit does not grant the one capability it needs")
	}
	if !strings.Contains(edge, "CapabilityBoundingSet=CAP_NET_BIND_SERVICE") {
		t.Error("the edge unit does not drop the capabilities it does not need")
	}
	// Checked as directives rather than as substrings: both units *mention*
	// Type=notify in the comment explaining why they do not use it.
	for _, unit := range []string{service, edge} {
		for _, line := range strings.Split(unit, "\n") {
			if strings.HasPrefix(line, "Type=notify") {
				t.Error("a unit uses Type=notify, but nothing here sends sd_notify; " +
					"systemd would time out waiting and kill the service")
			}
		}
	}

	if _, err := os.Stat(filepath.Join(dir, "kanea-workloads.slice")); err != nil {
		t.Errorf("the workload slice was not written: %v", err)
	}
}

func TestUnitsHaveNoLeadingTabs(t *testing.T) {
	// The unit bodies are indented Go string literals. systemd tolerates
	// leading whitespace in some places and not others, and a file that is
	// subtly wrong fails at `systemctl daemon-reload` rather than here.
	dir := t.TempDir()
	if err := writeUnits(newOut(), unitOptions{
		dir: dir, dataDir: "/var/lib/kanea", logDir: "/var/log/kanea",
		reserve: "1G", binary: "/usr/local/bin/kanea",
	}); err != nil {
		t.Fatalf("write units: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(dir, entry.Name())) // #nosec G304 — a test path
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for i, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, " ") {
				t.Errorf("%s:%d is indented: %q", entry.Name(), i+1, line)
			}
		}
	}
}

// TestUnitExecStartFlagsAreDefined checks every flag the generated units pass
// against the flag set the subcommand actually builds.
//
// The units are strings and the flags are code, and nothing else connects them.
// That is how kanea-edge.service shipped passing --data-dir to a command that
// has never defined it: `flag.ContinueOnError` made fs.Parse return an error,
// runEdge returned it, and the unit restart-looped under Restart=always without
// ever having served a request.
//
// The flag names come from the subcommand's own usage output rather than from a
// list kept here, because a list kept here is a third thing to drift.
func TestUnitExecStartFlagsAreDefined(t *testing.T) {
	dir := t.TempDir()
	if err := writeUnits(newOut(), unitOptions{
		dir: dir, dataDir: "/var/lib/kanea", logDir: "/var/log/kanea",
		reserve: "1G", binary: "/usr/local/bin/kanea",
	}); err != nil {
		t.Fatalf("write units: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(dir, entry.Name())) // #nosec G304 — a test path
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for _, line := range strings.Split(string(body), "\n") {
			exec, ok := strings.CutPrefix(line, "ExecStart=")
			if !ok {
				continue
			}
			fields := strings.Fields(exec)
			if len(fields) < 2 {
				continue // a bare binary invocation passes no flags
			}
			sub := fields[1]
			defined := definedFlags(t, sub)
			for _, field := range fields[2:] {
				name, ok := strings.CutPrefix(field, "--")
				if !ok {
					continue // a flag value, or a positional argument
				}
				name, _, _ = strings.Cut(name, "=")
				if !defined[name] {
					t.Errorf("%s: ExecStart passes --%s to `kanea %s`, which defines no such flag; "+
						"the unit fails at every start", entry.Name(), name, sub)
				}
			}
		}
	}
}

// definedFlags asks a subcommand for its usage and reads back the flag names it
// declares. `-h` returns flag.ErrHelp straight out of Parse, so nothing the
// subcommand would otherwise do — open a database, bind a port — happens here.
func definedFlags(t *testing.T, sub string) map[string]bool {
	t.Helper()

	run, ok := map[string]func([]string) error{
		"agent": runAgent,
		"edge":  runEdge,
	}[sub]
	if !ok {
		t.Fatalf("no subcommand %q to check flags against; add it here", sub)
	}

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stderr
	os.Stderr = write
	usage := make(chan string, 1)
	go func() {
		body, _ := io.ReadAll(read)
		usage <- string(body)
	}()
	runErr := run([]string{"-h"})
	os.Stderr = saved
	if err := write.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	if !errors.Is(runErr, flag.ErrHelp) {
		t.Fatalf("kanea %s -h returned %v, not flag.ErrHelp; it may have started doing work", sub, runErr)
	}

	defined := map[string]bool{}
	for _, line := range strings.Split(<-usage, "\n") {
		// The flag package writes "  -name value" for each flag, and indents
		// the description by a tab on the following line.
		rest, ok := strings.CutPrefix(line, "  -")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(rest, " ")
		defined[name] = true
	}
	if len(defined) == 0 {
		t.Fatalf("kanea %s -h printed no flags; the usage format has changed", sub)
	}
	return defined
}

func TestKernelComparison(t *testing.T) {
	// The parser has to cope with what /proc/sys/kernel/osrelease actually
	// contains, which is rarely a bare "6.1".
	cases := []struct {
		have  string
		older bool
	}{
		{"6.8.0-generic", false},
		{"5.10.0", false},
		{"5.4.0-190-generic", true},
		{"4.19.0", true},
		{"6.1", false},
	}
	for _, tc := range cases {
		older, err := kernelOlderThan(tc.have, minKernel)
		if err != nil {
			t.Errorf("%s: %v", tc.have, err)
			continue
		}
		if older != tc.older {
			t.Errorf("%s older than %s = %v, want %v", tc.have, minKernel, older, tc.older)
		}
	}
}

func TestKeyCeremoryRefusesWhenTheKeyIsNotTypedBack(t *testing.T) {
	// The whole ceremony rests on this: an operator who cannot type the key
	// back does not have it, and writing it anyway produces exactly the
	// situation the ceremony exists to prevent.
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")

	stdin, err := os.CreateTemp(dir, "stdin")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := stdin.WriteString("not the key\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := stdin.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	saved := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin = saved; _ = stdin.Close() })

	if err := keyCeremony(newOut(), path); err == nil {
		t.Fatal("the ceremony accepted a wrong confirmation")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a key was written despite the confirmation failing")
	}
}

func TestDashboardURLIsSomethingABrowserCanUse(t *testing.T) {
	// A wildcard bind is not an address anyone can visit, and printing it is
	// how `kanea ui` becomes a command whose output does not work.
	cases := map[string]struct {
		listen string
		secure bool
		want   string
	}{
		"wildcard port only": {":8600", false, "http://localhost:8600"},
		"all interfaces":     {"0.0.0.0:8600", false, "http://localhost:8600"},
		"all v6 interfaces":  {"[::]:8600", true, "https://localhost:8600"},
		"a real address":     {"10.0.0.5:8600", true, "https://10.0.0.5:8600"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := dashboardURL(tc.listen, tc.secure); got != tc.want {
				t.Errorf("dashboardURL(%q, %v) = %q, want %q", tc.listen, tc.secure, got, tc.want)
			}
		})
	}
}

func TestExecArgumentsRequireTheSeparator(t *testing.T) {
	// Without `--`, `kanea exec web ls -la` is ambiguous: -la could be one of
	// kanea's flags. Guessing produces the failure where a flag meant for the
	// remote command is silently eaten here.
	if _, _, err := splitExecArgs([]string{"web", "ls", "-la"}); err == nil {
		t.Error("a command without `--` was accepted")
	} else if !strings.Contains(err.Error(), "--") {
		t.Errorf("the error does not show the fix: %v", err)
	}

	service, command, err := splitExecArgs([]string{"web", "--", "ls", "-la"})
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if service != "web" {
		t.Errorf("service = %q", service)
	}
	// The remote flags survive intact — that is the whole point of the
	// separator.
	if len(command) != 2 || command[1] != "-la" {
		t.Errorf("command = %q, want [ls -la]", command)
	}

	for _, args := range [][]string{{}, {"web"}, {"web", "--"}} {
		if _, _, err := splitExecArgs(args); err == nil {
			t.Errorf("accepted %q", args)
		}
	}
}

func TestExecQueryRoundTrips(t *testing.T) {
	// The command is repeated parameters rather than one joined string:
	// joining means the server has to split, and every splitting rule is wrong
	// for some argument someone will eventually pass.
	query := api.ExecQuery("shop", "shop-web-0",
		[]string{"/bin/sh", "-c", "echo hello world & true"}, true, "1000")
	values, err := url.ParseQuery(query)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := values["command"]; len(got) != 3 || got[2] != "echo hello world & true" {
		t.Errorf("command = %q, want the argument array intact including the ampersand", got)
	}
	if values.Get("tty") != "true" || values.Get("user") != "1000" {
		t.Errorf("query lost its options: %s", query)
	}
}
