package main

import (
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
)

func TestUsageListsAllCommands(t *testing.T) {
	var b strings.Builder
	if err := printUsage(&b); err != nil {
		t.Fatalf("printUsage: %v", err)
	}
	out := b.String()
	for _, c := range commands {
		if !strings.Contains(out, c.name) {
			t.Errorf("usage output missing command %q", c.name)
		}
	}
}

func TestVersionCommand(t *testing.T) {
	if err := runVersion(nil); err != nil {
		t.Fatalf("runVersion: %v", err)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	if err := run([]string{"does-not-exist"}); err == nil {
		t.Fatal("expected error for unknown command")
	}
}

// Aliases resolve before dispatch: every alias must target a real command and
// must not shadow one; a map entry naming an existing command would silently
// re-route it.
func TestAliasesResolveToRealCommands(t *testing.T) {
	names := map[string]bool{}
	for _, c := range commands {
		names[c.name] = true
	}
	for alias, target := range aliases {
		if !names[target] {
			t.Errorf("alias %q targets %q, which is not a command", alias, target)
		}
		if names[alias] {
			t.Errorf("alias %q shadows a real command", alias)
		}
	}
	if aliases["apply"] != "run" {
		t.Error(`kanea apply must be an alias for run (PRD v1.52, §16.2)`)
	}
}

func TestNoArgsPrintsUsage(t *testing.T) {
	if err := run(nil); err != nil {
		t.Fatalf("run with no args should print usage, got: %v", err)
	}
}

// Every command in the table does real work: there is no not-implemented stub
// left to point at, so the invariant is simply that dispatch can never reach a
// nil handler and that no name is claimed twice (the second entry would be
// unreachable, since dispatch takes the first match).
//
// Checked by identity rather than by calling: `kanea agent` and `kanea edge`
// are daemons that bind listeners and run until interrupted, so invoking one to
// find out whether it is wired would hang the suite.
func TestEveryCommandIsWired(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range commands {
		if c.run == nil {
			t.Errorf("command %q has no handler", c.name)
		}
		if c.name == "" {
			t.Error("a command in the table has no name")
		}
		if seen[c.name] {
			t.Errorf("command %q is listed twice; the second entry is unreachable", c.name)
		}
		seen[c.name] = true
		if c.desc == "" {
			t.Errorf("command %q has no description, so usage output cannot explain it", c.name)
		}
	}
}

func TestFindServiceResolvesTheSlashForm(t *testing.T) {
	// PRD §16.2 has always written `kanea stop shop/web`; v1.55 makes the CLI
	// actually parse it, and v1.56 routes every service-targeting command
	// through this one resolver: logs, exec, build and status included, the
	// four that used to carry their own weaker parsing. A service name is a
	// DNS-1123 label, so the slash is unambiguous.
	services := []reconciler.Desired{
		{Project: "shop", Service: "web", Count: 2},
		{Project: "blog", Service: "web", Count: 1},
		{Project: "shop", Service: "api", Count: 1},
	}
	tests := []struct {
		name        string
		project     string
		arg         string
		wantProject string
		wantErr     string
	}{
		{name: "slash form disambiguates", arg: "shop/web", wantProject: "shop"},
		{name: "bare name still works when unique", arg: "api", wantProject: "shop"},
		{name: "bare ambiguous name still asks for a project", arg: "web",
			wantErr: "use --project"},
		{name: "flag and slash agreeing is fine", project: "shop", arg: "shop/web",
			wantProject: "shop"},
		{name: "flag and slash disagreeing is refused", project: "blog", arg: "shop/web",
			wantErr: "disagrees"},
		{name: "slash form of a missing service", arg: "shop/worker",
			wantErr: "no service"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := findService(services, tc.project, tc.arg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Project != tc.wantProject {
				t.Errorf("resolved project = %q, want %q", got.Project, tc.wantProject)
			}
		})
	}
}

// The status table's scope filter: a project narrows, a resolved service
// narrows further, and the zero filter shows everything. Display-only: the
// dependency reasoning keeps the full list.
func TestVisibleServicesNarrowsTheStatusTable(t *testing.T) {
	services := []reconciler.Desired{
		{Project: "shop", Service: "web"},
		{Project: "shop", Service: "api"},
		{Project: "blog", Service: "web"},
	}
	if got := visibleServices(services, "", ""); len(got) != 3 {
		t.Errorf("unfiltered view shows %d services, want all 3", len(got))
	}
	if got := visibleServices(services, "shop", ""); len(got) != 2 {
		t.Errorf("project view shows %d services, want 2", len(got))
	}
	got := visibleServices(services, "shop", "web")
	if len(got) != 1 || got[0].Project != "shop" || got[0].Service != "web" {
		t.Errorf("service view shows %v, want exactly shop/web", got)
	}
}

func TestServiceHealth(t *testing.T) {
	// `kanea status` is where an operator looks to decide whether to worry, so
	// "ok" must mean settled, not merely "nothing has failed yet".
	tests := []struct {
		name                                         string
		desired, running, backoff, failed, unhealthy int
		want                                         string
		wantSettled                                  bool
	}{
		{"all running", 2, 2, 0, 0, 0, "ok", true},
		{"still starting", 3, 1, 0, 0, 0, "starting", false},
		{"restarting", 2, 1, 1, 0, 0, "1 restarting", false},
		{"failed wins over restarting", 2, 0, 1, 1, 0, "1 failed", false},
		{"scaled to zero and drained", 0, 0, 0, 0, 0, "stopped", true},
		{"draining after a stop", 0, 1, 0, 0, 0, "stopping", false},
		{"scaling in", 1, 3, 0, 0, 0, "stopping", false},
		// An alloc that is up but failing its check is a different problem from
		// one that has not started; reporting it as "starting" would suggest
		// that waiting is enough.
		{"running but failing its check", 2, 2, 0, 0, 1, "1 unhealthy", false},
		{"unhealthy while still scaling up", 3, 2, 0, 0, 1, "1 unhealthy", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, settled := serviceHealth(tc.desired, tc.running, tc.backoff, tc.failed, tc.unhealthy)
			if got != tc.want || settled != tc.wantSettled {
				t.Errorf("serviceHealth(%d,%d,%d,%d,%d) = %q,%v; want %q,%v",
					tc.desired, tc.running, tc.backoff, tc.failed, tc.unhealthy,
					got, settled, tc.want, tc.wantSettled)
			}
		})
	}
}

// A service gated on a dependency has no allocs and therefore no records, so
// "starting" is all the alloc states can say. Status has to reconstruct the
// reason or an operator watches nothing happen and has to read the agent log.
func TestBlockedOnExplainsWhyAServiceHasNotStarted(t *testing.T) {
	api := reconciler.Desired{
		Project: "shop", Service: "api", Count: 1, DependsOn: []string{"postgres", "cache"},
	}
	db := reconciler.Desired{Project: "shop", Service: "postgres", Count: 2}
	cache := reconciler.Desired{Project: "shop", Service: "cache", Count: 1}
	services := []reconciler.Desired{api, db, cache}

	tests := []struct {
		name   string
		counts map[string]*tally
		want   []string
	}{
		{
			name:   "nothing up yet",
			counts: map[string]*tally{},
			want:   []string{"cache", "postgres"},
		},
		{
			name: "one dependency partly up",
			counts: map[string]*tally{
				"shop/postgres": {running: 1}, // wants 2
				"shop/cache":    {running: 1},
			},
			want: []string{"postgres"},
		},
		{
			name: "dependency running but failing its check",
			counts: map[string]*tally{
				"shop/postgres": {running: 2},
				"shop/cache":    {running: 1, unhealthy: 1},
			},
			want: []string{"cache"},
		},
		{
			name: "everything healthy",
			counts: map[string]*tally{
				"shop/postgres": {running: 2},
				"shop/cache":    {running: 1},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := blockedOn(api, services, tc.counts)
			if len(got) != len(tc.want) {
				t.Fatalf("blockedOn = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("blockedOn = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// A dependency deliberately scaled to zero is satisfied, not a deadlock.
func TestBlockedOnIgnoresZeroCountAndMissingDependencies(t *testing.T) {
	api := reconciler.Desired{
		Project: "shop", Service: "api", Count: 1, DependsOn: []string{"postgres", "ghost"},
	}
	services := []reconciler.Desired{api, {Project: "shop", Service: "postgres", Count: 0}}

	if got := blockedOn(api, services, map[string]*tally{}); len(got) != 0 {
		t.Fatalf("blockedOn = %v, want nothing blocking", got)
	}
}

// PRD §6.2 R23-R24, end to end: HCL text through toDesired to the alloc spec
// the runtime is handed. Each layer has its own test; this is the one that
// would catch a field that is carried correctly everywhere and dropped at a
// seam, which is where a chain this long actually breaks.
func TestUserAndVolumeOwnershipSurviveConversion(t *testing.T) {
	src := `
spec_version = 1
project "shop" {}
storage "local-ssd" { type = "local" }
service "db" {
  project = "shop"
  task "pg" {
    image = "postgres:17"
    user {
      uid    = 999
      gid    = 998
      groups = [1000]
    }
  }
  volume "data" {
    storage    = "local-ssd"
    mount_path = "/var/lib/postgresql/data"
  }
  volume "shared" {
    storage    = "local-ssd"
    mount_path = "/shared"
    uid        = 0
    mode       = "0770"
  }
}
`
	spec, diags := jobspec.ParseSource(jobspec.Options{}, "test.hcl", []byte(src))
	if diags.HasErrors() {
		t.Fatalf("parse:\n%s", jobspec.FormatDiagnostics(diags))
	}
	all, err := toDesired(spec)
	if err != nil {
		t.Fatalf("toDesired: %v", err)
	}
	d := all[0]

	if d.User == nil || d.User.UID != 999 || d.User.GID != 998 {
		t.Fatalf("desired user = %+v, want 999:998", d.User)
	}
	if len(d.User.AdditionalGIDs) != 1 || d.User.AdditionalGIDs[0] != 1000 {
		t.Errorf("additional gids = %v, want [1000]", d.User.AdditionalGIDs)
	}

	// Inherited from the task, with the default mode.
	data := d.Volumes[0]
	if data.UID == nil || *data.UID != 999 || data.GID == nil || *data.GID != 998 {
		t.Errorf("data volume owner = %v:%v, want the task's 999:998", data.UID, data.GID)
	}
	if data.Mode == nil || *data.Mode != 0o700 {
		t.Errorf("data volume mode = %v, want 0700", data.Mode)
	}

	// Declared: uid 0 is root asked for on purpose, and the undeclared gid
	// still inherits rather than becoming 0.
	shared := d.Volumes[1]
	if shared.UID == nil || *shared.UID != 0 {
		t.Errorf("shared volume uid = %v, want an explicit 0", shared.UID)
	}
	if shared.GID == nil || *shared.GID != 998 {
		t.Errorf("shared volume gid = %v, want the inherited 998", shared.GID)
	}
	if shared.Mode == nil || *shared.Mode != 0o770 {
		t.Errorf("shared volume mode = %v, want 0770", shared.Mode)
	}

	// And through to what the runtime is handed.
	alloc := reconciler.AllocSpecFor(d, 0, t.TempDir(), t.TempDir())
	if alloc.User == nil || alloc.User.UID != 999 || alloc.User.GID != 998 {
		t.Fatalf("alloc user = %+v, want 999:998", alloc.User)
	}
	if err := alloc.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// The two refusals, with the positions R1 requires. A diagnostic without a
// file and line is what makes a spec error an unsolvable one.
func TestOwnershipRefusalsCarryPositions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		storage string
		wantErr string
	}{
		{
			name:    "host",
			storage: "storage \"vol\" {\n  type = \"host\"\n  path = \"/srv/data\"\n}",
			wantErr: "never changes its ownership",
		},
		{
			name:    "nfs",
			storage: "storage \"vol\" {\n  type   = \"nfs\"\n  server = \"10.0.0.5\"\n  export = \"/e\"\n}",
			wantErr: "no uid= or gid= mount option",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "spec_version = 1\nproject \"shop\" {}\n" + tc.storage + `
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
  volume "d" {
    storage    = "vol"
    mount_path = "/d"
    uid        = 999
  }
}
`
			_, diags := jobspec.ParseSource(jobspec.Options{}, "shop.hcl", []byte(src))
			if !diags.HasErrors() {
				t.Fatal("expected a refusal, got none")
			}
			out := jobspec.FormatDiagnostics(diags)
			if !strings.Contains(out, tc.wantErr) {
				t.Errorf("diagnostics = %q, want %q", out, tc.wantErr)
			}
			// file:line,col; the position, not just the complaint.
			if !strings.Contains(out, "shop.hcl:") {
				t.Errorf("diagnostics = %q, want a file and line", out)
			}
			t.Logf("%s", out)
		})
	}
}
