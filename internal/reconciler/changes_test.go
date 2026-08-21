package reconciler_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/storage"
)

// base is a service that declares one of most things, so a mutation in any test
// below is a change to something rather than the arrival of it.
func base() reconciler.Desired {
	uid := uint32(1000)
	return reconciler.Desired{
		Project: "shop", Service: "web", Count: 2, Image: "web:v1",
		Command:      []string{"/bin/app"},
		Capabilities: []string{"CAP_NET_BIND_SERVICE"},
		Env:          map[string]string{"LOG_LEVEL": "info"},
		Files: []reconciler.FileMount{
			{Name: "conf", Path: "/etc/app.conf", Mode: "0644", Content: []byte("a=1")},
		},
		User:      &runtime.User{UID: 1000, GID: 1000},
		Resources: runtime.Resources{CPUMillis: 500, MemoryBytes: 256 << 20, PidsLimit: 256},
		Volumes: []reconciler.Volume{
			{Name: "data", MountPath: "/data", UID: &uid},
		},
		Devices: []reconciler.DeviceRequest{{Name: "gpu", Grant: "nvidia0"}},
		Sockets: []reconciler.SocketRequest{
			{Name: "docker", Grant: "containerd", MountPath: "/run/c.sock"},
		},
		Ports:     []reconciler.Port{{Name: "http", Container: 8080}},
		AllowFrom: []reconciler.PeerRef{{Project: "shop", Service: "api"}},
		Expose:    &reconciler.Expose{Domains: []string{"shop.example.com"}, Port: 8080},
		Publish:   []reconciler.PublishedPort{{Port: "http", Host: 8443, Mode: "tcp"}},
		DependsOn: []string{"db"},
		Check:     &reconciler.HealthCheck{Type: "http", Path: "/healthz", Port: 8080},
		Scaling: &reconciler.ScalingPolicy{
			Min: 1, Max: 5,
			Metrics: []reconciler.ScalingMetric{{Name: "rps", Target: 100}},
		},
		Init: []reconciler.InitContainer{
			{Name: "migrate", Image: "mig:v1", Timeout: time.Minute},
		},
		Restart:         reconciler.RestartPolicy{Attempts: 5},
		Update:          reconciler.UpdatePolicy{Strategy: "rolling", MaxParallel: 1},
		PullPolicy:      "if-not-present",
		RegistryAuthRef: "secret:shop/registry",
	}
}

// changeFor runs one mutation through Changes and returns the single service
// change it produced, failing the test if it produced anything else.
func changeFor(t *testing.T, mutate func(*reconciler.Desired)) reconciler.ServiceChange {
	t.Helper()
	have, want := base(), base()
	mutate(&want)
	got := reconciler.Changes([]reconciler.Desired{have}, []reconciler.Desired{want}, nil)
	if len(got) != 1 {
		t.Fatalf("Changes produced %d entries, want exactly 1: %v", len(got),
			reconciler.RenderChanges(got))
	}
	return got[0]
}

// field returns the named field of a change, or fails.
func field(t *testing.T, c reconciler.ServiceChange, name string) reconciler.FieldChange {
	t.Helper()
	for _, f := range c.Fields {
		if f.Field == name {
			return f
		}
	}
	t.Fatalf("no %q field in %v", name, reconciler.RenderChanges([]reconciler.ServiceChange{c}))
	return reconciler.FieldChange{}
}

// mutations is the table every test below draws from. The Desired field name is
// what TestEveryDeclaredFieldIsDiffed matches against reflection, so a new field
// on Desired fails that test until somebody decides what a plan should say
// about it.
var mutations = []struct {
	desiredField string // the field of reconciler.Desired this exercises
	changeField  string // the field name the plan reports it under
	mutate       func(*reconciler.Desired)
}{
	{"Count", "count", func(d *reconciler.Desired) { d.Count = 3 }},
	{"Image", "image", func(d *reconciler.Desired) { d.Image = "web:v2" }},
	{"Command", "command", func(d *reconciler.Desired) { d.Command = []string{"/bin/app", "-v"} }},
	{"Capabilities", "capabilities", func(d *reconciler.Desired) { d.Capabilities = []string{"none"} }},
	{"Env", "env", func(d *reconciler.Desired) { d.Env = map[string]string{"LOG_LEVEL": "debug"} }},
	{"Files", "files", func(d *reconciler.Desired) { d.Files[0].Content = []byte("a=2") }},
	{"User", "user", func(d *reconciler.Desired) { d.User = &runtime.User{UID: 2000, GID: 2000} }},
	{"Resources", "resources", func(d *reconciler.Desired) { d.Resources.MemoryBytes = 512 << 20 }},
	{"Volumes", "volumes", func(d *reconciler.Desired) { d.Volumes[0].MountPath = "/srv/data" }},
	{"Devices", "devices", func(d *reconciler.Desired) { d.Devices[0].Grant = "nvidia1" }},
	{"Sockets", "sockets", func(d *reconciler.Desired) { d.Sockets[0].ReadOnly = true }},
	{"Ports", "ports", func(d *reconciler.Desired) { d.Ports[0].Container = 9090 }},
	{"Init", "init", func(d *reconciler.Desired) { d.Init[0].Image = "mig:v2" }},
	{"ReadOnlyRootfs", "read_only_rootfs", func(d *reconciler.Desired) { d.ReadOnlyRootfs = true }},
	{"Runtime", "runtime", func(d *reconciler.Desired) { d.Runtime = runtime.RuntimeWasmtime }},
	{"PullPolicy", "pull_policy", func(d *reconciler.Desired) { d.PullPolicy = "always" }},
	{"RegistryAuthRef", "registry_auth", func(d *reconciler.Desired) { d.RegistryAuthRef = "secret:shop/other" }},
	{"AllowFrom", "allow_from", func(d *reconciler.Desired) { d.AllowFrom = nil }},
	{"Expose", "expose", func(d *reconciler.Desired) { d.Expose.Domains = []string{"www.example.com"} }},
	{"ExtraExposes", "expose", func(d *reconciler.Desired) {
		d.ExtraExposes = []reconciler.Expose{{Domains: []string{"api.example.com"}, Port: 8080}}
	}},
	{"Publish", "publish", func(d *reconciler.Desired) { d.Publish[0].Host = 9443 }},
	{"DependsOn", "depends_on", func(d *reconciler.Desired) { d.DependsOn = []string{"db", "cache"} }},
	{"Check", "check", func(d *reconciler.Desired) { d.Check.Path = "/health" }},
	{"Scaling", "scaling", func(d *reconciler.Desired) { d.Scaling.Max = 10 }},
	{"Restart", "restart", func(d *reconciler.Desired) { d.Restart.Attempts = 10 }},
	{"Update", "update", func(d *reconciler.Desired) { d.Update.MaxParallel = 2 }},
	{"Function", "function", func(d *reconciler.Desired) {
		d.Function = &reconciler.FunctionMeta{Crons: []reconciler.CronTrigger{{Schedule: "* * * * *"}}}
	}},
}

// exemptFromDiff names the fields of Desired a plan deliberately never reports,
// with the reason. Every one of them is either the service's own identity or a
// value the *server* owns, which the client's desired state always has zeroed:
// comparing one would report a change on a service nobody edited.
var exemptFromDiff = map[string]string{
	"Project":        "identity: it selects which stored service this is",
	"Service":        "identity: it selects which stored service this is",
	"PinnedImage":    "server-owned (R19); applyServices carries it over",
	"RollbackImage":  "server-owned (R19) bookkeeping",
	"ImageCheckedAt": "server-owned (R19) bookkeeping",
	"ImageUpdatedAt": "server-owned (R19) bookkeeping",
	"Generation":     "server-owned; a restart bumps it and applyServices carries it over",
	"ResolvConfPath": "node-filled, json:\"-\": it never leaves the daemon",
}

// TestEveryDeclaredFieldIsDiffed is the drift guard. Adding a field to Desired
// without deciding what a plan says about it means a spec edit that applies
// silently, and for a hash-material field that means containers replaced with
// nothing on screen to explain why.
func TestEveryDeclaredFieldIsDiffed(t *testing.T) {
	covered := map[string]bool{}
	for _, m := range mutations {
		covered[m.desiredField] = true
	}
	typ := reflect.TypeOf(reconciler.Desired{})
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		if covered[name] {
			continue
		}
		if _, ok := exemptFromDiff[name]; ok {
			continue
		}
		t.Errorf("reconciler.Desired.%s is reported by no plan line.\n"+
			"Add a case to `mutations` naming the field a plan should show it under, "+
			"or an entry to `exemptFromDiff` saying why it is invisible on purpose.", name)
	}
}

// TestEveryMutationIsReported walks the table: each edit must produce exactly
// one service change, and it must name the field it changed.
func TestEveryMutationIsReported(t *testing.T) {
	for _, m := range mutations {
		t.Run(m.desiredField, func(t *testing.T) {
			c := changeFor(t, m.mutate)
			if c.Kind != reconciler.ChangeUpdate {
				t.Fatalf("kind = %q, want update", c.Kind)
			}
			field(t, c, m.changeField)
		})
	}
}

// TestRollsAgreesWithTheSpecHash is the other half of the drift guard, and the
// one that matters to whoever is about to type y. A field marked "(rolls
// allocs)" must be one that actually changes the hash, and a hash change must
// be marked: a plan that says a change is free while it replaces every
// container is worse than the silence it replaced.
func TestRollsAgreesWithTheSpecHash(t *testing.T) {
	for _, m := range mutations {
		t.Run(m.desiredField, func(t *testing.T) {
			have, want := base(), base()
			m.mutate(&want)
			hashMoved := reconciler.SpecHash(have) != reconciler.SpecHash(want)
			c := changeFor(t, m.mutate)
			if c.Rolls != hashMoved {
				t.Errorf("Rolls = %v but SpecHash moved = %v for a %s edit:\n%s",
					c.Rolls, hashMoved, m.desiredField,
					strings.Join(reconciler.RenderChanges([]reconciler.ServiceChange{c}), "\n"))
			}
		})
	}
}

// A budget is measured, never enforced (R31), and hashableVolumes strips it, so
// declaring one must be reported and must not claim to roll a database. This is
// the one field whose rendered detail is wider than its hash material, and the
// reason the volume roll flag is computed separately from the volume lines.
func TestAVolumeBudgetIsReportedWithoutRolling(t *testing.T) {
	c := changeFor(t, func(d *reconciler.Desired) { d.Volumes[0].SizeBytes = 10 << 30 })
	f := field(t, c, "volumes")
	if f.Rolls || c.Rolls {
		t.Errorf("a size budget claims to roll allocs: %v", f.Lines)
	}
	if !strings.Contains(strings.Join(f.Lines, "\n"), "budget") {
		t.Errorf("the budget is not on the volume line: %v", f.Lines)
	}
}

// hashableInit strips a step's timeout and pull policy, so raising a migration's
// timeout is visible and visibly free.
func TestAnInitTimeoutIsReportedWithoutRolling(t *testing.T) {
	c := changeFor(t, func(d *reconciler.Desired) { d.Init[0].Timeout = 10 * time.Minute })
	f := field(t, c, "init settings")
	if f.Rolls || c.Rolls {
		t.Errorf("an init timeout claims to roll allocs: %v", f.Lines)
	}
}

// hashableFiles clears a file block's Name, so renaming one rolls nothing and
// must therefore print nothing: a plan line with no consequence teaches people
// to stop reading plan lines.
func TestRenamingAFileBlockIsNotAChange(t *testing.T) {
	have, want := base(), base()
	want.Files[0].Name = "renamed"
	if got := reconciler.Changes([]reconciler.Desired{have}, []reconciler.Desired{want}, nil); len(got) != 0 {
		t.Errorf("renaming a file block produced %v", reconciler.RenderChanges(got))
	}
}

// An env value may be a `secret-env:` reference whose resolved form is a
// credential (constraint #4), and a plan is printed to a terminal and pasted
// into issues. Keys are the useful part; values are in the file being held.
func TestEnvLinesCarryKeysAndNeverValues(t *testing.T) {
	have, want := base(), base()
	have.Env = map[string]string{"KEEP": "same", "OLD": "gone", "ROTATED": "before-value"}
	want.Env = map[string]string{"KEEP": "same", "NEW": "arrived", "ROTATED": "after-value"}

	got := reconciler.Changes([]reconciler.Desired{have}, []reconciler.Desired{want}, nil)
	text := strings.Join(reconciler.RenderChanges(got), "\n")
	for _, secret := range []string{"before-value", "after-value", "arrived", "gone"} {
		if strings.Contains(text, secret) {
			t.Errorf("an env value reached the plan output (%q):\n%s", secret, text)
		}
	}
	for _, want := range []string{"+ NEW", "~ ROTATED", "- OLD"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan does not report %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "KEEP") {
		t.Errorf("an unchanged env key was reported:\n%s", text)
	}
}

// A file's content never reaches the output either: it carries R35 secret
// placeholders, and the record is the one place a resolved credential must not
// be. A short digest is what makes an edit visible without printing the bytes.
func TestFileLinesCarryNoContent(t *testing.T) {
	have, want := base(), base()
	have.Files[0].Content = []byte("password=hunter2")
	want.Files[0].Content = []byte("password=hunter3")

	got := reconciler.Changes([]reconciler.Desired{have}, []reconciler.Desired{want}, nil)
	text := strings.Join(reconciler.RenderChanges(got), "\n")
	if strings.Contains(text, "hunter") {
		t.Errorf("file content reached the plan output:\n%s", text)
	}
	if !strings.Contains(text, "/etc/app.conf") || !strings.Contains(text, "content ") {
		t.Errorf("a content edit is invisible:\n%s", text)
	}
}

// A create enumerates what arrives, so "+ create" is not a line that hides a
// volume, a route and three ports behind a count and an image.
func TestACreateEnumeratesItsResources(t *testing.T) {
	got := reconciler.Changes(nil, []reconciler.Desired{base()}, nil)
	if len(got) != 1 || got[0].Kind != reconciler.ChangeCreate {
		t.Fatalf("Changes = %v, want one create", got)
	}
	text := strings.Join(reconciler.RenderChanges(got), "\n")
	for _, want := range []string{
		"+ create shop/web", "volumes", "data", "files", "/etc/app.conf",
		"ports", "http", "expose", "shop.example.com", "publish", "8443/tcp",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("a create does not mention %q:\n%s", want, text)
		}
	}
	// A create replaces nothing, so nothing about it is marked as rolling: the
	// verb already says every container is new.
	if got[0].Rolls {
		t.Error("a create claims to replace running allocs")
	}
}

// A destroy says what goes, and says every time that the data does not: it is
// the reason a mistaken prune is survivable and the reason a deliberate one
// frees no disk.
func TestADestroySaysTheVolumeDataSurvives(t *testing.T) {
	got := reconciler.Changes([]reconciler.Desired{base()}, nil, []string{"shop"})
	text := strings.Join(reconciler.RenderChanges(got), "\n")
	if !strings.Contains(text, "- destroy shop/web") {
		t.Fatalf("no destroy line:\n%s", text)
	}
	if !strings.Contains(text, "NOT deleted") {
		t.Errorf("a destroy does not say the volume data survives:\n%s", text)
	}
}

// Middleware is a control the edge enforces, so adding one has to be visible;
// it is also not baked into a container, so it must not claim to roll.
func TestRouteMiddlewareIsReportedAndDoesNotRoll(t *testing.T) {
	c := changeFor(t, func(d *reconciler.Desired) {
		d.Expose.RateLimit = &edge.RateLimit{Requests: 10, Window: "1s", Burst: 20}
	})
	f := field(t, c, "expose")
	if f.Rolls || c.Rolls {
		t.Error("a rate limit claims to roll allocs")
	}
	if !strings.Contains(strings.Join(f.Lines, "\n"), "rate_limit") {
		t.Errorf("the rate limit is not on the route line: %v", f.Lines)
	}
}

// A storage resource has no Store kind of its own: it is inlined into the
// volumes that use it (§8), so a changed backend has to surface on the volume.
func TestAStorageChangeSurfacesOnTheVolume(t *testing.T) {
	c := changeFor(t, func(d *reconciler.Desired) {
		d.Volumes[0].Storage = "backups"
		d.Volumes[0].Resource = storage.Resource{Name: "backups", Type: "s3", Bucket: "b"}
	})
	f := field(t, c, "volumes")
	if !f.Rolls {
		t.Error("changing a volume's backing storage does not report as rolling")
	}
	if !strings.Contains(strings.Join(f.Lines, "\n"), "s3") {
		t.Errorf("the new storage type is not on the volume line: %v", f.Lines)
	}
}

// An unchanged spec is the common case and must stay silent: "no changes" is
// what makes a re-run of `kanea run` safe to type.
func TestAnUnchangedSpecProducesNothing(t *testing.T) {
	d := base()
	if got := reconciler.Changes([]reconciler.Desired{d}, []reconciler.Desired{d}, nil); len(got) != 0 {
		t.Errorf("an unchanged spec produced %v", reconciler.RenderChanges(got))
	}
}

// Changes are ordered by name, so one service's edits stay together. Before
// v1.90 the rendered lines were sorted as strings, which ordered them by the
// leading +/-/~ and scattered a multi-service spec's output.
func TestChangesAreOrderedByName(t *testing.T) {
	current := []reconciler.Desired{
		{Project: "shop", Service: "zeta", Image: "z:v1"},
		{Project: "data", Service: "alpha", Image: "a:v1"},
	}
	desired := []reconciler.Desired{
		{Project: "shop", Service: "zeta", Image: "z:v2"},
		{Project: "data", Service: "alpha", Image: "a:v2"},
		{Project: "data", Service: "beta", Image: "b:v1"},
	}
	var keys []string
	for _, c := range reconciler.Changes(current, desired, nil) {
		keys = append(keys, c.Key())
	}
	want := []string{"data/alpha", "data/beta", "shop/zeta"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("order = %v, want %v", keys, want)
	}
}
