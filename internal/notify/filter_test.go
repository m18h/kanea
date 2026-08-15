package notify_test

import (
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/notify"
)

func event(name string) notify.Event {
	return notify.NewEvent(name, "shop", "web", "something happened", time.Now())
}

func TestFilterMatchesGlobs(t *testing.T) {
	f, err := notify.NewFilter([]string{"deploy.*", "scale.up"}, notify.SeverityInfo)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}

	for _, tc := range []struct {
		name  string
		match bool
	}{
		{notify.EventDeployStarted, true},
		{notify.EventDeployFailed, true},
		{notify.EventScaleUp, true},
		{notify.EventScaleDown, false},
		{notify.EventBuildFailed, false},
	} {
		if got := f.Match(event(tc.name)); got != tc.match {
			t.Errorf("Match(%s) = %v, want %v", tc.name, got, tc.match)
		}
	}
}

func TestEmptyFilterMatchesNothing(t *testing.T) {
	// A channel with no `on` has not been told what to send. Guessing "all of
	// it" turns a half-finished config into a pager at 3am, which is how people
	// learn to ignore the channel.
	f, err := notify.NewFilter(nil, notify.SeverityInfo)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if !f.Empty() {
		t.Fatal("a filter with no patterns should report empty")
	}
	if f.Match(event(notify.EventDeployFailed)) {
		t.Fatal("an empty filter matched")
	}
}

func TestSeverityFloorAndPatternsCompose(t *testing.T) {
	// `on = ["*"]` with a warning floor is "everything that matters", which is
	// the configuration most operators actually want.
	f, err := notify.NewFilter([]string{"*"}, notify.SeverityWarning)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if f.Match(event(notify.EventDeploySucceeded)) {
		t.Error("an info event passed a warning floor")
	}
	if !f.Match(event(notify.EventServiceUnhealthy)) {
		t.Error("a warning was dropped by a warning floor")
	}
	if !f.Match(event(notify.EventDeployFailed)) {
		t.Error("an error was dropped by a warning floor")
	}
}

func TestFilterRejectsAPatternThatMatchesNothing(t *testing.T) {
	// The whole reason this is validated at configuration time: a typo produces
	// a channel that is silent, and a silent notification channel looks exactly
	// like a system with nothing to report.
	for _, bad := range []string{
		"deply.*",       // typo
		"deploy.finish", // not an event that exists
		"*.failed",      // leading glob, not supported
		"deploy.*.x",    // star in the middle
		"**",            // two stars
	} {
		if _, err := notify.NewFilter([]string{bad}, notify.SeverityInfo); err == nil {
			t.Errorf("pattern %q was accepted", bad)
		}
	}

	// And the error says what is allowed, rather than only that this is not.
	_, err := notify.NewFilter([]string{"deply.*"}, notify.SeverityInfo)
	if err == nil || !strings.Contains(err.Error(), notify.EventDeployStarted) {
		t.Fatalf("err = %v; it should list the known events", err)
	}
}

func TestSeverityOfIsExplicitNotGuessed(t *testing.T) {
	// `deploy.failed` and `service.healthy` both end in a past participle and
	// mean opposite things. A rule derived from the name would be wrong exactly
	// where it matters.
	if notify.SeverityOf(notify.EventDeployFailed) != notify.SeverityError {
		t.Error("deploy.failed is not an error")
	}
	if notify.SeverityOf(notify.EventServiceHealthy) != notify.SeverityInfo {
		t.Error("service.healthy is not info")
	}
	// An unknown name is a warning, not info: it means an emitter is sending
	// something the table does not know, and filing that at the lowest severity
	// is how it goes unnoticed.
	if notify.SeverityOf("something.new") != notify.SeverityWarning {
		t.Error("an unknown event should be a warning")
	}
}

func TestEveryKnownEventHasASeverity(t *testing.T) {
	// KnownEvents is derived from the severity table, so this checks the other
	// direction: that the §11 list and the table have not drifted apart.
	for _, name := range []string{
		notify.EventDeployStarted, notify.EventDeploySucceeded, notify.EventDeployFailed,
		notify.EventServiceUnhealthy, notify.EventServiceHealthy, notify.EventServiceCrashed,
		notify.EventScaleUp, notify.EventScaleDown,
		notify.EventCertIssued, notify.EventCertRenewed, notify.EventCertFailed,
		notify.EventBuildStarted, notify.EventBuildSucceeded, notify.EventBuildFailed,
		notify.EventBackupSucceeded, notify.EventBackupFailed,
		notify.EventAuthLoginFailed,
		notify.EventFunctionInvokeFailed,
		notify.EventSecretSynced, notify.EventSecretSyncFailed,
		notify.EventTest,
	} {
		if !contains(notify.KnownEvents(), name) {
			t.Errorf("%s is not in KnownEvents", name)
		}
	}
	// Twenty-six from §11 (v1.39 added function.invoke_failed — and
	// deliberately no function.invoked, which would be a metric at event
	// cardinality; v1.44 added secret.synced/sync_failed; v1.69 added the four
	// volume.* names), plus notify.test — the test action's payload, which is
	// in the vocabulary so it renders like any other event, and which the test
	// action deliberately does not route through the filters.
	if got, want := len(notify.KnownEvents()), 27; got != want {
		t.Errorf("KnownEvents has %d entries, want %d — §11 lists 26 plus notify.test", got, want)
	}
}

func TestEventIDsAreTimeOrderedAndUnique(t *testing.T) {
	// The Store orders by key bytes, so an id that does not sort by time makes
	// "the last 50 events" a full scan. And a burst — a fleet restart emits
	// one per alloc — must not collide within a nanosecond.
	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	first := notify.NewEvent(notify.EventServiceCrashed, "shop", "web", "one", at)
	same := notify.NewEvent(notify.EventServiceCrashed, "shop", "api", "two", at)
	later := notify.NewEvent(notify.EventServiceCrashed, "shop", "web", "three", at.Add(time.Second))

	if first.ID == same.ID {
		t.Fatal("two events in the same nanosecond share an id")
	}
	if first.ID >= later.ID {
		t.Fatalf("ids do not sort by time: %q then %q", first.ID, later.ID)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
