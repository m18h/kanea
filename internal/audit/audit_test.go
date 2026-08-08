package audit_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/audit"
	"github.com/m18h/kanea/internal/store"
)

// clock is a controllable time source: entry ordering and retention are both
// time-shaped, and neither is testable against a real clock.
type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

func (c *clock) advance(d time.Duration) { c.at = c.at.Add(d) }

func newLog(t *testing.T) (*audit.Log, store.Store, *clock) {
	t.Helper()
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	c := &clock{at: time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)}
	log, err := audit.Open(context.Background(), audit.Config{Store: st, Now: c.now})
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	return log, st, c
}

func record(t *testing.T, log *audit.Log, e audit.Entry) audit.Entry {
	t.Helper()
	got, err := log.Record(context.Background(), e)
	if err != nil {
		t.Fatalf("record %s: %v", e.Action, err)
	}
	return got
}

func TestRecordStampsAndChains(t *testing.T) {
	ctx := context.Background()
	log, _, c := newLog(t)

	first := record(t, log, audit.Entry{Actor: "ada", Role: "admin", Action: "service.apply", Target: "shop/web"})
	if first.ID == "" || first.Hash == "" {
		t.Fatalf("entry not stamped: %+v", first)
	}
	if first.Prev != "" {
		t.Errorf("first entry has a predecessor: %q", first.Prev)
	}
	if !first.Time.Equal(c.at) {
		t.Errorf("time = %v, want the injected clock %v", first.Time, c.at)
	}
	if first.Result != audit.ResultOK {
		t.Errorf("result = %q, want the ok default", first.Result)
	}

	c.advance(time.Second)
	second := record(t, log, audit.Entry{Actor: "ada", Action: "service.delete", Target: "shop/web"})
	if second.Prev != first.Hash {
		t.Errorf("chain broken: prev = %q, want %q", second.Prev, first.Hash)
	}
	if second.ID <= first.ID {
		t.Errorf("ids are not time-ordered: %q then %q", first.ID, second.ID)
	}

	if broken, checked, err := log.Verify(ctx); err != nil || broken != nil {
		t.Fatalf("verify = %+v, %d, %v; want a clean chain", broken, checked, err)
	}
}

func TestRecordNeedsAnAction(t *testing.T) {
	log, _, _ := newLog(t)
	if _, err := log.Record(context.Background(), audit.Entry{Actor: "ada"}); err == nil {
		t.Fatal("an entry with no action was accepted")
	}
}

func TestEntriesInTheSameNanosecondGetDistinctKeys(t *testing.T) {
	log, _, _ := newLog(t)

	// The clock does not advance: two actions in the same nanosecond must not
	// collide, or the second silently overwrites the first.
	a := record(t, log, audit.Entry{Action: "auth.login", Actor: "ada"})
	b := record(t, log, audit.Entry{Action: "auth.login", Actor: "grace"})
	if a.ID == b.ID {
		t.Fatalf("duplicate id %q", a.ID)
	}
	if b.ID <= a.ID {
		t.Errorf("second id %q does not sort after %q", b.ID, a.ID)
	}
	if b.Prev != a.Hash {
		t.Errorf("chain order disagrees with key order")
	}
}

func TestBackwardsClockKeepsKeyOrder(t *testing.T) {
	log, _, c := newLog(t)

	first := record(t, log, audit.Entry{Action: "auth.login"})
	c.advance(-time.Hour) // NTP step, or a VM resumed from a snapshot
	second := record(t, log, audit.Entry{Action: "auth.logout"})

	if second.ID <= first.ID {
		t.Fatalf("a backwards clock reordered the log: %q then %q", first.ID, second.ID)
	}
	// The real timestamp is preserved rather than fudged: the discrepancy is
	// evidence, and hiding it would be the wrong kind of tidy.
	if !second.Time.Before(first.Time) {
		t.Errorf("recorded time was rewritten: %v is not before %v", second.Time, first.Time)
	}
}

func TestListIsNewestFirstAndPages(t *testing.T) {
	ctx := context.Background()
	log, _, c := newLog(t)

	for i := range 5 {
		c.advance(time.Minute)
		record(t, log, audit.Entry{Action: "service.apply", Target: fmt.Sprintf("shop/svc%d", i)})
	}

	page, err := log.List(ctx, audit.Filter{Limit: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(page.Entries))
	}
	if page.Entries[0].Target != "shop/svc4" || page.Entries[1].Target != "shop/svc3" {
		t.Fatalf("not newest-first: %q, %q", page.Entries[0].Target, page.Entries[1].Target)
	}
	if !page.More {
		t.Fatal("More = false with three entries left")
	}

	page, err = log.List(ctx, audit.Filter{Limit: 10, After: page.NextAfter})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(page.Entries) != 3 {
		t.Fatalf("second page = %d entries, want 3", len(page.Entries))
	}
	if page.Entries[0].Target != "shop/svc2" {
		t.Errorf("resumed at %q, want shop/svc2", page.Entries[0].Target)
	}
}

func TestListOldestFirst(t *testing.T) {
	ctx := context.Background()
	log, _, c := newLog(t)
	for i := range 3 {
		c.advance(time.Minute)
		record(t, log, audit.Entry{Action: "auth.login", Actor: fmt.Sprintf("u%d", i)})
	}

	page, err := log.List(ctx, audit.Filter{Oldest: true})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Entries) != 3 || page.Entries[0].Actor != "u0" {
		t.Fatalf("oldest-first listing = %+v", page.Entries)
	}
}

func TestListFilters(t *testing.T) {
	ctx := context.Background()
	log, _, c := newLog(t)

	record(t, log, audit.Entry{Action: "auth.login", Actor: "ada", Result: audit.ResultOK})
	c.advance(time.Minute)
	record(t, log, audit.Entry{Action: "auth.login", Actor: "mallory", Result: audit.ResultDenied})
	c.advance(time.Minute)
	record(t, log, audit.Entry{Action: "service.apply", Actor: "ada", Result: audit.ResultOK})

	tests := []struct {
		name   string
		filter audit.Filter
		want   int
	}{
		{"by actor", audit.Filter{Actor: "ada"}, 2},
		{"by result", audit.Filter{Result: audit.ResultDenied}, 1},
		{"action is a prefix", audit.Filter{Action: "auth."}, 2},
		{"exact action", audit.Filter{Action: "service.apply"}, 1},
		{"no match", audit.Filter{Actor: "nobody"}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			page, err := log.List(ctx, tc.filter)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(page.Entries) != tc.want {
				t.Fatalf("entries = %d, want %d: %+v", len(page.Entries), tc.want, page.Entries)
			}
		})
	}
}

func TestListTimeWindow(t *testing.T) {
	ctx := context.Background()
	log, _, c := newLog(t)

	var times []time.Time
	for range 4 {
		e := record(t, log, audit.Entry{Action: "service.apply"})
		times = append(times, e.Time)
		c.advance(time.Hour)
	}

	// Since is inclusive of an entry written exactly at the boundary.
	page, err := log.List(ctx, audit.Filter{Since: times[2]})
	if err != nil {
		t.Fatalf("list since: %v", err)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("since = %d entries, want 2", len(page.Entries))
	}

	page, err = log.List(ctx, audit.Filter{Until: times[1]})
	if err != nil {
		t.Fatalf("list until: %v", err)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("until = %d entries, want 2: %+v", len(page.Entries), page.Entries)
	}
	if page.Entries[0].Time != times[1] {
		t.Errorf("newest in window = %v, want the boundary entry %v", page.Entries[0].Time, times[1])
	}
}

func TestListSkipsPagesThatFailTheFilter(t *testing.T) {
	ctx := context.Background()
	log, _, c := newLog(t)

	// The one interesting entry is older than a full page of noise, so a
	// single-page scan would report "nothing found" while it sits one page in.
	record(t, log, audit.Entry{Action: "auth.login", Actor: "mallory", Result: audit.ResultDenied})
	for range 10 {
		c.advance(time.Second)
		record(t, log, audit.Entry{Action: "service.apply", Actor: "ada"})
	}

	page, err := log.List(ctx, audit.Filter{Result: audit.ResultDenied, Limit: 3})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Actor != "mallory" {
		t.Fatalf("entries = %+v, want the single denied login", page.Entries)
	}
}

func TestPruneDropsOnlyOldEntries(t *testing.T) {
	ctx := context.Background()
	log, _, c := newLog(t)

	for range 6 {
		record(t, log, audit.Entry{Action: "service.apply"})
		c.advance(time.Hour)
	}
	cut := c.at.Add(-3 * time.Hour)

	pruned, err := log.Prune(ctx, cut)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 3 {
		t.Fatalf("pruned = %d, want 3", pruned)
	}

	page, err := log.List(ctx, audit.Filter{Oldest: true})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Entries) != 3 {
		t.Fatalf("remaining = %d, want 3", len(page.Entries))
	}
	if page.Entries[0].Time.Before(cut) {
		t.Errorf("kept an entry older than the cut-off: %v", page.Entries[0].Time)
	}
	// A pruned prefix is a legitimate chain boundary, not a tampered log.
	if broken, _, err := log.Verify(ctx); err != nil || broken != nil {
		t.Fatalf("verify after prune = %+v, %v; want clean", broken, err)
	}
}

func TestPruneIsANoOpWhenNothingIsOldEnough(t *testing.T) {
	ctx := context.Background()
	log, _, c := newLog(t)
	record(t, log, audit.Entry{Action: "service.apply"})

	pruned, err := log.Prune(ctx, c.at.Add(-time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 0 {
		t.Fatalf("pruned = %d, want 0", pruned)
	}
}

func TestVerifyCatchesATamperedEntry(t *testing.T) {
	ctx := context.Background()
	log, st, c := newLog(t)

	record(t, log, audit.Entry{Action: "auth.login", Actor: "mallory", Result: audit.ResultDenied})
	c.advance(time.Minute)
	record(t, log, audit.Entry{Action: "service.apply", Actor: "ada"})

	// Rewrite history the way someone covering their tracks would: edit the
	// record in place and leave its hash alone.
	page, err := log.List(ctx, audit.Filter{Oldest: true, Limit: 1})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	tampered := page.Entries[0]
	tampered.Result = audit.ResultOK
	mut, err := store.PutMutation(store.KindAudit, tampered.ID, tampered)
	if err != nil {
		t.Fatalf("mutation: %v", err)
	}
	if _, err := st.Apply(ctx, mut); err != nil {
		t.Fatalf("apply: %v", err)
	}

	broken, _, err := log.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if broken == nil || broken.ID != tampered.ID {
		t.Fatalf("verify = %+v, want the tampered entry %s", broken, tampered.ID)
	}
}

func TestVerifyCatchesADeletedEntry(t *testing.T) {
	ctx := context.Background()
	log, st, c := newLog(t)

	for range 3 {
		record(t, log, audit.Entry{Action: "service.apply"})
		c.advance(time.Minute)
	}
	page, err := log.List(ctx, audit.Filter{Oldest: true})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// Removing the middle entry leaves the third pointing at a hash that is no
	// longer the one before it.
	if _, err := st.Apply(ctx, store.DeleteMutation(store.KindAudit, page.Entries[1].ID)); err != nil {
		t.Fatalf("delete: %v", err)
	}

	broken, _, err := log.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if broken == nil || broken.ID != page.Entries[2].ID {
		t.Fatalf("verify = %+v, want the entry after the gap", broken)
	}
}

func TestOpenResumesTheChainAcrossRestarts(t *testing.T) {
	ctx := context.Background()
	log, st, c := newLog(t)

	first := record(t, log, audit.Entry{Action: "auth.login"})
	c.advance(time.Minute)

	reopened, err := audit.Open(ctx, audit.Config{Store: st, Now: c.now})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	next := record(t, reopened, audit.Entry{Action: "auth.logout"})
	if next.Prev != first.Hash {
		t.Fatalf("restart broke the chain: prev = %q, want %q", next.Prev, first.Hash)
	}
	if broken, _, err := reopened.Verify(ctx); err != nil || broken != nil {
		t.Fatalf("verify = %+v, %v; want clean", broken, err)
	}
}

func TestOpenRequiresAStore(t *testing.T) {
	if _, err := audit.Open(context.Background(), audit.Config{}); err == nil {
		t.Fatal("a log with no store was accepted")
	}
}

func TestRecordRedactsCredentials(t *testing.T) {
	log, _, _ := newLog(t)

	got := record(t, log, audit.Entry{
		Action: "auth.login",
		Detail: "presented kanea_abc123.SuPeRsEcReTvALue on retry",
	})
	if strings.Contains(got.Detail, "SuPeRsEcReTvALue") {
		t.Fatalf("token secret survived redaction: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, "kanea_abc123") {
		t.Errorf("token id was redacted too; it is what revocation takes: %q", got.Detail)
	}
}

func TestRedact(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		gone   string
		intact string
	}{
		{
			name:   "token secret",
			in:     "Authorization used kanea_9f2b.tGV5c2VjcmV0X3ZhbHVl here",
			gone:   "tGV5c2VjcmV0X3ZhbHVl",
			intact: "kanea_9f2b",
		},
		{
			name: "query string password",
			in:   "POST /login?user=ada&password=hunter2",
			gone: "hunter2",
			// The parameter that is not a credential stays readable.
			intact: "user=ada",
		},
		{
			name:   "json field",
			in:     `{"user":"ada","token":"abcd1234"}`,
			gone:   "abcd1234",
			intact: "ada",
		},
		{
			name:   "authorization header",
			in:     "Authorization: Bearer abcd1234",
			gone:   "abcd1234",
			intact: "Authorization",
		},
		{
			name: "secret reference survives",
			// A `secret:` reference is a name, not a value — and it is the most
			// useful thing an audit entry can say about a secret.
			in:     "resolved secret:shop/db-password for shop/web",
			gone:   "",
			intact: "secret:shop/db-password",
		},
		{
			name:   "image digest survives",
			in:     "deployed nginx@sha256:9f2bd1e0c4",
			gone:   "",
			intact: "sha256:9f2bd1e0c4",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := audit.Redact(tc.in)
			if tc.gone != "" && strings.Contains(got, tc.gone) {
				t.Errorf("Redact(%q) = %q, still contains %q", tc.in, got, tc.gone)
			}
			if !strings.Contains(got, tc.intact) {
				t.Errorf("Redact(%q) = %q, lost %q", tc.in, got, tc.intact)
			}
		})
	}
}
