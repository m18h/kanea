package secretsource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/m18h/kanea/internal/secrets"
)

// fakeTarget is an in-memory Target that counts writes — the point of half
// these tests is how many times PutManaged runs.
type fakeTarget struct {
	mu      sync.Mutex
	values  map[string][]byte
	sources map[string]string
	puts    int
	putErr  error
}

func newFakeTarget() *fakeTarget {
	return &fakeTarget{values: map[string][]byte{}, sources: map[string]string{}}
}

func (f *fakeTarget) Resolve(_ context.Context, ref string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.values[ref]
	if !ok {
		return nil, fmt.Errorf("%w: %s", secrets.ErrNotFound, ref)
	}
	return append([]byte(nil), v...), nil
}

func (f *fakeTarget) PutManaged(_ context.Context, path string, value []byte, source string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
	f.puts++
	f.values[path] = append([]byte(nil), value...)
	f.sources[path] = source
	return nil
}

func (f *fakeTarget) Describe(_ context.Context, ref string) (secrets.Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.values[ref]; !ok {
		return secrets.Info{}, fmt.Errorf("%w: %s", secrets.ErrNotFound, ref)
	}
	return secrets.Info{Path: ref, Source: f.sources[ref]}, nil
}

// putOperator simulates `kanea secret put`: value stored, source cleared.
func (f *fakeTarget) putOperator(path string, value []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[path] = append([]byte(nil), value...)
	f.sources[path] = ""
}

// fakeProvider serves a fixed Result.
type fakeProvider struct {
	kind Kind
	name string
	res  Result
}

func (p *fakeProvider) Kind() Kind                   { return p.kind }
func (p *fakeProvider) Name() string                 { return p.name }
func (p *fakeProvider) Fetch(context.Context) Result { return p.res }

// fixedSet is a ProviderSet over a literal slice.
type fixedSet []Provider

func (s fixedSet) Current() []Provider { return s }

func newTestSyncer(target Target, providers ...Provider) *Syncer {
	return NewSyncer(SyncerConfig{
		Providers: fixedSet(providers), Target: target,
		Logger: slog.New(slog.DiscardHandler),
	})
}

func value(to, ref, data string) Value { return Value{To: to, Ref: ref, Data: []byte(data)} }

// The load-bearing test: an unchanged value produces zero Store writes, so a
// five-minute poll cannot become CDC/S3 write amplification (§5.2.13,
// constraint #2's spirit).
func TestAnUnchangedValueIsNotRewritten(t *testing.T) {
	target := newFakeTarget()
	prov := &fakeProvider{kind: KindDoppler, name: "ci",
		res: Result{Values: []Value{value("shop/db", "backend/prd/DB", "hunter2")}}}
	s := newTestSyncer(target, prov)

	first := s.SyncOnce(context.Background())
	if target.puts != 1 || len(first.PerProvider[0].Changed) != 1 {
		t.Fatalf("first pass: puts = %d, changed = %v", target.puts, first.PerProvider[0].Changed)
	}

	for range 5 {
		res := s.SyncOnce(context.Background())
		if pass := res.PerProvider[0]; len(pass.Changed) != 0 || pass.Unchanged != 1 {
			t.Fatalf("steady state pass: %+v", pass)
		}
	}
	if target.puts != 1 {
		t.Errorf("steady state produced %d writes, want the initial 1", target.puts)
	}
}

func TestAChangedValueIsWrittenWithItsSource(t *testing.T) {
	target := newFakeTarget()
	prov := &fakeProvider{kind: KindVault, name: "infra",
		res: Result{Values: []Value{value("media/s3", "kv/apps#s3", "old")}}}
	s := newTestSyncer(target, prov)
	s.SyncOnce(context.Background())

	prov.res = Result{Values: []Value{value("media/s3", "kv/apps#s3", "rotated")}}
	res := s.SyncOnce(context.Background())
	if got := res.PerProvider[0].Changed; len(got) != 1 || got[0] != "media/s3" {
		t.Errorf("Changed = %v", got)
	}
	if got := string(target.values["media/s3"]); got != "rotated" {
		t.Errorf("value = %q", got)
	}
	if got := target.sources["media/s3"]; got != "vault/infra" {
		t.Errorf("source = %q", got)
	}
}

// A provider that cannot serve a mapping leaves the local value alone — never
// deletes, never blanks. Removal is `kanea secret rm`'s job alone (§5.2.13).
func TestAProviderFailureLeavesTheLocalValueAlone(t *testing.T) {
	target := newFakeTarget()
	prov := &fakeProvider{kind: KindDoppler, name: "ci",
		res: Result{Values: []Value{value("shop/db", "ref", "v1")}}}
	s := newTestSyncer(target, prov)
	s.SyncOnce(context.Background())

	prov.res = Result{Failures: []Failure{{To: "shop/db", Ref: "ref", Err: errors.New("401")}}}
	res := s.SyncOnce(context.Background())
	if !res.Failed() {
		t.Fatal("the pass did not report the failure")
	}
	if got := string(target.values["shop/db"]); got != "v1" {
		t.Errorf("the local value moved to %q on a provider failure", got)
	}
}

// One provider failing entirely must not stop another from syncing — the
// certificate sources' isolation rule.
func TestOneProviderFailingDoesNotStopAnother(t *testing.T) {
	target := newFakeTarget()
	broken := &fakeProvider{kind: KindVault, name: "down",
		res: Result{Failures: []Failure{{To: "media/a", Ref: "r", Err: errors.New("dial tcp: refused")}}}}
	healthy := &fakeProvider{kind: KindDoppler, name: "ci",
		res: Result{Values: []Value{value("shop/db", "ref", "v")}}}
	s := newTestSyncer(target, broken, healthy)

	res := s.SyncOnce(context.Background())
	if len(res.PerProvider) != 2 {
		t.Fatalf("PerProvider = %+v", res.PerProvider)
	}
	if string(target.values["shop/db"]) != "v" {
		t.Error("the healthy provider did not sync past the broken one")
	}
}

// The mapping is declarative intent: a manual `kanea secret put` over a
// managed path holds until the next pass, which reasserts and says so once.
func TestAManualOverwriteIsReasserted(t *testing.T) {
	target := newFakeTarget()
	prov := &fakeProvider{kind: KindDoppler, name: "ci",
		res: Result{Values: []Value{value("shop/db", "ref", "provider-value")}}}

	var logs strings.Builder
	s := NewSyncer(SyncerConfig{
		Providers: fixedSet{prov}, Target: target,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	s.SyncOnce(context.Background())

	target.putOperator("shop/db", []byte("typed-by-hand"))
	s.SyncOnce(context.Background())
	if got := string(target.values["shop/db"]); got != "provider-value" {
		t.Errorf("value = %q, want the mapping reasserted", got)
	}
	if got := target.sources["shop/db"]; got != "doppler/ci" {
		t.Errorf("source = %q after reassertion", got)
	}
	first := strings.Count(logs.String(), "reasserted by its sync mapping")
	if first != 1 {
		t.Fatalf("reassertion warned %d times, want 1", first)
	}

	// The same contested path warns once, not once per pass.
	target.putOperator("shop/db", []byte("typed-again"))
	s.SyncOnce(context.Background())
	if got := strings.Count(logs.String(), "reasserted by its sync mapping"); got != 1 {
		t.Errorf("reassertion warned %d times across passes, want 1", got)
	}
}

// An ordinary rotation — provider value moves while the local record is still
// provider-stamped — is not a contested write and must not warn.
func TestARotationDoesNotWarn(t *testing.T) {
	target := newFakeTarget()
	prov := &fakeProvider{kind: KindDoppler, name: "ci",
		res: Result{Values: []Value{value("shop/db", "ref", "v1")}}}

	var logs strings.Builder
	s := NewSyncer(SyncerConfig{
		Providers: fixedSet{prov}, Target: target,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	s.SyncOnce(context.Background())
	prov.res = Result{Values: []Value{value("shop/db", "ref", "v2")}}
	s.SyncOnce(context.Background())

	if strings.Contains(logs.String(), "reasserted") {
		t.Errorf("a rotation warned as a contested write:\n%s", logs.String())
	}
}

func TestStatusIsMetadataOnly(t *testing.T) {
	target := newFakeTarget()
	ok := &fakeProvider{kind: KindDoppler, name: "ci",
		res: Result{Values: []Value{value("shop/db", "backend/prd/DB", "super-secret-value")}}}
	failing := &fakeProvider{kind: KindVault, name: "infra",
		res: Result{Failures: []Failure{{To: "media/a", Ref: "kv/a#f", Err: errors.New("permission denied")}}}}
	s := newTestSyncer(target, ok, failing)
	s.SyncOnce(context.Background())

	status := s.Status()
	if len(status) != 2 {
		t.Fatalf("Status = %+v", status)
	}
	if status[0].LastSuccess.IsZero() {
		t.Error("the healthy provider has no LastSuccess")
	}
	if !status[1].LastSuccess.IsZero() {
		t.Error("the failing provider claims a success")
	}
	if e := status[1].Entries[0]; e.Error == "" || e.To != "media/a" {
		t.Errorf("failing entry = %+v", e)
	}
	// Nothing in the status may carry the value. Serialise-and-scan is the
	// structural check: there is no field for it, and this pins that nobody
	// adds one.
	if strings.Contains(fmt.Sprintf("%+v", status), "super-secret-value") {
		t.Fatal("a secret value reached the status surface")
	}
}

// A failing mapping keeps its previous LastSynced: the status answers "when
// did this last work".
func TestStatusKeepsLastSyncedThroughAFailure(t *testing.T) {
	target := newFakeTarget()
	prov := &fakeProvider{kind: KindDoppler, name: "ci",
		res: Result{Values: []Value{value("shop/db", "ref", "v")}}}
	s := newTestSyncer(target, prov)
	s.SyncOnce(context.Background())

	synced := s.Status()[0].Entries[0].LastSynced
	if synced.IsZero() {
		t.Fatal("no LastSynced after a clean pass")
	}

	prov.res = Result{Failures: []Failure{{To: "shop/db", Ref: "ref", Err: errors.New("500")}}}
	s.SyncOnce(context.Background())
	e := s.Status()[0].Entries[0]
	if e.Error == "" {
		t.Error("the failure did not surface")
	}
	if !e.LastSynced.Equal(synced) {
		t.Errorf("LastSynced moved through a failure: %v -> %v", synced, e.LastSynced)
	}
}

// An undecryptable local record — a dead master key — is repaired by the
// provider's fresh value rather than wedging the mapping forever.
func TestAnUndecryptableRecordIsReplaced(t *testing.T) {
	target := newFakeTarget()
	prov := &fakeProvider{kind: KindDoppler, name: "ci",
		res: Result{Values: []Value{value("shop/db", "ref", "fresh")}}}
	s := newTestSyncer(&undecryptableTarget{fakeTarget: target}, prov)

	res := s.SyncOnce(context.Background())
	if res.Failed() {
		t.Fatalf("pass failed: %+v", res.PerProvider)
	}
	if got := string(target.values["shop/db"]); got != "fresh" {
		t.Errorf("value = %q", got)
	}
}

type undecryptableTarget struct{ *fakeTarget }

func (u *undecryptableTarget) Resolve(_ context.Context, ref string) ([]byte, error) {
	if _, ok := u.values[ref]; !ok {
		return nil, fmt.Errorf("%w: %s", secrets.ErrUndecryptable, ref)
	}
	return u.fakeTarget.Resolve(context.Background(), ref)
}

// The comparison is exact bytes; a value differing by a trailing newline is a
// change, because what the store serves is what an alloc reads.
func TestComparisonIsExact(t *testing.T) {
	target := newFakeTarget()
	target.values["shop/db"] = []byte("value\n")
	target.sources["shop/db"] = "doppler/ci"
	prov := &fakeProvider{kind: KindDoppler, name: "ci",
		res: Result{Values: []Value{value("shop/db", "ref", "value")}}}
	s := newTestSyncer(target, prov)

	s.SyncOnce(context.Background())
	if !bytes.Equal(target.values["shop/db"], []byte("value")) {
		t.Error("a byte-level difference was not written")
	}
}
