package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKeys(t *testing.T, seed byte) Keys {
	t.Helper()
	master := bytes.Repeat([]byte{seed}, 32)
	keys, err := DeriveKeys(master)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	return keys
}

func TestStreamRoundTripsAtEveryChunkBoundary(t *testing.T) {
	keys := testKeys(t, 1)

	// The sizes that break a chunked format: nothing, one byte, exactly a
	// chunk, one either side of a chunk, and two whole chunks. An exact
	// multiple is the one that catches an implementation which guesses "short
	// read means final" without always writing a final chunk.
	for _, size := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 2 * chunkSize} {
		plain := make([]byte, size)
		if _, err := rand.Read(plain); err != nil {
			t.Fatalf("random plaintext: %v", err)
		}

		var sealed bytes.Buffer
		sum, written, err := encryptStream(&sealed, bytes.NewReader(plain), keys)
		if err != nil {
			t.Fatalf("size %d: encrypt: %v", size, err)
		}
		if written != int64(sealed.Len()) {
			t.Errorf("size %d: reported %d bytes, wrote %d", size, written, sealed.Len())
		}
		if sum == "" {
			t.Errorf("size %d: no ciphertext hash", size)
		}

		var back bytes.Buffer
		if err := decryptStream(&back, bytes.NewReader(sealed.Bytes()), keys); err != nil {
			t.Fatalf("size %d: decrypt: %v", size, err)
		}
		if !bytes.Equal(back.Bytes(), plain) {
			t.Errorf("size %d: round trip lost data (%d bytes back)", size, back.Len())
		}
	}
}

func TestTruncationIsDetected(t *testing.T) {
	// The attack this defends: someone with write access to the bucket cuts a
	// snapshot short. Without the final-chunk marker the archive decrypts
	// cleanly to a prefix of the state, and a restore silently brings back half
	// a platform.
	keys := testKeys(t, 2)
	plain := make([]byte, 3*chunkSize)
	if _, err := rand.Read(plain); err != nil {
		t.Fatalf("random plaintext: %v", err)
	}

	var sealed bytes.Buffer
	if _, _, err := encryptStream(&sealed, bytes.NewReader(plain), keys); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Cut at an exact chunk boundary, which is the cut that would otherwise
	// look like a complete shorter archive.
	cut := len(magic) + noncePrefixSize + 2*(chunkSize+overhead)
	err := decryptStream(io.Discard, bytes.NewReader(sealed.Bytes()[:cut]), keys)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a truncated archive decrypted: %v", err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	keys := testKeys(t, 3)
	var sealed bytes.Buffer
	if _, _, err := encryptStream(&sealed, strings.NewReader("state"), keys); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	body := sealed.Bytes()
	body[len(body)-1] ^= 0xff
	if err := decryptStream(io.Discard, bytes.NewReader(body), keys); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a modified archive decrypted: %v", err)
	}
}

func TestTheWrongKeyDoesNotDecrypt(t *testing.T) {
	var sealed bytes.Buffer
	if _, _, err := encryptStream(&sealed, strings.NewReader("state"), testKeys(t, 4)); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := decryptStream(io.Discard, bytes.NewReader(sealed.Bytes()), testKeys(t, 5)); err == nil {
		t.Fatal("an archive decrypted under the wrong key")
	}
}

func TestKeyIDsDifferAndLeakNothing(t *testing.T) {
	a, b := testKeys(t, 6), testKeys(t, 7)
	if a.ID == b.ID {
		t.Fatal("two different master keys produced the same key id")
	}
	if bytes.Contains([]byte(a.ID), a.stream) {
		t.Fatal("the key id contains the stream key")
	}
	// Stable across derivations: a manifest written last week has to match the
	// key today.
	if again := testKeys(t, 6); again.ID != a.ID {
		t.Errorf("key id is not deterministic: %s then %s", a.ID, again.ID)
	}
}

func TestNotAnArchiveIsRejectedBeforeDecryption(t *testing.T) {
	err := decryptStream(io.Discard, strings.NewReader("this is a JPEG, honestly"), testKeys(t, 8))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a non-archive was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "not a Kanea archive") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

// ---- sink ----

func TestFileSinkRefusesAnEscapingName(t *testing.T) {
	// Object names come out of manifests, and manifests come out of the bucket.
	// On restore that makes them attacker-influenced, and a write outside the
	// backup directory is a write anywhere the daemon can reach.
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	ctx := context.Background()

	for _, name := range []string{"../escaped", "a/../../escaped", ""} {
		if err := sink.Put(ctx, name, 1, strings.NewReader("x")); err == nil {
			t.Errorf("Put accepted %q", name)
		}
		if _, err := sink.Get(ctx, name); err == nil {
			t.Errorf("Get accepted %q", name)
		}
	}
}

func TestFileSinkPutIsAtomic(t *testing.T) {
	// A List that can see a half-written object is a List that can offer a
	// corrupt archive as a restore candidate.
	root := t.TempDir()
	sink, err := NewFileSink(root, nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	ctx := context.Background()

	if err := sink.Put(ctx, "snapshots/a.snap", 5, &blockingReader{data: "hello"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	objects, err := sink.List(ctx, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(objects) != 1 || objects[0].Name != "snapshots/a.snap" {
		t.Fatalf("objects = %+v, want exactly the one written", objects)
	}

	// And a leftover partial file from a crashed write is never listed.
	if err := os.WriteFile(filepath.Join(root, "snapshots", ".partial-xyz"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("write partial: %v", err)
	}
	objects, err = sink.List(ctx, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(objects) != 1 {
		t.Errorf("a partial file was listed as an object: %+v", objects)
	}
}

// blockingReader delivers its data one byte at a time, so a Put that published
// early would be observable.
type blockingReader struct {
	data string
	at   int
}

func (b *blockingReader) Read(p []byte) (int, error) {
	if b.at >= len(b.data) {
		return 0, io.EOF
	}
	p[0] = b.data[b.at]
	b.at++
	return 1, nil
}

func TestFileSinkDeleteIsIdempotent(t *testing.T) {
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	// Retention runs on a schedule and must not fail because it already ran.
	if err := sink.Delete(context.Background(), "snapshots/gone.snap"); err != nil {
		t.Errorf("deleting a missing object failed: %v", err)
	}
}

func TestFileSinkGetReportsNotFound(t *testing.T) {
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	if _, err := sink.Get(context.Background(), "snapshots/nope.snap"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// ---- archive ----

// fakeSnapshotter writes a fixed payload, standing in for a Store.
type fakeSnapshotter struct {
	payload []byte
	index   uint64
	err     error
}

func (f fakeSnapshotter) Snapshot(_ context.Context, path string) (uint64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.index, os.WriteFile(path, f.payload, 0o600)
}

func newArchiver(t *testing.T, sink Sink, keys Keys, snap Snapshotter) *Archiver {
	t.Helper()
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	a, err := New(Config{
		Sink: sink, Keys: keys, Snapshotter: snap, WorkDir: t.TempDir(),
		Node: "node-1", Version: "test",
		Now: func() time.Time { at = at.Add(time.Second); return at },
	})
	if err != nil {
		t.Fatalf("new archiver: %v", err)
	}
	return a
}

func TestArchiveRoundTrip(t *testing.T) {
	ctx := context.Background()
	keys := testKeys(t, 9)
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}

	state := bytes.Repeat([]byte("state"), 100000)
	a := newArchiver(t, sink, keys, fakeSnapshotter{payload: state, index: 42})

	m, err := a.Create(ctx, "test", map[string]int{"services": 3})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if m.Index != 42 || m.KeyID != keys.ID || m.Node != "node-1" {
		t.Errorf("manifest does not describe the archive: %+v", m)
	}

	if err := a.Verify(ctx, m); err != nil {
		t.Fatalf("verify: %v", err)
	}

	out := filepath.Join(t.TempDir(), "restored.db")
	if err := a.Fetch(ctx, m, out); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	back, err := os.ReadFile(out) // #nosec G304 — a test path
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(back, state) {
		t.Error("the restored database does not match the snapshot")
	}
}

func TestNoPlaintextSnapshotIsLeftBehind(t *testing.T) {
	// The staged copy is the whole database unencrypted, secrets included. It
	// must not survive the upload.
	ctx := context.Background()
	work := t.TempDir()
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	a, err := New(Config{
		Sink: sink, Keys: testKeys(t, 10), WorkDir: work,
		Snapshotter: fakeSnapshotter{payload: []byte("secret state"), index: 1},
	})
	if err != nil {
		t.Fatalf("new archiver: %v", err)
	}
	if _, err := a.Create(ctx, "test", nil); err != nil {
		t.Fatalf("create: %v", err)
	}

	left, err := os.ReadDir(work)
	if err != nil {
		t.Fatalf("read work dir: %v", err)
	}
	for _, entry := range left {
		t.Errorf("left behind in the work directory: %s", entry.Name())
	}
}

func TestRestoreRefusesAnArchiveFromAnotherKey(t *testing.T) {
	// The message an operator needs is "find the other key", not "these bytes
	// are damaged" — the remedies are completely different.
	ctx := context.Background()
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	written := newArchiver(t, sink, testKeys(t, 11), fakeSnapshotter{payload: []byte("state"), index: 1})
	m, err := written.Create(ctx, "test", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	other := newArchiver(t, sink, testKeys(t, 12), fakeSnapshotter{})
	err = other.Fetch(ctx, m, filepath.Join(t.TempDir(), "out.db"))
	if !errors.Is(err, ErrKey) {
		t.Fatalf("err = %v, want ErrKey", err)
	}
	if !strings.Contains(err.Error(), "DR_RUNBOOK") {
		t.Errorf("the error does not point at the recovery procedure: %v", err)
	}
}

func TestVerifyCatchesADamagedSnapshot(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	sink, err := NewFileSink(root, nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	a := newArchiver(t, sink, testKeys(t, 13), fakeSnapshotter{payload: []byte("state"), index: 1})
	m, err := a.Create(ctx, "test", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Corrupt the object in place, the way a bad disk or a bad actor would.
	path := filepath.Join(root, filepath.FromSlash(m.Snapshot.Name))
	body, err := os.ReadFile(path) // #nosec G304 — a test path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body[len(body)/2] ^= 0xff
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := a.Verify(ctx, m); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("verify = %v, want ErrCorrupt", err)
	}
	// Verification needs no key, which is the point: an operator can ask "is
	// this backup worth recovering the key for" before finding the key.
	keyless := newArchiver(t, sink, testKeys(t, 14), fakeSnapshotter{})
	if err := keyless.Verify(ctx, m); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("keyless verify = %v, want ErrCorrupt", err)
	}
}

func TestListIsNewestFirstAndSurvivesOneBadManifest(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	sink, err := NewFileSink(root, nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	a := newArchiver(t, sink, testKeys(t, 15), fakeSnapshotter{payload: []byte("state"), index: 1})

	var ids []string
	for range 3 {
		m, err := a.Create(ctx, "test", nil)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		ids = append(ids, m.ID)
	}

	all, err := a.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 || all[0].ID != ids[2] {
		t.Fatalf("list is not newest-first: %+v", all)
	}

	// A manifest that cannot be read must not hide the others: the archive
	// someone needs is very possibly one of the rest.
	if err := os.WriteFile(filepath.Join(root, prefixManifests+ids[1]+".json"),
		[]byte("{{{"), 0o600); err != nil {
		t.Fatalf("corrupt manifest: %v", err)
	}
	all, err = a.List(ctx)
	if err != nil {
		t.Fatalf("list after corruption: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("one bad manifest hid the others: %+v", all)
	}
}

func TestPruneKeepsTheNewest(t *testing.T) {
	ctx := context.Background()
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	a := newArchiver(t, sink, testKeys(t, 16), fakeSnapshotter{payload: []byte("state"), index: 1})

	for range 5 {
		if _, err := a.Create(ctx, "test", nil); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	removed, err := a.Prune(ctx, 2)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 3 {
		t.Errorf("removed %d, want 3", removed)
	}

	all, err := a.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("kept %d archives, want 2", len(all))
	}
	// Both are still restorable: pruning must not leave a manifest whose parts
	// are gone.
	for _, m := range all {
		if err := a.Verify(ctx, m); err != nil {
			t.Errorf("archive %s did not survive the prune: %v", m.ID, err)
		}
	}

	if _, err := a.Prune(ctx, 0); err == nil {
		t.Error("a retention of zero was accepted; it would delete everything")
	}
}

func TestLatestOnAnEmptyBucketSaysSo(t *testing.T) {
	sink, err := NewFileSink(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	a := newArchiver(t, sink, testKeys(t, 17), fakeSnapshotter{})
	if _, err := a.Latest(context.Background()); !errors.Is(err, ErrNoArchives) {
		t.Fatalf("err = %v, want ErrNoArchives", err)
	}
}

// ---- staged restore ----

func TestRestoreRequestRoundTrips(t *testing.T) {
	dir := t.TempDir()
	if req, err := ReadRequest(dir); err != nil || req != nil {
		t.Fatalf("a fresh directory reported a request: %+v, %v", req, err)
	}

	want := Request{ArchiveID: "20260808T120000Z", SkipReplay: true, RequestedBy: "ada"}
	if err := WriteRequest(dir, want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadRequest(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got == nil || got.ArchiveID != want.ArchiveID || !got.SkipReplay || got.RequestedBy != "ada" {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	if err := ClearRequest(dir); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if req, _ := ReadRequest(dir); req != nil {
		t.Error("the request survived being cleared; the next start would restore again")
	}
	// Clearing twice must work: it runs after a restore that may itself be a
	// retry.
	if err := ClearRequest(dir); err != nil {
		t.Errorf("clearing an absent request failed: %v", err)
	}
}

func TestAnUnparseableRestoreRequestIsRefusedNotIgnored(t *testing.T) {
	// A request file that does not parse is a request somebody made. Starting
	// normally would silently not restore a node whose operator believes it
	// did.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, RequestFileName), []byte("{{{"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := ReadRequest(dir)
	if err == nil {
		t.Fatal("a corrupt restore request was ignored")
	}
	if !strings.Contains(err.Error(), "delete it") {
		t.Errorf("the error does not say how to proceed: %v", err)
	}
}
