package reconciler_test

// Mounted files (PRD v1.85, §6.2 R35).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/secrets"
	"github.com/m18h/kanea/internal/store"
)

func withFile(f reconciler.FileMount) reconciler.Desired {
	d := desired(1)
	d.Files = []reconciler.FileMount{f}
	return d
}

// --- upgrade safety: the tests whose failure costs somebody a night ------

// TestAServiceWithoutFilesSerializesUnchanged pins the R23 rule. A record that
// declares no files must marshal exactly as it did before v1.85, or every
// SpecHash on every node changes and upgrading kanead replaces every container.
func TestAServiceWithoutFilesSerializesUnchanged(t *testing.T) {
	body, err := json.Marshal(desired(1))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), `"files"`) {
		t.Errorf("a service declaring no files serialized a files key;\n"+
			"it needs omitempty, or upgrading kanead re-hashes and rolls every alloc\n%s", body)
	}
}

// TestTwoParsesOfOneSpecHashIdentically is the nonce trap.
//
// The nonce is fresh on every parse and lives *inside* the content bytes, so
// hashing content verbatim would give an unchanged spec a different hash every
// time and roll every file-bearing service on every apply. hashableFiles has to
// canonicalise it away; clearing the Nonce field alone is not enough.
func TestTwoParsesOfOneSpecHashIdentically(t *testing.T) {
	build := func(nonce string) reconciler.Desired {
		return withFile(reconciler.FileMount{
			Name:       "pgpass",
			Path:       "/etc/app/pgpass",
			Content:    []byte("pw=" + secrets.PlaceholderText(nonce, 0)),
			SecretRefs: []string{"secret:shop/db"},
			Nonce:      nonce,
		})
	}
	first := reconciler.SpecHash(build("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	second := reconciler.SpecHash(build("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	if first != second {
		t.Errorf("two parses of one spec hashed differently:\n  %s\n  %s\n"+
			"every apply would roll every file-bearing service on the node", first, second)
	}
}

// TestChangingFileContentRollsTheAlloc is the other half: content is baked into
// the container at create and nothing re-renders it for a running one, so
// editing a config file rolling the service *is* the feature.
func TestChangingFileContentRollsTheAlloc(t *testing.T) {
	base := withFile(reconciler.FileMount{Name: "c", Path: "/etc/a", Content: []byte("x")})
	before := reconciler.SpecHash(base)

	for name, mutate := range map[string]func(*reconciler.FileMount){
		"content": func(f *reconciler.FileMount) { f.Content = []byte("y") },
		"path":    func(f *reconciler.FileMount) { f.Path = "/etc/b" },
		"mode":    func(f *reconciler.FileMount) { f.Mode = "0600" },
		"refs":    func(f *reconciler.FileMount) { f.SecretRefs = []string{"secret:shop/k"} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := withFile(base.Files[0])
			mutate(&changed.Files[0])
			if reconciler.SpecHash(changed) == before {
				t.Errorf("changing a file's %s did not roll the alloc", name)
			}
		})
	}
}

// TestRenamingAFileBlockIsFree: the container sees path, mode and content, and
// nothing else, so a block's name is not container state.
func TestRenamingAFileBlockIsFree(t *testing.T) {
	a := withFile(reconciler.FileMount{Name: "one", Path: "/etc/a", Content: []byte("x")})
	b := withFile(reconciler.FileMount{Name: "two", Path: "/etc/a", Content: []byte("x")})
	if reconciler.SpecHash(a) != reconciler.SpecHash(b) {
		t.Error("renaming a file block rolled the alloc; the container never sees the name")
	}
}

// TestReorderingFilesIsFree: a file block's declaration order carries no
// meaning, unlike an init step's, so reordering two must not roll.
func TestReorderingFilesIsFree(t *testing.T) {
	one := reconciler.FileMount{Name: "a", Path: "/etc/a", Content: []byte("1")}
	two := reconciler.FileMount{Name: "b", Path: "/etc/b", Content: []byte("2")}

	forward, backward := desired(1), desired(1)
	forward.Files = []reconciler.FileMount{one, two}
	backward.Files = []reconciler.FileMount{two, one}

	if reconciler.SpecHash(forward) != reconciler.SpecHash(backward) {
		t.Error("reordering two file blocks rolled the alloc")
	}
}

// TestHashingFilesDoesNotMutateThem: hashableFiles copies before it strips, or
// hashing would silently rewrite the record the reconciler is about to project.
func TestHashingFilesDoesNotMutateThem(t *testing.T) {
	nonce := "cccccccccccccccccccccccccccccccc"
	content := []byte("pw=" + secrets.PlaceholderText(nonce, 0))
	d := withFile(reconciler.FileMount{
		Name: "c", Path: "/etc/a", Content: content,
		SecretRefs: []string{"secret:shop/db"}, Nonce: nonce,
	})

	_ = reconciler.SpecHash(d)

	if d.Files[0].Nonce != nonce {
		t.Error("hashing cleared the record's nonce; the placeholders would be unsubstitutable")
	}
	if string(d.Files[0].Content) != string(content) {
		t.Errorf("hashing rewrote the record's content: %q", d.Files[0].Content)
	}
	if d.Files[0].Name != "c" {
		t.Error("hashing cleared the record's file name")
	}
}

// TestAFileWithNoSecretsIsNotSecretBearing decides which tree a file is
// materialised into and with what mode, so it is read from the record rather
// than derived from the bytes.
func TestAFileWithNoSecretsIsNotSecretBearing(t *testing.T) {
	plain := reconciler.FileMount{Name: "c", Path: "/etc/a", Content: []byte("x")}
	if plain.HasSecrets() {
		t.Error("a file with no references reported as secret-bearing")
	}
	bearing := reconciler.FileMount{Name: "c", SecretRefs: []string{"secret:shop/k"}}
	if !bearing.HasSecrets() {
		t.Error("a file with a reference reported as plain")
	}
}

// --- node-side materialisation ------------------------------------------

// filesHarness builds a reconciler whose file trees are directories this test
// owns, plus the secrets it can resolve.
func filesHarness(t *testing.T, store fakeSecrets) (*harness, string, string) {
	t.Helper()
	plain, tmpfs := t.TempDir(), t.TempDir()
	h := newHarness(t, func(cfg *reconciler.Config) {
		cfg.Secrets = store
		cfg.PlainFilesDir = plain
		cfg.FilesDir = tmpfs
	})
	return h, plain, tmpfs
}

// TestAPlainFileIsSharedAndWorldReadable: it holds nothing secret and is
// bind-mounted into a container that may run as any uid, which is exactly
// resolv.conf's argument for 0644.
func TestAPlainFileIsSharedAndWorldReadable(t *testing.T) {
	h, plain, _ := filesHarness(t, fakeSecrets{})
	d := desired(1)
	d.Files = []reconciler.FileMount{{Name: "conf", Path: "/etc/app.conf", Content: []byte("listen=8080")}}
	h.setDesired(t, d)
	h.reconcile(t)

	path := filepath.Join(plain, "shop", "web", "conf")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the file was not written: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 644", info.Mode().Perm())
	}
	body, err := os.ReadFile(path) // #nosec G304: a path this test created
	if err != nil || string(body) != "listen=8080" {
		t.Errorf("content = %q, %v", body, err)
	}
}

// TestASecretBearingFileIsSubstitutedAndOwnerOnly. This is where the value
// finally exists, and it must exist only here: 0400, on the files tree, and
// nowhere in the record.
func TestASecretBearingFileIsSubstitutedAndOwnerOnly(t *testing.T) {
	const value = "s3cr3t-value"
	h, plain, tmpfs := filesHarness(t, fakeSecrets{"secret:shop/pw": []byte(value)})

	nonce := "dddddddddddddddddddddddddddddddd"
	d := desired(1)
	// The file is chowned to its reader, and this test is not root: declaring
	// the running user makes that a chown-to-self, which is permitted. In
	// production the reader is the workload's uid and kanead is root.
	d.User = &runtime.User{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())} // #nosec G115: real ids
	d.Files = []reconciler.FileMount{{
		Name:       "pgpass",
		Path:       "/etc/app/pgpass",
		Content:    []byte("db:app:" + secrets.PlaceholderText(nonce, 0)),
		SecretRefs: []string{"secret:shop/pw"},
		Nonce:      nonce,
	}}
	h.setDesired(t, d)
	h.reconcile(t)

	path := filepath.Join(tmpfs, reconciler.AllocID("shop", "web", 0), "pgpass")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the file was not written to the files tree: %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Errorf("mode = %o, want 400", info.Mode().Perm())
	}
	body, err := os.ReadFile(path) // #nosec G304: a path this test created
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "db:app:"+value {
		t.Errorf("content = %q, want the substituted value", body)
	}

	// And it is not in the plain tree, which is world-readable and on disk.
	if entries, err := os.ReadDir(plain); err == nil && len(entries) > 0 {
		t.Errorf("a secret-bearing file reached the world-readable tree: %v", entries)
	}
}

// TestAnUnresolvableReferenceFailsTheAllocWithoutLeaking. The failure has to
// happen before any container exists (R3's rule), and the error is a place a
// credential could escape to a log, so it names the reference and never a value.
func TestAnUnresolvableReferenceFailsTheAllocWithoutLeaking(t *testing.T) {
	h, _, _ := filesHarness(t, fakeSecrets{}) // resolves nothing

	nonce := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	d := desired(1)
	d.User = &runtime.User{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())} // #nosec G115: real ids
	d.Files = []reconciler.FileMount{{
		Name:       "pgpass",
		Path:       "/etc/app/pgpass",
		Content:    []byte("x=" + secrets.PlaceholderText(nonce, 0)),
		SecretRefs: []string{"secret:shop/missing"},
		Nonce:      nonce,
	}}
	h.setDesired(t, d)

	res, err := h.r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Failed == 0 {
		t.Fatal("an unresolvable reference did not fail the alloc")
	}
	if _, exists := h.driver.allocs[reconciler.AllocID("shop", "web", 0)]; exists {
		t.Error("a container was created despite the reference not resolving")
	}

	rec, _, err := store.GetValue[reconciler.AllocRecord](context.Background(), h.store,
		store.KindAlloc, reconciler.AllocKey("shop", "web", 0))
	if err != nil {
		t.Fatalf("load record: %v", err)
	}
	if rec.LastExitReason != reconciler.ExitFilesFailed {
		t.Errorf("reason = %q, want %q", rec.LastExitReason, reconciler.ExitFilesFailed)
	}
	if !strings.Contains(rec.LastExitMessage, "pgpass") {
		t.Errorf("the message should name the file; got %q", rec.LastExitMessage)
	}
}

// TestARenderedFileIsCappedOnTheNode closes the gap plan-time caps leave open:
// a placeholder is tens of bytes and the secret it names may be 64 KiB, so a
// record that passed every plan check can still render to far more.
func TestARenderedFileIsCappedOnTheNode(t *testing.T) {
	huge := strings.Repeat("x", reconciler.MaxRenderedFileBytes+1)
	h, _, _ := filesHarness(t, fakeSecrets{"secret:shop/big": []byte(huge)})

	nonce := "ffffffffffffffffffffffffffffffff"
	d := desired(1)
	d.User = &runtime.User{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())} // #nosec G115: real ids
	d.Files = []reconciler.FileMount{{
		Name:       "big",
		Path:       "/etc/app/big",
		Content:    []byte(secrets.PlaceholderText(nonce, 0)),
		SecretRefs: []string{"secret:shop/big"},
		Nonce:      nonce,
	}}
	h.setDesired(t, d)

	res, err := h.r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Failed == 0 {
		t.Fatal("a file that rendered past the ceiling was written anyway; the plan-time " +
			"caps bound the record, not what substitution produces")
	}
}

// TestAFileBindIsReadOnlyAndHardened. A file block delivers configuration, so
// the mount says so rather than depending on the mode.
func TestAFileBindIsReadOnlyAndHardened(t *testing.T) {
	h, _, _ := filesHarness(t, fakeSecrets{})
	d := desired(1)
	d.Files = []reconciler.FileMount{{Name: "conf", Path: "/etc/app.conf", Content: []byte("x")}}
	h.setDesired(t, d)
	h.reconcile(t)

	spec, ok := h.driver.specs[reconciler.AllocID("shop", "web", 0)]
	if !ok {
		t.Fatal("no spec was created")
	}
	var found bool
	for _, m := range spec.Mounts {
		if m.Destination != "/etc/app.conf" {
			continue
		}
		found = true
		if !m.ReadOnly {
			t.Error("a file mount is writable")
		}
		for _, want := range []string{"nosuid", "noexec", "nodev"} {
			if !slices.Contains(m.Options, want) {
				t.Errorf("the mount is missing %s: %v", want, m.Options)
			}
		}
	}
	if !found {
		t.Fatalf("no mount for the file: %+v", spec.Mounts)
	}
}

// TestFilesMountAfterVolumes: a file at a path inside a volume must win, or
// "declare a file at a path" does not mean what it says.
func TestFilesMountAfterVolumes(t *testing.T) {
	h, _, _ := filesHarness(t, fakeSecrets{})
	d := desired(1)
	d.Volumes = []reconciler.Volume{{Name: "data", MountPath: "/data"}}
	d.Files = []reconciler.FileMount{{Name: "conf", Path: "/data/app.conf", Content: []byte("x")}}
	h.setDesired(t, d)
	h.reconcile(t)

	spec := h.driver.specs[reconciler.AllocID("shop", "web", 0)]
	volumeAt, fileAt := -1, -1
	for i, m := range spec.Mounts {
		switch m.Destination {
		case "/data":
			volumeAt = i
		case "/data/app.conf":
			fileAt = i
		}
	}
	if volumeAt < 0 || fileAt < 0 {
		t.Fatalf("expected both mounts: %+v", spec.Mounts)
	}
	if fileAt < volumeAt {
		t.Errorf("the file mounts before its volume (%d < %d); the volume would shadow it",
			fileAt, volumeAt)
	}
}
