package reconciler_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/store"
)

// Env-secret injection (PRD §6.2 R3, v1.76): the reconciler resolves a
// `secret:` env value into a per-alloc tmpfs file and hands the container the
// path; `secret-env:` inlines the value. The record keeps the reference
// either way.

type fakeSecretStore map[string][]byte

func (f fakeSecretStore) Resolve(_ context.Context, ref string) ([]byte, error) {
	if v, ok := f[ref]; ok {
		return v, nil
	}
	return nil, errors.New("no such secret")
}

func withSecrets(dir string, values map[string][]byte) func(*reconciler.Config) {
	return func(cfg *reconciler.Config) {
		cfg.SecretsDir = dir
		cfg.Secrets = fakeSecretStore(values)
	}
}

func TestAEnvSecretArrivesAsATmpfsFile(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, withSecrets(dir, map[string][]byte{
		"secret:shop/database-url": []byte("postgres://db:5432/shop"),
	}))

	d := desired(1)
	d.Env = map[string]string{
		"DATABASE_URL": "secret:shop/database-url",
		"NODE_ENV":     "production",
	}
	// The chown to the effective user runs as root in production; in tests it
	// has to be a uid the process may chown to, i.e. its own.
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	d.User = &runtime.User{UID: uid, GID: gid}
	h.setDesired(t, d)
	h.reconcile(t)

	spec := h.driver.specs["shop-web-0"]
	// The env var carries the file's path, never the value.
	wantPath := filepath.Join(reconciler.DefaultSecretsDir, "shop-web-0", "shop", "database-url")
	if spec.Env["DATABASE_URL"] != wantPath {
		t.Errorf("DATABASE_URL = %q, want %q", spec.Env["DATABASE_URL"], wantPath)
	}
	if spec.Env["NODE_ENV"] != "production" {
		t.Errorf("NODE_ENV = %q; a plain value must pass through untouched", spec.Env["NODE_ENV"])
	}
	if strings.Contains(spec.Env["DATABASE_URL"], "postgres://") {
		t.Error("the value reached the container's environment")
	}

	// The file itself: resolved content, 0400, owned by the alloc's user.
	target := filepath.Join(dir, "shop-web-0", "shop", "database-url")
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read the secret file: %v", err)
	}
	if string(body) != "postgres://db:5432/shop" {
		t.Errorf("content = %q", body)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o400 {
		t.Errorf("mode = %04o, want 0400", fi.Mode().Perm())
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != uid || st.Gid != gid {
		t.Errorf("owner = %d:%d, want %d:%d", st.Uid, st.Gid, uid, gid)
	}

	// And it is presented read-only at the same path.
	var found bool
	for _, m := range spec.Mounts {
		if m.Destination == filepath.Join(reconciler.DefaultSecretsDir, "shop-web-0") {
			found = true
			if !m.ReadOnly {
				t.Error("the secrets mount is not read-only")
			}
		}
	}
	if !found {
		t.Error("no secrets mount on the spec")
	}

	// The record keeps the reference: nothing resolved enters the Store, so
	// nothing readable there carries a value.
	svc, _, err := store.GetValue[reconciler.Desired](context.Background(),
		h.store, store.KindService, "shop/web")
	if err != nil {
		t.Fatalf("get desired: %v", err)
	}
	if svc.Env["DATABASE_URL"] != "secret:shop/database-url" {
		t.Errorf("stored env = %q, want the reference", svc.Env["DATABASE_URL"])
	}
}

func TestTheInlineFormCarriesTheValue(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, withSecrets(dir, map[string][]byte{
		"secret:shop/api-key": []byte("hunter2"),
	}))

	d := desired(1)
	d.Env = map[string]string{"API_KEY": "secret-env:shop/api-key"}
	h.setDesired(t, d)
	h.reconcile(t)

	spec := h.driver.specs["shop-web-0"]
	if spec.Env["API_KEY"] != "hunter2" {
		t.Errorf("API_KEY = %q; the inline form must carry the value (the documented weaker option)", spec.Env["API_KEY"])
	}
	// And nothing is written for an inline ref: it is env-shaped by choice.
	if _, err := os.Stat(filepath.Join(dir, "shop-web-0", "shop", "api-key")); !os.IsNotExist(err) {
		t.Error("an inline reference produced a file")
	}
}

func TestAnUnresolvableEnvSecretFailsTheAlloc(t *testing.T) {
	h := newHarness(t, withSecrets(t.TempDir(), map[string][]byte{}))

	d := desired(1)
	d.Env = map[string]string{"DATABASE_URL": "secret:shop/missing"}
	h.setDesired(t, d)

	res, err := h.r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Failed != 1 {
		t.Fatalf("failed = %d, want 1", res.Failed)
	}
	rec := h.allocRecord(t, 0)
	if rec.LastExitReason != reconciler.ExitSecretsFailed {
		t.Errorf("reason = %q, want %q", rec.LastExitReason, reconciler.ExitSecretsFailed)
	}
	if _, created := h.driver.specs["shop-web-0"]; created {
		t.Error("the container was created despite the unresolvable secret")
	}
}

func TestSecretsDieWithTheAlloc(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, withSecrets(dir, map[string][]byte{
		"secret:shop/database-url": []byte("postgres://db:5432/shop"),
	}))

	d := desired(1)
	d.Env = map[string]string{"DATABASE_URL": "secret:shop/database-url"}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	d.User = &runtime.User{UID: uid, GID: gid}
	h.setDesired(t, d)
	h.reconcile(t)
	if _, err := os.Stat(filepath.Join(dir, "shop-web-0")); err != nil {
		t.Fatalf("no secrets directory after create: %v", err)
	}

	h.deleteDesired(t, "shop", "web")
	h.reconcile(t)
	if _, err := os.Stat(filepath.Join(dir, "shop-web-0")); !os.IsNotExist(err) {
		t.Error("the secrets directory outlived the alloc")
	}
}

func TestAServiceWithNoSecretEnvGetsNoInjection(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, withSecrets(dir, map[string][]byte{}))

	d := desired(1)
	d.Env = map[string]string{"NODE_ENV": "production"}
	h.setDesired(t, d)
	h.reconcile(t)

	spec := h.driver.specs["shop-web-0"]
	for _, m := range spec.Mounts {
		if strings.HasPrefix(m.Destination, reconciler.DefaultSecretsDir) {
			t.Error("a service with no references got a secrets mount")
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the secrets dir was used for nothing: %v, %d entries", err, len(entries))
	}
}
