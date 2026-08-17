package gitops_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/m18h/kanea/internal/gitops"
)

// repo builds a real git repository on disk and returns its path.
//
// A real repository rather than a mocked transport: the interesting behaviour
// is what go-git does with a tree (which files it finds, what a shallow clone
// of a branch yields) and a fake would only assert this code against itself.
func repo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()

	r, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	commit(t, r, dir, files, "initial commit")
	return dir
}

// commit writes files and commits them, returning the sha.
func commit(t *testing.T, r *gogit.Repository, dir string, files map[string]string, message string) string {
	t.Helper()

	tree, err := r.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	for name, content := range files {
		writeRepoFile(t, dir, name, content)
		if _, err := tree.Add(name); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}
	hash, err := tree.Commit(message, &gogit.CommitOptions{
		Author: &object.Signature{
			Name: "Ada Lovelace", Email: "ada@example.com",
			When: time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return hash.String()
}

func newSyncer(t *testing.T, secrets gitops.Resolver) *gitops.Syncer {
	t.Helper()
	return gitops.NewSyncer(gitops.SyncerConfig{Secrets: secrets})
}

func TestFetchReadsTheKaneaDirectory(t *testing.T) {
	dir := repo(t, map[string]string{
		".kanea/web.hcl": `project "shop" {}`,
		".kanea/api.hcl": `project "shop" {}`,
		"README.md":      "not a spec",
	})

	got, err := newSyncer(t, nil).Fetch(context.Background(), gitops.Source{URL: dir})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got.Specs) != 2 {
		t.Fatalf("specs = %v, want the two .hcl files", got.SpecPaths())
	}
	// Sorted, so a multi-file project parses in a stable order and a diff
	// between syncs is about content rather than about map iteration.
	paths := got.SpecPaths()
	if paths[0] != ".kanea/api.hcl" || paths[1] != ".kanea/web.hcl" {
		t.Fatalf("paths = %v, want sorted", paths)
	}
	if got.Commit == "" || got.Author != "Ada Lovelace" || got.Message != "initial commit" {
		t.Errorf("checkout = %+v; the commit context an event needs is missing", got)
	}
}

func TestFetchFallsBackToRootKaneaFile(t *testing.T) {
	dir := repo(t, map[string]string{"kanea.hcl": `project "shop" {}`})

	got, err := newSyncer(t, nil).Fetch(context.Background(), gitops.Source{URL: dir})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, ok := got.Specs["kanea.hcl"]; !ok {
		t.Fatalf("specs = %v, want the root file", got.SpecPaths())
	}
}

func TestFetchPrefersTheDirectoryOverTheRootFile(t *testing.T) {
	dir := repo(t, map[string]string{
		".kanea/web.hcl": `project "shop" {}`,
		"kanea.hcl":      `project "old" {}`,
	})

	got, err := newSyncer(t, nil).Fetch(context.Background(), gitops.Source{URL: dir})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// The convention is ordered: a repository that grew a `.kanea/` should not
	// also keep applying the file it replaced.
	if _, ok := got.Specs["kanea.hcl"]; ok {
		t.Fatalf("both layouts were read: %v", got.SpecPaths())
	}
}

func TestFetchHonoursAnExplicitPath(t *testing.T) {
	dir := repo(t, map[string]string{
		"deploy/prod/web.hcl": `project "shop" {}`,
		".kanea/web.hcl":      `project "ignored" {}`,
	})

	got, err := newSyncer(t, nil).Fetch(context.Background(),
		gitops.Source{URL: dir, Path: "deploy/prod"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got.Specs) != 1 {
		t.Fatalf("specs = %v, want only the configured path", got.SpecPaths())
	}
	if _, ok := got.Specs["deploy/prod/web.hcl"]; !ok {
		t.Fatalf("specs = %v", got.SpecPaths())
	}
}

func TestFetchAcceptsAPathNamingOneFile(t *testing.T) {
	dir := repo(t, map[string]string{
		"deploy/prod.hcl": `project "shop" {}`,
		"deploy/dev.hcl":  `project "dev" {}`,
	})

	got, err := newSyncer(t, nil).Fetch(context.Background(),
		gitops.Source{URL: dir, Path: "deploy/prod.hcl"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Naming one environment's file must not sweep in its neighbour.
	if len(got.Specs) != 1 || got.SpecPaths()[0] != "deploy/prod.hcl" {
		t.Fatalf("specs = %v, want just the named file", got.SpecPaths())
	}
}

func TestFetchDoesNotRecurse(t *testing.T) {
	dir := repo(t, map[string]string{
		".kanea/web.hcl":          `project "shop" {}`,
		".kanea/examples/bad.hcl": `this is not valid hcl at all {{{`,
	})

	got, err := newSyncer(t, nil).Fetch(context.Background(), gitops.Source{URL: dir})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// A `.kanea/examples/` of broken specs would otherwise break every sync.
	if len(got.Specs) != 1 {
		t.Fatalf("specs = %v, want only the top-level file", got.SpecPaths())
	}
}

func TestFetchReportsARepositoryWithNoSpecs(t *testing.T) {
	dir := repo(t, map[string]string{"README.md": "nothing to deploy"})

	_, err := newSyncer(t, nil).Fetch(context.Background(), gitops.Source{URL: dir})
	if !errors.Is(err, gitops.ErrNoSpecs) {
		t.Fatalf("err = %v, want ErrNoSpecs", err)
	}
	// The message has to say where it looked, or the operator has to read the
	// source to find out.
	if !strings.Contains(err.Error(), ".kanea") {
		t.Errorf("err = %v; it does not say where it looked", err)
	}
}

func TestFetchReadsANamedBranch(t *testing.T) {
	dir := repo(t, map[string]string{".kanea/web.hcl": `project "main" {}`})

	r, err := gogit.PlainOpen(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	tree, err := r.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if err := tree.Checkout(&gogit.CheckoutOptions{
		Branch: "refs/heads/staging", Create: true,
	}); err != nil {
		t.Fatalf("branch: %v", err)
	}
	commit(t, r, dir, map[string]string{".kanea/web.hcl": `project "staging" {}`}, "staging change")

	got, err := newSyncer(t, nil).Fetch(context.Background(),
		gitops.Source{URL: dir, Branch: "staging"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.Ref != "staging" {
		t.Errorf("ref = %q, want staging", got.Ref)
	}
	if !strings.Contains(string(got.Specs[".kanea/web.hcl"]), "staging") {
		t.Errorf("read the wrong branch's content: %s", got.Specs[".kanea/web.hcl"])
	}
}

func TestFetchReportsAMissingBranch(t *testing.T) {
	dir := repo(t, map[string]string{".kanea/web.hcl": `project "shop" {}`})

	_, err := newSyncer(t, nil).Fetch(context.Background(),
		gitops.Source{URL: dir, Branch: "does-not-exist"})
	if err == nil {
		t.Fatal("a missing branch was accepted")
	}
	// Naming the branch is what turns "clone failed" into something fixable.
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("err = %v; it does not name the branch", err)
	}
}

func TestFetchNeedsAURL(t *testing.T) {
	if _, err := newSyncer(t, nil).Fetch(context.Background(), gitops.Source{}); err == nil {
		t.Fatal("a source with no url was accepted")
	}
}

// resolver is a stand-in for the secrets store.
type resolver struct {
	values map[string][]byte
	err    error
	// asked records what was resolved, so a test can assert the credential was
	// fetched per sync rather than cached.
	asked int
}

func (r *resolver) Resolve(_ context.Context, ref string) ([]byte, error) {
	r.asked++
	if r.err != nil {
		return nil, r.err
	}
	value, ok := r.values[ref]
	if !ok {
		return nil, errors.New("no such secret")
	}
	return value, nil
}

func TestFetchResolvesCredentialsPerSync(t *testing.T) {
	dir := repo(t, map[string]string{".kanea/web.hcl": `project "shop" {}`})
	secrets := &resolver{values: map[string][]byte{"secret:git/token": []byte("ghp_example")}}
	syncer := newSyncer(t, secrets)

	src := gitops.Source{URL: dir, AuthRef: "secret:git/token"}
	for range 3 {
		if _, err := syncer.Fetch(context.Background(), src); err != nil {
			t.Fatalf("Fetch: %v", err)
		}
	}
	// A rotated deploy key takes effect on the next poll, and a revoked one
	// stops working then too, which is only true if it is not cached.
	if secrets.asked != 3 {
		t.Fatalf("resolved the credential %d times across 3 syncs; it is being cached", secrets.asked)
	}
}

func TestFetchReportsAnUnresolvableCredential(t *testing.T) {
	dir := repo(t, map[string]string{".kanea/web.hcl": `project "shop" {}`})
	secrets := &resolver{err: errors.New("secrets: not found")}

	_, err := newSyncer(t, secrets).Fetch(context.Background(),
		gitops.Source{URL: dir, AuthRef: "secret:git/missing"})
	if err == nil {
		t.Fatal("a missing credential was ignored")
	}
	if !strings.Contains(err.Error(), "secret:git/missing") {
		t.Errorf("err = %v; it does not name the reference", err)
	}
}

func TestFetchWithoutASecretsStore(t *testing.T) {
	dir := repo(t, map[string]string{".kanea/web.hcl": `project "shop" {}`})

	// A source that references a secret on a daemon with no secrets store is a
	// configuration error worth naming, not a silent public-repo attempt.
	_, err := newSyncer(t, nil).Fetch(context.Background(),
		gitops.Source{URL: dir, AuthRef: "secret:git/token"})
	if err == nil {
		t.Fatal("an auth_ref was silently ignored")
	}
}

func TestFetchRejectsAnUnusableSSHKey(t *testing.T) {
	secrets := &resolver{values: map[string][]byte{"secret:git/key": []byte("not a private key")}}

	_, err := newSyncer(t, secrets).Fetch(context.Background(), gitops.Source{
		URL: "git@github.com:example/deploy.git", AuthRef: "secret:git/key",
	})
	if err == nil {
		t.Fatal("an unparseable SSH key was accepted")
	}
	// The distinction matters: "your key is malformed" and "the server refused
	// you" send an operator to different places.
	if !strings.Contains(err.Error(), "SSH private key") {
		t.Errorf("err = %v; it does not say the key itself is the problem", err)
	}
}

func TestFetchRejectsAnEmptyToken(t *testing.T) {
	dir := repo(t, map[string]string{".kanea/web.hcl": `project "shop" {}`})
	secrets := &resolver{values: map[string][]byte{"secret:git/token": []byte("  \n")}}

	_, err := newSyncer(t, secrets).Fetch(context.Background(),
		gitops.Source{URL: dir, AuthRef: "secret:git/token"})
	if err == nil {
		t.Fatal("an empty token was sent to the remote")
	}
}

// writeRepoFile writes a file inside a repository, creating its directory.
func writeRepoFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", name, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
