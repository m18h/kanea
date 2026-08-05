package gitops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-git/go-git/v5/storage/memory"
)

// Git-backed projects (PRD §10.1).
//
// **Why go-git rather than shelling out to `git`.** Both are defensible and
// most GitOps tools pick one or the other. The deciding property here is that
// a deploy key never touches the filesystem and never enters a child process's
// environment: `git` would need either an askpass script, a key file for
// `GIT_SSH_COMMAND -i`, or a token in the environment — and /proc/<pid>/environ
// is readable by the same user. Every other credential in Kanea is either
// in-memory or materialised to 0600 only because a separate process forced it
// (§6.2 R3, the mount helpers). A clone does not force it, so it does not
// happen. The second reason is smaller: no host `git` to install and version.
//
// The cost is a dependency tail, which §14 A06 makes a release-gate concern.
// It is accepted here and recorded in §23.2 rather than absorbed silently.

// Source is a project's git source, as the job spec declares it (§6.1).
type Source struct {
	// URL is an HTTPS or SSH remote.
	URL string
	// Branch defaults to the remote's HEAD when empty.
	Branch string
	// Path is where job specs live in the repo. Empty means the convention:
	// `.kanea/` first, then `kanea.hcl` at the root.
	Path string
	// AuthRef is a `secret:` reference to a deploy key or token. Empty means a
	// public repository, which is a legitimate thing to deploy from.
	AuthRef string
}

// DefaultSpecDir and DefaultSpecFile are the layout convention §10.1 sets.
const (
	DefaultSpecDir  = ".kanea"
	DefaultSpecFile = "kanea.hcl"
)

// Checkout is what one sync produced.
type Checkout struct {
	// Commit is the revision the specs came from, full sha.
	Commit string
	// Ref is the branch it was read from.
	Ref string
	// Specs are the job spec files found, keyed by their path in the repo.
	// Sorted by path when iterated, so a multi-file project parses in a stable
	// order and a diff between syncs is about content.
	Specs map[string][]byte
	// Message is the commit subject, for the event an apply emits.
	Message string
	// Author is who made the commit, for the same reason.
	Author string
	// At is the commit timestamp.
	At time.Time
}

// SpecPaths returns the spec file paths in sorted order.
func (c Checkout) SpecPaths() []string {
	out := make([]string, 0, len(c.Specs))
	for path := range c.Specs {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// Resolver reads a `secret:` reference. The syncer never sees a raw credential
// in its configuration; it asks for one when it needs it.
type Resolver interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

// SyncerConfig configures the git syncer.
type SyncerConfig struct {
	// Secrets resolves AuthRef. Nil means only public repositories work.
	Secrets Resolver
	// Timeout bounds one clone. A repository that is not answering must not
	// hold the sync loop open indefinitely.
	Timeout time.Duration
	Logger  *slog.Logger
}

// Syncer fetches job specs from a git remote.
type Syncer struct {
	secrets Resolver
	timeout time.Duration
	log     *slog.Logger
}

// DefaultSyncTimeout bounds one clone.
const DefaultSyncTimeout = 2 * time.Minute

// NewSyncer builds the syncer.
func NewSyncer(cfg SyncerConfig) *Syncer {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultSyncTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Syncer{secrets: cfg.Secrets, timeout: cfg.Timeout, log: cfg.Logger}
}

// Errors a sync distinguishes.
var (
	// ErrNoSpecs means the repository was reachable but carries no job specs
	// where the convention says to look. It is a configuration mistake, not a
	// transport failure, and the two need different messages.
	ErrNoSpecs = errors.New("gitops: no job specs found in the repository")
	// ErrAuthRequired means the remote refused the credentials — or the lack
	// of them.
	ErrAuthRequired = errors.New("gitops: the repository requires credentials")
)

// Fetch clones the source into memory and returns what it found.
//
// Into memory, not onto disk: a deploy repository is job specs, measured in
// kilobytes, and a checkout directory is a thing to clean up, to protect, and
// to leave behind when the process dies mid-sync. The build context is the one
// case that genuinely needs a working tree, and it materialises its own.
func (s *Syncer) Fetch(ctx context.Context, src Source) (Checkout, error) {
	if src.URL == "" {
		return Checkout{}, errors.New("gitops: a git source needs a url")
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	auth, err := s.auth(ctx, src)
	if err != nil {
		return Checkout{}, err
	}

	opts := &gogit.CloneOptions{
		URL: src.URL,
		// Depth 1: the history is not wanted, only the tip. A deploy repo with
		// years of commits would otherwise be fetched in full every time a new
		// node joins.
		Depth: 1,
		// One branch, single-branch: fetching every branch to read one is work
		// and bandwidth spent on refs nobody asked about.
		SingleBranch: true,
		Auth:         auth,
		Tags:         gogit.NoTags,
	}
	if src.Branch != "" {
		opts.ReferenceName = plumbing.NewBranchReferenceName(src.Branch)
	}

	repo, err := gogit.CloneContext(ctx, memory.NewStorage(), memfs.New(), opts)
	if err != nil {
		return Checkout{}, cloneError(src, err)
	}

	head, err := repo.Head()
	if err != nil {
		return Checkout{}, fmt.Errorf("gitops: read HEAD of %s: %w", src.URL, err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return Checkout{}, fmt.Errorf("gitops: read commit %s: %w", head.Hash(), err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return Checkout{}, fmt.Errorf("gitops: read tree of %s: %w", head.Hash(), err)
	}

	specs, err := collectSpecs(tree, src.Path)
	if err != nil {
		return Checkout{}, err
	}
	if len(specs) == 0 {
		return Checkout{}, fmt.Errorf("%w: looked in %s", ErrNoSpecs, describeSpecLocation(src.Path))
	}

	return Checkout{
		Commit:  head.Hash().String(),
		Ref:     head.Name().Short(),
		Specs:   specs,
		Message: strings.SplitN(strings.TrimSpace(commit.Message), "\n", 2)[0],
		Author:  commit.Author.Name,
		At:      commit.Author.When,
	}, nil
}

// auth resolves the source's credentials, or nil for a public repository.
//
// The credential is fetched per sync rather than cached: a rotated deploy key
// takes effect on the next poll, and a revoked one stops working then too.
// Sixty seconds of a stale credential is the worst case, and the alternative is
// a copy of it living in this struct for the life of the process.
func (s *Syncer) auth(ctx context.Context, src Source) (transport.AuthMethod, error) {
	if src.AuthRef == "" {
		return nil, nil
	}
	if s.secrets == nil {
		return nil, fmt.Errorf("gitops: %s references %s but no secrets store is configured",
			src.URL, src.AuthRef)
	}

	value, err := s.secrets.Resolve(ctx, src.AuthRef)
	if err != nil {
		return nil, fmt.Errorf("gitops: resolve %s: %w", src.AuthRef, err)
	}

	if isSSHURL(src.URL) {
		// An SSH remote wants a private key. go-git parses it in memory, so
		// the key never lands on disk — the property that chose this library.
		user := sshUser(src.URL)
		keys, err := gitssh.NewPublicKeys(user, value, "")
		if err != nil {
			return nil, fmt.Errorf("gitops: %s is not a usable SSH private key: %w", src.AuthRef, err)
		}
		return keys, nil
	}

	// HTTPS wants a token. GitHub and GitLab both accept it as the password
	// with any non-empty username; "kanea" is used so a server log shows what
	// authenticated rather than a blank field.
	token := strings.TrimSpace(string(value))
	if token == "" {
		return nil, fmt.Errorf("gitops: %s is empty", src.AuthRef)
	}
	return &githttp.BasicAuth{Username: "kanea", Password: token}, nil
}

// collectSpecs reads the job specs out of a commit's tree.
//
// The convention (§10.1): everything matching `.kanea/*.hcl`, or a single
// `kanea.hcl` at the root. An explicit `path` overrides both and may name
// either a directory or a file.
func collectSpecs(tree *object.Tree, specPath string) (map[string][]byte, error) {
	specs := map[string][]byte{}

	read := func(entryPath string) error {
		file, err := tree.File(entryPath)
		if err != nil {
			return err
		}
		content, err := file.Contents()
		if err != nil {
			return fmt.Errorf("gitops: read %s: %w", entryPath, err)
		}
		specs[entryPath] = []byte(content)
		return nil
	}

	switch {
	case specPath != "" && strings.HasSuffix(specPath, ".hcl"):
		if err := read(specPath); err != nil {
			return nil, fmt.Errorf("gitops: %s: %w", specPath, err)
		}
		return specs, nil

	case specPath != "":
		if err := collectDir(tree, strings.TrimSuffix(specPath, "/"), specs); err != nil {
			return nil, err
		}
		return specs, nil
	}

	// The convention, in order.
	if err := collectDir(tree, DefaultSpecDir, specs); err != nil {
		return nil, err
	}
	if len(specs) > 0 {
		return specs, nil
	}
	if err := read(DefaultSpecFile); err == nil {
		return specs, nil
	}
	return specs, nil
}

// collectDir reads every .hcl file directly inside a directory.
//
// Not recursive: a deploy repository's `.kanea/` is a flat set of job specs,
// and walking into subdirectories would sweep up whatever else lives there —
// a `.kanea/examples/` of broken specs would break every sync.
func collectDir(tree *object.Tree, dir string, into map[string][]byte) error {
	entries, err := tree.Tree(dir)
	if err != nil {
		if errors.Is(err, object.ErrDirectoryNotFound) || errors.Is(err, plumbing.ErrObjectNotFound) {
			return nil
		}
		return fmt.Errorf("gitops: read %s/: %w", dir, err)
	}

	for _, entry := range entries.Entries {
		if !entry.Mode.IsFile() || !strings.HasSuffix(entry.Name, ".hcl") {
			continue
		}
		file, err := entries.File(entry.Name)
		if err != nil {
			return fmt.Errorf("gitops: read %s: %w", path.Join(dir, entry.Name), err)
		}
		content, err := file.Contents()
		if err != nil {
			return fmt.Errorf("gitops: read %s: %w", path.Join(dir, entry.Name), err)
		}
		into[path.Join(dir, entry.Name)] = []byte(content)
	}
	return nil
}

// describeSpecLocation says where the syncer looked, for the error.
func describeSpecLocation(specPath string) string {
	if specPath != "" {
		return specPath
	}
	return DefaultSpecDir + "/*.hcl or " + DefaultSpecFile
}

// cloneError turns go-git's transport errors into ones an operator can act on.
func cloneError(src Source, err error) error {
	switch {
	case errors.Is(err, transport.ErrAuthenticationRequired),
		errors.Is(err, transport.ErrAuthorizationFailed):
		return fmt.Errorf("%w: %s (check the deploy key or token in %s)",
			ErrAuthRequired, src.URL, src.AuthRef)
	case errors.Is(err, plumbing.ErrReferenceNotFound):
		return fmt.Errorf("gitops: %s has no branch %q", src.URL, src.Branch)
	case errors.Is(err, transport.ErrRepositoryNotFound):
		return fmt.Errorf("gitops: no repository at %s", src.URL)
	default:
		return fmt.Errorf("gitops: clone %s: %w", src.URL, err)
	}
}

// isSSHURL reports whether a remote wants an SSH key rather than a token.
func isSSHURL(url string) bool {
	return strings.HasPrefix(url, "ssh://") ||
		(!strings.Contains(url, "://") && strings.Contains(url, "@") && strings.Contains(url, ":"))
}

// sshUser extracts the user from an SSH remote, defaulting to "git".
func sshUser(url string) string {
	trimmed := strings.TrimPrefix(url, "ssh://")
	if at := strings.Index(trimmed, "@"); at > 0 {
		return trimmed[:at]
	}
	return "git"
}
