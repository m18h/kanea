package registry

import (
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Retention (§5.2.14): keep-last-5 manifests per repository, then an
// orphan-blob sweep. Triggered behind every manifest write and once at boot -
// steady state writes nothing, so an idle registry never sweeps - and always
// best-effort: a sweep failure is a log line, never a failed push, because
// this is the platform's third content store (§5.2.4) tidying itself, not a
// correctness step.

// sweep applies retention and removes orphaned blobs.
func (s *contentStore) sweep(log *slog.Logger) {
	referenced := map[string]bool{}

	repos, err := s.listRepos()
	if err != nil {
		log.Warn("registry sweep cannot list repositories", "error", err)
		return
	}
	for _, repo := range repos {
		s.retainManifests(repo, log)
		s.pruneTags(repo, log)
		s.collectReferenced(repo, referenced, log)
	}

	// Orphans: blobs no kept manifest references. The age guard is what makes
	// this safe against an in-flight push, whose layers land before the
	// manifest that will reference them: a blob younger than the upload
	// expiry is never touched.
	blobDir := filepath.Join(s.dir, "blobs", "sha256")
	entries, err := os.ReadDir(blobDir)
	if err != nil {
		log.Warn("registry sweep cannot list blobs", "error", err)
		return
	}
	removed := 0
	for _, entry := range entries {
		dgst := "sha256:" + entry.Name()
		if referenced[dgst] {
			continue
		}
		fi, err := entry.Info()
		if err != nil || s.now().Sub(fi.ModTime()) < uploadExpiry {
			continue
		}
		if err := os.Remove(filepath.Join(blobDir, entry.Name())); err != nil {
			log.Warn("registry sweep cannot remove an orphaned blob", "digest", dgst, "error", err)
			continue
		}
		removed++
	}
	if removed > 0 {
		log.Info("registry sweep removed orphaned blobs", "count", removed)
	}
}

// listRepos lists every <project>/<service> directory.
func (s *contentStore) listRepos() ([]string, error) {
	var out []string
	root := filepath.Join(s.dir, "repos")
	projects, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, project := range projects {
		if !project.IsDir() {
			continue
		}
		services, err := os.ReadDir(filepath.Join(root, project.Name()))
		if err != nil {
			return nil, err
		}
		for _, service := range services {
			if service.IsDir() {
				out = append(out, filepath.Join(root, project.Name(), service.Name()))
			}
		}
	}
	return out, nil
}

// retainManifests keeps the newest keepManifests markers in one repository.
func (s *contentStore) retainManifests(repo string, log *slog.Logger) {
	dir := filepath.Join(repo, "manifests")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type marker struct {
		name string
		mod  int64
	}
	markers := make([]marker, 0, len(entries))
	for _, entry := range entries {
		fi, err := entry.Info()
		if err != nil {
			continue
		}
		markers = append(markers, marker{entry.Name(), fi.ModTime().UnixNano()})
	}
	sort.Slice(markers, func(i, j int) bool { return markers[i].mod > markers[j].mod })
	for _, m := range markers[min(len(markers), keepManifests):] {
		if err := os.Remove(filepath.Join(dir, m.name)); err != nil {
			log.Warn("registry sweep cannot remove a retired manifest",
				"repo", repo, "digest", "sha256:"+m.name, "error", err)
		}
	}
}

// pruneTags drops tags whose manifest the retention just retired.
func (s *contentStore) pruneTags(repo string, log *slog.Logger) {
	dir := filepath.Join(repo, "tags")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(dir, entry.Name())) // #nosec G304; a directory listing under the store root
		if err != nil {
			continue
		}
		dgst := strings.TrimSpace(string(body))
		if !validDigest(dgst) {
			continue
		}
		marker := filepath.Join(repo, "manifests", strings.TrimPrefix(dgst, "sha256:"))
		if _, err := os.Stat(marker); err == nil { // #nosec G703; dgst passed validDigest above, so the joined segment is 64 hex chars
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			log.Warn("registry sweep cannot remove a dangling tag",
				"repo", repo, "tag", entry.Name(), "error", err)
		}
	}
}

// collectReferenced marks every digest the repository's kept manifests reach:
// the manifests themselves and every child they name.
func (s *contentStore) collectReferenced(repo string, referenced map[string]bool, log *slog.Logger) {
	dir := filepath.Join(repo, "manifests")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		dgst := "sha256:" + entry.Name()
		referenced[dgst] = true
		body, err := os.ReadFile(s.blobFile(dgst)) // #nosec G304; a path composed from a directory listing under the store root
		if err != nil {
			continue
		}
		children, err := referencedDigests(body)
		if err != nil {
			log.Warn("registry sweep cannot parse a stored manifest", "digest", dgst, "error", err)
			continue
		}
		for _, child := range children {
			referenced[child] = true
		}
	}
}
