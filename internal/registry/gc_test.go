package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// White-box: retention and the orphan sweep order by file mtimes and age
// against the store's clock, which only direct access to the layout can
// arrange deterministically.

func newTestStore(t *testing.T, now func() time.Time) *contentStore {
	t.Helper()
	s, err := newContentStore(t.TempDir(), now)
	if err != nil {
		t.Fatalf("newContentStore: %v", err)
	}
	return s
}

// putImage writes a config blob, a manifest referencing it, and a tag, aging
// every file to the given time so the sweep's ordering is deterministic.
func putImage(t *testing.T, s *contentStore, repo string, n int, at time.Time) (manifestDgst, configDgst string) {
	t.Helper()
	config := fmt.Appendf(nil, `{"n":%d}`, n)
	configDgst = testDigest(config)
	if err := writeFileAtomic(s.blobFile(configDgst), config); err != nil {
		t.Fatalf("write config blob: %v", err)
	}
	manifest := fmt.Appendf(nil, `{"schemaVersion":2,"config":{"digest":%q},"layers":[]}`, configDgst)
	manifestDgst = testDigest(manifest)
	if err := writeFileAtomic(s.blobFile(manifestDgst), manifest); err != nil {
		t.Fatalf("write manifest blob: %v", err)
	}
	project, service := "shop", "web"
	if repo != "" {
		project, service = filepath.Dir(repo), filepath.Base(repo)
	}
	if err := s.putManifest(project, service, manifestDgst,
		"application/vnd.oci.image.manifest.v1+json", fmt.Sprintf("v%d", n)); err != nil {
		t.Fatalf("putManifest: %v", err)
	}
	for _, path := range []string{
		s.blobFile(configDgst), s.blobFile(manifestDgst),
		s.manifestMarker(project, service, manifestDgst),
	} {
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatalf("age %s: %v", path, err)
		}
	}
	return manifestDgst, configDgst
}

func TestSweepKeepsTheNewestFiveManifests(t *testing.T) {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	now := base.Add(48 * time.Hour)
	s := newTestStore(t, func() time.Time { return now })

	var manifests, configs []string
	for i := range 7 {
		m, c := putImage(t, s, "shop/web", i, base.Add(time.Duration(i)*time.Hour))
		manifests, configs = append(manifests, m), append(configs, c)
	}

	s.sweep(slog.New(slog.DiscardHandler))

	// The two oldest are retired: marker, tag and (aged well past the upload
	// window) their blobs.
	for i := range 2 {
		if _, _, ok := s.statManifest("shop", "web", manifests[i]); ok {
			t.Errorf("manifest %d survived retention", i)
		}
		if _, ok := s.resolveTag("shop", "web", fmt.Sprintf("v%d", i)); ok {
			t.Errorf("tag v%d dangles after its manifest retired", i)
		}
		if _, _, ok := s.statBlob(configs[i]); ok {
			t.Errorf("config blob %d survived as an orphan", i)
		}
	}
	for i := 2; i < 7; i++ {
		if _, _, ok := s.statManifest("shop", "web", manifests[i]); !ok {
			t.Errorf("manifest %d was swept; the newest five must stay", i)
		}
		if _, _, ok := s.statBlob(configs[i]); !ok {
			t.Errorf("config blob %d of a kept manifest was swept", i)
		}
	}
}

func TestSweepSparesYoungBlobs(t *testing.T) {
	// An unreferenced blob younger than the upload window belongs to a push
	// whose manifest has not landed yet; sweeping it would corrupt that push.
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	s := newTestStore(t, func() time.Time { return now })

	young := testDigest([]byte("just pushed"))
	if err := writeFileAtomic(s.blobFile(young), []byte("just pushed")); err != nil {
		t.Fatalf("write blob: %v", err)
	}

	s.sweep(slog.New(slog.DiscardHandler))
	if _, _, ok := s.statBlob(young); !ok {
		t.Fatal("the sweep removed a blob inside the in-flight window")
	}
}

func TestSweepKeepsBlobsSharedAcrossRepositories(t *testing.T) {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	now := base.Add(48 * time.Hour)
	s := newTestStore(t, func() time.Time { return now })

	// The same image in two repositories: retiring it from one must not
	// orphan the other's blobs, because the blob set is global.
	m1, c1 := putImage(t, s, "shop/web", 1, base)
	putImage(t, s, "shop/api", 1, base.Add(time.Hour))
	// Push five newer images into shop/web so image 1 retires there.
	for i := 2; i < 7; i++ {
		putImage(t, s, "shop/web", i, base.Add(time.Duration(i)*time.Hour))
	}

	s.sweep(slog.New(slog.DiscardHandler))

	if _, _, ok := s.statManifest("shop", "web", m1); ok {
		t.Error("image 1 survived retention in shop/web")
	}
	if _, _, ok := s.statManifest("shop", "api", m1); !ok {
		t.Fatal("image 1 retired from shop/api, where it is the only image")
	}
	if _, _, ok := s.statBlob(c1); !ok {
		t.Fatal("a blob still referenced by shop/api was swept")
	}
}

func testDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
