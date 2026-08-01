package edge

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRoute() Route {
	return Route{
		Project: "shop", Service: "web",
		Domains:  []string{"web.shop.apps.example.com"},
		Upstream: "10.201.0.1", Port: 3000,
	}
}

func TestPublishAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge", SnapshotName)
	want := Snapshot{Index: 42, Routes: []Route{testRoute()}}

	if err := Publish(path, want); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Index != want.Index || len(got.Routes) != 1 {
		t.Fatalf("Load = %+v, want %+v", got, want)
	}
	if got.Routes[0].Address() != "10.201.0.1:3000" {
		t.Errorf("Address = %q", got.Routes[0].Address())
	}
}

// The edge runs as a different, less privileged user than kanead. A snapshot it
// cannot read is a route table that never loads.
func TestPublishLeavesTheSnapshotReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := Publish(path, Snapshot{Routes: []Route{testRoute()}}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o044 == 0 {
		t.Errorf("mode = %v; the edge user cannot read it", perm)
	}
}

// Publishing must leave nothing behind for a reader that globs the directory,
// and in particular nothing ending in .json.
func TestPublishLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	for range 3 {
		if err := Publish(path, Snapshot{Routes: []Route{testRoute()}}); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "routes.json" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory holds %v, want just routes.json", names)
	}
}

func TestPublishRefusesAnInvalidSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")

	tests := []struct {
		name string
		snap Snapshot
		want string
	}{
		{"no upstream", Snapshot{Routes: []Route{{
			Project: "shop", Service: "web", Domains: []string{"a.example.com"}, Port: 80,
		}}}, "not an address"},
		{"port out of range", Snapshot{Routes: []Route{{
			Project: "shop", Service: "web", Domains: []string{"a.example.com"},
			Upstream: "10.201.0.1", Port: 70000,
		}}}, "out of range"},
		{"no domain", Snapshot{Routes: []Route{{
			Project: "shop", Service: "web", Upstream: "10.201.0.1", Port: 80,
		}}}, "claims no domain"},
		{"uncanonical domain", Snapshot{Routes: []Route{{
			Project: "shop", Service: "web", Domains: []string{"Web.Example.com"},
			Upstream: "10.201.0.1", Port: 80,
		}}}, "not canonical"},
		{"no service", Snapshot{Routes: []Route{{
			Domains: []string{"a.example.com"}, Upstream: "10.201.0.1", Port: 80,
		}}}, "no project or service"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Publish(path, tc.snap)
			if !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("Publish = %v, want ErrInvalidSnapshot", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v does not mention %q", err, tc.want)
			}
			if _, statErr := os.Stat(path); statErr == nil {
				t.Error("an invalid snapshot was written anyway")
			}
		})
	}
}

// R16 catches this at plan time, but a snapshot assembled from several separate
// applies can still collide — and last-writer-wins in a routing table is a
// silent misdelivery.
func TestSnapshotRefusesADomainClaimedTwice(t *testing.T) {
	snap := Snapshot{Routes: []Route{
		{Project: "shop", Service: "web", Domains: []string{"one.example.com"},
			Upstream: "10.201.0.1", Port: 80},
		{Project: "blog", Service: "www", Domains: []string{"one.example.com"},
			Upstream: "10.201.0.2", Port: 80},
	}}
	err := snap.Validate()
	if !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("Validate = %v, want ErrInvalidSnapshot", err)
	}
	for _, want := range []string{"shop/web", "blog/www", "one.example.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not name %q", err, want)
		}
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("Load = %v, want ErrInvalidSnapshot", err)
	}
}

// A truncated file — the failure a non-atomic write would produce — must be
// rejected rather than serve half a route table.
func TestLoadRejectsATruncatedSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	body, err := json.Marshal(Snapshot{Routes: []Route{testRoute()}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, body[:len(body)/2], 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a truncated snapshot loaded")
	}
}

// The snapshot lives outside data_dir on purpose: that directory is 0750 and
// holds the database, so an unprivileged edge user cannot traverse into it.
func TestSnapshotPath(t *testing.T) {
	if got := SnapshotPath("/run/kanea-edge"); got != "/run/kanea-edge/routes.json" {
		t.Errorf("SnapshotPath = %q", got)
	}
	if filepath.Dir(DefaultSnapshotPath) == "/var/lib/kanea" {
		t.Error("the default snapshot path is inside the state directory")
	}
}
