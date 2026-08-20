package api

// An internal test: elidedServiceViews is unexported, and exporting it so a
// test could reach it would make a private decision part of the package's API.

import (
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/reconciler"
)

// TestTheFeedViewNeverCarriesFileContent (PRD v1.85, R35).
//
// feedServices ships every service's whole record to every subscriber on every
// store-index change. A service carrying the per-service maximum of file
// content would put that much into a send buffer whose overflow closes the
// connection - which is the v1.70 defect wearing new clothes.
//
// Elided **always, never conditionally**: a client that sometimes receives
// content cannot tell an elided file from an empty one, and content_bytes is
// what it renders instead.
func TestTheFeedViewNeverCarriesFileContent(t *testing.T) {
	svc := reconciler.Desired{
		Project: "shop", Service: "web",
		Files: []reconciler.FileMount{
			{Name: "a", Path: "/etc/a", Content: []byte("listen=8080")},
			{Name: "b", Path: "/etc/b", Content: []byte(strings.Repeat("x", 4096))},
		},
	}
	views := elidedServiceViews([]reconciler.Desired{svc})
	if len(views) != 1 || len(views[0].Files) != 2 {
		t.Fatalf("unexpected view: %+v", views)
	}
	for _, f := range views[0].Files {
		if len(f.Content) != 0 {
			t.Errorf("file %q carried %d bytes of content onto the feed", f.Name, len(f.Content))
		}
		if f.ContentBytes == 0 {
			t.Errorf("file %q reports no size; a client cannot tell elided from empty", f.Name)
		}
	}
	if views[0].Files[0].ContentBytes != len("listen=8080") {
		t.Errorf("content_bytes = %d, want %d",
			views[0].Files[0].ContentBytes, len("listen=8080"))
	}

	// The caller's record must be untouched: Desired is embedded by value, but
	// Files is a slice and its backing array is the Store's.
	if string(svc.Files[0].Content) != "listen=8080" {
		t.Errorf("eliding rewrote the caller's record: %q", svc.Files[0].Content)
	}
}
