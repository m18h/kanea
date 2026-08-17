package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolvConfFor(t *testing.T) {
	got, err := ResolvConfFor("shop", "10.200.1.1:53")
	if err != nil {
		t.Fatalf("ResolvConfFor: %v", err)
	}
	// The port must be stripped: resolv.conf has no syntax for one, and a
	// nameserver line the resolver cannot parse is silently ignored.
	if !strings.Contains(got, "nameserver 10.200.1.1\n") {
		t.Errorf("missing or malformed nameserver line:\n%s", got)
	}
	// The search list is what lets a spec name a peer as `postgres`.
	if !strings.Contains(got, "search shop.kanea kanea\n") {
		t.Errorf("missing search list:\n%s", got)
	}
	// ndots:5 (the Kubernetes default) sends every dotted name through the
	// whole search list first: four wasted round trips on api.github.com.
	if !strings.Contains(got, "ndots:1") {
		t.Errorf("want ndots:1:\n%s", got)
	}
}

func TestResolvConfForRejectsBadInput(t *testing.T) {
	if _, err := ResolvConfFor("shop", "not-an-address"); err == nil {
		t.Error("accepted a nameserver that is not an address")
	}
	if _, err := ResolvConfFor("shop evil", "10.200.1.1"); err == nil {
		t.Error("accepted a project name that is not a label")
	}
}

func TestWriteResolvConf(t *testing.T) {
	dir := t.TempDir()

	path, err := WriteResolvConf(dir, "shop", "10.200.1.1:53")
	if err != nil {
		t.Fatalf("WriteResolvConf: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("path %q is outside %q", path, dir)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// The file is bind-mounted into containers that may run as any uid, and it
	// holds no secret.
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want 644: containers run as arbitrary uids", perm)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(raw), "search shop.kanea kanea") {
		t.Errorf("contents:\n%s", raw)
	}
}

func TestWriteResolvConfIsPerProject(t *testing.T) {
	dir := t.TempDir()

	shop, err := WriteResolvConf(dir, "shop", "10.200.1.1")
	if err != nil {
		t.Fatalf("shop: %v", err)
	}
	blog, err := WriteResolvConf(dir, "blog", "10.200.1.1")
	if err != nil {
		t.Fatalf("blog: %v", err)
	}
	if shop == blog {
		t.Fatal("both projects share one resolv.conf; their search lists differ")
	}
}
