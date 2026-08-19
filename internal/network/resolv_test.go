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

// A stock Debian or Ubuntu server runs systemd-resolved, whose stub is the
// only nameserver in /etc/resolv.conf. Dropping it left nothing behind and
// kanead refused to start on that host, which is most of them; the addresses
// are read by kanead's own forwarder, in kanead's own namespace, and never by
// an alloc (WriteResolvConf hands an alloc the internal resolver instead).
func TestParseResolversKeepsLoopback(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "the systemd-resolved stub, alone",
			raw:  "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n",
			want: []string{"127.0.0.53:53"},
		},
		{
			name: "file order is the host's preference order",
			raw:  "nameserver 127.0.0.53\nnameserver 213.186.33.99\n",
			want: []string{"127.0.0.53:53", "213.186.33.99:53"},
		},
		{
			name: "ordinary resolvers are untouched",
			raw:  "nameserver 213.186.33.99\nnameserver 1.1.1.1\n",
			want: []string{"213.186.33.99:53", "1.1.1.1:53"},
		},
		{
			name: "v6 loopback counts too",
			raw:  "nameserver ::1\n",
			want: []string{"[::1]:53"},
		},
		{
			name: "comments and junk are skipped, not guessed at",
			raw:  "# generated\nnameserver\nnameserver not-an-address\nnameserver 9.9.9.9\n",
			want: []string{"9.9.9.9:53"},
		},
		{
			name: "a file with no nameserver yields nothing",
			raw:  "search example.com\noptions ndots:1\n",
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseResolvers([]byte(tc.raw))
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("entry %d: got %q, want %q (full: %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}
