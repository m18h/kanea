package notify_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/notify"
)

func TestAllowedIPRefusesEverythingNotPubliclyRoutable(t *testing.T) {
	// This is the §14 A10 boundary. A notification target comes out of a job
	// spec, and the addresses worth reaching from inside a node are exactly the
	// ones a firewall was meant to protect.
	for _, tc := range []struct {
		addr  string
		allow bool
		why   string
	}{
		{"1.1.1.1", true, "an ordinary public address"},
		{"2606:4700:4700::1111", true, "public IPv6"},

		{"127.0.0.1", false, "loopback is the control plane itself"},
		{"::1", false, "IPv6 loopback"},
		{"169.254.169.254", false, "the cloud metadata service"},
		{"fe80::1", false, "IPv6 link-local"},
		{"10.0.0.5", false, "RFC1918"},
		{"172.16.3.4", false, "RFC1918"},
		{"192.168.1.1", false, "RFC1918"},
		{"fd00::1", false, "IPv6 unique-local"},
		{"0.0.0.0", false, "the unspecified address"},
		{"224.0.0.1", false, "multicast"},

		// The same destinations written differently. A check that only looks at
		// the notation is a check that is bypassed by changing the notation.
		{"::ffff:10.0.0.5", false, "IPv4-mapped IPv6 hiding an RFC1918 address"},
		{"::ffff:169.254.169.254", false, "IPv4-mapped metadata service"},
		{"64:ff9b::7f00:1", false, "NAT64 carrying 127.0.0.1"},
		{"64:ff9b::a00:5", false, "NAT64 carrying 10.0.0.5"},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			ip := net.ParseIP(tc.addr)
			if ip == nil {
				t.Fatalf("cannot parse %q", tc.addr)
			}
			if got := notify.AllowedIP(ip); got != tc.allow {
				t.Fatalf("AllowedIP(%s) = %v, want %v — %s", tc.addr, got, tc.allow, tc.why)
			}
		})
	}
}

func TestCheckURLRequiresHTTPS(t *testing.T) {
	var policy notify.EgressPolicy

	if _, err := policy.CheckURL("http://hooks.example.com/x"); !errors.Is(err, notify.ErrInsecureScheme) {
		t.Fatalf("err = %v, want ErrInsecureScheme", err)
	}
	// A signed payload over cleartext is still a payload anyone on the path can
	// read, and the signature only proves it was not altered.
	if _, err := policy.CheckURL("https://hooks.example.com/x"); err != nil {
		t.Fatalf("https refused: %v", err)
	}
	// Neither http nor https: a file:// or gopher:// target is a way to make
	// the daemon touch something that is not a network service at all.
	if _, err := policy.CheckURL("file:///etc/passwd"); !errors.Is(err, notify.ErrInsecureScheme) {
		t.Fatalf("err = %v, want ErrInsecureScheme", err)
	}

	// The opt-out §11 names, for an internal chat server.
	relaxed := notify.EgressPolicy{AllowHTTP: true}
	if _, err := relaxed.CheckURL("http://chat.internal/x"); err != nil {
		t.Fatalf("opt-out refused: %v", err)
	}
}

func TestClientRefusesToDialAPrivateAddress(t *testing.T) {
	// httptest listens on loopback, which is precisely what the policy blocks —
	// so this both tests the block and proves it happens at dial time rather
	// than on the hostname.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var policy notify.EgressPolicy
	client := policy.HTTPClient(0)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req) //nolint:bodyclose // the request must not succeed
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a loopback destination was reached")
	}
	if !strings.Contains(err.Error(), notify.ErrPrivateDestination.Error()) {
		t.Fatalf("err = %v, want a private-destination refusal", err)
	}
}

func TestClientReachesAPrivateAddressWhenAllowed(t *testing.T) {
	// The opt-out has to actually work, or an operator with an internal
	// Mattermost has no way to use this at all.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	policy := notify.EgressPolicy{AllowPrivate: true, AllowHTTP: true}
	client := policy.HTTPClient(0)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestClientRefusesToFollowARedirect(t *testing.T) {
	// The bypass this closes: a public, allowed target answers 302 to
	// http://169.254.169.254/ and every check above has already passed.
	var reached bool
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer metadata.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, metadata.URL, http.StatusFound)
	}))
	defer redirector.Close()

	// Private allowed, so the only thing that can stop the hop is the redirect
	// rule itself.
	policy := notify.EgressPolicy{AllowPrivate: true, AllowHTTP: true}
	client := policy.HTTPClient(0)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, redirector.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req) //nolint:bodyclose // checked below
	if err == nil {
		_ = resp.Body.Close()
	}
	if reached {
		t.Fatal("the redirect was followed to the second server")
	}
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v, want a refusal to redirect", err)
	}
}
