package runtime

import (
	"testing"

	"github.com/containerd/containerd/v2/core/remotes/docker"
)

// White-box: resolverOptions is the decision, and the decision is what these
// pin - which scheme each host gets, without dialing anything.

// hostFor resolves one host through the options' registry configuration.
func hostFor(t *testing.T, options docker.ResolverOptions, host string) docker.RegistryHost {
	t.Helper()
	if options.Hosts == nil {
		t.Fatal("no Hosts configured; the anonymous path never reaches this helper")
	}
	hosts, err := options.Hosts(host)
	if err != nil {
		t.Fatalf("Hosts(%s): %v", host, err)
	}
	if len(hosts) != 1 {
		t.Fatalf("Hosts(%s) = %d entries, want 1", host, len(hosts))
	}
	return hosts[0]
}

// A credentialed pull must still speak plain HTTP to a loopback registry:
// pairing a registry_auth_ref (say, for a ghcr fallback image) with an
// internal-registry image (§5.2.14) is a legitimate service, and without the
// localhost match the authenticated resolver insists on HTTPS from a listener
// that is plain HTTP by design.
func TestAuthenticatedResolverAllowsPlainHTTPOnLocalhost(t *testing.T) {
	auth := []byte(`{"auths":{"ghcr.io":{"username":"u","password":"p"}}}`)
	options, err := resolverOptions(auth)
	if err != nil {
		t.Fatalf("resolverOptions: %v", err)
	}

	for _, host := range []string{"127.0.0.1:5100", "localhost:5100", "[::1]:5100"} {
		if got := hostFor(t, options, host).Scheme; got != "http" {
			t.Errorf("scheme for %s = %q, want http", host, got)
		}
	}

	// And TLS is not weakened for anything routable: only loopback matches.
	for _, host := range []string{"ghcr.io", "registry.example.com:5000", "10.0.0.5:5100"} {
		entry := hostFor(t, options, host)
		if entry.Scheme != "https" {
			t.Errorf("scheme for %s = %q, want https", host, entry.Scheme)
		}
		if entry.Authorizer == nil {
			t.Errorf("no authorizer for %s; the credential would never be sent", host)
		}
	}
}

func TestAnonymousResolverOptionsStayDefault(t *testing.T) {
	options, err := resolverOptions(nil)
	if err != nil {
		t.Fatalf("resolverOptions: %v", err)
	}
	// Zero options: NewResolver's own defaults already carry
	// WithPlainHTTP(MatchLocalhost) on this path, and configuring hosts here
	// would silently replace those defaults.
	if options.Hosts != nil {
		t.Fatal("the anonymous path configured Hosts; it must stay on NewResolver's defaults")
	}
}
