package jobspec_test

import (
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/jobspec"
)

// exposeSpec builds a one-service spec with the given network and expose bodies.
func exposeSpec(network, expose string) string {
	return `
spec_version = 1

project "shop" {}

service "web" {
  project = "shop"
  task "app" { image = "nginx:1.27-alpine" }
  ` + network + `
  expose {
    ` + expose + `
  }
}
`
}

// A single-line HCL block holds at most one argument and no nested block
// (the v1.10 correction to the PRD example), so this cannot be a one-liner.
const httpPort = `network {
    port "http" { container = 8080 }
  }`

// rateLimit renders a multi-line rate_limit block from its arguments.
func rateLimit(args ...string) string {
	return "rate_limit {\n      " + strings.Join(args, "\n      ") + "\n    }"
}

func TestExposeAcceptsAValidBlock(t *testing.T) {
	spec := parse(t, exposeSpec(httpPort, `
    domains = ["shop.example.com", "www.shop.example.com"]
    tls { letsencrypt = true }
    ip_restriction {
      allow = ["10.0.0.0/8"]
      deny  = ["198.51.100.7"]
    }
    rate_limit {
      requests = 100
      window   = "1m"
      per      = "ip"
      burst    = 20
    }
    headers {
      response_remove = ["Server"]
    }
  `))

	svc := spec.ServiceByName("shop", "web")
	if svc == nil || svc.Expose == nil {
		t.Fatal("service or expose block missing")
	}
	port := svc.EdgePort()
	if port == nil || port.Container != 8080 {
		t.Fatalf("EdgePort = %+v, want the http port", port)
	}
	domains := svc.EdgeDomains("apps.example.com")
	if len(domains) != 2 || domains[0] != "shop.example.com" {
		t.Errorf("EdgeDomains = %v", domains)
	}
}

// The auto-FQDN is what makes one wildcard DNS record enough (PRD §7.2).
func TestExposeGeneratesAnAutoFQDN(t *testing.T) {
	spec := parse(t, exposeSpec(httpPort, `tls { letsencrypt = true }`))
	svc := spec.ServiceByName("shop", "web")

	got := svc.EdgeDomains("apps.example.com")
	if len(got) != 1 || got[0] != "web.shop.apps.example.com" {
		t.Errorf("EdgeDomains = %v, want [web.shop.apps.example.com]", got)
	}
	// Without a base domain the name cannot be computed, and inventing one
	// would make the same spec mean different things on different nodes.
	if got := svc.EdgeDomains(""); len(got) != 0 {
		t.Errorf("EdgeDomains(\"\") = %v, want none", got)
	}
}

// R16: an exposed service with no port is a route to nowhere.
func TestExposeRequiresAPort(t *testing.T) {
	got := parseErr(t, exposeSpec("", `domains = ["shop.example.com"]`))
	if !strings.Contains(got, "no port") {
		t.Errorf("diagnostics = %q, want a missing-port error", got)
	}
}

// With several ports and no "http" among them there is nothing in a
// host-routed request left to choose with, so the spec has to say.
func TestExposeRejectsAnAmbiguousPort(t *testing.T) {
	multi := `network {
    port "api"     { container = 8080 }
    port "metrics" { container = 9090 }
  }`
	got := parseErr(t, exposeSpec(multi, `domains = ["shop.example.com"]`))
	if !strings.Contains(got, "Ambiguous exposed port") {
		t.Errorf("diagnostics = %q, want an ambiguity error", got)
	}
	for _, want := range []string{`"api"`, `"metrics"`, `"http"`} {
		if !strings.Contains(got, want) {
			t.Errorf("diagnostics %q does not name %s", got, want)
		}
	}
}

// One port needs no name: there is no ambiguity to resolve.
func TestExposeAcceptsASoleUnnamedPort(t *testing.T) {
	sole := `network {
    port "api" { container = 8080 }
  }`
	spec := parse(t, exposeSpec(sole, `domains = ["shop.example.com"]`))
	port := spec.ServiceByName("shop", "web").EdgePort()
	if port == nil || port.Container != 8080 {
		t.Fatalf("EdgePort = %+v", port)
	}
}

func TestExposeRejectsInvalidDomains(t *testing.T) {
	tests := []struct {
		name, domain, want string
	}{
		{"url", "https://shop.example.com", "looks like a URL"},
		{"path", "shop.example.com/app", "contains a path"},
		{"port", "shop.example.com:8443", "contains a port"},
		{"wildcard", "*.example.com", "is a wildcard"},
		{"trailing dot", "shop.example.com.", "trailing dot"},
		{"empty label", "shop..example.com", "invalid label"},
		{"leading dash", "-shop.example.com", "start or end with"},
		{"underscore", "my_shop.example.com", "letters, digits"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseErr(t, exposeSpec(httpPort, `domains = ["`+tc.domain+`"]`))
			if !strings.Contains(got, tc.want) {
				t.Errorf("diagnostics = %q, want %q", got, tc.want)
			}
		})
	}
}

// One host reaches one service. Left to the edge this would be last-writer-wins
// on a map iteration order.
func TestExposeRejectsADomainClaimedTwice(t *testing.T) {
	src := `
spec_version = 1

project "shop" {}

service "web" {
  project = "shop"
  task "app" { image = "nginx:1.27-alpine" }
  network {
    port "http" { container = 80 }
  }
  expose {
    domains = ["shop.example.com"]
  }
}

service "legacy" {
  project = "shop"
  task "app" { image = "nginx:1.27-alpine" }
  network {
    port "http" { container = 80 }
  }
  expose {
    domains = ["SHOP.example.com"]
  }
}
`
	got := parseErr(t, src)
	if !strings.Contains(got, "claimed") {
		t.Errorf("diagnostics = %q, want a collision error", got)
	}
	// Case is not a distinction DNS makes, so it cannot be one here.
	if !strings.Contains(got, "shop.example.com") {
		t.Errorf("diagnostics = %q does not name the domain", got)
	}
}

func TestExposeRejectsInvalidIPRestriction(t *testing.T) {
	got := parseErr(t, exposeSpec(httpPort, `ip_restriction {
      allow = ["10.0.0.0/33"]
    }`))
	if !strings.Contains(got, "Invalid CIDR") {
		t.Errorf("diagnostics = %q", got)
	}
	got = parseErr(t, exposeSpec(httpPort, `ip_restriction {
      deny = ["not-an-address"]
    }`))
	if !strings.Contains(got, "Invalid CIDR") {
		t.Errorf("diagnostics = %q", got)
	}
}

func TestExposeRejectsInvalidRateLimit(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"no window", rateLimit(`requests = 10`, `window = ""`), "no window"},
		{"bad window", rateLimit(`requests = 10`, `window = "1 minute"`), "Invalid duration"},
		{"zero requests", rateLimit(`requests = 0`, `window = "1m"`), "must be positive"},
		{"negative burst", rateLimit(`requests = 10`, `window = "1m"`, `burst = -1`), "not be negative"},
		{"unknown key", rateLimit(`requests = 10`, `window = "1m"`, `per = "user"`), "Invalid rate limit key"},
		{"bad header key", rateLimit(`requests = 10`, `window = "1m"`, `per = "header:bad header"`), "invalid header"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseErr(t, exposeSpec(httpPort, tc.body))
			if !strings.Contains(got, tc.want) {
				t.Errorf("diagnostics = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExposeAcceptsAHeaderRateLimitKey(t *testing.T) {
	parse(t, exposeSpec(httpPort, rateLimit(`requests = 10`, `window = "1m"`, `per = "header:X-API-Key"`)))
}

// A spec that could rewrite X-Forwarded-For would be forging the client
// identity every other ingress control is keyed on.
func TestExposeRejectsEdgeOwnedHeaders(t *testing.T) {
	for _, body := range []string{
		`headers {
      request_set = { X-Forwarded-For = "1.2.3.4" }
    }`,
		`headers {
      request_set = { X-Forwarded-Proto = "https" }
    }`,
		`headers {
      request_remove = ["X-Real-IP"]
    }`,
		`headers {
      request_set = { Forwarded = "for=1.2.3.4" }
    }`,
	} {
		got := parseErr(t, exposeSpec(httpPort, body))
		if !strings.Contains(got, "belongs to the edge") {
			t.Errorf("%s: diagnostics = %q", body, got)
		}
	}
}

// Rewriting a connection-scoped header breaks request framing or the WebSocket
// upgrade.
func TestExposeRejectsHopByHopHeaders(t *testing.T) {
	for _, body := range []string{
		`headers {
      request_remove = ["Connection"]
    }`,
		`headers {
      response_set = { Transfer-Encoding = "chunked" }
    }`,
		`headers {
      request_set = { Upgrade = "websocket" }
    }`,
	} {
		got := parseErr(t, exposeSpec(httpPort, body))
		if !strings.Contains(got, "belongs to the proxy") {
			t.Errorf("%s: diagnostics = %q", body, got)
		}
	}
}

// A header name with a newline in it is a response-splitting attempt.
func TestExposeRejectsMalformedHeaderNames(t *testing.T) {
	got := parseErr(t, exposeSpec(httpPort, `headers {
      response_set = { "X-Bad: injected" = "v" }
    }`))
	if !strings.Contains(got, "Invalid header name") {
		t.Errorf("diagnostics = %q", got)
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"10.0.0.0/8", "10.0.0.0/8", true},
		// A prefix given with host bits set means the prefix it names.
		{"10.1.2.3/8", "10.0.0.0/8", true},
		{"203.0.113.7", "203.0.113.7/32", true},
		{"2001:db8::1", "2001:db8::1/128", true},
		{"10.0.0.0/33", "", false},
		{"nonsense", "", false},
	}
	for _, tc := range tests {
		got, err := jobspec.ParseCIDR(tc.in)
		if tc.ok != (err == nil) {
			t.Errorf("ParseCIDR(%q) err = %v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && got.String() != tc.want {
			t.Errorf("ParseCIDR(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// R20: a tls block names a source, and the errors have to name it back.
func TestExposeRejectsAnInvalidTLSBlock(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"unknown mode", `tls { mode = "letsencrypt" }`, "Unknown TLS mode"},
		{"a path is not a mode", `tls { mode = "/etc/kanea/tls/shop.crt" }`, "Unknown TLS mode"},
		{"both spellings", "tls {\n      mode = \"acme\"\n      letsencrypt = true\n    }", "Two TLS spellings"},
		{"name without provided", "tls {\n      mode = \"acme\"\n      name = \"shop\"\n    }", "Certificate name without a provided mode"},
		{"name with no mode at all", `tls { name = "shop" }`, "whatever this node defaults to"},
		{"name is not a label", "tls {\n      mode = \"provided\"\n      name = \"Shop Cert\"\n    }", "DNS-1123"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseErr(t, exposeSpec(httpPort, tc.body)); !strings.Contains(got, tc.want) {
				t.Errorf("diagnostics = %q, want it to name %q", got, tc.want)
			}
		})
	}
}

func TestExposeAcceptsEveryTLSMode(t *testing.T) {
	for _, mode := range []string{"acme", "self-signed", "provided", "plaintext"} {
		t.Run(mode, func(t *testing.T) {
			spec := parse(t, exposeSpec(httpPort, `tls { mode = "`+mode+`" }`))
			if got := spec.Services[0].Expose.TLS.Mode; got != mode {
				t.Errorf("mode = %q, want %q", got, mode)
			}
		})
	}
	spec := parse(t, exposeSpec(httpPort, "tls {\n      mode = \"provided\"\n      name = \"shop\"\n    }"))
	if got := spec.Services[0].Expose.TLS.Name; got != "shop" {
		t.Errorf("name = %q, want shop", got)
	}
}

// The whole point of --tls-default is that a homelabber annotates nothing. A
// service with no tls block must be silent, not merely valid: a warning on
// every service is a warning nobody reads.
func TestExposeWithoutATLSBlockSaysNothing(t *testing.T) {
	_, diags := jobspec.ParseSource(jobspec.Options{}, "test.hcl",
		[]byte(exposeSpec(httpPort, `domains = ["shop.example.com"]`)))
	if len(diags) != 0 {
		t.Errorf("diagnostics = %s, want none", jobspec.FormatDiagnostics(diags))
	}
}

// The old spelling still parses — a spec written against v1.32 must not become
// an error — and warns, with `letsencrypt = false` warning about the meaning
// that changed underneath it rather than about the field's age.
func TestExposeWarnsOnTheDeprecatedTLSSpelling(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"true", `tls { letsencrypt = true }`, `mode = "acme"`},
		{"false", `tls { letsencrypt = false }`, "no longer means no certificate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, diags := jobspec.ParseSource(jobspec.Options{}, "test.hcl",
				[]byte(exposeSpec(httpPort, tc.body)))
			if diags.HasErrors() {
				t.Fatalf("the old spelling became an error:\n%s", jobspec.FormatDiagnostics(diags))
			}
			got := jobspec.FormatDiagnostics(diags)
			if !strings.Contains(got, "Warning") || !strings.Contains(got, tc.want) {
				t.Errorf("diagnostics = %q, want a warning naming %q", got, tc.want)
			}
		})
	}
}
