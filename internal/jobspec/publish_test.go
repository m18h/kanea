package jobspec_test

import (
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/jobspec"
)

// publishSpec builds a one-service spec with a network block holding the given
// publish body.
func publishSpec(body string) string {
	return `
spec_version = 1

project "media" {}

service "jellyfin" {
  project = "media"
  task "app" { image = "jellyfin:10.9" }
  network {
    port "http" { container = 8096 }
    ` + body + `
  }
}
`
}

// publishBlock renders a publish block from its arguments; a single-line HCL
// block holds at most one, so this cannot be a one-liner.
func publishBlock(port string, args ...string) string {
	return "publish \"" + port + "\" {\n      " + strings.Join(args, "\n      ") + "\n    }"
}

func TestPublishAcceptsAValidBlock(t *testing.T) {
	spec := parse(t, publishSpec(publishBlock("http", "host = 8096")))
	got := spec.Services[0].Network.Publish
	if len(got) != 1 {
		t.Fatalf("publish = %+v, want 1", got)
	}
	if got[0].Host != 8096 || got[0].Port != "http" {
		t.Errorf("publish = %+v", got[0])
	}
	// http is the default, and the default is resolved in one place.
	if got[0].ResolvedMode() != jobspec.PublishHTTP {
		t.Errorf("mode = %q, want http", got[0].ResolvedMode())
	}
}

// A published port cannot name a port the service did not declare — there is
// no field for a container port number, so the label is the only way in.
func TestPublishRejectsAnUndeclaredPort(t *testing.T) {
	got := parseErr(t, publishSpec(publishBlock("grpc", "host = 9000")))
	if !strings.Contains(got, "names no declared port") {
		t.Errorf("diagnostics = %q", got)
	}
}

func TestPublishRejectsAnInvalidBlock(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{"port zero", publishBlock("http", "host = 0"), "a TCP port is 1 to 65535"},
		{"port too high", publishBlock("http", "host = 70000"), "a TCP port is 1 to 65535"},
		{"unknown mode", publishBlock("http", "host = 9000", `mode = "udp"`), "Unknown publish mode"},
		{
			"max_conns on http",
			publishBlock("http", "host = 9000", "max_conns = 10"),
			"It is a tcp setting",
		},
		{
			"negative max_conns",
			publishBlock("http", "host = 9000", `mode = "tcp"`, "max_conns = -1"),
			"must not be negative",
		},
		{
			"same port twice in one service",
			publishBlock("http", "host = 9000") + "\n    " + publishBlock("http", "host = 9000"),
			"Port published twice",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseErr(t, publishSpec(tc.body)); !strings.Contains(got, tc.want) {
				t.Errorf("diagnostics = %q, want it to name %q", got, tc.want)
			}
		})
	}
}

// R22's static half: Kanea holds these four whatever the node's range says, and
// the error names which of Kanea's own listeners is in the way.
func TestPublishRejectsAReservedPort(t *testing.T) {
	for port, reason := range jobspec.ReservedPorts {
		got := parseErr(t, publishSpec(publishBlock("http", "host = "+itoa(port))))
		if !strings.Contains(got, "Reserved port") || !strings.Contains(got, reason) {
			t.Errorf("port %d: diagnostics = %q, want the reason named", port, got)
		}
	}
}

// A control the edge would silently drop is refused rather than ignored. R16's
// rule read the other way round: a spec claiming a rate limit that nothing
// applies is worse than a spec that never claimed one.
func TestPublishRejectsMiddlewareATCPListenerCannotHonour(t *testing.T) {
	tests := []struct {
		name, body, want string
	}{
		{
			"rate_limit",
			publishBlock("http", "host = 5432", `mode = "tcp"`,
				"rate_limit {\n        requests = 10\n        window = \"1m\"\n      }"),
			"rate_limit",
		},
		{
			"headers",
			publishBlock("http", "host = 5432", `mode = "tcp"`,
				"headers {\n        request_set = { X-Real-IP = \"1\" }\n      }"),
			"headers",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseErr(t, publishSpec(tc.body))
			if !strings.Contains(got, "cannot honour") || !strings.Contains(got, tc.want) {
				t.Errorf("diagnostics = %q, want it to name %q", got, tc.want)
			}
		})
	}
}

// ip_restriction works on both kinds, and on a tcp listener it is the only
// ingress control there is.
func TestPublishAcceptsIPRestrictionOnATCPListener(t *testing.T) {
	spec := parse(t, publishSpec(publishBlock("http", "host = 5432", `mode = "tcp"`,
		"ip_restriction {\n        allow = [\"192.168.0.0/16\"]\n      }")))
	got := spec.Services[0].Network.Publish[0]
	if got.IPRestriction == nil || len(got.IPRestriction.Allow) != 1 {
		t.Errorf("ip_restriction = %+v, want it carried through", got.IPRestriction)
	}
}

// The middleware validators are the expose block's own, so their errors have to
// be the same errors — with the publish block named instead.
func TestPublishReusesTheMiddlewareValidators(t *testing.T) {
	got := parseErr(t, publishSpec(publishBlock("http", "host = 9000",
		"ip_restriction {\n        allow = [\"10.0.0.0/33\"]\n      }")))
	if !strings.Contains(got, "Invalid CIDR") {
		t.Errorf("diagnostics = %q, want the shared CIDR error", got)
	}
	if !strings.Contains(got, `publish "http"`) {
		t.Errorf("diagnostics = %q, want the publish block named", got)
	}
}

// A node has one of each port. Two specs are each individually fine and the
// collision is between them, which is why this is a whole-set check.
func TestPublishRejectsAPortClaimedByTwoServices(t *testing.T) {
	src := `
spec_version = 1

project "media" {}

service "jellyfin" {
  project = "media"
  task "app" { image = "jellyfin:10.9" }
  network {
    port "http" { container = 8096 }
    publish "http" {
      host = 8096
    }
  }
}

service "plex" {
  project = "media"
  task "app" { image = "plex:1.40" }
  network {
    port "http" { container = 32400 }
    publish "http" {
      host = 8096
    }
  }
}
`
	got := parseErr(t, src)
	if !strings.Contains(got, "Node port claimed twice") {
		t.Errorf("diagnostics = %q", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
