package jobspec_test

// Env groups and mounted files (PRD v1.85, §6.2 R34/R35).

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/secrets"
)

func parseSpec(t *testing.T, src string) (*jobspec.Spec, hcl.Diagnostics) {
	t.Helper()
	return jobspec.ParseSource(jobspec.Options{}, "shop.hcl", []byte(src))
}

// oneFile wraps a file block in a minimal one-service spec.
func oneFile(body string) string {
	return `spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  file "f" {
` + body + `
  }
  task "app" {
    image = "nginx:1.27"
  }
}
`
}

// --- the rule constraint #4 rests on -------------------------------------

// TestASecretValueNeverEntersTheRecord is the most important test here. A file
// interpolating a secret must carry a placeholder and a reference, never the
// value: the record is CDC-replicated, lands in every backup archive, and is
// readable over GET /v1/services.
func TestASecretValueNeverEntersTheRecord(t *testing.T) {
	spec, diags := parseSpec(t, oneFile(`    path    = "/etc/app/pgpass"
    mode    = "0400"
    content = "db:5432:app:${secret.shop["database-password"]}"`))
	if diags.HasErrors() {
		t.Fatalf("refused: %s", jobspec.FormatDiagnostics(diags))
	}
	f := spec.ServiceByName("shop", "web").Files[0]

	if len(f.SecretRefs) != 1 || f.SecretRefs[0] != "secret:shop/database-password" {
		t.Fatalf("refs = %v, want [secret:shop/database-password]", f.SecretRefs)
	}
	if f.Nonce == "" {
		t.Fatal("no nonce; placeholders would be predictable and therefore forgeable")
	}
	body, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), "secret:shop/database-password") {
		t.Error("the reference did not survive into the record")
	}
	if !strings.Contains(string(f.Content), secrets.PlaceholderText(f.Nonce, 0)) {
		t.Errorf("content carries no placeholder: %q", f.Content)
	}
}

// TestAPlaceholderCannotBeForged: content that contains a marker with a guessed
// nonce renders verbatim, because the real nonce is drawn after the content is
// read and only that one is substituted.
func TestAPlaceholderCannotBeForged(t *testing.T) {
	spec, diags := parseSpec(t, oneFile(`    path    = "/etc/app/f"
    content = "before kanea:secret:GUESS:0 after${secret.shop["real"]}"`))
	if diags.HasErrors() {
		t.Fatalf("refused: %s", jobspec.FormatDiagnostics(diags))
	}
	f := spec.ServiceByName("shop", "web").Files[0]

	if len(f.SecretRefs) != 1 || f.SecretRefs[0] != "secret:shop/real" {
		t.Fatalf("refs = %v; a forged marker must not add one", f.SecretRefs)
	}
	// Stripping this file's own placeholders leaves the forged text behind: it
	// is content, not a placeholder.
	left := secrets.StripPlaceholders(f.Content, f.Nonce, len(f.SecretRefs))
	if !strings.Contains(string(left), "kanea:secret:GUESS:0") {
		t.Errorf("the forged marker was consumed as a placeholder: %q", left)
	}
	// And a forger who guessed the *real* nonce could still only select an
	// index of a reference list every entry of which was R5-scoped at parse.
	if got := secrets.StripPlaceholders([]byte(secrets.PlaceholderText("wrong", 0)),
		f.Nonce, len(f.SecretRefs)); len(got) == 0 {
		t.Error("a placeholder with the wrong nonce was stripped; it must be left alone")
	}
}

// TestNULInContentIsRefused is the other half of unforgeability: with the byte
// refused, no author-supplied text can form a placeholder at all. It is checked
// at the apply seam most of all, where content arrives base64-encoded and a NUL
// is perfectly expressible.
func TestNULInContentIsRefused(t *testing.T) {
	withNUL := []byte("a" + string(rune(0)) + "b")
	if err := jobspec.CheckFileContent("f", withNUL, "", 0); err == nil {
		t.Fatal("content containing a NUL was accepted")
	} else if !strings.Contains(err.Error(), "NUL") {
		t.Errorf("the refusal should name the byte; got %v", err)
	}
	if err := jobspec.CheckFileContent("f", []byte("plain text"), "", 0); err != nil {
		t.Errorf("ordinary content was refused: %v", err)
	}
}

// TestTwoParsesDifferInNonceButNotInCanonicalForm. The nonce must be fresh (or
// a placeholder is predictable) and must canonicalise away (or an unchanged
// spec re-hashes and rolls every file-bearing service on every apply).
func TestTwoParsesDifferInNonceButNotInCanonicalForm(t *testing.T) {
	src := oneFile(`    path    = "/etc/app/f"
    content = "x=${secret.shop["k"]}"`)
	first, d1 := parseSpec(t, src)
	second, d2 := parseSpec(t, src)
	if d1.HasErrors() || d2.HasErrors() {
		t.Fatal("refused a valid spec")
	}
	a := first.ServiceByName("shop", "web").Files[0]
	b := second.ServiceByName("shop", "web").Files[0]

	if a.Nonce == b.Nonce {
		t.Error("two parses share a nonce; placeholders would be predictable")
	}
	canonA := secrets.CanonicalPlaceholders(a.Content, a.Nonce, len(a.SecretRefs))
	canonB := secrets.CanonicalPlaceholders(b.Content, b.Nonce, len(b.SecretRefs))
	if string(canonA) != string(canonB) {
		t.Errorf("canonical forms differ:\n  %q\n  %q\nan unchanged spec would roll every "+
			"file-bearing service on every apply", canonA, canonB)
	}
}

// TestACrossProjectSecretInAFileIsRefused (R5, at the point of use).
func TestACrossProjectSecretInAFileIsRefused(t *testing.T) {
	_, diags := parseSpec(t, oneFile(`    path    = "/etc/app/f"
    mode    = "0400"
    content = "x=${secret.other["k"]}"`))
	if !diags.HasErrors() {
		t.Fatal("a file read another project's secret")
	}
	if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, "another project") {
		t.Errorf("want a cross-project refusal; got %s", got)
	}
}

// --- refusals ------------------------------------------------------------

func TestFileRefusalsNameTheProblem(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"relative path", `    path = "etc/app.conf"`, "must be absolute"},
		{"dotdot", `    path = "/etc/../etc/app.conf"`, "must be clean"},
		{"root", `    path = "/"`, "replace the root"},
		{"proc", `    path = "/proc/self/environ"`, "under /proc"},
		{"resolv.conf", `    path = "/etc/resolv.conf"`, "internal zone"},
		{"executable mode", "    path = \"/etc/a\"\n    mode = \"0755\"", "executable"},
		{"setuid", "    path = \"/etc/a\"\n    mode = \"4644\"", "setuid"},
		{"owner-only, no secret", "    path = \"/etc/a\"\n    mode = \"0600\"", "is a secret"},
		{"absolute source", "    path = \"/etc/a\"\n    source = \"/etc/shadow\"", "must be relative"},
		{"escaping source", "    path = \"/etc/a\"\n    source = \"../../etc/shadow\"", "may not leave"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if !strings.Contains(body, "source") {
				body += "\n    content = \"x\""
			}
			_, diags := parseSpec(t, oneFile(body))
			if !diags.HasErrors() {
				t.Fatal("expected a refusal, got none")
			}
			if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, tc.want) {
				t.Errorf("want substring %q; got %s", tc.want, got)
			}
		})
	}
}

// TestSourceIsRefusedWithoutAReader is the security property in test form: the
// dashboard's spec editor and MCP parse inside kanead as root and supply no
// reader, so `source` must refuse rather than read the node's filesystem.
func TestSourceIsRefusedWithoutAReader(t *testing.T) {
	_, diags := parseSpec(t, oneFile(`    path   = "/etc/app/f"
    source = "config.yaml"`))
	if !diags.HasErrors() {
		t.Fatal("source was accepted with no reader; a parse inside kanead would have " +
			"read the node's filesystem")
	}
	if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, "without a directory") {
		t.Errorf("the refusal should explain why; got %s", got)
	}
}

func TestContentAndSourceAreMutuallyExclusive(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"both", "    path = \"/etc/a\"\n    content = \"x\"\n    source = \"a.conf\"", "content and source"},
		{"neither", `    path = "/etc/a"`, "must set content or source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, diags := parseSpec(t, oneFile(tc.body))
			if !diags.HasErrors() {
				t.Fatal("expected a refusal")
			}
			if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, tc.want) {
				t.Errorf("want %q; got %s", tc.want, got)
			}
		})
	}
}

// TestAFileMayNotCollideWithAVolume: two things on one path means one of them
// silently wins, whichever kind they are.
func TestAFileMayNotCollideWithAVolume(t *testing.T) {
	_, diags := parseSpec(t, `spec_version = 1
project "shop" {}
storage "d" {
  type = "local"
}
service "web" {
  project = "shop"
  volume "data" {
    storage    = "d"
    mount_path = "/data"
  }
  file "f" {
    path    = "/data"
    content = "x"
  }
  task "app" {
    image = "nginx:1.27"
  }
}
`)
	if !diags.HasErrors() {
		t.Fatal("a file mounting on a volume path was accepted")
	}
	if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, "already mounted") {
		t.Errorf("the refusal should say so; got %s", got)
	}
}

func TestFileContentIsCapped(t *testing.T) {
	big := strings.Repeat("x", jobspec.MaxFileBytes+1)
	_, diags := parseSpec(t, oneFile(`    path    = "/etc/app/f"
    content = "`+big+`"`))
	if !diags.HasErrors() {
		t.Fatal("oversized content was accepted")
	}
	if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, "too large") {
		t.Errorf("want a size refusal; got %s", got)
	}
}

// TestALiteralDollarBraceSurvives. nginx and prometheus configs are full of
// ${...}; the literal form is $${...}, and getting it wrong is the first thing
// anyone will hit.
func TestALiteralDollarBraceSurvives(t *testing.T) {
	spec, diags := parseSpec(t, oneFile(`    path    = "/etc/nginx/app.conf"
    content = "proxy_set_header Host $${host};"`))
	if diags.HasErrors() {
		t.Fatalf("refused: %s", jobspec.FormatDiagnostics(diags))
	}
	got := string(spec.ServiceByName("shop", "web").Files[0].Content)
	if got != "proxy_set_header Host ${host};" {
		t.Errorf("content = %q, want the literal dollar-brace", got)
	}
}

// TestAFileMayNotCollideWithASocket: sockets are the other thing that can hold
// a path, and the collision diagnostic must not depend on which kind got there
// first.
func TestAFileMayNotCollideWithASocket(t *testing.T) {
	_, diags := parseSpec(t, `spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  file "f" {
    path    = "/var/run/docker.sock"
    content = "x"
  }
  task "app" {
    image = "nginx:1.27"
    socket "rt" {
      grant      = "runtime"
      mount_path = "/var/run/docker.sock"
    }
  }
}
`)
	if !diags.HasErrors() {
		t.Fatal("a file mounting on a socket's path was accepted")
	}
	if got := jobspec.FormatDiagnostics(diags); !strings.Contains(got, "already mounted") {
		t.Errorf("the refusal should say so; got %s", got)
	}
}

// TestTwoFilesMayNotShareAPath, for the same reason.
func TestTwoFilesMayNotShareAPath(t *testing.T) {
	_, diags := parseSpec(t, `spec_version = 1
project "shop" {}
service "web" {
  project = "shop"
  file "a" {
    path    = "/etc/app.conf"
    content = "1"
  }
  file "b" {
    path    = "/etc/app.conf"
    content = "2"
  }
  task "app" {
    image = "nginx:1.27"
  }
}
`)
	if !diags.HasErrors() {
		t.Fatal("two files on one path were accepted")
	}
}

// TestTheDocumentedHeredocExampleParses drives the exact example README.md and
// site/docs/index.html print for a multi-line `file` body.
//
// It is here because a documentation example nobody has parsed is a claim, not
// a fact, and this one makes three at once: that a heredoc interpolates like a
// quoted string (it is a template expression either way, evaluated against the
// same EvalContext), that `${service.…}` and `${secret.…}` coexist in one file,
// and that `$${…}` survives as a literal for content with template syntax of
// its own. Change the docs, change this; that is the point of it.
func TestTheDocumentedHeredocExampleParses(t *testing.T) {
	const src = `spec_version = 1
project "shop" {}

service "api" {
  project = "shop"
  network {
    port "http" { container = 8080 }
  }
  task "app" {
    image = "nginx:1.27"
  }
}

service "web" {
  project = "shop"

  file "app-config" {
    path    = "/etc/app/config.yaml"
    content = <<-EOT
      server:
        addr: ":8080"
        upstream: "${service.api.host}:${service.api.port.http}"
      database:
        dsn: "postgres://app:${secret.shop["database-password"]}@db:5432/app"
      log:
        # a literal dollar-brace the app expands itself
        format: "$${level} $${msg}"
    EOT
  }

  task "app" {
    image = "nginx:1.27"
  }
}
`
	spec, diags := parseSpec(t, src)
	if diags.HasErrors() {
		t.Fatalf("the documented example does not parse: %v", diags)
	}

	var file *jobspec.File
	for _, svc := range spec.Services {
		if svc.Name != "web" {
			continue
		}
		for _, f := range svc.Files {
			if f.Name == "app-config" {
				file = f
			}
		}
	}
	if file == nil {
		t.Fatal("the file block did not survive parsing")
	}

	// The multi-line body is a body, not one line with escapes in it.
	if strings.Count(string(file.Content), "\n") < 6 {
		t.Fatalf("content is not multi-line:\n%q", file.Content)
	}
	// The service reference resolved; the secret did not, and must not have.
	if !strings.Contains(string(file.Content), "api.shop.kanea:8080") {
		t.Errorf("the service reference did not resolve:\n%s", file.Content)
	}
	if strings.Contains(string(file.Content), "database-password") {
		t.Errorf("a secret reference was resolved into the content:\n%s", file.Content)
	}
	if len(file.SecretRefs) != 1 || file.SecretRefs[0] != "secret:shop/database-password" {
		t.Errorf("secret refs = %v, want the one reference the file names", file.SecretRefs)
	}
	// The escaped dollar-brace is content, not interpolation.
	if !strings.Contains(string(file.Content), "${level} ${msg}") {
		t.Errorf("$${…} did not survive as a literal:\n%s", file.Content)
	}
	// The mode stays unset in the spec: which default applies is decided on
	// the node, from whether the file carries references, so what the parser
	// owes is the reference list checked above. The docs' claim that one
	// credential line makes the whole file 0400 rests on that list being
	// non-empty, not on a mode written here.
	if file.Mode != "" {
		t.Errorf("mode = %q, want it left for the node to default", file.Mode)
	}
}
