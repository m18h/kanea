package secretsource

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile writes a file with the given mode and returns its path.
func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile does not chmod an existing file, and umask can narrow the
	// requested mode; set it explicitly so the test means what it says.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// minimalConfig is a valid one-provider config over the given token file.
func minimalConfig(tokenFile string) string {
	return fmt.Sprintf(`
provider "doppler" "ci" {
  token_file = %q
  project    = "backend"
  config     = "prd"
  allow      = ["shop"]
  sync {
    name = "DATABASE_URL"
    to   = "shop/db-url"
  }
}
`, tokenFile)
}

func TestParseAcceptsAFullConfig(t *testing.T) {
	dir := t.TempDir()
	token := writeFile(t, dir, "token", "t", 0o600)
	src := fmt.Sprintf(`
provider "doppler" "ci" {
  token_file = %[1]q
  project    = "backend"
  config     = "prd"
  allow      = ["shop", "shared"]
  sync {
    name = "DATABASE_URL"
    to   = "shop/db-url"
  }
  sync {
    name = "SHARED_KEY"
    to   = "shared/api-key"
  }
}
provider "vault" "infra" {
  address    = "https://vault.internal:8200"
  token_file = %[1]q
  mount      = "kv"
  allow      = ["media"]
  sync {
    path  = "apps/media"
    field = "s3_secret_key"
    to    = "media/s3-secret"
  }
}
provider "aws-sm" "prod" {
  region          = "eu-west-1"
  access_key      = "AKIAEXAMPLE"
  secret_key_file = %[1]q
  allow           = ["shop"]
  sync {
    id       = "prod/shop/db"
    json_key = "password"
    to       = "shop/db-password"
  }
}
provider "azure-kv" "corp" {
  vault_uri          = "https://corp.vault.azure.net"
  tenant_id          = "tenant"
  client_id          = "client"
  client_secret_file = %[1]q
  allow              = ["shop"]
  sync {
    name = "kv-secret"
    to   = "shop/kv-secret"
  }
}
provider "gcp-sm" "gcp" {
  credentials_file = %[1]q
  allow            = ["shop"]
  sync {
    name = "gcp-secret"
    to   = "shop/gcp-secret"
  }
}
`, token)
	configs, err := parseConfig("test.hcl", []byte(src))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if len(configs) != 5 {
		t.Fatalf("parsed %d providers, want 5", len(configs))
	}
	// Defaults applied where the schema promises them.
	if got := configs[2].maps[0].VersionStage; got != "AWSCURRENT" {
		t.Errorf("aws version_stage default = %q", got)
	}
	if got := configs[4].maps[0].Version; got != "latest" {
		t.Errorf("gcp version default = %q", got)
	}
}

// dopplerBlock renders a doppler provider with the given attribute lines and
// sync body, for the refusal table.
func dopplerBlock(attrs, sync string) string {
	return "provider \"doppler\" \"ci\" {\n" +
		"  token_file = \"/t\"\n  project = \"p\"\n  config = \"c\"\n" +
		attrs + "\n  sync {\n" + sync + "\n  }\n}\n"
}

// Every refusal is by name: a config error is met by an operator, and
// "invalid" is not something they can act on.
func TestParseRefusesByName(t *testing.T) {
	cases := map[string]struct {
		src  string
		want string
	}{
		"unknown kind": {
			src: "provider \"consul\" \"x\" {\n  allow = [\"shop\"]\n" +
				"  sync {\n    name = \"a\"\n    to = \"shop/a\"\n  }\n}\n",
			want: "unknown kind",
		},
		"duplicate provider name": {
			src: dopplerBlock(`  allow = ["shop"]`, "    name = \"a\"\n    to = \"shop/a\"") +
				"provider \"vault\" \"ci\" {\n  token_file = \"/t\"\n  address = \"https://v\"\n" +
				"  mount = \"kv\"\n  allow = [\"shop\"]\n" +
				"  sync {\n    path = \"p\"\n    field = \"f\"\n    to = \"shop/b\"\n  }\n}\n",
			want: "defined twice",
		},
		"duplicate target across providers": {
			src: dopplerBlock(`  allow = ["shop"]`, "    name = \"a\"\n    to = \"shop/a\"") +
				"provider \"vault\" \"infra\" {\n  token_file = \"/t\"\n  address = \"https://v\"\n" +
				"  mount = \"kv\"\n  allow = [\"shop\"]\n" +
				"  sync {\n    path = \"p\"\n    field = \"f\"\n    to = \"shop/a\"\n  }\n}\n",
			want: "one local path has one writer",
		},
		"target outside allow": {
			src:  dopplerBlock(`  allow = ["shop"]`, "    name = \"a\"\n    to = \"media/a\""),
			want: "`allow` does not list",
		},
		"shared needs stating": {
			src:  dopplerBlock(`  allow = ["shop"]`, "    name = \"a\"\n    to = \"shared/a\""),
			want: "`allow` does not list",
		},
		"empty allow": {
			src:  dopplerBlock(`  allow = []`, "    name = \"a\"\n    to = \"shop/a\""),
			want: "no scopes in `allow`",
		},
		"relative token file": {
			src: "provider \"doppler\" \"ci\" {\n  token_file = \"t\"\n  project = \"p\"\n" +
				"  config = \"c\"\n  allow = [\"shop\"]\n" +
				"  sync {\n    name = \"a\"\n    to = \"shop/a\"\n  }\n}\n",
			want: "relative path",
		},
		"bad target path": {
			src:  dopplerBlock(`  allow = ["shop"]`, "    name = \"a\"\n    to = \"just-one-segment\""),
			want: "must be <project>/<name>",
		},
		"missing required field": {
			src: "provider \"vault\" \"infra\" {\n  token_file = \"/t\"\n  address = \"https://v\"\n" +
				"  allow = [\"shop\"]\n" +
				"  sync {\n    path = \"p\"\n    field = \"f\"\n    to = \"shop/a\"\n  }\n}\n",
			want: `missing "mount"`,
		},
		"field from another kind": {
			src:  dopplerBlock("  region = \"eu-west-1\"\n  allow = [\"shop\"]", "    name = \"a\"\n    to = \"shop/a\""),
			want: "not a doppler field",
		},
		"sync field from another kind": {
			src:  dopplerBlock(`  allow = ["shop"]`, "    name = \"a\"\n    json_key = \"k\"\n    to = \"shop/a\""),
			want: "not a doppler sync field",
		},
		"no sync blocks": {
			src: "provider \"doppler\" \"ci\" {\n  token_file = \"/t\"\n  project = \"p\"\n" +
				"  config = \"c\"\n  allow = [\"shop\"]\n}\n",
			want: "no sync blocks",
		},
		"endpoint is not a URL": {
			src: "provider \"vault\" \"infra\" {\n  token_file = \"/t\"\n" +
				"  address = \"vault.internal:8200\"\n  mount = \"kv\"\n  allow = [\"shop\"]\n" +
				"  sync {\n    path = \"p\"\n    field = \"f\"\n    to = \"shop/a\"\n  }\n}\n",
			want: "not an http(s) URL",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig("test.hcl", []byte(tc.src))
			if err == nil {
				t.Fatal("the config was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the problem (%q)", err, tc.want)
			}
		})
	}
}

// A rewritten credential file with the same size is still a change — the
// certbot lesson, applied to provider tokens.
func TestChangedSeesACredentialRewrite(t *testing.T) {
	dir := t.TempDir()
	token := writeFile(t, dir, "token", "aaaa", 0o600)
	config := writeFile(t, dir, "providers.hcl", minimalConfig(token), 0o644)

	p := NewProviders(config, nil, discardLogger())
	if !p.Changed() {
		t.Fatal("the first poll should report a change")
	}
	if p.Changed() {
		t.Fatal("an untouched config reported a change")
	}
	// Same length, same file, new content.
	writeFile(t, dir, "token", "bbbb", 0o600)
	if !p.Changed() {
		t.Fatal("a rewritten token file went unnoticed")
	}
}

// A half-saved config keeps the last set that built, and complains once.
func TestCurrentKeepsTheLastGoodConfig(t *testing.T) {
	dir := t.TempDir()
	token := writeFile(t, dir, "token", "t", 0o600)
	config := writeFile(t, dir, "providers.hcl", minimalConfig(token), 0o644)

	p := NewProviders(config, nil, discardLogger())
	if got := p.Current(); len(got) != 1 {
		t.Fatalf("Current = %d providers, want 1", len(got))
	}

	writeFile(t, dir, "providers.hcl", `provider "doppler" {`, 0o644)
	if got := p.Current(); len(got) != 1 {
		t.Fatalf("a broken config dropped the working providers (got %d)", len(got))
	}
}

// Provider instances survive an unchanged pass — that is what keeps Azure's
// and GCP's cached tokens alive between passes — and a credential rewrite
// rebuilds them, which is what drops a cache built on a rotated secret.
func TestCurrentRebuildsOnlyOnAChange(t *testing.T) {
	dir := t.TempDir()
	token := writeFile(t, dir, "token", "t", 0o600)
	config := writeFile(t, dir, "providers.hcl", minimalConfig(token), 0o644)

	p := NewProviders(config, nil, discardLogger())
	first := p.Current()
	second := p.Current()
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("Current = %d, %d providers, want 1 each", len(first), len(second))
	}
	if first[0] != second[0] {
		t.Error("an unchanged config rebuilt the providers")
	}

	writeFile(t, dir, "token", "rotated", 0o600)
	third := p.Current()
	if len(third) != 1 {
		t.Fatalf("Current = %d providers after rotation", len(third))
	}
	if third[0] == first[0] {
		t.Error("a rotated credential did not rebuild the providers")
	}
}

func TestUnconfiguredProvidersDoNothing(t *testing.T) {
	p := NewProviders("", nil, discardLogger())
	if p.Configured() {
		t.Error("an empty path reports configured")
	}
	if p.Changed() {
		t.Error("an empty path reports changes")
	}
	if got := p.Current(); got != nil {
		t.Errorf("an empty path serves providers: %v", got)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
