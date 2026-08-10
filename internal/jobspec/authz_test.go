package jobspec_test

// R27 (v1.40): the auth block — one mode, R5-scoped references, jwt key/alg
// consistency.

import (
	"strings"
	"testing"
)

func TestAuthAcceptsEachMode(t *testing.T) {
	specs := map[string]string{
		"basic": `auth { basic_ref = "secret:shop/users" }`,
		"bearer": `auth { bearer_ref = "secret:shop/tokens" }`,
		"jwt-hs256": `auth {
			jwt {
			  algorithm  = "HS256"
			  secret_ref = "secret:shop/jwt"
			}
		}`,
		"jwt-rs256": `auth {
			jwt {
			  algorithm      = "RS256"
			  public_key_ref = "secret:shop/jwt-pub"
			  issuer         = "https://issuer.test"
			  audience       = "web"
			}
		}`,
	}
	for name, authBlock := range specs {
		t.Run(name, func(t *testing.T) {
			parse(t, serviceWithExposeAuth(authBlock))
		})
	}
}

func TestAuthRefusals(t *testing.T) {
	tests := []struct {
		name string
		auth string
		want string
	}{
		{
			"two modes",
			`auth {
			   basic_ref  = "secret:shop/users"
			   bearer_ref = "secret:shop/tokens"
			 }`,
			"exactly one",
		},
		{
			"no mode",
			`auth {}`,
			"exactly one",
		},
		{
			"cross-project ref",
			`auth { basic_ref = "secret:other/users" }`,
			"project",
		},
		{
			"inlined credential",
			`auth { bearer_ref = "hunter2" }`,
			"not a secret reference",
		},
		{
			"unknown jwt algorithm",
			`auth {
			   jwt {
			     algorithm  = "none"
			     secret_ref = "secret:shop/jwt"
			   }
			 }`,
			"not one of",
		},
		{
			"hs256 with public key",
			`auth {
			   jwt {
			     algorithm      = "HS256"
			     public_key_ref = "secret:shop/pub"
			   }
			 }`,
			"does not match",
		},
		{
			"rs256 with secret",
			`auth {
			   jwt {
			     algorithm  = "RS256"
			     secret_ref = "secret:shop/jwt"
			   }
			 }`,
			"does not match",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseErr(t, serviceWithExposeAuth(tc.auth))
			if !strings.Contains(got, tc.want) {
				t.Errorf("diagnostics do not mention %q:\n%s", tc.want, got)
			}
		})
	}
}

// A function's http trigger carries the same block, validated the same way.
func TestFunctionHTTPTriggerAuth(t *testing.T) {
	parse(t, `
spec_version = 1
project "shop" {}

function "fn" {
  project = "shop"
  module  = "example.com/fn:1"
  trigger "http" {
    auth { bearer_ref = "secret:shop/tokens" }
  }
}
`)

	got := parseErr(t, `
spec_version = 1
project "shop" {}

function "fn" {
  project = "shop"
  module  = "example.com/fn:1"
  trigger "http" {
    auth {
      basic_ref  = "secret:shop/a"
      bearer_ref = "secret:shop/b"
    }
  }
}
`)
	if !strings.Contains(got, "exactly one") {
		t.Errorf("a function trigger with two auth modes was not refused:\n%s", got)
	}
}

// signing_ref is R5-scoped like every credential (R26, v1.40).
func TestFunctionSigningRef(t *testing.T) {
	parse(t, `
spec_version = 1
project "shop" {}

function "fn" {
  project     = "shop"
  module      = "example.com/fn:1"
  signing_ref = "secret:shop/sign"
  trigger "event" { on = ["deploy.failed"] }
}
`)

	got := parseErr(t, `
spec_version = 1
project "shop" {}

function "fn" {
  project     = "shop"
  module      = "example.com/fn:1"
  signing_ref = "secret:other/sign"
  trigger "event" { on = ["deploy.failed"] }
}
`)
	if !strings.Contains(got, "project") {
		t.Errorf("a cross-project signing_ref was not refused:\n%s", got)
	}
}

func serviceWithExposeAuth(authBlock string) string {
	return `
spec_version = 1
project "shop" {}

service "web" {
  project = "shop"
  task "app" { image = "nginx:1.29-alpine" }
  network {
    port "http" { container = 8080 }
  }
  expose {
    ` + authBlock + `
  }
}
`
}
