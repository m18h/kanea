package jobspec

// The `auth` block (PRD v1.40, §6.2 R27): request authentication on an
// `expose` block or a function's http trigger. Every field is a `secret:`
// reference (R3/R5) — the spec never carries a credential, a key or a path,
// and the node resolves references into the verifier material the edge is
// handed (R17's split, applied to authentication).

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

// JWT algorithms R27 accepts. A closed set, configured — never read from a
// token.
var jwtAlgorithms = map[string]bool{"HS256": true, "RS256": true, "ES256": true}

type hclAuth struct {
	BasicRef  string      `hcl:"basic_ref,optional"`
	BearerRef string      `hcl:"bearer_ref,optional"`
	JWT       *hclJWTAuth `hcl:"jwt,block"`
	DefRange  hcl.Range   `hcl:",def_range"`
}

type hclJWTAuth struct {
	Algorithm    string    `hcl:"algorithm"`
	SecretRef    string    `hcl:"secret_ref,optional"`
	PublicKeyRef string    `hcl:"public_key_ref,optional"`
	Issuer       string    `hcl:"issuer,optional"`
	Audience     string    `hcl:"audience,optional"`
	DefRange     hcl.Range `hcl:",def_range"`
}

// Auth is the domain form R27 validates.
type Auth struct {
	// BasicRef names a secret of htpasswd-format bcrypt lines.
	BasicRef string
	// BearerRef names a secret of accepted tokens, one per line. The edge is
	// published hashes of them, never the tokens.
	BearerRef string
	// JWT verifies tokens against a static key.
	JWT      *JWTAuth
	DefRange hcl.Range
}

// JWTAuth is R27's jwt block.
type JWTAuth struct {
	// Algorithm is HS256, RS256 or ES256.
	Algorithm string
	// SecretRef is the HS256 key; PublicKeyRef the RS256/ES256 PEM. Exactly
	// one, matched to the algorithm.
	SecretRef    string
	PublicKeyRef string
	// Issuer and Audience are required claim values when set.
	Issuer   string
	Audience string
	DefRange hcl.Range
}

func convertAuth(a *hclAuth) *Auth {
	if a == nil {
		return nil
	}
	out := &Auth{BasicRef: a.BasicRef, BearerRef: a.BearerRef, DefRange: a.DefRange}
	if j := a.JWT; j != nil {
		out.JWT = &JWTAuth{
			Algorithm: j.Algorithm, SecretRef: j.SecretRef, PublicKeyRef: j.PublicKeyRef,
			Issuer: j.Issuer, Audience: j.Audience, DefRange: j.DefRange,
		}
	}
	return out
}

// validateAuth is R27: exactly one mode, references R5-scoped, and a jwt
// block whose key kind matches its algorithm.
func validateAuth(svc *Service, a *Auth) hcl.Diagnostics {
	var diags hcl.Diagnostics

	modes := 0
	if a.BasicRef != "" {
		modes++
		diags = append(diags, checkSecretRef(a.BasicRef, svc.Project, "auth.basic_ref", a.DefRange)...)
	}
	if a.BearerRef != "" {
		modes++
		diags = append(diags, checkSecretRef(a.BearerRef, svc.Project, "auth.bearer_ref", a.DefRange)...)
	}
	if a.JWT != nil {
		modes++
		diags = append(diags, validateJWTAuth(svc, a.JWT)...)
	}
	if modes != 1 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Auth needs exactly one mode",
			Detail: fmt.Sprintf("Service %q declares %d auth modes; exactly one of basic_ref, "+
				"bearer_ref or a jwt block is required — two modes would be a fallback chain, "+
				"and a fallback in authentication is the weakest link wearing the strongest's name.",
				svc.Name, modes),
			Subject: a.DefRange.Ptr(),
		})
	}
	return diags
}

func validateJWTAuth(svc *Service, j *JWTAuth) hcl.Diagnostics {
	var diags hcl.Diagnostics
	bad := func(summary, detail string) {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError, Summary: summary, Detail: detail, Subject: j.DefRange.Ptr(),
		})
	}

	if !jwtAlgorithms[j.Algorithm] {
		bad("Unknown JWT algorithm",
			fmt.Sprintf("Service %q: algorithm %q is not one of HS256, RS256, ES256. "+
				"The algorithm is configuration — it is never read from a token.", svc.Name, j.Algorithm))
		return diags
	}

	// The key kind is the algorithm's: an HS256 with a public key or an RS256
	// with a shared secret is a config that cannot verify anything.
	switch j.Algorithm {
	case "HS256":
		if j.SecretRef == "" || j.PublicKeyRef != "" {
			bad("JWT key does not match the algorithm",
				fmt.Sprintf("Service %q: HS256 takes secret_ref and no public_key_ref.", svc.Name))
		}
	default: // RS256, ES256
		if j.PublicKeyRef == "" || j.SecretRef != "" {
			bad("JWT key does not match the algorithm",
				fmt.Sprintf("Service %q: %s takes public_key_ref and no secret_ref.", svc.Name, j.Algorithm))
		}
	}
	if j.SecretRef != "" {
		diags = append(diags, checkSecretRef(j.SecretRef, svc.Project, "auth.jwt.secret_ref", j.DefRange)...)
	}
	if j.PublicKeyRef != "" {
		diags = append(diags, checkSecretRef(j.PublicKeyRef, svc.Project, "auth.jwt.public_key_ref", j.DefRange)...)
	}
	return diags
}
