package main

// Wiring tests for the directory verifier (PRD v1.47): construction and
// nil-safety only. Verification behaviour lives in internal/auth's tests; what
// can go wrong here is the assembly: a typed nil reaching an interface field,
// a bind password in argv, or a config error demoted to a warning.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// validLDAPSettings is a full configuration buildLDAP accepts, pointing at an
// address nothing answers on: reachability is deliberately not construction's
// problem.
func validLDAPSettings() ldapSettings {
	return ldapSettings{
		url:         "ldaps://127.0.0.1:1",
		userBaseDN:  "ou=people,dc=example,dc=test",
		userFilter:  "(uid=%s)",
		adminGroups: []string{"cn=admins,ou=groups,dc=example,dc=test"},
	}
}

func TestBuildLDAPWithNothingConfiguredIsNil(t *testing.T) {
	directory, err := buildLDAP(context.Background(), ldapSettings{}, nil,
		slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("buildLDAP with no settings: %v", err)
	}
	if directory != nil {
		t.Fatalf("buildLDAP with no settings = %+v, want nil", directory)
	}

	// The typed-nil lesson (the buildOIDC rule): the auth store decides
	// whether directory fallthrough exists by comparing its PasswordVerifier
	// field against nil, and a nil *auth.LDAP stuffed straight into it would
	// be a non-nil interface holding a nil pointer; every unknown name would
	// then reach Verify and panic. The INTERFACE must be nil.
	if v := ldapVerifier(directory); v != nil {
		t.Fatalf("ldapVerifier(nil) = %#v, want a nil interface", v)
	}
	if name := ldapServerName(directory); name != "" {
		t.Fatalf("ldapServerName(nil) = %q, want empty", name)
	}
}

func TestBuildLDAPWarnsOnHalfAConfiguration(t *testing.T) {
	// Settings without --ldap-url mean the operator set LDAP up and is not
	// getting LDAP: worth a line, not an error, and definitely not a
	// half-built verifier.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	directory, err := buildLDAP(context.Background(),
		ldapSettings{userBaseDN: "ou=people,dc=example,dc=test"}, nil, logger)
	if err != nil || directory != nil {
		t.Fatalf("half-configured buildLDAP = %+v, %v; want nil, nil", directory, err)
	}
	if !strings.Contains(buf.String(), "--ldap-url") {
		t.Errorf("no warning naming --ldap-url was logged: %s", buf.String())
	}
}

func TestBuildLDAPRefusesABareBindPassword(t *testing.T) {
	// R3: everything in argv is world-readable through /proc/<pid>/cmdline, so
	// the flag takes a secret: reference and nothing else. The refusal fires
	// before any store access: a nil secrets store must not change the answer.
	cfg := validLDAPSettings()
	cfg.bindDN = "cn=svc,dc=example,dc=test"
	cfg.bindRef = "hunter2-not-a-reference"

	_, err := buildLDAP(context.Background(), cfg, nil, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("a literal bind password was accepted")
	}
	// The error meets the operator in front of the flag they typed.
	if !strings.Contains(err.Error(), "--ldap-bind-password") {
		t.Errorf("error does not name the flag: %v", err)
	}
	if !strings.Contains(err.Error(), "secret:") {
		t.Errorf("error does not say what the flag takes: %v", err)
	}
}

func TestBuildLDAPCannotResolveWithoutASecretsStore(t *testing.T) {
	cfg := validLDAPSettings()
	cfg.bindDN = "cn=svc,dc=example,dc=test"
	cfg.bindRef = "secret:shared/ldap-bind"

	_, err := buildLDAP(context.Background(), cfg, nil, slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "secrets store") {
		t.Fatalf("a well-formed reference with no store = %v, want a refusal naming the store", err)
	}
}

func TestBuildLDAPSurfacesAConfigRefusal(t *testing.T) {
	// Validation is hard (the OIDC rule): a config error refuses at startup in
	// front of the operator rather than becoming a daemon that cannot log
	// anyone in.
	cfg := validLDAPSettings()
	cfg.userBaseDN = ""

	_, err := buildLDAP(context.Background(), cfg, nil, slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "user base DN") {
		t.Fatalf("buildLDAP without a user base DN = %v, want NewLDAP's refusal", err)
	}
}

func TestBuildLDAPToleratesAnUnreachableDirectory(t *testing.T) {
	// Connection is soft, deliberately split from validation (§3.20): an
	// unreachable directory is weather, and must not keep kanead down.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	directory, err := buildLDAP(context.Background(), validLDAPSettings(), nil, logger)
	if err != nil {
		t.Fatalf("an unreachable directory refused startup: %v", err)
	}
	if directory == nil {
		t.Fatal("an unreachable directory produced no verifier")
	}
	if v := ldapVerifier(directory); v == nil {
		t.Error("ldapVerifier on a built directory = nil")
	}
	if name := ldapServerName(directory); name != "ldaps://127.0.0.1:1" {
		t.Errorf("ldapServerName = %q, want the configured URL", name)
	}
	if !strings.Contains(buf.String(), "unreachable") {
		t.Errorf("no reachability warning was logged: %s", buf.String())
	}
}

func TestLDAPSettingsConfigured(t *testing.T) {
	// Any one flag counts: configured() is what decides whether "no --ldap-url"
	// deserves the half-configuration warning.
	tests := []struct {
		name string
		cfg  ldapSettings
		want bool
	}{
		{"nothing set", ldapSettings{}, false},
		{"url", ldapSettings{url: "ldaps://dc.example.test"}, true},
		{"bind dn", ldapSettings{bindDN: "cn=svc,dc=example,dc=test"}, true},
		{"bind ref", ldapSettings{bindRef: "secret:shared/ldap-bind"}, true},
		{"user base dn", ldapSettings{userBaseDN: "ou=people,dc=example,dc=test"}, true},
		{"user filter", ldapSettings{userFilter: "(uid=%s)"}, true},
		{"group base dn", ldapSettings{groupBaseDN: "ou=groups,dc=example,dc=test"}, true},
		{"group filter", ldapSettings{groupFilter: "(member=%s)"}, true},
		{"admin groups", ldapSettings{adminGroups: []string{"cn=admins"}}, true},
		{"viewer groups", ldapSettings{viewerGroups: []string{"cn=viewers"}}, true},
		{"ca file", ldapSettings{caFile: "/etc/kanea/ldap-ca.pem"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.configured(); got != tc.want {
				t.Errorf("configured() = %v, want %v", got, tc.want)
			}
		})
	}
}
