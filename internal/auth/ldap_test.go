package auth

// LDAP tests (PRD v1.47). These live in the package's internal test package,
// unlike auth_test.go: roleFor is deliberately unexported (nothing outside
// Verify needs it) and testing the mapping directly beats simulating a whole
// directory for every row of the table.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// validLDAPConfig is a configuration NewLDAP accepts. Each refusal test breaks
// exactly one thing in it, so a failure names the rule that stopped working.
func validLDAPConfig() LDAPConfig {
	return LDAPConfig{
		URL:         "ldaps://dc.example.test:636",
		UserBaseDN:  "ou=people,dc=example,dc=test",
		UserFilter:  "(uid=%s)",
		AdminGroups: []string{"cn=admins,ou=groups,dc=example,dc=test"},
	}
}

func TestNewLDAPRefusesWhatItCannotRun(t *testing.T) {
	garbageCA := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(garbageCA, []byte("this is not PEM"), 0o600); err != nil {
		t.Fatalf("write garbage CA: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*LDAPConfig)
		wantErr string // empty means the configuration is accepted
	}{
		{
			// Cleartext LDAP would carry the user's actual password; there is
			// no insecure flag, so the scheme is where that door closes.
			name:    "an http URL is refused",
			mutate:  func(c *LDAPConfig) { c.URL = "http://dc.example.test" },
			wantErr: "must be ldaps",
		},
		{
			name:    "a URL with no host is refused",
			mutate:  func(c *LDAPConfig) { c.URL = "ldaps://" },
			wantErr: "has no host",
		},
		{
			name:    "a missing user base DN is refused",
			mutate:  func(c *LDAPConfig) { c.UserBaseDN = "" },
			wantErr: "user base DN",
		},
		{
			// A filter with no placeholder would search for the same literal
			// entry whoever logs in.
			name:    "a user filter without a placeholder is refused",
			mutate:  func(c *LDAPConfig) { c.UserFilter = "(uid=ada)" },
			wantErr: "exactly one %s",
		},
		{
			name:    "a user filter with two placeholders is refused",
			mutate:  func(c *LDAPConfig) { c.UserFilter = "(|(uid=%s)(cn=%s))" },
			wantErr: "exactly one %s",
		},
		{
			// Half a group search would silently fall back to memberOf and
			// look like it worked (the v1.41 all-or-none style).
			name:    "a group base without its filter is refused",
			mutate:  func(c *LDAPConfig) { c.GroupBaseDN = "ou=groups,dc=example,dc=test" },
			wantErr: "go together",
		},
		{
			name:    "a group filter without its base is refused",
			mutate:  func(c *LDAPConfig) { c.GroupFilter = "(member=%s)" },
			wantErr: "go together",
		},
		{
			name: "a group filter without a placeholder is refused",
			mutate: func(c *LDAPConfig) {
				c.GroupBaseDN = "ou=groups,dc=example,dc=test"
				c.GroupFilter = "(member=ada)"
			},
			wantErr: "exactly one %s",
		},
		{
			name:    "a bind DN without its password is refused",
			mutate:  func(c *LDAPConfig) { c.BindDN = "cn=svc,dc=example,dc=test" },
			wantErr: "go together",
		},
		{
			name:    "a bind password without its DN is refused",
			mutate:  func(c *LDAPConfig) { c.BindPassword = "hunter2-but-longer" },
			wantErr: "go together",
		},
		{
			// Deny-by-default: with no mapping, no directory login can ever
			// produce a role, and the refusal must say so up front rather
			// than let every login fail mysteriously at runtime.
			name: "zero role mappings are refused by name",
			mutate: func(c *LDAPConfig) {
				c.AdminGroups, c.ViewerGroups = nil, nil
			},
			wantErr: "every login is refused",
		},
		{
			name: "a missing CA file is refused",
			mutate: func(c *LDAPConfig) {
				c.CAFile = filepath.Join("/nonexistent", "ca.pem")
			},
			wantErr: "read --ldap-ca",
		},
		{
			// A CA file that parses to nothing would silently fall back to the
			// system pool, which is not what the operator asked for.
			name:    "a CA file holding no certificate is refused",
			mutate:  func(c *LDAPConfig) { c.CAFile = garbageCA },
			wantErr: "no usable CA certificate",
		},
		{
			name:   "ldaps is accepted",
			mutate: func(*LDAPConfig) {},
		},
		{
			// Construction accepts ldap:// because Verify forces StartTLS on
			// it; the wire is still TLS, just negotiated after connect.
			name:   "ldap is accepted with StartTLS forced later",
			mutate: func(c *LDAPConfig) { c.URL = "ldap://dc.example.test:389" },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validLDAPConfig()
			tc.mutate(&cfg)
			l, err := NewLDAP(cfg)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewLDAP refused a valid config: %v", err)
				}
				if l.Server() != cfg.URL {
					t.Errorf("Server() = %q, want %q", l.Server(), cfg.URL)
				}
				return
			}
			if err == nil {
				t.Fatal("NewLDAP accepted a config it cannot run")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestRoleForIsAdminFirstAndCaseInsensitive(t *testing.T) {
	// The config's DNs are deliberately case-mixed: directories are
	// inconsistent about the case they return, and DNs compare
	// case-insensitively.
	l, err := NewLDAP(LDAPConfig{
		URL:          "ldaps://dc.example.test:636",
		UserBaseDN:   "ou=people,dc=example,dc=test",
		UserFilter:   "(uid=%s)",
		AdminGroups:  []string{"CN=Admins,OU=Groups,DC=example,DC=test"},
		ViewerGroups: []string{"cn=viewers,ou=groups,dc=example,dc=test"},
	})
	if err != nil {
		t.Fatalf("NewLDAP: %v", err)
	}

	tests := []struct {
		name     string
		groups   []string
		wantRole Role
		wantOK   bool
	}{
		{
			// Admin first even when the viewer group comes earlier in the
			// membership: checking viewer first would demote every admin who
			// is also in a viewer group, which is most of them.
			name: "membership in both lists is admin",
			groups: []string{
				"cn=viewers,ou=groups,dc=example,dc=test",
				"CN=Admins,OU=Groups,DC=example,DC=test",
			},
			wantRole: RoleAdmin, wantOK: true,
		},
		{
			name:     "viewer membership alone is viewer",
			groups:   []string{"cn=viewers,ou=groups,dc=example,dc=test"},
			wantRole: RoleViewer, wantOK: true,
		},
		{
			// The directory returned lowercase; the config says CN=Admins.
			name:     "a case-flipped DN still matches",
			groups:   []string{"cn=admins,ou=groups,dc=example,dc=test"},
			wantRole: RoleAdmin, wantOK: true,
		},
		{
			name:     "an unmapped group is deny-by-default",
			groups:   []string{"cn=strangers,ou=groups,dc=example,dc=test"},
			wantRole: "", wantOK: false,
		},
		{
			name:     "no groups at all is deny-by-default",
			groups:   nil,
			wantRole: "", wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			role, ok := l.roleFor(tc.groups)
			if role != tc.wantRole || ok != tc.wantOK {
				t.Errorf("roleFor(%v) = (%q, %v), want (%q, %v)",
					tc.groups, role, ok, tc.wantRole, tc.wantOK)
			}
		})
	}
}

// blackholeAddr is an address that accepts a TCP connection and then says
// nothing: a dial "succeeds" instantly (kernel backlog) and the TLS handshake
// hangs until the configured timeout. That is what makes the timing assertion
// below meaningful: against a refused port, even a dial returns instantly.
func blackholeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// refusedAddr is an address nothing listens on: listen, note the port, close.
func refusedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

func TestVerifyRefusesAnEmptyPasswordBeforeDialing(t *testing.T) {
	// RFC 4513 §5.1.2: a bind with a DN and an empty password is an
	// "unauthenticated bind" many servers treat as anonymous success, so an
	// empty (or whitespace) password must be refused before the network is
	// touched; a directory's permissiveness must never become a login.
	cfg := validLDAPConfig()
	cfg.URL = "ldaps://" + blackholeAddr(t)
	cfg.Timeout = 3 * time.Second
	l, err := NewLDAP(cfg)
	if err != nil {
		t.Fatalf("NewLDAP: %v", err)
	}

	tests := []struct{ name, user, password string }{
		{"empty password", "ada", ""},
		{"whitespace password", "ada", "   "},
		{"tab and newline password", "ada", "\t\n"},
		{"empty name", "", "a-real-password"},
		{"oversized name", strings.Repeat("a", maxLDAPNameBytes+1), "a-real-password"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			_, _, err := l.Verify(context.Background(), tc.user, tc.password)
			elapsed := time.Since(start)

			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Verify = %v, want ErrUnauthenticated", err)
			}
			if errors.Is(err, ErrLDAPUnavailable) {
				t.Errorf("the refusal reads as an outage: %v", err)
			}
			// The blackhole makes a dial cost the full 3 s handshake timeout;
			// returning well inside that proves the network was never touched.
			if elapsed > 500*time.Millisecond {
				t.Errorf("Verify took %v: it dialed before refusing", elapsed)
			}
		})
	}
}

func TestVerifyReportsAnUnreachableDirectoryAsUnavailable(t *testing.T) {
	cfg := validLDAPConfig()
	cfg.URL = "ldaps://" + refusedAddr(t)
	cfg.Timeout = 2 * time.Second
	l, err := NewLDAP(cfg)
	if err != nil {
		t.Fatalf("NewLDAP: %v", err)
	}

	_, _, err = l.Verify(context.Background(), "ada", "a-real-password")
	if !errors.Is(err, ErrLDAPUnavailable) {
		t.Fatalf("Verify against a dead directory = %v, want ErrLDAPUnavailable", err)
	}
	// The distinction is the whole point of the second error: an outage is an
	// operational failure, never an authentication verdict, and the login path
	// keys "does this count against a lockout" on exactly this.
	if errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the outage also reads as an authentication verdict: %v", err)
	}

	// CheckConnection is the same weather report, for the startup warning.
	if err := l.CheckConnection(context.Background()); !errors.Is(err, ErrLDAPUnavailable) {
		t.Errorf("CheckConnection = %v, want ErrLDAPUnavailable", err)
	}
}

func TestFilterEscaping(t *testing.T) {
	// Pins the library behaviour findUser and groupsFor rely on: both
	// insertion points into a search filter pass through ldap.EscapeFilter, so
	// a typed name cannot rewrite the filter around itself (§14, A03 for LDAP).
	const hostile = `*)(uid=*`
	escaped := ldap.EscapeFilter(hostile)

	// RFC 4515: `*` → \2a, `)` → \29, `(` → \28; exactly these, as hex pairs.
	if escaped != `\2a\29\28uid=\2a` {
		t.Fatalf("EscapeFilter(%q) = %q, want %q", hostile, escaped, `\2a\29\28uid=\2a`)
	}

	filter := fmt.Sprintf("(uid=%s)", escaped)
	if filter != `(uid=\2a\29\28uid=\2a)` {
		t.Fatalf("assembled filter = %q", filter)
	}
	// The only metacharacters left are the template's own parentheses.
	inner := strings.TrimSuffix(strings.TrimPrefix(filter, "(uid="), ")")
	if strings.ContainsAny(inner, `*()`) {
		t.Errorf("a raw metacharacter survived escaping: %q", inner)
	}
}
