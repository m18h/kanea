package auth_test

// Session.Method wire-format compatibility (PRD v1.47). The field is new;
// the records are not: a Store full of pre-v1.47 sessions must keep working,
// and re-serialising an old record must not change its bytes (the R23 lesson).

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/auth"
)

func TestAPreV147SessionReadsAsALocalLogin(t *testing.T) {
	// Exactly what a pre-v1.47 record looks like: no method key at all. An
	// absent value must read as the local path, because every session that
	// existed before the field did was a local password login.
	raw := `{"hash":"abc","subject":"ada","role":"admin",` +
		`"created":"2026-06-01T12:00:00Z","expires":"2026-06-02T00:00:00Z","csrf":"tok"}`

	var s auth.Session
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("unmarshal a pre-v1.47 session: %v", err)
	}
	if s.Method != "" {
		t.Errorf("Method = %q, want empty for an old record", s.Method)
	}
	if s.Via() != auth.MethodSession {
		t.Errorf("Via() = %q, want %q", s.Via(), auth.MethodSession)
	}
	if s.Subject != "ada" || s.Role != auth.RoleAdmin {
		t.Errorf("the rest of the record did not survive: %+v", s)
	}
}

func TestASessionCarriesItsMethodOnTheWire(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	s, _, err := auth.NewSession("dirk", auth.RoleViewer, auth.MethodLDAP, now)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if s.Via() != auth.MethodLDAP {
		t.Fatalf("Via() = %q, want ldap", s.Via())
	}

	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"method":"ldap"`) {
		t.Errorf(`serialised session lacks "method":"ldap": %s`, raw)
	}
}

func TestAnEmptyMethodSerialisesToNothing(t *testing.T) {
	// omitempty is load-bearing (the R23 lesson): a session with no method
	// must serialise byte-identically to a pre-v1.47 one, so an upgrade never
	// rewrites what an old record means, and Via() fills the gap at read time.
	s := auth.Session{
		Hash: "abc", Subject: "ada", Role: auth.RoleAdmin,
		Created: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		Expires: time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC),
		CSRF:    "tok",
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "method") {
		t.Errorf("an empty method reached the wire: %s", raw)
	}
	if s.Via() != auth.MethodSession {
		t.Errorf("Via() on the zero method = %q, want %q", s.Via(), auth.MethodSession)
	}
}
