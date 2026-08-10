package reconciler_test

// R27 (v1.40): the auth projection — references resolved into verifier
// material, tokens reduced to hashes, and a route that fails to resolve left
// marked-without-material (503 at the edge) rather than dropped open.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/m18h/kanea/internal/edge"
	"github.com/m18h/kanea/internal/reconciler"
)

// fakeSecrets resolves refs from a map; a missing ref errors.
type fakeSecrets map[string][]byte

func (f fakeSecrets) Resolve(_ context.Context, ref string) ([]byte, error) {
	v, ok := f[ref]
	if !ok {
		return nil, errNoSecret(ref)
	}
	return v, nil
}

type errNoSecret string

func (e errNoSecret) Error() string { return "no such secret: " + string(e) }

// fakeAuthSink captures what the reconciler publishes.
type fakeAuthSink struct{ entries []edge.AuthEntry }

func (s *fakeAuthSink) SetAuth(entries []edge.AuthEntry) error {
	s.entries = entries
	return nil
}

func authHarness(t *testing.T, secrets fakeSecrets) (*harness, *fakeAuthSink) {
	t.Helper()
	sink := &fakeAuthSink{}
	h := newHarness(t, func(cfg *reconciler.Config) {
		cfg.EdgeSnapshot = t.TempDir() + "/routes.json"
		cfg.BaseDomain = "apps.test"
		cfg.Secrets = secrets
		cfg.Auth = sink
	})
	return h, sink
}

func bearerService(name string) reconciler.Desired {
	d := desiredWithPort(1)
	d.Service = name
	d.Expose = &reconciler.Expose{
		Port: 8080,
		Auth: &reconciler.AuthPolicy{BearerRef: "secret:shop/" + name + "-tokens"},
	}
	return d
}

// Bearer tokens are published as hashes, never as tokens: the restricted file
// must not be able to authenticate anyone.
func TestAuthProjectionHashesBearerTokens(t *testing.T) {
	token := "a-real-bearer-token"
	h, sink := authHarness(t, fakeSecrets{
		"secret:shop/web-tokens": []byte(token + "\n"),
	})
	h.setDesired(t, bearerService("web"))
	h.reconcile(t)

	if len(sink.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(sink.entries))
	}
	e := sink.entries[0]
	if e.Mode != edge.AuthBearer || len(e.TokenHashes) != 1 {
		t.Fatalf("entry = %+v", e)
	}
	sum := sha256.Sum256([]byte(token))
	if e.TokenHashes[0] != hex.EncodeToString(sum[:]) {
		t.Error("the published hash is not sha-256 of the token")
	}
	// The token itself must appear nowhere in the entry.
	if containsToken(e, token) {
		t.Error("the raw token leaked into the published entry")
	}
}

// A basic_ref holding a non-bcrypt line is refused: the route stays marked,
// its material is absent, and the edge answers 503 — fail closed.
func TestAuthProjectionRefusesPlaintextBasic(t *testing.T) {
	h, sink := authHarness(t, fakeSecrets{
		"secret:shop/web-users": []byte("ama:plaintext\n"),
	})
	d := desiredWithPort(1)
	d.Expose = &reconciler.Expose{Port: 8080, Auth: &reconciler.AuthPolicy{BasicRef: "secret:shop/web-users"}}
	h.setDesired(t, d)
	h.reconcile(t)

	if len(sink.entries) != 0 {
		t.Fatalf("a plaintext basic line was published: %+v", sink.entries)
	}
}

// A reference that will not resolve is skipped, not published open.
func TestAuthProjectionSkipsUnresolvable(t *testing.T) {
	h, sink := authHarness(t, fakeSecrets{}) // empty: nothing resolves
	h.setDesired(t, bearerService("web"))
	h.reconcile(t)

	if len(sink.entries) != 0 {
		t.Fatalf("an unresolvable ref was published: %+v", sink.entries)
	}
}

// A JWT HS256 key crosses base64-encoded; the public-key modes carry a PEM.
func TestAuthProjectionJWT(t *testing.T) {
	key := []byte("hs256-shared-key")
	h, sink := authHarness(t, fakeSecrets{
		"secret:shop/jwt": key,
	})
	d := desiredWithPort(1)
	d.Expose = &reconciler.Expose{
		Port: 8080,
		Auth: &reconciler.AuthPolicy{JWT: &reconciler.JWTAuthPolicy{
			Algorithm: "HS256", SecretRef: "secret:shop/jwt",
			Issuer: "https://issuer.test", Audience: "web",
		}},
	}
	h.setDesired(t, d)
	h.reconcile(t)

	if len(sink.entries) != 1 || sink.entries[0].JWT == nil {
		t.Fatalf("jwt entry not published: %+v", sink.entries)
	}
	jwt := sink.entries[0].JWT
	if jwt.SecretB64 != base64.StdEncoding.EncodeToString(key) {
		t.Error("HS256 key was not base64-encoded for the bundle")
	}
	if jwt.Issuer != "https://issuer.test" || jwt.Audience != "web" {
		t.Errorf("claim requirements did not carry: %+v", jwt)
	}
}

func containsToken(e edge.AuthEntry, token string) bool {
	for _, h := range e.TokenHashes {
		if h == token {
			return true
		}
	}
	for _, u := range e.Users {
		if u == token {
			return true
		}
	}
	return false
}
