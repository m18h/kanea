package reconciler

// The R27 auth projection (PRD v1.40): resolving the spec's references into
// the verifier material the edge is handed.
//
// This runs in the reconciler because the reconciler already holds the two
// things the projection needs (the desired-state view and the secret
// resolver) and because the shape mirrors syncEdgeRoutes exactly: derived
// state, rebuilt every pass, deduplicated at the write. What leaves here is
// deliberately less than what was resolved: bcrypt lines pass through as the
// verifier material they are, bearer tokens are reduced to SHA-256 hashes,
// and only a JWT HS256 key crosses as a secret, because MAC verification
// cannot be done with less.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/m18h/kanea/internal/edge"
)

// AuthSink receives the resolved verifier material. Implemented by
// certsource.Publisher, which merges it into the restricted bundle the edge
// polls; the interface lives here, at the consumer.
type AuthSink interface {
	SetAuth(entries []edge.AuthEntry) error
}

// SetAuthSink wires the auth projection after construction.
//
// The publisher that receives the material is built after the reconciler in
// cmd/kanea (it needs the ACME plumbing), so this is set once, before Run
// starts a reconcile pass: the same before-Run window the certificate loop
// is wired in. Not in Config only because of that ordering.
func (r *Reconciler) SetAuthSink(sink AuthSink) { r.authSink = sink }

// syncEdgeAuth publishes the R27 verifier material for every authenticated
// route.
//
// A reference that fails to resolve, or material that fails validation;
// skips the entry with the reason logged: the route stays marked in
// routes.json, and marked-without-material is a 503 at the edge. Fail closed
// costs an outage on the one service that is misconfigured; fail open would
// cost its authentication, silently.
func (r *Reconciler) syncEdgeAuth(ctx context.Context, w World) {
	if r.authSink == nil {
		return
	}
	entries := r.buildAuthEntries(ctx, w)
	if err := r.authSink.SetAuth(entries); err != nil {
		r.log.Error("cannot publish auth material", "error", err)
	}
}

func (r *Reconciler) buildAuthEntries(ctx context.Context, w World) []edge.AuthEntry {
	entries := []edge.AuthEntry{}
	for _, d := range sortedDesired(w.Desired) {
		a := serviceAuth(d)
		if a == nil {
			continue
		}
		entry, err := r.resolveAuthEntry(ctx, d, a)
		if err != nil {
			r.log.Error("cannot resolve auth material; the route will answer 503",
				"service", d.Project+"/"+d.Service, "error", err)
			continue
		}
		entries = append(entries, entry)
	}
	return entries
}

// serviceAuth is the service's one auth config: the first route that declares
// one stands for all of them, because R16 (v1.50) refuses blocks that
// disagree; the verifier bundle is keyed per service (v1.40's invariant).
func serviceAuth(d Desired) *AuthPolicy {
	for _, e := range d.AllExposes() {
		if e.Auth != nil {
			return e.Auth
		}
	}
	return nil
}

func (r *Reconciler) resolveAuthEntry(ctx context.Context, d Desired, a *AuthPolicy) (edge.AuthEntry, error) {
	entry := edge.AuthEntry{Project: d.Project, Service: d.Service}

	switch {
	case a.BasicRef != "":
		entry.Mode = edge.AuthBasic
		raw, err := r.secrets.Resolve(ctx, a.BasicRef)
		if err != nil {
			return entry, err
		}
		for _, line := range nonEmptyLines(string(raw)) {
			// bcrypt only (R27): a plaintext password in the "hash" secret is
			// a credential pretending to be verifier material, and publishing
			// it (even to a 0640 file) would make the mistake durable.
			_, hash, ok := strings.Cut(line, ":")
			if !ok || !strings.HasPrefix(hash, "$2") {
				return entry, errAuthNotBcrypt
			}
			// The cost is bounded (K-23): it is operator-chosen work the edge
			// performs per request against attacker-chosen request rates, and
			// a $2$31$ line is a CPU-exhaustion primitive with a valid syntax.
			if cost, err := bcrypt.Cost([]byte(hash)); err != nil || cost > MaxBcryptCost {
				return entry, errAuthCost
			}
			entry.Users = append(entry.Users, line)
		}

	case a.BearerRef != "":
		entry.Mode = edge.AuthBearer
		raw, err := r.secrets.Resolve(ctx, a.BearerRef)
		if err != nil {
			return entry, err
		}
		for _, token := range nonEmptyLines(string(raw)) {
			// Hashes, never tokens: the restricted file must not be able to
			// authenticate anyone.
			sum := sha256.Sum256([]byte(token))
			entry.TokenHashes = append(entry.TokenHashes, hex.EncodeToString(sum[:]))
		}

	case a.JWT != nil:
		entry.Mode = edge.AuthJWT
		cfg := &edge.JWTConfig{
			Algorithm: a.JWT.Algorithm, Issuer: a.JWT.Issuer, Audience: a.JWT.Audience,
		}
		if a.JWT.SecretRef != "" {
			key, err := r.secrets.Resolve(ctx, a.JWT.SecretRef)
			if err != nil {
				return entry, err
			}
			cfg.SecretB64 = base64.StdEncoding.EncodeToString(key)
		}
		if a.JWT.PublicKeyRef != "" {
			pemText, err := r.secrets.Resolve(ctx, a.JWT.PublicKeyRef)
			if err != nil {
				return entry, err
			}
			cfg.PublicKeyPEM = string(pemText)
		}
		entry.JWT = cfg
	}
	return entry, nil
}

// errAuthNotBcrypt names the one validation this projection owns.
var errAuthNotBcrypt = authError("basic_ref holds a line that is not user:<bcrypt-hash>; " +
	"generate entries with `htpasswd -B`")

// MaxBcryptCost bounds the work a basic_auth line may demand per request
// (K-23): 14 is ~16x the default cost and already far past a sane choice;
// beyond it the "hash" is a denial-of-service budget spent per login attempt.
const MaxBcryptCost = 14

// errAuthCost refuses the line that spends it.
var errAuthCost = authError(fmt.Sprintf("basic_ref holds a bcrypt hash with a cost above %d; "+
	"an operator-chosen cost meets an attacker-chosen request rate on the shared edge", MaxBcryptCost))

type authError string

func (e authError) Error() string { return string(e) }

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
