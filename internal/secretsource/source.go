// Package secretsource syncs secrets from external managers into the local
// encrypted store (PRD §5.2.13, v1.44).
//
// The direction is the design: values land in the store the rest of the
// platform already reads, so every consumer is untouched, the node keeps
// working through a provider outage on whatever the last pass wrote, and a
// rotation propagates on the next poll instead of on the next human. A job
// spec never sees any of this — it references `secret:<project>/<name>`
// exactly as before, and which of those paths are provider-backed is this
// node's config (`--secrets-providers-config`), never the spec's (R17's rule,
// applied to secret origin).
//
// The seam follows internal/certsource: a closed Kind set, a batch call per
// pass, partial failure as data rather than as an error that suppresses the
// rest, and explicit wiring in cmd/kanea — no registries.
package secretsource

import "context"

// Kind names a provider implementation. The set is closed: an unknown kind in
// the config is a parse error naming the known ones, not a plugin lookup.
type Kind string

// The five provider kinds (PRD §5.2.13): the config file's block labels.
const (
	KindDoppler Kind = "doppler"
	KindAWS     Kind = "aws-sm"
	KindVault   Kind = "vault"
	KindAzure   Kind = "azure-kv"
	KindGCP     Kind = "gcp-sm"
)

// Kinds lists every provider kind, in error-message order.
func Kinds() []Kind {
	return []Kind{KindDoppler, KindAWS, KindVault, KindAzure, KindGCP}
}

// Valid reports whether the kind is one of the closed set.
func (k Kind) Valid() bool {
	for _, known := range Kinds() {
		if k == known {
			return true
		}
	}
	return false
}

// Provider fetches current values for every mapping it was configured with.
// One call per pass; a mapping the provider cannot serve is a Failure, and one
// failure never suppresses its siblings (certsource.Result's rule).
type Provider interface {
	Kind() Kind
	// Name is the config block's label, for logs and status.
	Name() string
	Fetch(ctx context.Context) Result
}

// Value is one fetched secret. Data is plaintext held transiently in memory on
// its way into the encrypted store; it is never logged and never appears in
// Ref or in any error.
type Value struct {
	// To is the local path the mapping targets, <project|shared>/<name>.
	To string
	// Ref is the external coordinate, e.g. "backend/prd/DATABASE_URL" — safe
	// for logs and status because it names a secret, never holds one.
	Ref string
	// Data is the fetched plaintext.
	Data []byte
}

// Failure is one mapping the provider could not serve this pass.
type Failure struct {
	To  string
	Ref string
	// Err must never contain a secret value; the HTTP clients decode error
	// bodies into typed shapes or drop them for exactly this reason.
	Err error
}

// Result is one pass over one provider's mappings.
type Result struct {
	Values   []Value
	Failures []Failure
}
