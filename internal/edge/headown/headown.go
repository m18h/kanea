// Package headown names the HTTP headers the edge owns: its statement about
// who the client is. It exists as a leaf so both the plan-time validator
// (jobspec) and the edge's request path share one list — two implementations
// of "may a spec set this header" drift, and they drift into a spec that
// passes plan and then fails the whole node's route-table publish (K-22).
package headown

// Headers are the client-identity names the edge sets from the connection.
// Anything a client or a spec sends under these names is discarded or refused:
// ip_restriction, rate limiting and every access log are keyed on them (PRD
// §14 A01). All lower-case; callers canonicalize before consulting.
var Headers = []string{
	"forwarded",
	"x-forwarded-for",
	"x-forwarded-host",
	"x-forwarded-port",
	"x-forwarded-proto",
	"x-forwarded-server",
	"x-forwarded-ssl",
	"x-original-forwarded-for",
	"x-real-ip",
}

// Set answers membership.
func Set() map[string]bool {
	out := make(map[string]bool, len(Headers))
	for _, h := range Headers {
		out[h] = true
	}
	return out
}
