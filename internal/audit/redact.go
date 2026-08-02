package audit

import "regexp"

// Placeholder replaces a redacted value. It is deliberately conspicuous: an
// audit entry should show that something was removed, not read as though the
// field was empty.
const Placeholder = "[redacted]"

// Redaction patterns (PRD §14, A07 — no credentials in logs or audit).
//
// The rule they encode is narrow on purpose. Over-redaction is not free: an
// audit trail that hides which secret path was written, or which image digest
// was deployed, is a trail nobody can use during an incident. So each pattern
// matches a *credential-carrying shape*, never a topic that merely sounds
// sensitive.
var (
	// bearerToken matches a presented Kanea token. The id half is kept: it is
	// public, it is what `kanea token revoke` takes, and an audit entry naming
	// the token that was used is the entry someone needs. Only the secret half
	// is removed.
	//
	// The prefix is duplicated from internal/auth rather than imported: auth
	// records to this package, and an import back would be a cycle.
	bearerToken = regexp.MustCompile(`(kanea_[A-Za-z0-9]+)\.[A-Za-z0-9_\-]+`)

	// assignedSecret matches `password=…`, `token=…` and friends — the query
	// string and environment shapes. A bare colon is excluded so the
	// `secret:project/name` reference form of §6.2 R3 survives: that is a name,
	// not a value, and it is the most useful thing an audit entry can carry
	// about a secret.
	assignedSecret = regexp.MustCompile(
		`(?i)\b(password|passwd|secret|token|api[_-]?key|csrf)\b\s*=\s*"?([^\s,;&"]+)"?`)

	// quotedSecret matches the JSON shape, where the key is quoted. Requiring
	// the quote is what keeps `secret:shop/db-password` out of it.
	quotedSecret = regexp.MustCompile(
		`(?i)"(password|passwd|secret|token|api[_-]?key|csrf)"\s*:\s*"[^"]*"`)

	// headerSecret matches the two request headers that carry credentials.
	headerSecret = regexp.MustCompile(`(?i)\b(authorization|cookie|set-cookie)\s*:\s*[^\r\n]+`)
)

// Redact removes credentials from free text on its way into the log.
//
// It runs on every entry rather than at the call sites, because a redaction
// filter that each caller has to remember is a filter that will be forgotten
// exactly once, in the code path that mattered.
func Redact(s string) string {
	if s == "" {
		return s
	}
	s = bearerToken.ReplaceAllString(s, "$1."+Placeholder)
	s = quotedSecret.ReplaceAllString(s, `"$1": "`+Placeholder+`"`)
	s = assignedSecret.ReplaceAllString(s, "$1="+Placeholder)
	s = headerSecret.ReplaceAllString(s, "$1: "+Placeholder)
	return s
}
