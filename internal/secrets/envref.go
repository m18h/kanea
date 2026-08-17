package secrets

import "strings"

// ParseEnvRef classifies an env value that may reference a secret (PRD §6.2
// R3, v1.76).
//
// "secret:<scope>/<name>" is the **file** form and the primary mechanism: the
// reconciler resolves the value at alloc start into a per-alloc tmpfs file
// and the env var carries the file's path - the value is referenced, never
// inlined. "secret-env:<scope>/<name>" is the **inline** form, the documented
// weaker option for software that only reads env values: the env var carries
// the resolved value itself, which is then visible in /proc/<pid>/environ and
// inherited by child processes.
//
// The returned ref is always in canonical "secret:" form, ready for Resolve;
// ok is false for anything that is not a reference at all. This is the one
// classifier: jobspec validates with it, the apply seam re-validates with it,
// and the reconciler resolves with it, so the three paths cannot drift.
func ParseEnvRef(value string) (ref string, inline bool, ok bool) {
	if rest, found := strings.CutPrefix(value, "secret-env:"); found {
		return "secret:" + rest, true, true
	}
	if strings.HasPrefix(value, "secret:") {
		return value, false, true
	}
	return "", false, false
}
