package notify

import (
	"fmt"
	"strings"
)

// Event filters (PRD §11: `on = ["deploy.*", "scale.up"]`).
//
// Glob rather than regex, because the thing being matched is a two-part name
// with a fixed shape and an operator writing `deploy.*` should not have to know
// whether `.` means anything. It also means a filter cannot be a denial of
// service: there is no backtracking to exploit.

// Filter decides which events a channel receives.
type Filter struct {
	patterns []string
	// floor drops anything less severe, whatever the patterns say. The two
	// compose as an AND: `on = ["*"]` with a warning floor is "everything that
	// matters", which is the configuration most operators actually want.
	floor Severity
}

// NewFilter compiles a filter.
//
// An empty pattern list means **nothing**, not everything. A channel configured
// with no `on` has not been told what to send, and guessing "all of it" turns a
// half-finished config into a pager at 3am.
func NewFilter(patterns []string, floor Severity) (Filter, error) {
	out := Filter{floor: floor}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := validatePattern(p); err != nil {
			return Filter{}, err
		}
		out.patterns = append(out.patterns, p)
	}
	return out, nil
}

// Match reports whether an event passes.
func (f Filter) Match(e Event) bool {
	if e.Severity < f.floor {
		return false
	}
	for _, p := range f.patterns {
		if matchGlob(p, e.Name) {
			return true
		}
	}
	return false
}

// Empty reports a filter that can never match, so a channel with one can be
// dropped at construction rather than consulted per event.
func (f Filter) Empty() bool { return len(f.patterns) == 0 }

// Patterns returns the compiled patterns, for reporting configuration back.
func (f Filter) Patterns() []string { return f.patterns }

// Floor returns the severity floor.
func (f Filter) Floor() Severity { return f.floor }

// ValidatePattern is the exported form, so the job spec parser checks a filter
// against the same vocabulary the dispatcher matches against.
//
// One table, one matcher. Two implementations of "is this a known event" drift,
// and the way they drift is that a spec passes `kanea plan` and then matches
// nothing at runtime — which is the silent-channel failure this all exists to
// prevent.
func ValidatePattern(p string) error { return validatePattern(p) }

// validatePattern rejects a pattern that cannot match anything.
//
// Checked at configuration time, in front of the person who wrote it. A pattern
// with a typo silently matches nothing, and a notification channel that is
// silent looks exactly like a system with nothing to report — which is the one
// failure this whole subsystem exists to prevent.
func validatePattern(p string) error {
	if p == "*" {
		return nil
	}
	if strings.Count(p, "*") > 1 {
		return fmt.Errorf("notify: pattern %q has more than one *; "+
			"patterns look like \"deploy.*\" or \"scale.up\"", p)
	}
	if i := strings.IndexByte(p, '*'); i >= 0 && i != len(p)-1 {
		return fmt.Errorf("notify: pattern %q may only end with *", p)
	}

	for _, known := range KnownEvents() {
		if matchGlob(p, known) {
			return nil
		}
	}
	return fmt.Errorf("notify: pattern %q matches no known event; "+
		"events are %s", p, strings.Join(KnownEvents(), ", "))
}

// matchGlob matches a name against a pattern that may end in *.
func matchGlob(pattern, name string) bool {
	if pattern == "*" {
		return true
	}
	if prefix, found := strings.CutSuffix(pattern, "*"); found {
		return strings.HasPrefix(name, prefix)
	}
	return pattern == name
}
