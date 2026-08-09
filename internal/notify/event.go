package notify

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The event vocabulary (PRD §11).
//
// Events are the one thing every channel, the dashboard feed and the filters
// all agree on, so the names are fixed here rather than built by each emitter.
// A typo in a name is otherwise a notification that silently never matches a
// filter — the failure mode where nothing appears to be wrong.

// Event names, exactly as §11 lists them. The `<noun>.<verb>` shape is what
// makes `deploy.*` a useful filter.
const (
	EventDeployStarted   = "deploy.started"
	EventDeploySucceeded = "deploy.succeeded"
	EventDeployFailed    = "deploy.failed"

	EventServiceUnhealthy = "service.unhealthy"
	EventServiceHealthy   = "service.healthy"
	EventServiceCrashed   = "service.crashed"

	EventScaleUp   = "scale.up"
	EventScaleDown = "scale.down"

	EventCertIssued  = "cert.issued"
	EventCertRenewed = "cert.renewed"
	EventCertFailed  = "cert.failed"

	EventBuildStarted   = "build.started"
	EventBuildSucceeded = "build.succeeded"
	EventBuildFailed    = "build.failed"

	// Image auto-update (§6.2 R19). A failed update is an error rather than a
	// warning: it means the service was reverted, which somebody wants to know
	// about even though the platform recovered on its own.
	EventImageUpdated      = "image.updated"
	EventImageUpdateFailed = "image.update_failed"

	EventBackupSucceeded = "backup.succeeded"
	EventBackupFailed    = "backup.failed"

	EventAuthLoginFailed = "auth.login_failed"

	// EventTest is the test action's payload (§11). It is in the vocabulary so
	// that a test message renders like every other event rather than as a
	// special case each channel has to know about — but the test action does not
	// route it through the filters, so nobody has to add it to an `on` list to
	// be able to test their channel.
	EventTest = "notify.test"
)

// Severity orders events so a channel can carry a floor.
//
// Ordered smallest-to-largest deliberately: a floor is a comparison, and
// "at least warning" should be one `>=` rather than a table lookup.
type Severity int

const (
	// SeverityInfo is something that happened and went well.
	SeverityInfo Severity = iota
	// SeverityWarning is something that needs an eye but not a hand.
	SeverityWarning
	// SeverityError is something that is broken now.
	SeverityError
)

// String renders a severity for payloads and logs.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	default:
		return fmt.Sprintf("severity(%d)", int(s))
	}
}

// MarshalJSON writes a severity as its name.
//
// The int ordering is an implementation detail that exists so a floor is one
// comparison; a webhook receiver reading `"severity": 2` would be reading
// Kanea's iota order, which is not a contract anyone should depend on.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// UnmarshalJSON reads it back, so a stored event round-trips.
func (s *Severity) UnmarshalJSON(raw []byte) error {
	parsed, err := ParseSeverity(strings.Trim(string(raw), `"`))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// ParseSeverity reads a severity from configuration.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "":
		return SeverityInfo, nil
	case "warning", "warn":
		return SeverityWarning, nil
	case "error", "err":
		return SeverityError, nil
	default:
		return 0, fmt.Errorf("notify: unknown severity %q; expected info, warning or error", s)
	}
}

// severities is the name → severity table.
//
// Explicit rather than derived from a suffix. `deploy.failed` and
// `service.healthy` both end in a past participle and mean opposite things, and
// a rule guessing from the name would be wrong exactly when it matters.
var severities = map[string]Severity{
	EventDeployStarted:   SeverityInfo,
	EventDeploySucceeded: SeverityInfo,
	EventDeployFailed:    SeverityError,

	EventServiceUnhealthy: SeverityWarning,
	EventServiceHealthy:   SeverityInfo,
	// A crash is an error even though the reconciler will restart it: by the
	// time a human reads this the restart has happened, and the thing worth
	// knowing is that it was needed.
	EventServiceCrashed: SeverityError,

	EventScaleUp:   SeverityInfo,
	EventScaleDown: SeverityInfo,

	EventCertIssued:  SeverityInfo,
	EventCertRenewed: SeverityInfo,
	// A renewal that fails is an outage with a date on it.
	EventCertFailed: SeverityError,

	EventBuildStarted:   SeverityInfo,
	EventBuildSucceeded: SeverityInfo,
	EventBuildFailed:    SeverityError,

	EventImageUpdated:      SeverityInfo,
	EventImageUpdateFailed: SeverityError,

	EventBackupSucceeded: SeverityInfo,
	EventBackupFailed:    SeverityError,

	// Warning, not error: one failed login is a typo. What makes it interesting
	// is volume, which is what coalescing turns into a single useful message.
	EventAuthLoginFailed: SeverityWarning,

	EventTest: SeverityInfo,
}

// SeverityOf returns an event name's severity.
//
// An unknown name is a warning rather than info: it means an emitter is sending
// something this table does not know about, and silently filing that at the
// lowest severity is how it stays unnoticed.
func SeverityOf(name string) Severity {
	if s, ok := severities[name]; ok {
		return s
	}
	return SeverityWarning
}

// KnownEvents lists every event name, sorted. For validation and for `kanea`
// telling an operator what they may filter on.
func KnownEvents() []string {
	out := make([]string, 0, len(severities))
	for name := range severities {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Event is one thing that happened.
//
// Deliberately flat and small. It is fanned out to every channel and kept in
// the bounded Store-backed feed (feed.go), and a struct that grew a map of
// arbitrary payload would make each of those a different size problem.
type Event struct {
	// ID is unique and time-ordered, so a feed can resume and a digest can
	// name its span.
	ID string `json:"id"`
	// Name is one of the constants above.
	Name string `json:"name"`
	// Severity is derived from Name at construction, and carried so a consumer
	// does not need the table.
	Severity Severity `json:"severity"`
	// Project and Service scope the event. Both may be empty: a node-level
	// event such as auth.login_failed belongs to no project.
	Project string `json:"project,omitempty"`
	Service string `json:"service,omitempty"`
	// Message is one human-readable line. It is the thing a person reads in
	// Telegram, so it says what happened, not what struct it came from.
	Message string `json:"message"`
	// Detail is optional extra context — an error string, a digest, a count.
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// Subject is the scope an event belongs to, for grouping and rate limiting.
// Empty for node-level events, which is a real scope and not a missing one.
func (e Event) Subject() string {
	switch {
	case e.Project == "" && e.Service == "":
		return ""
	case e.Service == "":
		return e.Project
	default:
		return e.Project + "/" + e.Service
	}
}

// String renders the event the way a chat message wants it.
func (e Event) String() string {
	var b strings.Builder
	b.WriteString("[")
	b.WriteString(e.Severity.String())
	b.WriteString("] ")
	b.WriteString(e.Name)
	if subject := e.Subject(); subject != "" {
		b.WriteString(" ")
		b.WriteString(subject)
	}
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}
	return b.String()
}

// NewEvent builds an event, filling in the severity and the timestamp.
//
// The only constructor: an Event assembled by hand would carry the zero
// severity, which is info, which is the one a severity floor lets through.
func NewEvent(name, project, service, message string, at time.Time) Event {
	return Event{
		ID:       eventID(at),
		Name:     name,
		Severity: SeverityOf(name),
		Project:  project,
		Service:  service,
		Message:  message,
		At:       at,
	}
}

// WithDetail returns a copy carrying extra context.
func (e Event) WithDetail(detail string) Event {
	e.Detail = detail
	return e
}

// eventID is a time-ordered, unique id.
//
// The same shape a pipeline run uses: a zero-padded nanosecond prefix so the
// Store's byte-ordered keys are time-ordered for free, and random bytes so two
// events in the same nanosecond — which happens, a fleet restart emits a burst
// — do not collide and silently overwrite one another.
func eventID(at time.Time) string {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		// crypto/rand does not fail on any platform Kanea runs on, and an
		// event is not worth failing a deploy over. The timestamp alone still
		// orders correctly; the only thing lost is collision resistance
		// within one nanosecond.
		return fmt.Sprintf("%020d-0000000000000000", at.UTC().UnixNano())
	}
	return fmt.Sprintf("%020d-%s", at.UTC().UnixNano(), hex.EncodeToString(suffix))
}
