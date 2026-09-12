package api

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// PathUpdates is the host-update view (PRD v1.108, §12.2, §16.1).
const PathUpdates = "/v1/updates"

// HostInspector is the slice of the node the updates view needs (PRD v1.108).
// Implemented in cmd/kanea beside the doctor's own checks, which is where the
// receipt reading and the /proc conventions already live; nil answers 503,
// like every optional daemon dependency.
type HostInspector interface {
	// Inspect reads local state only: os-release, the kernel, the package
	// manager's own lists, the reboot flag, the component receipts. It never
	// refreshes a list, never installs a package, and never leaves the node.
	Inspect(ctx context.Context) (UpdatesView, error)
}

// UpdatesView is what the node runs beside what is waiting (PRD v1.108).
type UpdatesView struct {
	OS OSView `json:"os"`
	// Components is the §5.2.12 matrix: manifest pins against receipts.
	Components []ComponentView `json:"components,omitempty"`
	CheckedAt  time.Time       `json:"checked_at,omitzero"`
}

// OSView is the host's own update state. Absence is unknown, never zero
// (§9.2): a pointer field left nil means the node could not answer, which
// leads a reader to the opposite decision from a measured zero.
type OSView struct {
	// Name is os-release's PRETTY_NAME; empty when the file is unreadable.
	Name   string `json:"name,omitempty"`
	Kernel string `json:"kernel,omitempty"`
	// PackageManager is "apt" or "unsupported". The v1 probe speaks the apt
	// family only; anything else says so rather than answering zeroes.
	PackageManager string `json:"package_manager,omitempty"`
	// Pending is bounded (maxPendingShown); PendingTotal carries the truth.
	Pending       []PackageUpdate `json:"pending,omitempty"`
	PendingTotal  *int            `json:"pending_total,omitempty"`
	SecurityTotal *int            `json:"security_total,omitempty"`
	// ListsRefreshedAt is when the package lists were last fetched. A stale
	// list understates what is pending, so the staleness is data.
	ListsRefreshedAt *time.Time `json:"lists_refreshed_at,omitempty"`
	RebootRequired   *bool      `json:"reboot_required,omitempty"`
}

// PackageUpdate is one pending OS package.
type PackageUpdate struct {
	Name string `json:"name"`
	// Installed is empty for a package the upgrade newly pulls in.
	Installed string `json:"installed,omitempty"`
	Candidate string `json:"candidate"`
	Origin    string `json:"origin,omitempty"`
	Security  bool   `json:"security,omitempty"`
}

// ComponentView is one §5.2.12 host component: the manifest's pin against the
// receipt. Installed empty means no receipt: unknown, not absent.
type ComponentView struct {
	Name      string `json:"name"`
	Pinned    string `json:"pinned"`
	Installed string `json:"installed,omitempty"`
}

// updatesTTL is how long an inspection is served from memory. The probe reads
// local state only, so this bounds exec cost, not network chatter; it still
// runs only when an admin's open dashboard asks (PRD v1.108).
const updatesTTL = 5 * time.Minute

// handleUpdates reports the host's update state, from cache when fresh.
func (s *Server) handleUpdates(w http.ResponseWriter, r *http.Request) {
	if s.hostInspector == nil {
		writeError(w, http.StatusServiceUnavailable, errNoHostInspector)
		return
	}

	s.updatesCache.mu.Lock()
	cached := s.updatesCache.answer
	fresh := s.updatesCache.valid && s.now().Sub(cached.CheckedAt) < updatesTTL
	s.updatesCache.mu.Unlock()
	if fresh {
		writeJSON(w, http.StatusOK, cached)
		return
	}

	view, err := s.hostInspector.Inspect(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	view.CheckedAt = s.now().UTC()

	s.updatesCache.mu.Lock()
	s.updatesCache.answer, s.updatesCache.valid = view, true
	s.updatesCache.mu.Unlock()

	writeJSON(w, http.StatusOK, view)
}

var errNoHostInspector = errors.New("api: this daemon does not inspect its host (no inspector is wired)")
