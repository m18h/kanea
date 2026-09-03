package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/m18h/kanea/internal/backup"
)

// PathUpgrade is the release surface (PRD v1.107, §15.4, §16.1).
const PathUpgrade = "/v1/upgrade"

// Upgrader is the slice of the self-update machinery the API needs (PRD
// v1.107). Implemented in cmd/kanea beside `kanea upgrade`'s own fetch half,
// which is where the release contract (asset names, checksum and cosign
// verification, the rename(2) swap) already lives; nil answers 503 on both
// routes, like every optional daemon dependency.
type Upgrader interface {
	// Check resolves the latest published release and compares it to the
	// running daemon. It contacts the release host, so callers cache it.
	Check(ctx context.Context) (UpgradeCheck, error)
	// Upgrade resolves target ("" means latest), refuses a downgrade
	// (ErrUpgradeDowngrade) or a malformed tag (ErrUpgradeBadTarget),
	// downloads, verifies and installs the release over the running binary.
	// The outcome's notes are facts the operator must see either way: the
	// cosign posture is one of them.
	Upgrade(ctx context.Context, target string) (UpgradeOutcome, error)
	// Restart restarts kanea-edge and then this daemon, in that order (the
	// v1.59 order). Called only after the response has been written, and only
	// when CanRestart is true.
	Restart(ctx context.Context) error
	// CanRestart reports whether a restart would come back: this process is
	// supervised (systemd's Restart=always). Without a supervisor an exiting
	// kanead is just gone, so the install is staged instead.
	CanRestart() bool
}

// ErrUpgradeDowngrade is a target older than the running daemon. There is no
// override over the API (K-41): the Store's schema moves forward-only, and
// `--allow-downgrade` stays a CLI-on-the-node escape hatch.
var ErrUpgradeDowngrade = errors.New("the target release is older than the running daemon")

// ErrUpgradeBadTarget is a pinned version that is not a release tag.
var ErrUpgradeBadTarget = errors.New("not a release tag (vX.Y.Z)")

// ErrUpgradeInProgress refuses a second upgrade while one is running.
var ErrUpgradeInProgress = errors.New("an upgrade is already in progress")

// UpgradeCheck is running vs latest. CheckedAt is when the daemon last asked
// the release host, which the ~1h cache can put well before "now": the
// dashboard shows it so a reader knows how stale "latest" may be.
type UpgradeCheck struct {
	Running         string    `json:"running"`
	Latest          string    `json:"latest"`
	UpdateAvailable bool      `json:"update_available"`
	CheckedAt       time.Time `json:"checked_at,omitzero"`
}

// UpgradeRequest asks for an upgrade.
type UpgradeRequest struct {
	// Version pins a release (vX.Y.Z). Empty resolves to the latest.
	Version string `json:"version,omitempty"`
}

// UpgradeOutcome is what an Upgrader's install half reports.
type UpgradeOutcome struct {
	// Installed is the tag now on disk.
	Installed string
	// Notes are facts the operator must see: the signature posture, what was
	// installed where, or that there was nothing to do.
	Notes []string
	// RestartNeeded is false only when the daemon already runs Installed.
	RestartNeeded bool
}

// UpgradeResponse describes what happened and what happens next.
type UpgradeResponse struct {
	Installed string `json:"installed"`
	// Restarting means the daemons restart the moment this response lands: the
	// edge first, then kanead, which systemd brings back on the new binary.
	// The caller should poll health until the new version answers.
	Restarting bool `json:"restarting"`
	// RestartRequired is the unsupervised case: the binary is installed and
	// nothing restarts, because a kanead that exits with no supervisor does
	// not come back. Restarting and RestartRequired are never both true.
	RestartRequired bool      `json:"restart_required,omitempty"`
	Notes           []string  `json:"notes"`
	At              time.Time `json:"at"`
}

// upgradeCheckTTL is how long a resolved "latest" is served from memory. The
// check runs only when an admin's open dashboard asks (PRD v1.107: a node
// never contacts GitHub unprompted), and this cache is what turns a
// dashboard's refetch cadence into at most one request an hour upstream.
const upgradeCheckTTL = time.Hour

// upgradeTimeout bounds the download-verify-install half. The release client
// itself allows five minutes per fetch; this is the whole operation's ceiling.
const upgradeTimeout = 15 * time.Minute

// restartDelay is how long the daemon waits after writing the upgrade
// response before restarting anything: enough for the response to flush to a
// caller who needs to read "restarting: true" to know to start polling.
const restartDelay = time.Second

// handleUpgradeCheck reports running vs latest, from cache when fresh.
func (s *Server) handleUpgradeCheck(w http.ResponseWriter, r *http.Request) {
	if s.upgrader == nil {
		writeError(w, http.StatusServiceUnavailable, errNoUpgrader)
		return
	}

	s.upgradeCheck.mu.Lock()
	cached := s.upgradeCheck.answer
	fresh := s.upgradeCheck.valid && s.now().Sub(cached.CheckedAt) < upgradeCheckTTL
	s.upgradeCheck.mu.Unlock()
	if fresh {
		writeJSON(w, http.StatusOK, cached)
		return
	}

	check, err := s.upgrader.Check(r.Context())
	if err != nil {
		// The release host's failure, not this daemon's.
		writeError(w, http.StatusBadGateway, err)
		return
	}
	check.CheckedAt = s.now().UTC()

	s.upgradeCheck.mu.Lock()
	s.upgradeCheck.answer, s.upgradeCheck.valid = check, true
	s.upgradeCheck.mu.Unlock()

	writeJSON(w, http.StatusOK, check)
}

// handleUpgrade fetches, verifies and installs a release, then restarts the
// daemons.
//
// The order with the response is the unusual part: the handler answers
// *before* the restart, because the restart takes the answerer with it. The
// deliberate contrast with handleRestore (which stages and never restarts) is
// recorded in PRD v1.107: here the supervisor guarantees the return, and the
// unsupervised case degrades to exactly the staged posture.
func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	if s.upgrader == nil {
		writeError(w, http.StatusServiceUnavailable, errNoUpgrader)
		return
	}
	var req UpgradeRequest
	if r.ContentLength > 0 {
		if err := decodeBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	// One at a time: two concurrent installs racing rename(2) over the same
	// path is a coin flip about which release the node ends up on.
	if !s.upgradeCheck.running.CompareAndSwap(false, true) {
		writeError(w, http.StatusConflict, ErrUpgradeInProgress)
		return
	}
	defer s.upgradeCheck.running.Store(false)

	notes := []string{}

	// The pre-upgrade backup, the CLI's own order. An unconfigured
	// destination is a note, never a failure (the schema migration takes its
	// own local copy either way); a configured one that fails is a refusal,
	// because "upgrade anyway" is a decision `kanea upgrade --skip-backup`
	// exists to make explicit, and this route has no such flag on purpose.
	if s.backups == nil {
		notes = append(notes, backupSkippedNote)
	} else {
		manifest, err := s.backups.Create(r.Context(), "pre-upgrade")
		switch {
		case err == nil:
			notes = append(notes, fmt.Sprintf("pre-upgrade backup %s at index %d", manifest.ID, manifest.Index))
		case errors.Is(err, backup.ErrNotConfigured):
			notes = append(notes, backupSkippedNote)
		default:
			writeError(w, http.StatusInternalServerError,
				fmt.Errorf("pre-upgrade backup failed: %w (fix the destination, or use `kanea upgrade --skip-backup` on the node)", err))
			return
		}
	}

	// Bounded independently of the request: a dashboard tab closed mid-download
	// must not abandon a half-decided upgrade. The install itself is atomic
	// either way; this is about finishing what an admin started.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), upgradeTimeout)
	defer cancel()

	outcome, err := s.upgrader.Upgrade(ctx, req.Version)
	notes = append(notes, outcome.Notes...)
	if err != nil {
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, ErrUpgradeBadTarget):
			status = http.StatusBadRequest
		case errors.Is(err, ErrUpgradeDowngrade):
			status = http.StatusConflict
		}
		writeError(w, status, err)
		return
	}

	restarting := outcome.RestartNeeded && s.upgrader.CanRestart()
	auditTarget(r, outcome.Installed)
	if outcome.RestartNeeded {
		// Conspicuous on the node it happens to, like a staged restore: this
		// is the API call that replaces the binary under every unit.
		s.log.Warn("an upgrade was installed over the API",
			"installed", outcome.Installed, "running", s.version, "restarting", restarting)
	}

	writeJSON(w, http.StatusOK, UpgradeResponse{
		Installed: outcome.Installed, Restarting: restarting,
		RestartRequired: outcome.RestartNeeded && !restarting,
		Notes:           notes, At: s.now().UTC(),
	})

	if !restarting {
		return
	}
	go func() {
		// Detached from the request on purpose: the request is over, and the
		// restart must not die with a closed connection.
		time.Sleep(restartDelay)
		if err := s.upgrader.Restart(context.WithoutCancel(ctx)); err != nil {
			s.log.Error("post-upgrade restart failed",
				"error", err, "detail", "the new binary is installed; restart kanea-edge and kanead by hand")
		}
	}()
}

var errNoUpgrader = errors.New("api: this daemon cannot upgrade itself (no upgrader is wired; use `kanea upgrade` on the node)")

// backupSkippedNote is the honest answer for a node with nowhere to ship a
// pre-upgrade archive: said, never silently skipped, never a refusal.
const backupSkippedNote = "no backup destination is configured on this daemon; " +
	"the schema migration still takes a local copy before it runs"
