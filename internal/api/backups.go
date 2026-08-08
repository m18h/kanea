package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/kanea-dev/kanea/internal/auth"
	"github.com/kanea-dev/kanea/internal/backup"
)

// PathBackups is the archive surface (PRD §15.3, §16.1).
const PathBackups = "/v1/backups"

// Backups is the slice of the backup subsystem the API needs.
//
// Notably it cannot *perform* a restore. §15.3 puts a restore on a stopped
// node, and the interface says so: the API can stage one, and the daemon
// carries it out at the next start, before anything opens the Store.
type Backups interface {
	List(ctx context.Context) ([]backup.Manifest, error)
	Create(ctx context.Context, reason string) (backup.Manifest, error)
	Verify(ctx context.Context, id string) error
	// Stage records a restore for the next start and returns what it will
	// restore, so the response can name the archive rather than a promise.
	Stage(ctx context.Context, id string, skipReplay bool, by string) (backup.Manifest, error)
	// Status reports replication health.
	Status() backup.Status
}

// BackupsResponse lists archives.
type BackupsResponse struct {
	Backups []backup.Manifest `json:"backups"`
	// Replication is the loop's own health. "When did this last succeed" is
	// the number that decides whether a backup strategy is real, and the one an
	// operator normally does not have until the restore.
	Replication backup.Status `json:"replication"`
}

// BackupRequest asks for an on-demand archive.
type BackupRequest struct {
	Reason string `json:"reason,omitempty"`
}

// RestoreRequest stages a restore.
type RestoreRequest struct {
	// Archive selects one. Empty resolves to the newest at restore time.
	Archive string `json:"archive,omitempty"`
	// SkipReplay restores the snapshot without its change segments.
	SkipReplay bool `json:"skip_replay,omitempty"`
}

// RestoreResponse describes what was staged.
type RestoreResponse struct {
	Archive backup.Manifest `json:"archive"`
	// Staged is always true: nothing has been restored yet. The field exists so
	// a caller cannot read this response as "done" — the daemon has to restart,
	// and that is the operator's decision, not this route's.
	Staged  bool      `json:"staged"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// handleListBackups serves the archive list.
func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeError(w, http.StatusServiceUnavailable, errNoBackups)
		return
	}
	manifests, err := s.backups.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if manifests == nil {
		manifests = []backup.Manifest{}
	}
	writeJSON(w, http.StatusOK, BackupsResponse{
		Backups: manifests, Replication: s.backups.Status(),
	})
}

// handleCreateBackup takes an on-demand snapshot.
func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeError(w, http.StatusServiceUnavailable, errNoBackups)
		return
	}
	req := BackupRequest{Reason: "on-demand"}
	if r.ContentLength > 0 {
		if err := decodeBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if req.Reason == "" {
		req.Reason = "on-demand"
	}

	// Bounded independently of the request. A snapshot copies the whole
	// database and a client that hangs up must not cancel it half-written —
	// though the archive would be invisible either way, since the manifest is
	// what makes it real.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), backupTimeout)
	defer cancel()

	manifest, err := s.backups.Create(ctx, req.Reason)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	auditTarget(r, manifest.ID)
	s.log.Info("wrote an on-demand backup", "archive", manifest.ID, "index", manifest.Index)
	writeJSON(w, http.StatusOK, manifest)
}

// backupTimeout bounds an on-demand snapshot.
const backupTimeout = 30 * time.Minute

// handleVerifyBackup checks an archive against its manifest.
func (s *Server) handleVerifyBackup(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeError(w, http.StatusServiceUnavailable, errNoBackups)
		return
	}
	id := r.PathValue("id")
	if err := s.backups.Verify(r.Context(), id); err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, backup.ErrNotFound), errors.Is(err, backup.ErrNoArchives):
			status = http.StatusNotFound
		case errors.Is(err, backup.ErrCorrupt):
			// The archive is intact or it is not, and a damaged one is not this
			// server's error to report as a 500 — it is a fact about the bucket
			// that the caller asked for.
			status = http.StatusUnprocessableEntity
		}
		writeError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"archive": id, "verified": true})
}

// handleRestore stages a restore for the next start.
//
// It does not restore. §15.3 puts a restore on a stopped node — the daemon
// holds the database open, and swapping it under a running reconciler is not
// something to attempt — so this verifies the archive, writes the request, and
// says plainly that a restart is what applies it.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeError(w, http.StatusServiceUnavailable, errNoBackups)
		return
	}
	var req RestoreRequest
	if r.ContentLength > 0 {
		if err := decodeBody(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	by := "unknown"
	if id, ok := auth.FromContext(r.Context()); ok {
		by = id.Subject
	}

	manifest, err := s.backups.Stage(r.Context(), req.Archive, req.SkipReplay, by)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, backup.ErrNotFound), errors.Is(err, backup.ErrNoArchives):
			status = http.StatusNotFound
		case errors.Is(err, backup.ErrCorrupt), errors.Is(err, backup.ErrKey):
			status = http.StatusUnprocessableEntity
		}
		writeError(w, status, err)
		return
	}

	auditTarget(r, manifest.ID)
	// Logged at warning, not info. This is the one API call that discards
	// everything currently on the node, and it should be conspicuous in the log
	// of the node it happens to.
	s.log.Warn("a state restore has been staged",
		"archive", manifest.ID, "created", manifest.CreatedAt, "index", manifest.Index,
		"by", by, "detail", "it will be applied the next time kanead starts")

	writeJSON(w, http.StatusOK, RestoreResponse{
		Archive: manifest, Staged: true, At: time.Now().UTC(),
		Message: fmt.Sprintf(
			"Restore staged from archive %s (index %d, taken %s). Nothing has changed yet: "+
				"restart kanead to apply it. The current state will be moved aside, not deleted.",
			manifest.ID, manifest.Index, manifest.CreatedAt.Format(time.RFC3339)),
	})
}

var errNoBackups = errors.New(
	"api: no backup destination is configured on this daemon (see --backup-dir or --backup-s3-endpoint)")
