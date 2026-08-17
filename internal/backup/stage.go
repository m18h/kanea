package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// A staged restore (PRD §15.3).
//
// §15.3 is explicit that a restore happens "on a stopped node", and it has to
// be: the daemon holds the database open, and swapping it underneath a running
// reconciler is not a thing to attempt. But "stopped node" and "shell access"
// are not the same requirement, and an operator recovering at three in the
// morning may have neither a terminal on the box nor the patience for one.
//
// So a restore can be *requested* while the node runs and is *performed* at the
// next start, before anything opens the Store. The request is a file rather
// than a Store record for the obvious reason: the Store is the thing being
// replaced.

// RequestFileName is the marker's name under the data directory.
const RequestFileName = "restore-request.json"

// Request is a staged restore.
type Request struct {
	// ArchiveID names the archive. Empty means the newest at the time the
	// restore runs, which is deliberately resolved late: a node that has been
	// down for an hour should come back with the newest state, not with
	// whatever was newest when someone filed the request.
	ArchiveID   string    `json:"archive_id,omitempty"`
	SkipReplay  bool      `json:"skip_replay,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
	RequestedBy string    `json:"requested_by,omitempty"`
}

// WriteRequest stages a restore for the next start.
func WriteRequest(dir string, req Request) error {
	body, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return fmt.Errorf("backup: encode the restore request: %w", err)
	}
	path := filepath.Join(dir, RequestFileName)

	// Written through a temp file and renamed, like every other durable write
	// here: a half-written request that parsed would be a restore to a
	// half-specified archive.
	tmp := path + ".partial"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("backup: write the restore request: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return errors.Join(fmt.Errorf("backup: stage the restore request: %w", err), os.Remove(tmp))
	}
	return nil
}

// ReadRequest returns the staged restore, or nil when there is none.
func ReadRequest(dir string) (*Request, error) {
	path := filepath.Join(dir, RequestFileName)
	body, err := os.ReadFile(path) // #nosec G304; the daemon's own data directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("backup: read the restore request: %w", err)
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		// Refused rather than ignored. A request file that does not parse is a
		// request somebody made, and starting normally would silently not
		// restore a node whose operator believes it did.
		return nil, fmt.Errorf("backup: %s does not parse: %w "+
			"(delete it to start without restoring)", path, err)
	}
	return &req, nil
}

// ClearRequest removes the marker once the restore has run.
func ClearRequest(dir string) error {
	if err := os.Remove(filepath.Join(dir, RequestFileName)); err != nil &&
		!errors.Is(err, fs.ErrNotExist) {
		// This one is fatal to the caller, unlike most cleanup: a request that
		// survives its own restore restores again on the next start, and again
		// after that.
		return fmt.Errorf("backup: cannot clear the restore request: %w", err)
	}
	return nil
}
