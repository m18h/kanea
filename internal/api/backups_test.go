package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/backup"
)

// fakeBackups stands in for the daemon's archiver.
type fakeBackups struct {
	mu        sync.Mutex
	archives  []backup.Manifest
	staged    *string
	verifyErr error
	createErr error
}

func (f *fakeBackups) List(context.Context) ([]backup.Manifest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.archives, nil
}

func (f *fakeBackups) Create(_ context.Context, reason string) (backup.Manifest, error) {
	if f.createErr != nil {
		return backup.Manifest{}, f.createErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	m := backup.Manifest{
		ID: "20260808T120000Z", Index: 42, Reason: reason,
		CreatedAt: time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC),
	}
	f.archives = append(f.archives, m)
	return m, nil
}

func (f *fakeBackups) Verify(context.Context, string) error { return f.verifyErr }

func (f *fakeBackups) Stage(_ context.Context, id string, _ bool, _ string) (backup.Manifest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.archives) == 0 {
		return backup.Manifest{}, backup.ErrNoArchives
	}
	resolved := f.archives[0]
	if id != "" {
		resolved.ID = id
	}
	f.staged = &resolved.ID
	return resolved, nil
}

func (f *fakeBackups) Status() backup.Status {
	return backup.Status{Sink: "file:///backups", ShippedTo: 42}
}

func withBackups(f *fakeBackups) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) { cfg.Backups = f }
}

func TestBackupRoutesAre503WithoutADestination(t *testing.T) {
	// "No destination configured" and "the backup failed" are different
	// answers, and an operator acts differently on each.
	h := newHarness(t)
	if status, _ := h.raw(t, http.MethodGet, api.PathBackups); status != http.StatusServiceUnavailable {
		t.Errorf("list = %d, want 503", status)
	}
	if status, _ := h.raw(t, http.MethodPost, api.PathBackups); status != http.StatusServiceUnavailable {
		t.Errorf("create = %d, want 503", status)
	}
}

func TestBackupListReportsReplicationHealth(t *testing.T) {
	// The number that decides whether a backup strategy is real, and the one an
	// operator normally does not have until the restore.
	fake := &fakeBackups{}
	h := newHarness(t, withBackups(fake))

	status, body := h.raw(t, http.MethodGet, api.PathBackups)
	if status != http.StatusOK {
		t.Fatalf("list = %d: %s", status, body)
	}
	var resp api.BackupsResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Replication.Sink == "" {
		t.Error("the response does not say where state is being replicated")
	}
	if resp.Backups == nil {
		t.Error("an empty archive list came back as null rather than []")
	}
}

func TestVerifyReports422ForADamagedArchive(t *testing.T) {
	// A damaged archive is a fact about the bucket that the caller asked for,
	// not a server error.
	fake := &fakeBackups{verifyErr: backup.ErrCorrupt}
	h := newHarness(t, withBackups(fake))
	status, _ := h.raw(t, http.MethodGet, api.PathBackups+"/20260808T120000Z/verify")
	if status != http.StatusUnprocessableEntity {
		t.Errorf("verify = %d, want 422", status)
	}
}

func TestRestoreStagesRatherThanRestoring(t *testing.T) {
	// §15.3 puts a restore on a stopped node. This route must never claim to
	// have done one.
	fake := &fakeBackups{}
	h := newHarness(t, withBackups(fake))
	if _, err := h.client.CreateBackup(context.Background(), "test"); err != nil {
		t.Fatalf("create: %v", err)
	}

	resp, err := h.client.StageRestore(context.Background(), "", false)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if !resp.Staged {
		t.Error("the response does not mark itself as staged")
	}
	for _, want := range []string{"restart kanead", "Nothing has changed yet"} {
		if !strings.Contains(resp.Message, want) {
			t.Errorf("the message does not say %q:\n%s", want, resp.Message)
		}
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.staged == nil {
		t.Error("nothing was staged")
	}
}

func TestRestoreOfAMissingArchiveIs404(t *testing.T) {
	fake := &fakeBackups{}
	h := newHarness(t, withBackups(fake))
	_, err := h.client.StageRestore(context.Background(), "nope", false)
	if err == nil {
		t.Fatal("staging a restore from an empty bucket reported success")
	}
	var status *api.StatusError
	if !errors.As(err, &status) || status.Status != http.StatusNotFound {
		t.Errorf("err = %v, want a 404", err)
	}
}
