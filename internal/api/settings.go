package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/m18h/kanea/internal/backup"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/settings"
)

// PathSettings is the node-settings surface (PRD v1.46, §15.1, §16.1).
const PathSettings = "/v1/settings"

// ErrInvalidSettings marks a refusal the caller can fix (a malformed record,
// a destination that failed its probe) and maps to 400 rather than 500.
var ErrInvalidSettings = errors.New("api: invalid settings")

// SettingsService is the slice of the daemon the settings routes need. It is
// implemented in cmd/kanea, where the sinks and channels are actually built:
// the API decides who may change settings; the binary decides what a record
// becomes.
type SettingsService interface {
	// Node reports the flag-decided facts, read-only.
	Node() NodeConfigView
	Backup(ctx context.Context) (BackupSettingsView, error)
	// PutBackup validates, probes the new destination, commits the record and
	// swaps replication: in that order, so a bad destination leaves the old
	// replication untouched.
	PutBackup(ctx context.Context, rec settings.BackupSettings) (BackupSettingsView, error)
	// ResetBackup deletes the record, reverting to the flags.
	ResetBackup(ctx context.Context) (BackupSettingsView, error)
	Notifications(ctx context.Context) (NotificationSettingsView, error)
	PutNotifications(ctx context.Context, rec settings.NotificationSettings) (NotificationSettingsView, error)
	ResetNotifications(ctx context.Context) (NotificationSettingsView, error)
	ProjectNotifications(ctx context.Context, project string) (ProjectNotificationsView, error)
	PutProjectNotifications(ctx context.Context, project string, n *jobspec.Notifications) (ProjectNotificationsView, error)
}

// NodeConfigView is what the flags decided: shown, never edited here. Changing
// any of it is a unit edit and a restart, and the page says so.
type NodeConfigView struct {
	Listen       string `json:"listen,omitempty"`
	TLS          bool   `json:"tls"`
	BaseDomain   string `json:"base_domain,omitempty"`
	NetworkMode  string `json:"network_mode"`
	NodeCIDR     string `json:"node_cidr"`
	ClusterCIDR  string `json:"cluster_cidr"`
	ServiceCIDR  string `json:"service_cidr"`
	NodeCIDR6    string `json:"node_cidr6,omitempty"`
	ClusterCIDR6 string `json:"cluster_cidr6,omitempty"`
	ServiceCIDR6 string `json:"service_cidr6,omitempty"`
	DNSListen    string `json:"dns_listen,omitempty"`
	DataDir      string `json:"data_dir"`
	LogDir       string `json:"log_dir"`
	PublishPorts string `json:"publish_ports,omitempty"`
	TLSDefault   string `json:"tls_default,omitempty"`
}

// BackupSettingsView is the effective backup configuration and where it came
// from. The secret key travels only as the reference's name.
type BackupSettingsView struct {
	// Source is "store", "flags" or "none".
	Source   string                   `json:"source"`
	Settings *settings.BackupSettings `json:"settings,omitempty"`
	// Status is live replication health, when replication runs.
	Status *backup.Status `json:"status,omitempty"`
}

// NotificationSettingsView is the node-level channel record and its source.
type NotificationSettingsView struct {
	Source   string                         `json:"source"`
	Settings *settings.NotificationSettings `json:"settings,omitempty"`
}

// ProjectNotificationsView is one project's channel config. References are
// names, never values: safe for an admin to read back.
type ProjectNotificationsView struct {
	Project       string                 `json:"project"`
	Notifications *jobspec.Notifications `json:"notifications,omitempty"`
	// GitManaged warns that the next sync wins: the project has a git source,
	// and its spec file is the durable home of this block.
	GitManaged bool   `json:"git_managed"`
	Warning    string `json:"warning,omitempty"`
}

// SettingsResponse is GET /v1/settings.
type SettingsResponse struct {
	Node          NodeConfigView           `json:"node"`
	Backup        BackupSettingsView       `json:"backup"`
	Notifications NotificationSettingsView `json:"notifications"`
}

// handleGetSettings serves the whole settings view.
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeError(w, http.StatusServiceUnavailable, errNoSettings)
		return
	}
	backupView, err := s.settings.Backup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	notifyView, err := s.settings.Notifications(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, SettingsResponse{
		Node: s.settings.Node(), Backup: backupView, Notifications: notifyView,
	})
}

// handlePutBackupSettings replaces the backup destination.
func (s *Server) handlePutBackupSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeError(w, http.StatusServiceUnavailable, errNoSettings)
		return
	}
	var rec settings.BackupSettings
	if err := decodeBody(r, &rec); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	auditTarget(r, settings.KeyBackup)

	view, err := s.settings.PutBackup(r.Context(), rec)
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	s.log.Info("backup settings replaced", "source", view.Source)
	writeJSON(w, http.StatusOK, view)
}

// handleResetBackupSettings deletes the record, reverting to the flags.
func (s *Server) handleResetBackupSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeError(w, http.StatusServiceUnavailable, errNoSettings)
		return
	}
	auditTarget(r, settings.KeyBackup)
	view, err := s.settings.ResetBackup(r.Context())
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	s.log.Info("backup settings reverted to flags", "source", view.Source)
	writeJSON(w, http.StatusOK, view)
}

// handlePutNotificationSettings replaces the node-level channels.
func (s *Server) handlePutNotificationSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeError(w, http.StatusServiceUnavailable, errNoSettings)
		return
	}
	var rec settings.NotificationSettings
	if err := decodeBody(r, &rec); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	auditTarget(r, settings.KeyNotifications)

	view, err := s.settings.PutNotifications(r.Context(), rec)
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleResetNotificationSettings removes the node-level channels.
func (s *Server) handleResetNotificationSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeError(w, http.StatusServiceUnavailable, errNoSettings)
		return
	}
	auditTarget(r, settings.KeyNotifications)
	view, err := s.settings.ResetNotifications(r.Context())
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleTestNodeChannels tests the node-wide channels: the ones the
// project-scoped test route can never name, because their scope is empty.
func (s *Server) handleTestNodeChannels(w http.ResponseWriter, r *http.Request) {
	if s.notifier == nil {
		writeError(w, http.StatusServiceUnavailable,
			errors.New("api: no notification channels are configured on this daemon"))
		return
	}
	channel := r.URL.Query().Get("channel")
	auditTarget(r, "node/"+channel)
	results := s.notifier.TestNodeChannels(channel)
	if len(results) == 0 {
		writeError(w, http.StatusNotFound,
			errors.New("api: no node-level notification channel matches"))
		return
	}
	writeJSON(w, http.StatusOK, TestNotificationResponse{Results: results})
}

// handleGetProjectNotifications serves one project's channel config.
func (s *Server) handleGetProjectNotifications(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeError(w, http.StatusServiceUnavailable, errNoSettings)
		return
	}
	view, err := s.settings.ProjectNotifications(r.Context(), r.PathValue("project"))
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handlePutProjectNotifications replaces one project's channel config.
//
// It writes the same field on the same project record HCL apply and GitOps
// sync write, so the three writers converge on one config, and the response
// carries the git warning, because for a synced project the next sync wins.
func (s *Server) handlePutProjectNotifications(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeError(w, http.StatusServiceUnavailable, errNoSettings)
		return
	}
	project := r.PathValue("project")
	var body struct {
		Notifications *jobspec.Notifications `json:"notifications"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	auditTarget(r, project+"/notifications")

	view, err := s.settings.PutProjectNotifications(r.Context(), project, body.Notifications)
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// writeSettingsError maps a settings failure onto a status.
func writeSettingsError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidSettings):
		writeError(w, http.StatusBadRequest, err)
	case errors.Is(err, ErrNotFoundRoute):
		writeError(w, http.StatusNotFound, err)
	default:
		writeError(w, http.StatusInternalServerError, err)
	}
}

// ErrNotFoundRoute marks a settings target that does not exist (a project name
// nothing matches). Named oddly to avoid colliding with the store's ErrNotFound
// in this package's error space.
var ErrNotFoundRoute = errors.New("api: no such target")

var errNoSettings = errors.New("api: this daemon has no settings service wired")
