package main

// The settings service (PRD v1.46): the daemon's implementation of the API's
// SettingsService. It lives here because this is where records become running
// machinery: sinks are assembled beside the kanea.hcl settings they supersede, channels
// are built by the same RoutesFor every other path uses, and the API's job
// stays deciding who may ask.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/settings"
	"github.com/m18h/kanea/internal/store"
)

// settingsService implements api.SettingsService.
type settingsService struct {
	st store.Store
	// notifyCfg carries the store and secrets resolver channel building needs.
	notifyCfg notifySettings
	manager   *backupManager
	// fileRepl is the replication template from the backup stanza of
	// kanea.hcl: the seed the v1.46 precedence rule falls back to when no
	// Store record wins, and the base a record is assembled over.
	fileRepl replicationSettings
	resolver secretResolver
	node     api.NodeConfigView
	// wake pulses the notification reloader after a mutation, so a change
	// made here takes effect without waiting for a store-change fan-out.
	wake chan<- struct{}
	log  *slog.Logger
}

// Node reports the facts kanea.hcl decided.
func (s *settingsService) Node() api.NodeConfigView { return s.node }

// Backup reports the effective configuration and where it came from.
func (s *settingsService) Backup(ctx context.Context) (api.BackupSettingsView, error) {
	view := api.BackupSettingsView{Source: s.manager.Source()}
	switch view.Source {
	case sourceStore:
		rec, found, err := settings.LoadBackup(ctx, s.st)
		if err != nil {
			return view, err
		}
		if found {
			view.Settings = &rec
		}
	case sourceFile:
		rec := s.fileBackupRecord()
		view.Settings = &rec
	}
	if view.Source != sourceNone {
		status := s.manager.Status()
		view.Status = &status
	}
	return view, nil
}

// fileBackupRecord renders the backup stanza of kanea.hcl in the record
// shape, so the dashboard shows one form whatever the source. The secret key
// travels as the reference it already is.
func (s *settingsService) fileBackupRecord() settings.BackupSettings {
	rec := settings.BackupSettings{
		Dir:              s.fileRepl.sink.dir,
		SnapshotInterval: settings.Duration(s.fileRepl.snapshotInterval),
		SegmentInterval:  settings.Duration(s.fileRepl.segmentInterval),
		Retention:        s.fileRepl.retention,
	}
	if s.fileRepl.sink.s3URL != "" {
		pathStyle := s.fileRepl.sink.pathStyle
		rec.S3 = &settings.S3Destination{
			URL: s.fileRepl.sink.s3URL, Endpoint: s.fileRepl.sink.endpoint,
			Region: s.fileRepl.sink.region, AccessKey: s.fileRepl.sink.accessKey,
			SecretKeyRef: s.fileRepl.secretKeyRef, PathStyle: &pathStyle,
		}
	}
	return rec
}

// PutBackup validates, probes, commits and swaps: in that order (v1.46), so a
// bad destination leaves working replication untouched.
func (s *settingsService) PutBackup(
	ctx context.Context, rec settings.BackupSettings,
) (api.BackupSettingsView, error) {
	if err := rec.Validate(); err != nil {
		return api.BackupSettingsView{}, fmt.Errorf("%w: %w", api.ErrInvalidSettings, err)
	}
	svc, err := assembleReplication(ctx, settingsToReplication(rec, s.fileRepl), s.resolver, s.log)
	if err != nil {
		// An unresolvable secret ref, a bad URL: the caller's to fix.
		return api.BackupSettingsView{}, fmt.Errorf("%w: %w", api.ErrInvalidSettings, err)
	}
	if err := s.manager.swap(ctx, svc, sourceStore, func() error {
		return settings.SaveBackup(ctx, s.st, rec)
	}); err != nil {
		return api.BackupSettingsView{}, err
	}
	return s.Backup(ctx)
}

// ResetBackup deletes the record and reverts to the backup stanza of
// kanea.hcl, or to unconfigured, when the file never named a destination.
func (s *settingsService) ResetBackup(ctx context.Context) (api.BackupSettingsView, error) {
	var svc *backupService
	source := sourceNone
	if s.fileRepl.sink.configured() {
		built, err := assembleReplication(ctx, s.fileRepl, s.resolver, s.log)
		if err != nil {
			return api.BackupSettingsView{}, fmt.Errorf(
				"%w: the backup destination in kanea.hcl no longer builds: %w", api.ErrInvalidSettings, err)
		}
		svc, source = built, sourceFile
	}
	if err := s.manager.swap(ctx, svc, source, func() error {
		return settings.DeleteBackup(ctx, s.st)
	}); err != nil {
		return api.BackupSettingsView{}, err
	}
	return s.Backup(ctx)
}

// Notifications reports the node-level channel record.
func (s *settingsService) Notifications(ctx context.Context) (api.NotificationSettingsView, error) {
	rec, found, err := settings.LoadNotifications(ctx, s.st)
	if err != nil {
		return api.NotificationSettingsView{}, err
	}
	if !found {
		return api.NotificationSettingsView{Source: sourceNone}, nil
	}
	return api.NotificationSettingsView{Source: sourceStore, Settings: &rec}, nil
}

// PutNotifications validates by building the channels (a bad reference or a
// refused URL is a 400 now, not a skipped route later) then commits and
// pulses the reloader.
func (s *settingsService) PutNotifications(
	ctx context.Context, rec settings.NotificationSettings,
) (api.NotificationSettingsView, error) {
	if err := rec.Validate(); err != nil {
		return api.NotificationSettingsView{}, fmt.Errorf("%w: %w", api.ErrInvalidSettings, err)
	}
	if _, err := nodeRoutesFor(ctx, rec.Channels, s.notifyCfg.egress(), s.notifyCfg.secrets, nil); err != nil {
		return api.NotificationSettingsView{}, fmt.Errorf("%w: %w", api.ErrInvalidSettings, err)
	}
	if err := settings.SaveNotifications(ctx, s.st, rec); err != nil {
		return api.NotificationSettingsView{}, err
	}
	s.pulse()
	return s.Notifications(ctx)
}

// ResetNotifications removes the node-level channels.
func (s *settingsService) ResetNotifications(ctx context.Context) (api.NotificationSettingsView, error) {
	if err := settings.DeleteNotifications(ctx, s.st); err != nil {
		return api.NotificationSettingsView{}, err
	}
	s.pulse()
	return s.Notifications(ctx)
}

// ProjectNotifications reads one project's channel config off its record.
func (s *settingsService) ProjectNotifications(
	ctx context.Context, project string,
) (api.ProjectNotificationsView, error) {
	cfg, _, err := store.GetValue[gitops.Config](ctx, s.st, store.KindProject, project)
	if errors.Is(err, store.ErrNotFound) {
		return api.ProjectNotificationsView{}, fmt.Errorf(
			"%w: no such project: %s", api.ErrNotFoundRoute, project)
	}
	if err != nil {
		return api.ProjectNotificationsView{}, err
	}
	return projectNotificationsView(cfg), nil
}

// PutProjectNotifications writes the same field on the same project record the
// HCL apply and the GitOps sync write (three writers, one config) and warns
// when the project is git-managed, because the next sync wins.
func (s *settingsService) PutProjectNotifications(
	ctx context.Context, project string, n *jobspec.Notifications,
) (api.ProjectNotificationsView, error) {
	if n != nil {
		if err := (settings.NotificationSettings{Channels: n}).Validate(); err != nil {
			return api.ProjectNotificationsView{}, fmt.Errorf("%w: %w", api.ErrInvalidSettings, err)
		}
		// Built to validate, not to keep: a channel holds a resolved
		// credential and a client, and the reloader builds the ones that run.
		if _, err := RoutesFor(ctx, project, n, s.notifyCfg.egress(), s.notifyCfg.secrets, nil); err != nil {
			return api.ProjectNotificationsView{}, fmt.Errorf("%w: %w", api.ErrInvalidSettings, err)
		}
	}

	cfg, _, err := store.GetValue[gitops.Config](ctx, s.st, store.KindProject, project)
	if errors.Is(err, store.ErrNotFound) {
		// A project deployed without a git block may have no record yet; the
		// record is *the* project record (§10), so it is created, not refused.
		cfg = gitops.Config{Project: project}
		err = nil
	}
	if err != nil {
		return api.ProjectNotificationsView{}, err
	}
	cfg.Notifications = n
	if _, err := store.PutValue(ctx, s.st, store.KindProject, project, cfg); err != nil {
		return api.ProjectNotificationsView{}, err
	}
	s.pulse()
	return projectNotificationsView(cfg), nil
}

// projectNotificationsView renders one project's config with its git warning.
func projectNotificationsView(cfg gitops.Config) api.ProjectNotificationsView {
	view := api.ProjectNotificationsView{
		Project:       cfg.Project,
		Notifications: cfg.Notifications,
		GitManaged:    cfg.HasSource(),
	}
	if view.GitManaged {
		view.Warning = "this project syncs from git; the notifications block in its " +
			"spec file wins on the next sync; make the change there to keep it"
	}
	return view
}

// pulse wakes the notification reloader without blocking.
func (s *settingsService) pulse() {
	if s.wake == nil {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
