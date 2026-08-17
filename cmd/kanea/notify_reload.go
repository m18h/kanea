package main

// Change-driven notification routes (PRD v1.46, §11). Routes were
// startup-static because a channel holds a resolved credential and an HTTP
// client; what changes is not that reasoning but the trigger: routes rebuild
// when the configuration actually changed, detected by fingerprint, so a busy
// Store never causes a rebuild and a changed channel never needs a restart.

import (
	"context"
	"log/slog"
	"sort"

	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/settings"
)

// egress is the node's notification egress policy (§14 A10).
func (c notifySettings) egress() notify.EgressPolicy {
	return notify.EgressPolicy{AllowPrivate: c.allowPrivate, AllowHTTP: c.allowHTTP}
}

// nodeRoutesFor builds the node-level default routes (v1.46): the same builder
// projects use, with the scope cleared so the routes see every project.
func nodeRoutesFor(
	ctx context.Context, n *jobspec.Notifications,
	egress notify.EgressPolicy, secrets notify.Resolver, log *slog.Logger,
) ([]notify.Route, error) {
	if n == nil {
		return nil, nil
	}
	// "node" names the channels ("node/telegram"): a label, not a scope.
	routes, err := RoutesFor(ctx, "node", n, egress, secrets, log)
	if err != nil {
		return nil, err
	}
	for i := range routes {
		// An empty project is the dispatcher's "sees everything" (§11).
		routes[i].Project = ""
	}
	return routes, nil
}

// allNotifyRoutes is every route the node runs: each project's channels plus
// the node-level defaults. One builder for startup and reload, so the two
// cannot drift.
func allNotifyRoutes(
	ctx context.Context, cfg notifySettings, egress notify.EgressPolicy, logger *slog.Logger,
) ([]notify.Route, error) {
	routes, err := notifyRoutes(ctx, cfg, egress, logger)
	if err != nil {
		return nil, err
	}

	rec, found, err := settings.LoadNotifications(ctx, cfg.store)
	if err != nil {
		// The projects' channels still work; the node record is the one that
		// is broken, and it is one Store read that will be retried on the
		// next change.
		logger.Error("cannot read the node notification settings", "error", err)
		return routes, nil
	}
	if found {
		node, err := nodeRoutesFor(ctx, rec.Channels, egress, cfg.secrets, logger)
		if err != nil {
			// The same isolation notifyRoutes gives one broken project: the
			// node-level mistake must not silence every project's channels.
			logger.Error("cannot configure the node-level notification channels", "error", err)
		} else {
			routes = append(routes, node...)
		}
	}
	return routes, nil
}

// notifyFingerprint hashes everything the route set is built from, so the
// reloader rebuilds only when configuration actually changed; the v1.44
// Providers.Current rule: a rebuild per store write would re-resolve
// credentials on every deploy.
func notifyFingerprint(ctx context.Context, cfg notifySettings) (string, error) {
	configs, err := listProjectConfigs(ctx, cfg.store)
	if err != nil {
		return "", err
	}
	type entry struct {
		Project string
		N       *jobspec.Notifications
	}
	var entries []entry
	for _, pc := range configs {
		if pc.Notifications != nil {
			entries = append(entries, entry{pc.Project, pc.Notifications})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Project < entries[j].Project })

	rec, _, err := settings.LoadNotifications(ctx, cfg.store)
	if err != nil {
		return "", err
	}
	return settings.Fingerprint(struct {
		Projects []entry
		Node     settings.NotificationSettings
	}{entries, rec}), nil
}

// runNotifyReload rebuilds the dispatcher's routes when notification config
// changes. It listens on a fanned-out store-change signal, so HCL apply,
// GitOps sync and the settings routes all land here through one door.
func runNotifyReload(
	ctx context.Context, wake <-chan struct{}, cfg notifySettings,
	egress notify.EgressPolicy, dispatcher *notify.Dispatcher, logger *slog.Logger,
) {
	last, err := notifyFingerprint(ctx, cfg)
	if err != nil {
		// An empty baseline just means the first wake rebuilds, which is safe.
		logger.Warn("cannot fingerprint the notification config", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
		}

		fp, err := notifyFingerprint(ctx, cfg)
		if err != nil {
			logger.Warn("cannot fingerprint the notification config", "error", err)
			continue
		}
		if fp == last {
			continue
		}
		routes, err := allNotifyRoutes(ctx, cfg, egress, logger)
		if err != nil {
			logger.Error("cannot rebuild notification routes; keeping the current ones",
				"error", err)
			continue
		}
		dispatcher.SetRoutes(routes)
		last = fp
	}
}
