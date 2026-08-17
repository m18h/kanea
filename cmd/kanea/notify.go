package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/m18h/kanea/internal/store"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/notify"
)

// Building routes from a project's `notifications` block (PRD §6.1, §11).
//
// This is the seam between what an operator writes and what the dispatcher
// runs. It lives here rather than in internal/notify because the dependency has
// to point one way: the job spec validates event filters against notify's
// vocabulary, so notify cannot also depend on the job spec. Wiring is the
// binary's job anyway: the same reason toDesired lives beside the CLI.
//
// It is deliberately strict: a channel that cannot be built is an error, not a
// warning that gets logged and forgotten, because a notification channel
// silently missing is the failure this subsystem exists to prevent.

// RoutesFor builds the routes a project's notification block asks for.
//
// One route per channel rather than one per project, so a project can send
// deploy failures to email and everything to a webhook, and so a channel that
// gets rate limited does not hold back the others.
func RoutesFor(
	ctx context.Context, project string, n *jobspec.Notifications,
	egress notify.EgressPolicy, secrets notify.Resolver, log *slog.Logger,
) ([]notify.Route, error) {
	if n == nil {
		return nil, nil
	}
	floor, err := notify.ParseSeverity(n.Severity)
	if err != nil {
		return nil, fmt.Errorf("project %s: %w", project, err)
	}
	filter, err := notify.NewFilter(n.On, floor)
	if err != nil {
		return nil, fmt.Errorf("project %s: %w", project, err)
	}
	if filter.Empty() {
		// Already a spec error at parse time; reaching here means a spec that
		// bypassed the parser, so say so rather than build silent channels.
		return nil, fmt.Errorf("project %s: notification channels with no `on` filter", project)
	}

	var built []notify.Channel
	if t := n.Telegram; t != nil {
		ch, err := notify.NewTelegram(ctx, notify.TelegramConfig{
			Name: project + "/telegram", TokenRef: t.TokenRef, ChatID: t.ChatID,
			Egress: egress,
		}, secrets)
		if err != nil {
			return nil, err
		}
		built = append(built, ch)
	}
	if w := n.Webhook; w != nil {
		ch, err := notify.NewWebhook(ctx, notify.WebhookConfig{
			Name: project + "/webhook", URL: w.URL, SecretRef: w.SecretRef,
			Egress: egress,
		}, secrets)
		if err != nil {
			return nil, err
		}
		built = append(built, ch)
	}
	if s := n.Slack; s != nil {
		ch, err := notify.NewSlack(ctx, notify.SlackConfig{
			Name: project + "/slack", URLRef: s.URLRef, Egress: egress,
		}, secrets)
		if err != nil {
			return nil, err
		}
		built = append(built, ch)
	}
	if nt := n.Ntfy; nt != nil {
		ch, err := notify.NewNtfy(ctx, notify.NtfyConfig{
			Name: project + "/ntfy", URL: nt.URL, TokenRef: nt.TokenRef,
			Egress: egress,
		}, secrets)
		if err != nil {
			return nil, err
		}
		built = append(built, ch)
	}
	if sm := n.SMTP; sm != nil {
		ch, err := notify.NewSMTP(ctx, notify.SMTPConfig{
			Name: project + "/smtp", Host: sm.Host, Port: sm.Port,
			From: sm.From, To: sm.To,
			Username: sm.Username, PasswordRef: sm.PasswordRef,
			Egress: egress,
		}, secrets)
		if err != nil {
			return nil, err
		}
		built = append(built, ch)
	}

	routes := make([]notify.Route, 0, len(built))
	for _, ch := range built {
		// Project-scoped, always. A project's own notification block must not
		// become a way to watch another project's failures: the same boundary
		// R5 draws for secrets.
		routes = append(routes, notify.Route{Channel: ch, Filter: filter, Project: project})
	}
	if log != nil && len(routes) > 0 {
		log.Info("notification channels configured",
			"project", project, "channels", len(routes), "on", filter.Patterns())
	}
	return routes, nil
}

// notifySettings is what the agent knows about notifications.
type notifySettings struct {
	store        store.Store
	secrets      notify.Resolver
	allowPrivate bool
	allowHTTP    bool
	retention    int
}

// buildNotifier assembles the dispatcher and the feed.
//
// The feed exists even with no channels configured. §11 mirrors every channel
// into the dashboard, and a node whose operator has not set up Telegram still
// wants to see that a cert renewal failed, so the feed is the floor, and
// channels are what is built on top of it.
func buildNotifier(
	ctx context.Context, cfg notifySettings, logger *slog.Logger,
) (*notify.Dispatcher, *notify.Feed, *teeSink, error) {
	feed, err := notify.NewFeed(notify.FeedConfig{
		Store: cfg.store, Logger: logger, Retention: cfg.retention,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	// The dispatcher's Sink is a tee: the feed is the record and comes first,
	// and the function invoker (v1.39, §11) attaches as the second consumer;
	// after construction, before Run starts. Routes reload on config change
	// since v1.46; the Sink remains the one place a live event trigger sees
	// everything regardless of what channels exist.
	tee := &teeSink{primary: feed}

	egress := cfg.egress()
	if cfg.allowPrivate {
		// Worth a line in the log: it is the §14 A10 guard being switched off,
		// and an operator who did not mean to should find out from the startup
		// log rather than from an incident.
		logger.Warn("notification egress may reach private addresses",
			"reason", "--notify-allow-private is set")
	}

	// Projects' channels plus the node-level defaults (v1.46): the same
	// builder the runtime reloader uses, so startup and reload cannot drift.
	routes, err := allNotifyRoutes(ctx, cfg, egress, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	dispatcher, err := notify.New(notify.Config{
		Routes: routes, Sink: tee, Logger: logger,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return dispatcher, feed, tee, nil
}

// listProjectConfigs reads every project record.
func listProjectConfigs(ctx context.Context, st store.Store) ([]gitops.Config, error) {
	var out []gitops.Config
	var after string
	for {
		values, page, err := store.ListValues[gitops.Config](ctx, st,
			store.KindProject, store.ListOptions{After: after, Limit: 200})
		if err != nil {
			return nil, fmt.Errorf("list projects: %w", err)
		}
		out = append(out, values...)
		if !page.More {
			return out, nil
		}
		after = page.NextAfter
	}
}

// notifyRoutes reads every project's notification block out of the Store.
//
// Read at startup rather than per event: a channel holds a resolved credential
// and an HTTP client, and rebuilding those on every notification would put a
// secrets-store read on the path of a crash-loop storm.
func notifyRoutes(
	ctx context.Context, cfg notifySettings, egress notify.EgressPolicy, logger *slog.Logger,
) ([]notify.Route, error) {
	configs, err := listProjectConfigs(ctx, cfg.store)
	if err != nil {
		return nil, err
	}

	var routes []notify.Route
	for _, pc := range configs {
		if pc.Notifications == nil {
			continue
		}
		built, err := RoutesFor(ctx, pc.Project, pc.Notifications, egress, cfg.secrets, logger)
		if err != nil {
			// One project's broken channel must not stop the daemon: the other
			// projects' notifications are the ones that would go missing, and
			// they are not the ones with the mistake.
			logger.Error("cannot configure notifications for a project",
				"project", pc.Project, "error", err)
			continue
		}
		routes = append(routes, built...)
	}
	return routes, nil
}
