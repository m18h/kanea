package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/secretsource"
)

// The secret sync loop (PRD §5.2.13): pull mapped external secrets into the
// local store on an interval. It mirrors the certificate loop's shape — an
// immediate pass at startup, a slow work timer, a fast config poll — and the
// reconciler never waits for it: the store serves whatever the last pass
// wrote, which is the point of syncing into the store at all.

const (
	// secretSyncDefaultInterval is the steady-state poll. Five minutes is the
	// replication RPO's number (§15.3): rotation tools work in minutes, and
	// anything faster is spending someone else's API rate limit.
	secretSyncDefaultInterval = 5 * time.Minute
	// secretSyncMinInterval is the floor the flag refuses below — a poll is a
	// request against a provider's rate limit, five of them per pass.
	secretSyncMinInterval = 30 * time.Second
	// secretSyncRetryInterval is the first retry after a failed pass; each
	// consecutive failure doubles it, capped at the configured interval. A bad
	// token against a rate-limited provider must not be hammered at retry
	// cadence forever.
	secretSyncRetryInterval = time.Minute
	// secretConfigCheckInterval is how often the config and credential files
	// are checked for movement — certFileCheckInterval's twin, because a
	// rotation tool rewrites a token without telling Kanea.
	secretConfigCheckInterval = time.Minute
)

// runSecretSync is kanead's secret sync loop.
func runSecretSync(ctx context.Context, syncer *secretsource.Syncer,
	providers *secretsource.Providers, interval time.Duration,
	logger *slog.Logger, emit func(notify.Event),
) error {
	// consecutiveFailures drives the backoff; it resets on the first clean
	// pass.
	consecutiveFailures := 0
	pass := func() {
		result := syncer.SyncOnce(ctx)
		emitSecretEvents(emit, result, logger)
		if result.Failed() {
			consecutiveFailures++
		} else {
			consecutiveFailures = 0
		}
	}

	// Consume the initial Changed() so the config ticker below only fires on
	// an actual edit, then pass immediately: a restart must re-establish
	// whatever the providers hold now, not at the first tick.
	providers.Changed()
	pass()

	timer := time.NewTimer(secretSyncWait(interval, consecutiveFailures))
	defer timer.Stop()
	files := time.NewTicker(secretConfigCheckInterval)
	defer files.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		case <-files.C:
			if !providers.Changed() {
				continue
			}
			logger.Info("secret provider config changed on disk", "path", providers.Path())
		}

		pass()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(secretSyncWait(interval, consecutiveFailures))
	}
}

// secretSyncWait picks the next wait: the interval on success, a doubling
// backoff capped at the interval after consecutive failures, and ±10% jitter
// either way so a fleet of nodes does not align against one Vault.
func secretSyncWait(interval time.Duration, consecutiveFailures int) time.Duration {
	wait := interval
	if consecutiveFailures > 0 {
		wait = secretSyncRetryInterval
		for i := 1; i < consecutiveFailures && wait < interval; i++ {
			wait *= 2
		}
		if wait > interval {
			wait = interval
		}
	}
	jitter := 0.9 + 0.2*rand.Float64() // #nosec G404 — jitter, not cryptography
	return time.Duration(float64(wait) * jitter)
}

// emitSecretEvents turns one pass's result into §11 events: one
// secret.synced per provider that changed something (steady state is
// silent), one secret.sync_failed per provider with failures. Paths and
// refs, never values.
func emitSecretEvents(emit func(notify.Event), result secretsource.PassResult, logger *slog.Logger) {
	for _, pass := range result.PerProvider {
		source := string(pass.Kind) + "/" + pass.Name
		if len(pass.Changed) > 0 {
			message := fmt.Sprintf("%s synced %s", source, joinBounded(pass.Changed, 5))
			logger.Info("secrets synced", "provider", source, "paths", pass.Changed)
			if emit != nil {
				emit(notify.NewEvent(notify.EventSecretSynced, "", "", message, time.Now()).
					WithDetail(source))
			}
		}
		if len(pass.Failures) > 0 {
			details := make([]string, 0, len(pass.Failures))
			for _, f := range pass.Failures {
				details = append(details, fmt.Sprintf("%s (%s): %v", f.To, f.Ref, f.Err))
			}
			message := fmt.Sprintf("%s failed to sync %s", source, joinBounded(details, 3))
			logger.Error("secret sync failed", "provider", source, "failures", len(pass.Failures),
				"detail", joinBounded(details, 3))
			if emit != nil {
				emit(notify.NewEvent(notify.EventSecretSyncFailed, "", "", message, time.Now()).
					WithDetail(source))
			}
		}
	}
}

// joinBounded joins up to n items and counts the rest, so a forty-mapping
// provider failing whole does not become a forty-line notification.
func joinBounded(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(items[:n], ", "), len(items)-n)
}

// secretSyncStatus adapts the syncer for the API, with the explicit-nil rule
// buildReplication follows: a typed nil in an interface field is a non-nil
// interface, so an unconfigured node must pass untyped nil.
func secretSyncStatus(syncer *secretsource.Syncer, providers *secretsource.Providers) api.SecretSyncStatus {
	if providers == nil || !providers.Configured() {
		return nil
	}
	return syncer
}
