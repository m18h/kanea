package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/store"
)

// GitOps and build pipelines in kanead (PRD §10).
//
// Four moving parts run here: the queue's single worker, the sync loop that
// polls every project with a git source, the runner behind both, and the two
// seams — an Applier that turns a synced spec into desired state and a Deployer
// that pins a built digest. Everything else lives in internal/gitops.

// DefaultSyncInterval is how often a project with a git source is polled.
//
// Two minutes is a compromise: a webhook makes a push land in seconds, so the
// poll is the fallback for the repositories that have no webhook configured and
// for the deliveries that were dropped. Making it much shorter would put a
// clone on every remote every few seconds for changes that mostly are not
// there; much longer and an operator without webhooks is waiting too long to
// see whether their commit deployed.
const DefaultSyncInterval = 2 * time.Minute

// pipelineSettings is what the agent knows about pipelines.
type pipelineSettings struct {
	buildkit   string
	logDir     string
	interval   time.Duration
	baseDomain string
	insecure   bool

	store   store.Store
	secrets gitops.Resolver
	notify  chan<- struct{}
	emit    func(notify.Event)
}

// buildPipelines assembles the pipeline stack.
//
// Returns a nil service when pipelines are switched off, which is a supported
// configuration: a node that only ever runs pre-built images has no reason to
// hold a builder connection open or to poll anything.
func buildPipelines(cfg pipelineSettings, logger *slog.Logger) (*gitops.Service, *gitops.Queue, error) {
	if cfg.buildkit == "off" {
		logger.Info("build pipelines disabled")
		return nil, nil, nil
	}

	runs, err := gitops.NewRuns(cfg.store, time.Now)
	if err != nil {
		return nil, nil, err
	}
	builder, err := gitops.NewBuilder(gitops.BuilderConfig{
		Socket: cfg.buildkit,
		// Scratch lives beside the logs rather than in /tmp: it briefly holds a
		// materialised registry config.json, and the log directory is already
		// the one place with the permissions that deserves (§10.2).
		WorkDir: filepath.Join(cfg.logDir, "scratch"),
		Logger:  logger,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("buildkit: %w", err)
	}
	runner, err := gitops.NewRunner(gitops.RunnerConfig{
		Runs:    runs,
		Syncer:  gitops.NewSyncer(gitops.SyncerConfig{Secrets: cfg.secrets, Logger: logger}),
		Builder: builder,
		// A build that produced a digest and did not deploy it is a build
		// nobody asked for, so the deployer is not optional here.
		Deployer: storeDeployer{store: cfg.store, notify: cfg.notify, log: logger},
		Secrets:  cfg.secrets,
		LogDir:   cfg.logDir,
		Logger:   logger,
	})
	if err != nil {
		return nil, nil, err
	}
	queue, err := gitops.NewQueue(gitops.QueueConfig{
		Runner: runner, Logger: logger,
		// The adapter that keeps gitops free of a notify dependency: it hands
		// out strings, and the event vocabulary stays in one package.
		Emit: func(project, service, name, message string) {
			if cfg.emit != nil {
				cfg.emit(notify.NewEvent(name, project, service, message, time.Now()))
			}
		},
	})
	if err != nil {
		return nil, nil, err
	}

	svc, err := gitops.NewService(gitops.ServiceConfig{
		Store:    cfg.store,
		Runs:     runs,
		Runner:   runner,
		Queue:    queue,
		Syncer:   gitops.NewSyncer(gitops.SyncerConfig{Secrets: cfg.secrets, Logger: logger}),
		Webhooks: gitops.NewWebhooks(gitops.WebhooksConfig{Secrets: cfg.secrets}),
		Applier:  storeApplier{store: cfg.store, notify: cfg.notify, log: logger},
		// The same options `kanea deploy` parses with, so a spec means the same
		// thing whether it arrives over the API or out of a repository.
		SpecOptions: jobspec.Options{BaseDomain: cfg.baseDomain},
		Insecure:    cfg.insecure,
		Logger:      logger,
	})
	if err != nil {
		return nil, nil, err
	}

	// Reachability is probed but not required. buildkitd may be starting
	// alongside kanead, and refusing to start the control plane because a
	// builder is not up yet would take the whole node down for something only
	// builds need.
	if err := builder.Probe(context.Background()); err != nil {
		logger.Warn("buildkitd is not reachable; builds will fail until it is",
			"address", cfg.buildkit, "error", err)
	}
	return svc, queue, nil
}

// runSync polls every project with a git source, and syncs on demand.
//
// One loop for every project rather than one per project: syncs are cheap when
// nothing changed (a remote ref listing), builds are queued rather than run
// here, and a single loop makes the total work a node does for GitOps
// proportional to the number of projects instead of to a goroutine count.
func runSync(ctx context.Context, svc *gitops.Service, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = DefaultSyncInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case project := <-svc.Wake():
			// A webhook said this project changed. Sync only that one: a push
			// to one repository is no reason to go and clone every other.
			syncOne(ctx, svc, project, "webhook", logger)
		case <-ticker.C:
			projects, err := svc.Projects(ctx)
			if err != nil {
				logger.Error("cannot list projects to sync", "error", err)
				continue
			}
			for _, cfg := range projects {
				if !cfg.HasSource() {
					continue
				}
				// A project's own poll_interval is honoured by skipping ticks,
				// not by a second timer: the loop already runs at the shortest
				// useful cadence and this only makes a project poll less often.
				if cfg.PollInterval > 0 && !cfg.LastSyncAt.IsZero() &&
					time.Since(cfg.LastSyncAt) < cfg.PollInterval {
					continue
				}
				syncOne(ctx, svc, cfg.Project, "poll", logger)
			}
		}
	}
}

// syncOne syncs a single project, bounded in time.
//
// The timeout is the point: a clone from a remote that accepts the connection
// and then stops talking would otherwise hold the loop forever, and every other
// project stops syncing behind it.
func syncOne(ctx context.Context, svc *gitops.Service, project, why string, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(ctx, gitops.DefaultSyncTimeout)
	defer cancel()

	result, err := svc.Sync(ctx, project, why)
	switch {
	case err == nil:
		if result.Unchanged {
			return
		}
		logger.Info("git sync applied", "project", project, "trigger", why,
			"commit", gitops.ShortID(result.Commit),
			"applied", result.Applied, "queued", result.Built, "held", result.Held)
	case errors.Is(err, context.Canceled):
		// Shutdown, not a failure.
	case errors.Is(err, gitops.ErrNoSource), errors.Is(err, gitops.ErrNotFound):
		// A project deleted, or one that never had a source. Nothing to say.
	default:
		logger.Error("git sync failed", "project", project, "trigger", why, "error", err)
	}
}

// storeApplier turns a synced job spec into desired state.
type storeApplier struct {
	store  store.Store
	notify chan<- struct{}
	log    *slog.Logger
}

// Apply writes every service in the synced spec as one batch.
//
// One batch, because they describe one commit: a multi-service change must land
// atomically or the reconciler converges on half a deploy. The project's
// pipeline configuration is written by the caller immediately after, since only
// it knows which commit succeeded — a crash in between costs one repeated sync,
// which applies the same specs again and changes nothing.
func (a storeApplier) Apply(ctx context.Context, spec *jobspec.Spec) ([]string, error) {
	desired, err := toDesired(spec)
	if err != nil {
		return nil, err
	}

	muts := make([]store.Mutation, 0, len(desired))
	applied := make([]string, 0, len(desired))
	for _, d := range desired {
		mut, err := store.PutMutation(store.KindService, d.Project+"/"+d.Service, d)
		if err != nil {
			return nil, err
		}
		muts = append(muts, mut)
		applied = append(applied, d.Project+"/"+d.Service)
	}

	if _, err := a.store.Apply(ctx, muts...); err != nil {
		return nil, fmt.Errorf("apply synced spec: %w", err)
	}
	// The reconciler converges on its own schedule; this only saves the change
	// waiting out an interval it does not need to.
	select {
	case a.notify <- struct{}{}:
	default:
	}
	return applied, nil
}

// storeDeployer pins a built image on a service.
type storeDeployer struct {
	store  store.Store
	notify chan<- struct{}
	log    *slog.Logger
}

// Deploy sets the service's image to the digest the build produced.
//
// Read-modify-write against the stored index, like every other partial update:
// a Desired assembled from the deployer's own view would drop the count, the
// volumes and the scaling policy, and a blind put would silently overwrite an
// operator's edit made while the build was running.
func (d storeDeployer) Deploy(ctx context.Context, project, service, imageRef string) error {
	key := project + "/" + service
	current, index, err := store.GetValue[reconciler.Desired](ctx, d.store, store.KindService, key)
	if err != nil {
		return fmt.Errorf("read %s: %w", key, err)
	}
	if current.Image == imageRef {
		// A rebuild of an unchanged tree produces the same digest. Writing it
		// again would bump the store index and wake the reconciler for nothing.
		return nil
	}
	previous := current.Image
	current.Image = imageRef

	mut, err := store.UpdateMutation(store.KindService, key, current, index)
	if err != nil {
		return err
	}
	if _, err := d.store.Apply(ctx, mut); err != nil {
		return fmt.Errorf("deploy %s: %w", key, err)
	}
	d.log.Info("deployed a built image", "service", key, "image", imageRef, "previous", previous)

	select {
	case d.notify <- struct{}{}:
	default:
	}
	return nil
}

// resolveBuildLogDir resolves the build log directory under the data directory when
// it was not given explicitly.
func resolveBuildLogDir(explicit, dataDir string) string {
	if explicit != "" {
		return explicit
	}
	return filepath.Join(dataDir, "builds")
}
