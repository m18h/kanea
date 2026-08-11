package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/backup"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/secrets"
	"github.com/m18h/kanea/internal/settings"
	"github.com/m18h/kanea/internal/store"
)

// Backup wiring (PRD §15.3): turning flags into a sink, and the running daemon
// into the small interface the API asks for.

// sinkOptions is a destination as the flags describe it.
type sinkOptions struct {
	// dir is a filesystem destination.
	dir string
	// s3URL is "s3://bucket[/prefix]".
	s3URL     string
	endpoint  string
	region    string
	accessKey string
	secretKey string
	pathStyle bool
}

// configured reports whether any destination was named.
func (o sinkOptions) configured() bool { return o.dir != "" || o.s3URL != "" }

// sinkFromFlags builds the destination, or reports why it cannot.
//
// A misconfigured backup destination fails loudly at startup rather than at the
// first snapshot. The failure an operator must never have is the one where
// backups were never happening and nothing said so.
func sinkFromFlags(opts sinkOptions, log *slog.Logger) (backup.Sink, error) {
	switch {
	case opts.dir != "" && opts.s3URL != "":
		return nil, errors.New("give one backup destination: a directory or an S3 bucket, not both")

	case opts.dir != "":
		return backup.NewFileSink(opts.dir, log)

	case opts.s3URL != "":
		bucket, prefix, err := parseS3URL(opts.s3URL)
		if err != nil {
			return nil, err
		}
		if opts.endpoint == "" {
			// No region-to-endpoint table, deliberately: guessing an endpoint
			// is how backups end up in a jurisdiction nobody chose.
			return nil, errors.New("an S3 destination also needs --backup-s3-endpoint")
		}
		return backup.NewS3Sink(backup.S3Config{
			Endpoint: opts.endpoint, Bucket: bucket, Prefix: prefix, Region: opts.region,
			AccessKey: opts.accessKey, SecretKey: opts.secretKey,
			PathStyle: opts.pathStyle, Logger: log,
		})

	default:
		return nil, errors.New("no backup destination configured")
	}
}

// parseS3URL splits "s3://bucket/prefix".
func parseS3URL(raw string) (bucket, prefix string, err error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("backup destination %q: %w", raw, err)
	}
	if parsed.Scheme != "s3" || parsed.Host == "" {
		return "", "", fmt.Errorf("backup destination %q is not s3://bucket[/prefix]", raw)
	}
	return parsed.Host, strings.Trim(parsed.Path, "/"), nil
}

// backupService is the daemon's implementation of api.Backups.
//
// It is a thin adapter and stays one: the API asks four questions, and none of
// the answers involve logic the archiver does not already own. What it adds is
// the one thing the API cannot do for itself — refusing to restore in place,
// and staging the request instead.
type backupService struct {
	archiver   *backup.Archiver
	replicator *backup.Replicator
	// dataDir is where a staged restore request is written.
	dataDir string
	log     *slog.Logger
}

// List returns the archives.
func (b backupService) List(ctx context.Context) ([]backup.Manifest, error) {
	return b.archiver.List(ctx)
}

// Create takes an on-demand snapshot through the replicator, so retention and
// segment pruning happen exactly as they do for a scheduled one.
func (b backupService) Create(ctx context.Context, reason string) (backup.Manifest, error) {
	if err := b.replicator.Snapshot(ctx, reason); err != nil {
		return backup.Manifest{}, err
	}
	return b.archiver.Latest(ctx)
}

// Verify checks an archive against its manifest.
func (b backupService) Verify(ctx context.Context, id string) error {
	manifest, err := b.archiver.Find(ctx, id)
	if err != nil {
		return err
	}
	return b.archiver.Verify(ctx, manifest)
}

// Stage records a restore for the next start.
//
// The archive is verified *now*, while there is someone to tell. A restore that
// discovers its archive is corrupt after the daemon has moved the live state
// aside is a much worse conversation.
func (b backupService) Stage(
	ctx context.Context, id string, skipReplay bool, by string,
) (backup.Manifest, error) {
	manifest, err := b.archiver.Find(ctx, id)
	if err != nil {
		return backup.Manifest{}, err
	}
	if err := b.archiver.Verify(ctx, manifest); err != nil {
		return backup.Manifest{}, err
	}

	// The id is recorded as resolved, not as asked for. "The newest" means
	// something different at restore time than it did at request time, and an
	// operator who verified one archive should get that archive.
	req := backup.Request{
		ArchiveID: manifest.ID, SkipReplay: skipReplay,
		RequestedAt: time.Now().UTC(), RequestedBy: by,
	}
	if err := backup.WriteRequest(b.dataDir, req); err != nil {
		return backup.Manifest{}, err
	}
	return manifest, nil
}

// Status reports replication health.
func (b backupService) Status() backup.Status { return b.replicator.Status() }

// storeCounts summarises the Store for a manifest, so `kanea backup list` can
// say what an archive holds without decrypting it.
//
// Best effort: a count that cannot be read is omitted rather than failing the
// snapshot. The archive is the point; the label on it is not.
func storeCounts(st store.Store, log *slog.Logger) func(context.Context) map[string]int {
	kinds := map[string]store.Kind{
		"projects": store.KindProject,
		"services": store.KindService,
		"allocs":   store.KindAlloc,
		"secrets":  store.KindSecret,
		"certs":    store.KindCert,
	}
	return func(ctx context.Context) map[string]int {
		out := make(map[string]int, len(kinds))
		for label, kind := range kinds {
			count, err := countKind(ctx, st, kind)
			if err != nil {
				log.Debug("cannot count records for the backup manifest",
					"kind", kind, "error", err)
				continue
			}
			out[label] = count
		}
		return out
	}
}

// countKind counts a bucket's records, paginated.
//
// Paginated because bbolt holds a read transaction open for the duration of a
// List, and a long one pins pages against the single writer (AGENTS.md #2) —
// even here, where the caller is a background snapshot nobody is waiting on.
func countKind(ctx context.Context, st store.Store, kind store.Kind) (int, error) {
	count := 0
	after := ""
	for {
		page, err := st.List(ctx, kind, store.ListOptions{
			After: after, Limit: 500, KeysOnly: true,
		})
		if err != nil {
			return 0, err
		}
		count += len(page.Records)
		if !page.More {
			return count, nil
		}
		after = page.NextAfter
	}
}

// replicationSettings is what the agent's flags say about replication.
type replicationSettings struct {
	sink         sinkOptions
	secretKeyRef string
	dataDir      string

	snapshotInterval time.Duration
	segmentInterval  time.Duration
	retention        int
	store            store.Store
	emit             func(notify.Event)
}

// assembleReplication builds the pipeline for one configured destination.
//
// A misconfigured destination is an error rather than a warning: the failure an
// operator must never have is the one where backups were never happening and
// nothing said so.
func assembleReplication(
	ctx context.Context, cfg replicationSettings, resolver secretResolver, log *slog.Logger,
) (*backupService, error) {
	if cfg.secretKeyRef != "" {
		// A `secret:` reference like every other credential (R3): the S3 secret
		// key is never a literal in a flag or a settings record, because argv
		// is world-readable and the record replicates as metadata.
		value, err := resolver.Resolve(ctx, cfg.secretKeyRef)
		if err != nil {
			return nil, fmt.Errorf("backup S3 secret key: %w", err)
		}
		cfg.sink.secretKey = string(value)
	}

	sink, err := sinkFromFlags(cfg.sink, log)
	if err != nil {
		return nil, err
	}

	master, err := secrets.LoadKey(filepath.Join(cfg.dataDir, secrets.KeyFileName))
	if err != nil {
		return nil, err
	}
	keys, err := backup.DeriveKeys(master)
	if err != nil {
		return nil, err
	}

	archiver, err := backup.New(backup.Config{
		Sink: sink, Keys: keys,
		Snapshotter: backup.StoreSnapshotter{Store: cfg.store},
		// Staged in the data directory rather than /tmp: the plaintext copy is
		// the size of the database, and a tmpfs that cannot hold it would fail
		// the snapshot at the worst possible moment.
		WorkDir: cfg.dataDir,
		Node:    nodeName(), Version: version, Logger: log,
	})
	if err != nil {
		return nil, err
	}

	replicator, err := backup.NewReplicator(backup.ReplicatorConfig{
		Archiver: archiver, Store: cfg.store, Logger: log,
		SnapshotInterval: cfg.snapshotInterval, SegmentInterval: cfg.segmentInterval,
		Retention: cfg.retention, Counts: storeCounts(cfg.store, log),
		Emit: cfg.emit,
	})
	if err != nil {
		return nil, err
	}

	log.Info("state replication configured",
		"sink", sink.Describe(), "snapshot_every", cfg.snapshotInterval,
		"segment_every", cfg.segmentInterval, "keep", cfg.retention, "key_id", keys.ID)

	return &backupService{
		archiver: archiver, replicator: replicator, dataDir: cfg.dataDir, log: log,
	}, nil
}

// settingsToReplication converts a settings record into the same shape the
// flags produce. The record wins wholesale: a zero interval means the
// replicator's default, never the flag value it superseded.
func settingsToReplication(rec settings.BackupSettings, base replicationSettings) replicationSettings {
	out := base
	out.sink = sinkOptions{}
	out.secretKeyRef = ""
	if rec.Dir != "" {
		out.sink.dir = rec.Dir
	}
	if rec.S3 != nil {
		out.sink.s3URL = rec.S3.URL
		out.sink.endpoint = rec.S3.Endpoint
		out.sink.region = rec.S3.Region
		out.sink.accessKey = rec.S3.AccessKey
		out.sink.pathStyle = rec.S3.UsePathStyle()
		out.secretKeyRef = rec.S3.SecretKeyRef
	}
	out.snapshotInterval = rec.SnapshotInterval.Std()
	out.segmentInterval = rec.SegmentInterval.Std()
	out.retention = rec.Retention
	return out
}

// buildBackups settles the startup precedence (v1.46): a Store record wins; a
// corrupt or unbuildable record falls back to the flags loudly, because "the
// node silently stopped replicating" is the failure the whole subsystem exists
// to prevent; no record means the flags, and no flags means unconfigured.
func buildBackups(
	ctx context.Context, cfg replicationSettings, resolver secretResolver, log *slog.Logger,
) (*backupManager, error) {
	m := newBackupManager(log)

	rec, found, err := settings.LoadBackup(ctx, cfg.store)
	if err != nil {
		log.Error("the backup settings record is unreadable; falling back to the unit's flags",
			"error", err)
		found = false
	}
	if found {
		if verr := rec.Validate(); verr != nil {
			log.Error("the backup settings record is invalid; falling back to the unit's flags",
				"error", verr)
			found = false
		}
	}
	if found {
		svc, err := assembleReplication(ctx, settingsToReplication(rec, cfg), resolver, log)
		if err != nil {
			log.Error("cannot build replication from the settings record; "+
				"falling back to the unit's flags", "error", err)
		} else {
			m.adopt(svc, sourceStore)
			return m, nil
		}
	}

	if cfg.sink.configured() {
		// A misconfigured *flag* destination stays a startup error, exactly as
		// before: the operator wrote it into the unit, and the journal is
		// where that refusal has always landed.
		svc, err := assembleReplication(ctx, cfg, resolver, log)
		if err != nil {
			return nil, err
		}
		m.adopt(svc, sourceFlags)
	}
	return m, nil
}

// secretResolver is the slice of the secrets store this file needs.
type secretResolver interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

// nodeName labels an archive with where it came from, so a bucket shared by two
// nodes does not silently restore the wrong one.
func nodeName() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}
