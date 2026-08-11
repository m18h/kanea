package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/m18h/kanea/internal/settings"
	"github.com/m18h/kanea/internal/store"
)

// The v1.46 startup precedence: a Store record wins over the unit's flags; a
// record that cannot be used falls back to the flags *loudly* rather than
// leaving the node silently unreplicated — "backups were never happening and
// nothing said so" is the failure the whole subsystem exists to prevent.

func TestBuildBackupsPrefersTheStoreRecordOverFlags(t *testing.T) {
	ctx := context.Background()
	st := openScalingStore(t)
	dataDir := t.TempDir()
	writeMasterKey(t, dataDir)

	if err := settings.SaveBackup(ctx, st, settings.BackupSettings{Dir: t.TempDir()}); err != nil {
		t.Fatalf("save record: %v", err)
	}
	// Flags name a *different* directory: whichever destination the manager
	// reports is the one that won.
	cfg := replicationSettings{
		sink: sinkOptions{dir: t.TempDir()}, dataDir: dataDir, store: st,
	}

	m, err := buildBackups(ctx, cfg, nopResolver{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("buildBackups: %v", err)
	}
	if got := m.Source(); got != sourceStore {
		t.Errorf("Source = %q, want %q — the record, once written, wins", got, sourceStore)
	}
	if !m.configured() {
		t.Error("configured() = false with a valid record")
	}
}

func TestBuildBackupsFallsBackToFlagsWithoutARecord(t *testing.T) {
	ctx := context.Background()
	st := openScalingStore(t)
	dataDir := t.TempDir()
	writeMasterKey(t, dataDir)

	cfg := replicationSettings{
		sink: sinkOptions{dir: t.TempDir()}, dataDir: dataDir, store: st,
	}
	m, err := buildBackups(ctx, cfg, nopResolver{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("buildBackups: %v", err)
	}
	if got := m.Source(); got != sourceFlags {
		t.Errorf("Source = %q, want %q — no record means the flags are the seed", got, sourceFlags)
	}
}

func TestBuildBackupsIsUnconfiguredWithNeither(t *testing.T) {
	// No record and no flags is a legitimate state — a node that has never
	// configured backups — and must build a working (refusing) manager rather
	// than fail the daemon's start.
	ctx := context.Background()
	st := openScalingStore(t)

	m, err := buildBackups(ctx, replicationSettings{store: st, dataDir: t.TempDir()},
		nopResolver{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("buildBackups: %v", err)
	}
	if got := m.Source(); got != sourceNone {
		t.Errorf("Source = %q, want %q", got, sourceNone)
	}
	if m.configured() {
		t.Error("configured() = true with no destination anywhere")
	}
}

func TestBuildBackupsFallsBackToFlagsOnABadRecord(t *testing.T) {
	// A record the daemon cannot act on must not take replication down with it:
	// the flags were running yesterday and keep running today, and the error is
	// logged rather than returned — a startup that fails on a bad *record*
	// would leave the operator with no daemon to fix the record through.
	for _, tc := range []struct {
		name  string
		write func(t *testing.T, ctx context.Context, st store.Store)
	}{
		{
			// JSON that does not parse: the load itself fails.
			name: "corrupt record",
			write: func(t *testing.T, ctx context.Context, st store.Store) {
				t.Helper()
				if _, err := st.Apply(ctx, store.Mutation{
					Op: store.OpPut, Kind: store.KindKV,
					Key: settings.KeyBackup, Value: []byte(`{this is not json`),
				}); err != nil {
					t.Fatalf("write corrupt record: %v", err)
				}
			},
		},
		{
			// JSON that parses and fails Validate: both destinations at once.
			// SaveBackup does not validate — the API path does — so a record
			// like this can exist after a partial write or a schema change.
			name: "record failing validation",
			write: func(t *testing.T, ctx context.Context, st store.Store) {
				t.Helper()
				if err := settings.SaveBackup(ctx, st, settings.BackupSettings{
					Dir: "/somewhere",
					S3:  &settings.S3Destination{URL: "s3://bucket", Endpoint: "https://s3.example"},
				}); err != nil {
					t.Fatalf("save invalid record: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st := openScalingStore(t)
			dataDir := t.TempDir()
			writeMasterKey(t, dataDir)
			tc.write(t, ctx, st)

			cfg := replicationSettings{
				sink: sinkOptions{dir: t.TempDir()}, dataDir: dataDir, store: st,
			}
			m, err := buildBackups(ctx, cfg, nopResolver{}, slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatalf("buildBackups returned an error for a bad record; it must fall back: %v", err)
			}
			if got := m.Source(); got != sourceFlags {
				t.Errorf("Source = %q, want %q — a bad record falls back to the flags", got, sourceFlags)
			}
		})
	}
}

func TestBuildBackupsRefusesMisconfiguredFlags(t *testing.T) {
	// A misconfigured *flag* destination stays a startup error, exactly as
	// before v1.46: the operator wrote it into the unit, and the journal is
	// where that refusal has always landed. Falling back to "unconfigured"
	// here would be the silent-no-backups failure.
	ctx := context.Background()
	st := openScalingStore(t)

	cfg := replicationSettings{
		// An S3 URL with no endpoint is the canonical flag misconfiguration.
		sink:    sinkOptions{s3URL: "s3://bucket"},
		dataDir: t.TempDir(), store: st,
	}
	if _, err := buildBackups(ctx, cfg, nopResolver{}, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("buildBackups accepted flags naming an S3 bucket with no endpoint")
	}
}
