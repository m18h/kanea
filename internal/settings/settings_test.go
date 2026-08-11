package settings_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/settings"
	"github.com/m18h/kanea/internal/store"
)

func openStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestBackupSettingsValidation(t *testing.T) {
	// Validate is the shape check that lands in front of whoever typed the
	// record — a record the daemon cannot act on must be refused at PUT time,
	// not discovered at the first snapshot.
	boolPtr := func(b bool) *bool { return &b }

	for _, tc := range []struct {
		name string
		rec  settings.BackupSettings
		// wantErr is a substring the refusal must carry; empty means accepted.
		wantErr string
	}{
		{
			// Two destinations is an ambiguous record: which one is the backup?
			name: "both destinations refused",
			rec: settings.BackupSettings{
				Dir: "/backups",
				S3:  &settings.S3Destination{URL: "s3://bucket", Endpoint: "https://s3.example"},
			},
			wantErr: "not both",
		},
		{
			// A record with no destination is not "backups off" — deleting the
			// record is. Accepting it would make an empty PUT silently disable
			// replication.
			name:    "neither destination refused",
			rec:     settings.BackupSettings{},
			wantErr: "needs a destination",
		},
		{
			name: "s3 url without the scheme refused",
			rec: settings.BackupSettings{
				S3: &settings.S3Destination{URL: "bucket/prefix", Endpoint: "https://s3.example"},
			},
			wantErr: "s3://",
		},
		{
			// No region-to-endpoint guessing: a guessed endpoint is how backups
			// end up in a jurisdiction nobody chose.
			name: "s3 without an endpoint refused",
			rec: settings.BackupSettings{
				S3: &settings.S3Destination{URL: "s3://bucket"},
			},
			wantErr: "endpoint",
		},
		{
			// The refusal must name the `secret:` shape: a literal key here would
			// be a credential stored beside the state it protects, replicated in
			// cleartext metadata terms with every backup.
			name: "secret_key_ref that is not a secret: reference refused by name",
			rec: settings.BackupSettings{
				S3: &settings.S3Destination{
					URL: "s3://bucket", Endpoint: "https://s3.example",
					SecretKeyRef: "AKIAIOSFODNN7EXAMPLEKEY",
				},
			},
			wantErr: "secret:",
		},
		{
			name:    "negative snapshot interval refused",
			rec:     settings.BackupSettings{Dir: "/backups", SnapshotInterval: settings.Duration(-time.Minute)},
			wantErr: "negative",
		},
		{
			name:    "negative segment interval refused",
			rec:     settings.BackupSettings{Dir: "/backups", SegmentInterval: settings.Duration(-time.Second)},
			wantErr: "negative",
		},
		{
			name:    "negative retention refused",
			rec:     settings.BackupSettings{Dir: "/backups", Retention: -1},
			wantErr: "negative",
		},
		{
			name: "dir-only record accepted",
			rec:  settings.BackupSettings{Dir: "/backups", Retention: 7},
		},
		{
			name: "s3 record accepted",
			rec: settings.BackupSettings{
				S3: &settings.S3Destination{
					URL: "s3://bucket/prefix", Endpoint: "https://s3.example",
					Region: "eu-west-1", AccessKey: "AKIA...",
					SecretKeyRef: "secret:shared/backup-s3", PathStyle: boolPtr(false),
				},
				SnapshotInterval: settings.Duration(6 * time.Hour),
				SegmentInterval:  settings.Duration(time.Minute),
				Retention:        7,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rec.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want the record accepted", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() accepted a record it must refuse")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %q, want a refusal mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestNotificationSettingsValidation(t *testing.T) {
	// The record reuses the job spec's channel shape, so the same silent-channel
	// mistakes the spec parser refuses must be refused here too — a node-level
	// channel that matches nothing looks exactly like a system with nothing to
	// report.
	for _, tc := range []struct {
		name    string
		rec     settings.NotificationSettings
		wantErr string
	}{
		{
			name:    "nil channels refused",
			rec:     settings.NotificationSettings{},
			wantErr: "at least one channel",
		},
		{
			// A Notifications block with every channel nil is a filter with
			// nowhere to send: shape-valid JSON, operationally nothing.
			name: "empty channels refused",
			rec: settings.NotificationSettings{
				Channels: &jobspec.Notifications{On: []string{"*"}},
			},
			wantErr: "at least one channel",
		},
		{
			name: "bad severity refused",
			rec: settings.NotificationSettings{
				Channels: &jobspec.Notifications{
					Webhook:  &jobspec.WebhookChannel{URL: "https://example.com/hook"},
					On:       []string{"*"},
					Severity: "catastrophic",
				},
			},
			wantErr: "unknown severity",
		},
		{
			// A channel nobody has told what to send would be silent forever
			// (the v1.24 rule) — refused rather than defaulted to everything.
			name: "empty on filter refused",
			rec: settings.NotificationSettings{
				Channels: &jobspec.Notifications{
					Webhook: &jobspec.WebhookChannel{URL: "https://example.com/hook"},
				},
			},
			wantErr: "`on` filter",
		},
		{
			// The event vocabulary lives in internal/notify and NewFilter checks
			// patterns against it: a typo'd pattern matches nothing at runtime,
			// which is exactly the silent-channel failure, so it is refused here
			// with the known events in the message.
			name: "unknown event pattern refused",
			rec: settings.NotificationSettings{
				Channels: &jobspec.Notifications{
					Webhook: &jobspec.WebhookChannel{URL: "https://example.com/hook"},
					On:      []string{"frobnicate.*"},
				},
			},
			wantErr: "matches no known event",
		},
		{
			name: "valid record accepted",
			rec: settings.NotificationSettings{
				Channels: &jobspec.Notifications{
					Webhook:  &jobspec.WebhookChannel{URL: "https://example.com/hook"},
					On:       []string{"deploy.*", "backup.failed"},
					Severity: "warning",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rec.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want the record accepted", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() accepted a record it must refuse")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %q, want a refusal mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestDurationRoundTripsThroughJSON(t *testing.T) {
	// Durations travel as the strings operators already type on the flags this
	// record supersedes. Marshal uses time.Duration.String(), so "5m" comes
	// back out as "5m0s" — different spelling, same duration — and the value
	// must survive the round trip exactly.
	var d settings.Duration
	if err := json.Unmarshal([]byte(`"5m"`), &d); err != nil {
		t.Fatalf("unmarshal \"5m\": %v", err)
	}
	if d.Std() != 5*time.Minute {
		t.Fatalf("parsed %v, want 5m", d.Std())
	}

	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != `"5m0s"` {
		t.Fatalf("marshalled as %s, want \"5m0s\" (time.Duration.String form)", raw)
	}

	var back settings.Duration
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	if back != d {
		t.Fatalf("round trip changed the value: %v -> %v", d.Std(), back.Std())
	}

	// A duration that is not a string is refused with a message that says what
	// the shape is, because the record is hand-edited JSON on the API.
	if err := json.Unmarshal([]byte(`300`), &back); err == nil {
		t.Fatal("a bare number unmarshalled; a duration must be a string like \"5m\"")
	}
	if err := json.Unmarshal([]byte(`"fast"`), &back); err == nil {
		t.Fatal("an unparseable duration string was accepted")
	}
}

func TestBackupRecordRoundTripsThroughTheStore(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)

	// An empty store means "no record", never an error: absence is the normal
	// state of a node that runs on its flags.
	if _, found, err := settings.LoadBackup(ctx, st); err != nil || found {
		t.Fatalf("LoadBackup on empty store = found %v, err %v; want false, nil", found, err)
	}

	pathStyle := false
	rec := settings.BackupSettings{
		S3: &settings.S3Destination{
			URL: "s3://bucket/prefix", Endpoint: "https://s3.example",
			Region: "eu-west-1", AccessKey: "AKIA",
			SecretKeyRef: "secret:shared/backup-s3", PathStyle: &pathStyle,
		},
		SnapshotInterval: settings.Duration(6 * time.Hour),
		SegmentInterval:  settings.Duration(time.Minute),
		Retention:        3,
	}
	if err := settings.SaveBackup(ctx, st, rec); err != nil {
		t.Fatalf("SaveBackup: %v", err)
	}

	got, found, err := settings.LoadBackup(ctx, st)
	if err != nil || !found {
		t.Fatalf("LoadBackup = found %v, err %v; want the saved record", found, err)
	}
	if !reflect.DeepEqual(got, rec) {
		t.Fatalf("record changed through the store:\n got  %+v\n want %+v", got, rec)
	}

	// Delete reverts the node to its flags: the record is gone, not zeroed.
	if err := settings.DeleteBackup(ctx, st); err != nil {
		t.Fatalf("DeleteBackup: %v", err)
	}
	if _, found, err := settings.LoadBackup(ctx, st); err != nil || found {
		t.Fatalf("LoadBackup after delete = found %v, err %v; want false, nil", found, err)
	}
}

func TestNotificationsRecordRoundTripsThroughTheStore(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)

	if _, found, err := settings.LoadNotifications(ctx, st); err != nil || found {
		t.Fatalf("LoadNotifications on empty store = found %v, err %v; want false, nil", found, err)
	}

	rec := settings.NotificationSettings{
		Channels: &jobspec.Notifications{
			Webhook:  &jobspec.WebhookChannel{URL: "https://example.com/hook", SecretRef: "secret:shared/hook"},
			On:       []string{"deploy.*"},
			Severity: "warning",
		},
	}
	if err := settings.SaveNotifications(ctx, st, rec); err != nil {
		t.Fatalf("SaveNotifications: %v", err)
	}

	got, found, err := settings.LoadNotifications(ctx, st)
	if err != nil || !found {
		t.Fatalf("LoadNotifications = found %v, err %v; want the saved record", found, err)
	}
	if !reflect.DeepEqual(got, rec) {
		t.Fatalf("record changed through the store:\n got  %+v\n want %+v", got, rec)
	}

	if err := settings.DeleteNotifications(ctx, st); err != nil {
		t.Fatalf("DeleteNotifications: %v", err)
	}
	if _, found, err := settings.LoadNotifications(ctx, st); err != nil || found {
		t.Fatalf("LoadNotifications after delete = found %v, err %v; want false, nil", found, err)
	}
}

func TestFingerprintChangesOnlyWithTheValue(t *testing.T) {
	// Fingerprint is what reloaders compare to rebuild only on real change (the
	// v1.44 Providers.Current rule) — equal values must hash equal, different
	// values must not.
	a := settings.BackupSettings{Dir: "/backups"}
	b := settings.BackupSettings{Dir: "/backups"}
	c := settings.BackupSettings{Dir: "/other"}

	if settings.Fingerprint(a) != settings.Fingerprint(b) {
		t.Fatal("equal values fingerprint differently; every pass would rebuild")
	}
	if settings.Fingerprint(a) == settings.Fingerprint(c) {
		t.Fatal("different values share a fingerprint; a change would never be seen")
	}
}
