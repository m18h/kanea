// Package settings holds the node settings that live in the Store (PRD v1.46,
// §15.1): the decisions that change while a node runs, as opposed to the facts
// about the node that stay on kanead's argv.
//
// Records live in the existing kv bucket under a `settings/` prefix: no new
// Kind, no schema migration, and they replicate and restore with everything
// else, which is the reason they are here and not in a file. Precedence is the
// v1.46 rule: flags are the seed; a record, once written, wins; deleting it
// reverts to the flags.
package settings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/store"
)

// Storage keys, in the kv bucket beside auth/* and reconciler/*.
const (
	KeyBackup        = "settings/backup"
	KeyNotifications = "settings/notifications"
)

// secretPrefix mirrors secrets.Prefix without importing the package: settings
// validates the *shape* of a reference, and resolution stays with the caller.
const secretPrefix = "secret:"

// Duration is a time.Duration that travels as a string ("5m", "6h"): the
// spelling operators already use on the flags this record supersedes.
type Duration time.Duration

// MarshalJSON renders the duration as its string form.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON accepts a duration string.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("settings: a duration is a string like \"5m\": %w", err)
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("settings: bad duration %q: %w", raw, err)
	}
	*d = Duration(parsed)
	return nil
}

// Std returns the standard-library value.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// BackupSettings is the `settings/backup` record: where replication ships and
// on what cadence. Exactly one destination: a directory or an S3 bucket.
type BackupSettings struct {
	// Dir is a filesystem destination.
	Dir string `json:"dir,omitempty"`
	// S3 is an object-store destination.
	S3 *S3Destination `json:"s3,omitempty"`
	// SnapshotInterval, SegmentInterval and Retention take the replicator's
	// defaults when zero, exactly as the flags do.
	SnapshotInterval Duration `json:"snapshot_interval,omitempty"`
	SegmentInterval  Duration `json:"segment_interval,omitempty"`
	Retention        int      `json:"retention,omitempty"`
}

// S3Destination names a bucket.
type S3Destination struct {
	// URL is "s3://bucket[/prefix]".
	URL string `json:"url"`
	// Endpoint is required; no region-to-endpoint table, deliberately, for
	// the reason the flags refuse to guess one: a guessed endpoint is how
	// backups end up in a jurisdiction nobody chose.
	Endpoint string `json:"endpoint"`
	Region   string `json:"region,omitempty"`
	// AccessKey is the key id: configuration, like on the flags.
	AccessKey string `json:"access_key,omitempty"`
	// SecretKeyRef is a `secret:` reference (R3). Never a literal: the record
	// replicates in cleartext metadata terms, and Validate refuses by shape
	// anything that looks like a pasted key.
	SecretKeyRef string `json:"secret_key_ref,omitempty"`
	// PathStyle defaults to true when absent, matching --backup-s3-path-style.
	PathStyle *bool `json:"path_style,omitempty"`
}

// UsePathStyle resolves the default.
func (s *S3Destination) UsePathStyle() bool {
	return s.PathStyle == nil || *s.PathStyle
}

// Validate refuses a record the daemon could not act on. Resolution (the
// secret reference, the endpoint's reachability) happens at use, not here;
// this is about shape, so a refusal can land in front of whoever typed it.
func (b BackupSettings) Validate() error {
	switch {
	case b.Dir != "" && b.S3 != nil:
		return errors.New("settings: give one backup destination: a directory or an S3 bucket, not both")
	case b.Dir == "" && b.S3 == nil:
		return errors.New("settings: a backup record needs a destination (dir or s3)")
	}
	if b.S3 != nil {
		if !strings.HasPrefix(b.S3.URL, "s3://") {
			return fmt.Errorf("settings: S3 destination %q is not s3://bucket[/prefix]", b.S3.URL)
		}
		if b.S3.Endpoint == "" {
			return errors.New("settings: an S3 destination also needs an endpoint")
		}
		if ref := b.S3.SecretKeyRef; ref != "" && !strings.HasPrefix(ref, secretPrefix) {
			// Refused by shape, and the message says why: a value here would be
			// a credential stored beside the state it protects, shipped in
			// every backup.
			return fmt.Errorf("settings: secret_key_ref must be a %s reference, "+
				"e.g. %sshared/backup-s3, never the key itself", secretPrefix, secretPrefix)
		}
	}
	if b.SnapshotInterval < 0 || b.SegmentInterval < 0 {
		return errors.New("settings: backup intervals cannot be negative")
	}
	if b.Retention < 0 {
		return errors.New("settings: backup retention cannot be negative")
	}
	return nil
}

// NotificationSettings is the `settings/notifications` record: the node-level
// default channels §11 has promised since v1.1. Routes built from it carry no
// project scope, so they see every project's events.
type NotificationSettings struct {
	// Channels reuses the project spec's own type: one shape, wherever a
	// channel is declared, and the same builder turns both into routes.
	Channels *jobspec.Notifications `json:"channels,omitempty"`
}

// Validate refuses what the dispatcher could not run. Channel construction
// (resolving references, dialing nothing) stays with the builder; this checks
// the shape and the event vocabulary, which is one place (internal/notify).
func (n NotificationSettings) Validate() error {
	ch := n.Channels
	if ch == nil {
		return errors.New("settings: a notifications record needs at least one channel")
	}
	if ch.Telegram == nil && ch.Webhook == nil && ch.Slack == nil && ch.Ntfy == nil && ch.SMTP == nil {
		return errors.New("settings: a notifications record needs at least one channel")
	}
	floor, err := notify.ParseSeverity(ch.Severity)
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	filter, err := notify.NewFilter(ch.On, floor)
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	if filter.Empty() {
		// The v1.24 rule: a channel nobody has told what to send is silent,
		// and a silent channel is indistinguishable from nothing to report.
		return errors.New("settings: notification channels need an `on` filter")
	}
	return nil
}

// LoadBackup reads the backup record. found is false when none was written.
func LoadBackup(ctx context.Context, st store.Reader) (BackupSettings, bool, error) {
	return load[BackupSettings](ctx, st, KeyBackup)
}

// SaveBackup writes the backup record.
func SaveBackup(ctx context.Context, st store.Store, b BackupSettings) error {
	return save(ctx, st, KeyBackup, b)
}

// DeleteBackup removes the record, reverting the node to its flags.
func DeleteBackup(ctx context.Context, st store.Store) error {
	_, err := st.Apply(ctx, store.DeleteMutation(store.KindKV, KeyBackup))
	return err
}

// LoadNotifications reads the node-level channel record.
func LoadNotifications(ctx context.Context, st store.Reader) (NotificationSettings, bool, error) {
	return load[NotificationSettings](ctx, st, KeyNotifications)
}

// SaveNotifications writes the node-level channel record.
func SaveNotifications(ctx context.Context, st store.Store, n NotificationSettings) error {
	return save(ctx, st, KeyNotifications, n)
}

// DeleteNotifications removes the record.
func DeleteNotifications(ctx context.Context, st store.Store) error {
	_, err := st.Apply(ctx, store.DeleteMutation(store.KindKV, KeyNotifications))
	return err
}

func load[T any](ctx context.Context, st store.Reader, key string) (T, bool, error) {
	value, _, err := store.GetValue[T](ctx, st, store.KindKV, key)
	if errors.Is(err, store.ErrNotFound) {
		var zero T
		return zero, false, nil
	}
	if err != nil {
		var zero T
		return zero, false, fmt.Errorf("settings: read %s: %w", key, err)
	}
	return value, true, nil
}

func save[T any](ctx context.Context, st store.Store, key string, value T) error {
	if _, err := store.PutValue(ctx, st, store.KindKV, key, value); err != nil {
		return fmt.Errorf("settings: write %s: %w", key, err)
	}
	return nil
}

// Fingerprint hashes a value's canonical JSON, for reloaders that must rebuild
// only when configuration actually changed (the v1.44 Providers.Current rule:
// a rebuild per pass would re-resolve credentials for nothing).
func Fingerprint(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		// A value that cannot marshal cannot be stored either; an empty
		// fingerprint just means "always rebuild", which is safe.
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
