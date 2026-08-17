package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/backup"
	"github.com/m18h/kanea/internal/logging"
	"github.com/m18h/kanea/internal/secrets"
)

// runBackup is `kanea backup <create|list|verify>`.
//
// These go through the running daemon, like every other CLI command: it holds
// the database open, and a second process reading it would either block on
// bbolt's single writer or copy a file being written underneath it.
func runBackup(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kanea backup <create|list|verify> [args]")
	}
	switch args[0] {
	case "create", "now":
		return runBackupCreate(args[1:])
	case "ls", "list":
		return runBackupList(args[1:])
	case "verify", "check":
		return runBackupVerify(args[1:])
	default:
		return fmt.Errorf("unknown backup command %q: want create, list or verify", args[0])
	}
}

func runBackupCreate(args []string) error {
	fs := flag.NewFlagSet("backup create", flag.ContinueOnError)
	socket := socketFlag(fs)
	reason := fs.String("reason", "on-demand", "recorded in the archive manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client := api.NewClient(*socket)
	manifest, err := client.CreateBackup(context.Background(), *reason)
	if err != nil {
		return err
	}

	o := newOut()
	o.printf("archive %s written at index %d (%s)\n",
		manifest.ID, manifest.Index, manifest.CreatedAt.Format(time.RFC3339))
	if len(manifest.Counts) > 0 {
		o.printf("  contents: %s\n", renderCounts(manifest.Counts))
	}
	return o.Err()
}

func runBackupList(args []string) error {
	fs := flag.NewFlagSet("backup list", flag.ContinueOnError)
	socket := socketFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	client := api.NewClient(*socket)
	resp, err := client.Backups(context.Background())
	if err != nil {
		return err
	}

	o := newOut()
	// Replication health first, because it is the thing an operator has come to
	// check and the thing they otherwise only discover during a restore.
	o.printf("replicating to %s\n", orUnset(resp.Replication.Sink))
	if !resp.Replication.LastSnapshotAt.IsZero() {
		o.printf("  last snapshot  %s (%s ago)\n",
			resp.Replication.LastSnapshotAt.Format(time.RFC3339),
			shortDuration(time.Since(resp.Replication.LastSnapshotAt)))
	}
	if !resp.Replication.LastSegmentAt.IsZero() {
		o.printf("  last segment   %s (%s ago), shipped to index %d\n",
			resp.Replication.LastSegmentAt.Format(time.RFC3339),
			shortDuration(time.Since(resp.Replication.LastSegmentAt)),
			resp.Replication.ShippedTo)
	}
	if resp.Replication.Failures > 0 {
		o.printf("  failures       %d since start\n", resp.Replication.Failures)
	}
	o.println()

	if len(resp.Backups) == 0 {
		o.println("No archives. Nothing on this node has been backed up.")
		return o.Err()
	}

	o.table()
	o.printf("ARCHIVE\tCREATED\tINDEX\tREASON\tCONTENTS\n")
	for _, m := range resp.Backups {
		o.printf("%s\t%s\t%d\t%s\t%s\n",
			m.ID, m.CreatedAt.Format(time.RFC3339), m.Index,
			orUnset(m.Reason), renderCounts(m.Counts))
	}
	return o.Err()
}

func runBackupVerify(args []string) error {
	fs := flag.NewFlagSet("backup verify", flag.ContinueOnError)
	socket := socketFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea backup verify <archive-id>")
	}

	client := api.NewClient(*socket)
	if err := client.VerifyBackup(context.Background(), fs.Arg(0)); err != nil {
		return err
	}
	o := newOut()
	o.printf("archive %s is intact (every part matches its manifest hash)\n", fs.Arg(0))
	return o.Err()
}

// runRestore is `kanea restore`.
//
// Two shapes, and the difference matters. With --from it works offline: it
// talks to a bucket directly, needs no daemon, and writes a state file, which
// is the §15.3 procedure for a node that has lost its disk. Without it, it asks
// the running daemon to stage a restore for the next start, which is the
// procedure for a node that is up and wrong.
func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	socket := socketFlag(fs)
	from := fs.String("from", "",
		"restore offline from a destination: a directory, or s3://bucket/prefix")
	endpoint := fs.String("s3-endpoint", "", "S3 endpoint URL (with --from s3://…)")
	region := fs.String("s3-region", "", "S3 region (with --from s3://…)")
	accessKey := fs.String("s3-access-key", "", "S3 access key id (with --from s3://…)")
	secretKeyFile := fs.String("s3-secret-key-file", "",
		"file holding the S3 secret key (never an argument: argv is world-readable)")
	pathStyle := fs.Bool("s3-path-style", true, "address the bucket as /bucket/key")
	keyPath := fs.String("master-key", "", "master key file (default <data-dir>/master.key)")
	dataDir := fs.String("data-dir", defaultDataDir, "node data directory")
	archive := fs.String("snapshot", "", "archive id to restore (default: the newest)")
	target := fs.String("target", "", "where to write the restored state (default <data-dir>/state.db)")
	skipReplay := fs.Bool("skip-replay", false,
		"restore the snapshot without its change segments (loses everything after it)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *from == "" {
		return stageRestore(*socket, *archive, *skipReplay)
	}
	return offlineRestore(offlineRestoreOptions{
		from: *from, endpoint: *endpoint, region: *region,
		accessKey: *accessKey, secretKeyFile: *secretKeyFile, pathStyle: *pathStyle,
		keyPath: *keyPath, dataDir: *dataDir, archive: *archive,
		target: *target, skipReplay: *skipReplay,
	})
}

// stageRestore asks the daemon to restore at its next start.
func stageRestore(socket, archive string, skipReplay bool) error {
	client := api.NewClient(socket)
	resp, err := client.StageRestore(context.Background(), archive, skipReplay)
	if err != nil {
		return err
	}
	o := newOut()
	o.println(resp.Message)
	o.println()
	o.println("Nothing has been restored yet. Restart kanead to apply it:")
	o.println("    systemctl restart kanead")
	return o.Err()
}

type offlineRestoreOptions struct {
	from, endpoint, region    string
	accessKey, secretKeyFile  string
	pathStyle                 bool
	keyPath, dataDir, archive string
	target                    string
	skipReplay                bool
}

// offlineRestore recovers a node from a destination without a running daemon.
func offlineRestore(opts offlineRestoreOptions) error {
	log, closer, err := logging.New(logging.Config{Format: "text"})
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closer.Close(); cerr != nil {
			fmt.Fprintln(os.Stderr, "kanea restore: closing the log sink:", cerr)
		}
	}()

	if opts.keyPath == "" {
		opts.keyPath = filepath.Join(opts.dataDir, secrets.KeyFileName)
	}
	// Step zero of the runbook, and the one that cannot be worked around: no
	// key, no readable backup.
	master, err := secrets.LoadKey(opts.keyPath)
	if err != nil {
		return err
	}
	keys, err := backup.DeriveKeys(master)
	if err != nil {
		return err
	}

	// One of the two, never both: sinkFromFlags refuses a destination that is
	// somehow a directory and a bucket at once, and --from is one string.
	destination := sinkOptions{
		endpoint: opts.endpoint, region: opts.region, accessKey: opts.accessKey,
		secretKey: readSecretFile(opts.secretKeyFile), pathStyle: opts.pathStyle,
	}
	if strings.HasPrefix(opts.from, "s3://") {
		destination.s3URL = opts.from
	} else {
		destination.dir = strings.TrimPrefix(opts.from, "file://")
	}
	sink, err := sinkFromFlags(destination, log)
	if err != nil {
		return err
	}

	// No snapshotter: this direction only reads. Passing a nil Store would be a
	// panic waiting to happen, so the archiver gets one that refuses.
	archiver, err := backup.New(backup.Config{
		Sink: sink, Keys: keys, Snapshotter: refusingSnapshotter{},
		WorkDir: os.TempDir(), Logger: log, Version: version,
	})
	if err != nil {
		return err
	}

	target := opts.target
	if target == "" {
		target = filepath.Join(opts.dataDir, stateFile)
	}
	result, err := archiver.Restore(context.Background(), backup.RestoreOptions{
		ArchiveID: opts.archive, Target: target, SkipReplay: opts.skipReplay, Logger: log,
	})
	if err != nil {
		return err
	}

	o := newOut()
	o.printf("\nRestored %s to %s\n", result.Archive.ID, result.Path)
	o.printf("  taken     %s at index %d on node %q\n",
		result.Archive.CreatedAt.Format(time.RFC3339), result.Archive.Index,
		orUnset(result.Archive.Node))
	o.printf("  replayed  %d change(s), now at index %d\n", result.Replayed, result.Index)
	o.println()
	o.println("Start kanead. The reconciler rebuilds the rest: the network datapath is")
	o.println("derived state and is never restored, images are re-pulled, and endpoints")
	o.println("and edge routes come back as services converge.")
	return o.Err()
}

// refusingSnapshotter is what a read-only archiver holds. Reaching it is a bug,
// and it says so rather than dereferencing a nil Store.
type refusingSnapshotter struct{}

func (refusingSnapshotter) Snapshot(context.Context, string) (uint64, error) {
	return 0, errors.New("kanea restore: this archiver is read-only and cannot take a snapshot")
}

// readSecretFile reads a credential from a file, never from an argument.
//
// Everything in argv is world-readable through /proc/<pid>/cmdline and lands in
// shell history: the same reasoning that keeps mount credentials and secret
// values out of it.
func readSecretFile(path string) string {
	if path == "" {
		return ""
	}
	body, err := os.ReadFile(path) // #nosec G304: an operator-supplied path
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func renderCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "-"
	}
	// Fixed order rather than map order, so two runs of `kanea backup list`
	// produce the same table.
	var parts []string
	for _, key := range []string{"services", "allocs", "secrets", "certs", "projects"} {
		if n, ok := counts[key]; ok {
			parts = append(parts, fmt.Sprintf("%d %s", n, key))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

func orUnset(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
