package edge

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// DefaultSnapshotPath is where kanead projects the edge's state.
//
// Deliberately not under data_dir. The state directory is 0750 and holds the
// database, so an unprivileged kanea-edge user cannot even traverse into it —
// and widening it to hand one file over would be the wrong trade. This is
// derived, node-local state that is rebuilt from the Store on every start
// (constraint #9), which is what /run is for; it sits beside the Cilium file
// interfaces rather than beside the durable state.
const DefaultSnapshotPath = "/run/kanea-edge/routes.json"

// SnapshotName is the published file's name.
const SnapshotName = "routes.json"

// tempSuffix is used for the write-then-rename. It deliberately does not end in
// ".json": a reader that globs the directory must never pick up a half-written
// file (the same rule the Cilium file interfaces follow — PRD §5.2.5).
const tempSuffix = ".tmp"

// Snapshot is everything kanea-edge needs to serve traffic.
//
// It exists because the edge cannot read the Store. bbolt locks the whole
// database file, so a second process opening state.db — even read-only —
// blocks until kanead exits rather than returning stale data. The Store stays
// the source of truth and kanead stays its only opener; what the edge gets is
// this projection of it (PRD §5.2.6).
//
// The projection is one-directional. The edge never writes state, which is what
// lets it run as an unprivileged user with no database access at all: the
// process terminating untrusted public traffic cannot mutate the platform.
type Snapshot struct {
	// Index is the Store index this projection was built from. It makes a
	// reload loggable and a stale file recognisable.
	Index uint64 `json:"index"`
	// Routes is the full route table. It is a whole-file replacement, never a
	// delta: rebuilding from desired state is how every other derived thing in
	// Kanea works (constraint #9), and it means a missed update self-corrects.
	Routes []Route `json:"routes"`
}

// Route sends one or more hostnames to one service.
type Route struct {
	Project string `json:"project"`
	Service string `json:"service"`
	// Domains are the hostnames this service answers on, lowercased.
	Domains []string `json:"domains"`
	// Upstream is the service's Cilium frontend address (§7.1), not an alloc
	// address. The eBPF LB does the balancing, so the edge holds one address
	// per service and never a backend list — a scale event changes nothing here.
	Upstream string `json:"upstream"`
	// Port is the frontend port, chosen by the R16 rule: the port named "http",
	// or the only one declared.
	Port int `json:"port"`
}

// Name identifies the route in logs and errors.
func (r Route) Name() string { return r.Project + "/" + r.Service }

// Address is the upstream host:port.
func (r Route) Address() string { return fmt.Sprintf("%s:%d", r.Upstream, r.Port) }

// ErrInvalidSnapshot marks a projection that cannot be served.
var ErrInvalidSnapshot = errors.New("edge: invalid snapshot")

// Validate checks a snapshot before it is written or served.
//
// Validating on both sides is deliberate. On the write side it stops kanead
// publishing something the edge will reject; on the read side it stops a
// hand-edited or truncated file from taking routing down. The edge is the one
// process whose failure is directly visible to the public.
func (s Snapshot) Validate() error {
	seen := map[string]string{}
	for i, r := range s.Routes {
		where := fmt.Sprintf("route %d (%s)", i, r.Name())
		if r.Project == "" || r.Service == "" {
			return fmt.Errorf("%w: %s has no project or service", ErrInvalidSnapshot, where)
		}
		if _, err := netip.ParseAddr(r.Upstream); err != nil {
			return fmt.Errorf("%w: %s upstream %q is not an address", ErrInvalidSnapshot, where, r.Upstream)
		}
		if r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("%w: %s port %d is out of range", ErrInvalidSnapshot, where, r.Port)
		}
		if len(r.Domains) == 0 {
			return fmt.Errorf("%w: %s claims no domain", ErrInvalidSnapshot, where)
		}
		for _, d := range r.Domains {
			if d != strings.ToLower(d) || strings.TrimSpace(d) != d {
				return fmt.Errorf("%w: %s domain %q is not canonical (lowercase, unpadded)",
					ErrInvalidSnapshot, where, d)
			}
			if first, dup := seen[d]; dup {
				// R16 catches this at plan time. Catching it again here is not
				// redundant: a snapshot assembled from several applies could
				// still collide, and last-writer-wins in a routing table is a
				// silent misdelivery.
				return fmt.Errorf("%w: domain %q is claimed by both %s and %s",
					ErrInvalidSnapshot, d, first, r.Name())
			}
			seen[d] = r.Name()
		}
	}
	return nil
}

// Publish writes the snapshot for the edge to read.
//
// Temp-then-rename, because the reader is a separate process polling the file:
// a partially written table must never be observable, and rename(2) is the only
// way to make the swap atomic.
func Publish(path string, snap Snapshot) error {
	if err := snap.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	body = append(body, '\n')

	// The directory and the file are world-readable, which is the point rather
	// than an oversight: kanea-edge runs as its own unprivileged user (§5.2.6)
	// and cannot read this otherwise. Nothing here is a secret — the domains
	// are in public DNS and the upstreams are node-local addresses — and the
	// alternative, a shared group, is a `kanea init` prerequisite this cannot
	// assume exists.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 — see above
		return fmt.Errorf("edge dir: %w", err)
	}

	// The temp file lives in the destination directory so the rename stays on
	// one filesystem; a cross-device rename is not atomic and is the whole
	// reason for doing this.
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*"+tempSuffix)
	if err != nil {
		return fmt.Errorf("create temp snapshot: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// A no-op once the rename succeeded. A failure to clean up after a
		// failed publish would leave a temp file behind, which is untidy but
		// harmless — the name does not end in .json.
		if err := os.Remove(tmpName); err != nil && !os.IsNotExist(err) {
			slog.Default().Debug("cannot remove temp snapshot", "path", tmpName, "error", err)
		}
	}()

	if err := writeSnapshotFile(tmp, tmpName, body); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publish snapshot: %w", err)
	}
	return nil
}

// writeSnapshotFile fills and closes the temp file the publish will rename.
func writeSnapshotFile(tmp *os.File, name string, body []byte) error {
	defer func() {
		if err := tmp.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			slog.Default().Debug("cannot close temp snapshot", "path", name, "error", err)
		}
	}()

	if _, err := tmp.Write(body); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	// Durability before visibility: a snapshot that survives the rename but not
	// a power cut would leave the edge serving an empty table after a reboot.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync snapshot: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil { // #nosec G302 — readable by the edge user
		return fmt.Errorf("chmod snapshot: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close snapshot: %w", err)
	}
	return nil
}

// Load reads a published snapshot.
func Load(path string) (Snapshot, error) {
	body, err := os.ReadFile(path) // #nosec G304 — the path is operator configuration
	if err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %w", ErrInvalidSnapshot, err)
	}
	if err := snap.Validate(); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// SnapshotPath is where the projection lives under a given directory.
func SnapshotPath(dir string) string {
	return filepath.Join(dir, SnapshotName)
}
