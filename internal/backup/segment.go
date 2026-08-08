package backup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/kanea-dev/kanea/internal/store"
)

// Change segments (PRD §15.3).
//
// bbolt has no write-ahead log — it is a copy-on-write B+tree that rewrites
// pages in place — so Litestream-style log shipping is impossible. What Kanea
// ships instead is the Store's own CDC record: every mutation carries the
// monotonic index it was stamped with (§15.2), and a segment is a contiguous
// run of them.
//
// Segments are what makes the RPO five minutes rather than the snapshot
// interval. A snapshot is expensive — it copies the whole database — and taking
// one every five minutes on a node with real state would spend more time
// snapshotting than serving.

// prefixSegments is where segments live in the sink.
const prefixSegments = "segments/"

// Segment describes one shipped run of changes.
type Segment struct {
	// From and To are the inclusive index bounds. They are in the object name,
	// so a restore can decide what to replay from a listing alone, without
	// downloading or decrypting anything.
	From uint64
	To   uint64
	Name string
	Size int64
}

// segmentName encodes the bounds into a sortable object name.
//
// Zero-padded, because these sort as strings in every sink listing and
// "segments/9-10.seg" must not come after "segments/10-11.seg".
func segmentName(from, to uint64) string {
	return fmt.Sprintf("%s%020d-%020d.seg", prefixSegments, from, to)
}

// parseSegmentName reads the bounds back out.
func parseSegmentName(name string) (Segment, error) {
	base := strings.TrimPrefix(name, prefixSegments)
	base = strings.TrimSuffix(base, ".seg")
	fromRaw, toRaw, found := strings.Cut(base, "-")
	if !found {
		return Segment{}, fmt.Errorf("backup: %q is not a segment name", name)
	}
	from, err := strconv.ParseUint(fromRaw, 10, 64)
	if err != nil {
		return Segment{}, fmt.Errorf("backup: %q has no start index: %w", name, err)
	}
	to, err := strconv.ParseUint(toRaw, 10, 64)
	if err != nil {
		return Segment{}, fmt.Errorf("backup: %q has no end index: %w", name, err)
	}
	return Segment{From: from, To: to, Name: name}, nil
}

// encodeChanges renders changes as newline-delimited JSON.
//
// One object per line rather than one array, so a segment can be read
// incrementally and a partially-decrypted one still yields the changes it did
// contain — though that never happens in practice, because the AEAD refuses a
// truncated stream outright. The real reason is that it is readable: an
// operator debugging a restore can decrypt a segment and see what is in it.
func encodeChanges(w io.Writer, changes []store.Change) error {
	encoder := json.NewEncoder(w)
	for _, change := range changes {
		if err := encoder.Encode(change); err != nil {
			return fmt.Errorf("backup: encode change %d: %w", change.Index, err)
		}
	}
	return nil
}

// decodeChanges reads a segment back.
func decodeChanges(r io.Reader) ([]store.Change, error) {
	var out []store.Change
	scanner := bufio.NewScanner(r)
	// A change's value is a whole record — a service spec with an environment
	// and a middleware chain — so the default 64 KiB line limit is too small.
	scanner.Buffer(make([]byte, 0, 64<<10), maxChangeBytes)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var change store.Change
		if err := json.Unmarshal(line, &change); err != nil {
			return nil, fmt.Errorf("backup: decode change: %w", err)
		}
		out = append(out, change)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("backup: read segment: %w", err)
	}
	return out, nil
}

// maxChangeBytes bounds one encoded change. Well above any record the Store
// holds, and a bound rather than none because this parses data from the bucket.
const maxChangeBytes = 8 << 20

// PutSegment encrypts and uploads a run of changes.
func (a *Archiver) PutSegment(ctx context.Context, changes []store.Change) (Segment, error) {
	if len(changes) == 0 {
		return Segment{}, errors.New("backup: refusing to ship an empty segment")
	}
	from, to := changes[0].Index, changes[len(changes)-1].Index

	var plain bytes.Buffer
	if err := encodeChanges(&plain, changes); err != nil {
		return Segment{}, err
	}
	// Buffered in memory, unlike a snapshot: a segment is one polling interval
	// of mutations on a single-node control plane, which is kilobytes. The
	// interval is what bounds it, and the replicator caps how many changes it
	// reads per tick.
	var sealed bytes.Buffer
	if _, _, err := encryptStream(&sealed, &plain, a.keys); err != nil {
		return Segment{}, err
	}

	name := segmentName(from, to)
	if err := a.sink.Put(ctx, name, int64(sealed.Len()), &sealed); err != nil {
		return Segment{}, err
	}
	return Segment{From: from, To: to, Name: name, Size: int64(sealed.Len())}, nil
}

// Segments lists the shipped segments, oldest first.
func (a *Archiver) Segments(ctx context.Context) ([]Segment, error) {
	objects, err := a.sink.List(ctx, prefixSegments)
	if err != nil {
		return nil, err
	}

	out := make([]Segment, 0, len(objects))
	for _, obj := range objects {
		segment, err := parseSegmentName(obj.Name)
		if err != nil {
			// Something else in the prefix. Skipped rather than fatal: a
			// listing that failed on one stray object would take the whole
			// restore with it.
			a.log.Warn("ignoring an unrecognised object in the segment prefix",
				"name", obj.Name, "error", err)
			continue
		}
		segment.Size = obj.Size
		out = append(out, segment)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].From < out[j].From })
	return out, nil
}

// GetSegment downloads and decrypts one segment.
func (a *Archiver) GetSegment(ctx context.Context, segment Segment) (_ []store.Change, err error) {
	body, err := a.sink.Get(ctx, segment.Name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, body.Close()) }()

	var plain bytes.Buffer
	if err := decryptStream(&plain, body, a.keys); err != nil {
		return nil, fmt.Errorf("backup: segment %s: %w", segment.Name, err)
	}
	return decodeChanges(&plain)
}

// ShippedTo reports the highest index the sink already holds.
//
// Derived from the sink rather than remembered locally, deliberately. A cursor
// kept in the Store would be state, and writing it would emit a change, which
// would need shipping, which would write the cursor again — a loop that never
// goes quiet. A cursor in a local file would be one more thing to lose in
// exactly the failure this subsystem exists for. The bucket already knows what
// is in it.
func (a *Archiver) ShippedTo(ctx context.Context) (uint64, error) {
	segments, err := a.Segments(ctx)
	if err != nil {
		return 0, err
	}
	var highest uint64
	for _, segment := range segments {
		highest = max(highest, segment.To)
	}

	// A snapshot also establishes a floor: everything up to its index is in it,
	// whether or not a segment covering that range survives.
	manifests, err := a.List(ctx)
	if err != nil {
		return 0, err
	}
	for _, m := range manifests {
		highest = max(highest, m.Index)
	}
	return highest, nil
}

// PruneSegments deletes segments fully covered by a snapshot.
//
// "Fully covered" is `To <= upto`, not `From <= upto`: a segment straddling the
// snapshot index still holds changes newer than it, and deleting it would lose
// them.
func (a *Archiver) PruneSegments(ctx context.Context, upto uint64) (int, error) {
	segments, err := a.Segments(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, segment := range segments {
		if segment.To > upto {
			continue
		}
		if err := a.sink.Delete(ctx, segment.Name); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
