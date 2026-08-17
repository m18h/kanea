package provision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
)

// Source supplies a component's bytes. It is the only thing in this package
// that knows where an artefact comes from.
//
// The point of the interface is that there is exactly one install
// implementation. [HTTPSource] fetches from upstream and [BundleSource] reads a
// directory an operator carried in on a disk; everything downstream
// (verification, extraction, placement, units) cannot tell which it got. An
// air-gapped install is therefore the same code path as an online one, tested
// by the same tests, rather than a parallel one that rots between releases
// (PRD §5.2.12).
//
// A Source is *not* trusted. Whatever it returns is hashed against the manifest
// compiled into this binary before anything is written where it could be
// executed: see [VerifiedReader]. That is deliberate for the bundle case in
// particular: a bundle that carried its own hashes would be a bundle that
// authenticates itself.
type Source interface {
	// Open returns the artefact for a component and architecture. The caller
	// closes it.
	Open(ctx context.Context, c *Component, arch string) (io.ReadCloser, error)

	// Describe says where this Source gets things, for logs and errors.
	// "upstream" and "the bundle at /mnt/usb/kanea.tar.gz" lead to very
	// different next actions when an install fails.
	Describe() string

	// Offline reports whether this Source reaches the network. `kanea doctor`
	// and the install summary use it to say so, and selecting a bundle turns
	// network fetching off entirely rather than leaving it as a fallback: an
	// air-gapped install that silently reaches upstream for one component
	// fails later, on a node nobody can reach.
	Offline() bool
}

// ErrHashMismatch is returned when an artefact is not what the manifest pins.
var ErrHashMismatch = errors.New("artefact does not match the pinned hash")

// VerifiedReader wraps r and fails the final Read if the bytes do not hash to
// want.
//
// Streaming rather than buffer-then-check because a containerd tarball is ~50
// MiB and a bundle holds all of them; the cost of holding one in memory is
// avoidable and the cost of holding six is not. The safety property is
// preserved by never letting a caller *finish* reading a bad artefact:
// [Fetch] writes to a temporary path and only renames after Close reports
// success, so a mismatched payload is never at a path anything would execute.
type VerifiedReader struct {
	r    io.Reader
	h    hash.Hash
	want string
	// n is only for the error message. "hash mismatch" on a zero-byte body is
	// a proxy returning an error page, and saying so saves an hour.
	n    int64
	done bool
}

// NewVerifiedReader checks r against a lowercase hex SHA-256.
func NewVerifiedReader(r io.Reader, want string) *VerifiedReader {
	return &VerifiedReader{r: r, h: sha256.New(), want: want}
}

func (v *VerifiedReader) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	if n > 0 {
		v.n += int64(n)
		// hash.Hash never errors.
		_, _ = v.h.Write(p[:n])
	}
	if errors.Is(err, io.EOF) {
		if verr := v.verify(); verr != nil {
			return n, verr
		}
	}
	return n, err
}

// Verify reports whether what has been read so far matches. Callers that do
// not read to EOF (an extractor that stops at the last member it wants) must
// call this, or a truncated artefact passes.
func (v *VerifiedReader) Verify() error { return v.verify() }

func (v *VerifiedReader) verify() error {
	if v.done {
		return nil
	}
	got := hex.EncodeToString(v.h.Sum(nil))
	if got != v.want {
		return fmt.Errorf("%w: got sha256:%s over %d bytes, want sha256:%s",
			ErrHashMismatch, got, v.n, v.want)
	}
	v.done = true
	return nil
}
