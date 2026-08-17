package backup

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Client-side encryption for archives (PRD §15.3, §14 A02).
//
// Everything shipped off the node is encrypted here, before it touches a sink.
// The bucket is assumed hostile: an S3 bucket is a credential away from being
// public, and the state it holds is every secret, every certificate and the
// whole shape of what the operator runs.

// ErrKey marks a key that cannot decrypt this archive.
var ErrKey = errors.New("backup: wrong master key")

// ErrCorrupt marks an archive that failed authentication or was truncated.
var ErrCorrupt = errors.New("backup: archive is corrupt or truncated")

// Keys are the archive keys derived from the node's master key.
type Keys struct {
	// stream encrypts archive parts.
	stream []byte
	// mac authenticates manifests. The snapshot's hash is recorded *in* the
	// manifest, so without this a bucket-write attacker could swap in an older
	// (manifest, snapshot) pair - both genuine, both key-produced - and a
	// restore would roll the node back past revocations. A keyed MAC is not a
	// signature: it attributes nothing, and it needs nothing but the key the
	// archive already requires.
	mac []byte
	// ID is a non-secret fingerprint of the master key, written into every
	// manifest.
	//
	// It exists so that restoring with the wrong key says so. Without it the
	// failure is an authentication error on the first chunk, which is
	// indistinguishable from a corrupt archive, and those two have completely
	// different remedies: find the escrowed key, or fetch another backup.
	ID string
}

// DeriveKeys derives the archive keys from the node's master key.
//
// Derived rather than used directly, for domain separation: the same 32 bytes
// encrypt secrets in the Store under a different construction, and a key used
// for two purposes is a key where a flaw in one becomes a flaw in both. HKDF
// with distinct info strings makes them independent.
func DeriveKeys(master []byte) (Keys, error) {
	if len(master) != chacha20poly1305.KeySize {
		return Keys{}, fmt.Errorf("%w: master key is %d bytes, want %d",
			ErrKey, len(master), chacha20poly1305.KeySize)
	}

	stream, err := derive(master, "kanea backup stream v1", chacha20poly1305.KeySize)
	if err != nil {
		return Keys{}, err
	}
	mac, err := derive(master, "kanea backup manifest mac v1", 32)
	if err != nil {
		return Keys{}, err
	}
	// The id is derived rather than hashed straight off the master key, so that
	// publishing it in a manifest leaks nothing usable about the key itself.
	id, err := derive(master, "kanea backup key id v1", 8)
	if err != nil {
		return Keys{}, err
	}
	return Keys{stream: stream, mac: mac, ID: hex.EncodeToString(id)}, nil
}

func derive(master []byte, info string, size int) ([]byte, error) {
	// No salt: the master key is already a uniformly random 32 bytes, which is
	// the case RFC 5869 says a salt is unnecessary for.
	out, err := hkdf.Key(sha256.New, master, nil, info, size)
	if err != nil {
		return nil, fmt.Errorf("%w: derive %q: %w", ErrKey, info, err)
	}
	return out, nil
}

// The stream format. A snapshot is a whole bbolt database and can be hundreds of
// megabytes, so it is encrypted in chunks rather than as one buffer: a control
// plane with a memory floor to defend (§5.2.11) must not need twice the archive
// in RAM to write it.
const (
	// magic identifies the format and its version. Read before anything is
	// decrypted, so a file from a future Kanea produces "I do not understand
	// this" rather than a decryption failure.
	magic = "KANEA-BACKUP-1\n"
	// noncePrefixSize is the random half of every chunk nonce. The other eight
	// bytes are the chunk counter, which is what makes the nonces unique
	// within a stream without a counter ever repeating across streams.
	noncePrefixSize = chacha20poly1305.NonceSizeX - 8
	// chunkSize is the plaintext per chunk.
	chunkSize = 1 << 20
	// overhead is the Poly1305 tag.
	overhead = chacha20poly1305.Overhead
)

// Chunk domain separators, used as additional authenticated data.
//
// This is what makes truncation detectable. Every chunk but the last is sealed
// as "c" and the last as "f", so a stream that ends without an "f" chunk cannot
// be decrypted to a shorter-but-valid plaintext. Without it, an attacker with
// write access to the bucket could truncate a snapshot and a restore would
// succeed against half the state.
var (
	aadChunk = []byte("c")
	aadFinal = []byte("f")
)

// encryptStream writes src to dst, encrypted.
//
// It returns the SHA-256 of the ciphertext, which is what the manifest records:
// hashing the ciphertext lets an archive be verified without the key, so
// `kanea backup verify` on a node that has lost its key still reports whether
// the bytes in the bucket are intact.
func encryptStream(dst io.Writer, src io.Reader, keys Keys) (sum string, size int64, err error) {
	aead, err := chacha20poly1305.NewX(keys.stream)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %w", ErrKey, err)
	}

	prefix := make([]byte, noncePrefixSize)
	if _, err := rand.Read(prefix); err != nil {
		return "", 0, fmt.Errorf("backup: nonce prefix: %w", err)
	}

	hash := sha256.New()
	counted := &countingWriter{w: io.MultiWriter(dst, hash)}
	if _, err := counted.Write([]byte(magic)); err != nil {
		return "", 0, err
	}
	if _, err := counted.Write(prefix); err != nil {
		return "", 0, err
	}

	plain := make([]byte, chunkSize)
	sealed := make([]byte, 0, chunkSize+overhead)
	var counter uint64

	for {
		n, readErr := io.ReadFull(src, plain)
		final := readErr != nil
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return "", 0, fmt.Errorf("backup: read source: %w", readErr)
		}

		aad := aadChunk
		if final {
			aad = aadFinal
		}
		sealed = aead.Seal(sealed[:0], nonceFor(prefix, counter), plain[:n], aad)
		if _, err := counted.Write(sealed); err != nil {
			return "", 0, err
		}
		counter++

		if final {
			// A final chunk is always written, even when it is empty. That is
			// what keeps "a short read means the last chunk" true on the way
			// back in: a full-size ciphertext chunk is never the last one, so
			// the reader never has to guess.
			break
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), counted.n, nil
}

// decryptStream reads an encrypted stream and writes the plaintext to dst.
func decryptStream(dst io.Writer, src io.Reader, keys Keys) error {
	aead, err := chacha20poly1305.NewX(keys.stream)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKey, err)
	}

	// The magic is read on its own, before the nonce prefix. Reading both at
	// once would make a file that is merely *short* (the common case for
	// something that is not an archive at all) fail with "unexpected EOF",
	// which sends an operator looking for a truncated backup rather than for the
	// file they meant to point at.
	header := make([]byte, len(magic))
	if _, err := io.ReadFull(src, header); err != nil || string(header) != magic {
		return fmt.Errorf("%w: this is not a Kanea archive, or it was written by a newer version",
			ErrCorrupt)
	}
	prefix := make([]byte, noncePrefixSize)
	if _, err := io.ReadFull(src, prefix); err != nil {
		return fmt.Errorf("%w: the archive ends inside its header", ErrCorrupt)
	}

	sealed := make([]byte, chunkSize+overhead)
	plain := make([]byte, 0, chunkSize)
	var counter uint64

	for {
		n, readErr := io.ReadFull(src, sealed)
		switch {
		case readErr == nil:
			// A full chunk, so by construction not the last one.
		case errors.Is(readErr, io.ErrUnexpectedEOF):
			// A short chunk is the final one.
		case errors.Is(readErr, io.EOF):
			// Ran out of input without ever seeing a final chunk. The stream
			// was cut, and saying so is the whole point of the "f" marker.
			return fmt.Errorf("%w: the archive ends without its final chunk", ErrCorrupt)
		default:
			return fmt.Errorf("backup: read archive: %w", readErr)
		}

		final := readErr != nil
		aad := aadChunk
		if final {
			aad = aadFinal
		}
		plain, err = aead.Open(plain[:0], nonceFor(prefix, counter), sealed[:n], aad)
		if err != nil {
			// Deliberately one message for every authentication failure. The
			// reasons: wrong key, flipped bit, reordered chunk, truncation;
			// are not distinguishable here, and guessing between them in the
			// error would be a guess presented as a diagnosis. The manifest's
			// key id is what tells the two apart, and it is checked first.
			return fmt.Errorf("%w: chunk %d failed authentication", ErrCorrupt, counter)
		}
		if _, err := dst.Write(plain); err != nil {
			return fmt.Errorf("backup: write plaintext: %w", err)
		}
		counter++
		if final {
			return nil
		}
	}
}

// nonceFor builds a chunk's nonce: the stream's random prefix, then the counter.
func nonceFor(prefix []byte, counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	copy(nonce, prefix)
	binary.BigEndian.PutUint64(nonce[noncePrefixSize:], counter)
	return nonce
}

// countingWriter tracks how much was written, so a part's size lands in the
// manifest without buffering the part to measure it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
