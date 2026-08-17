package edge

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultBundlePath is where kanead projects certificates for the edge.
//
// Separate from the route table, and not by accident. Routes are world-readable
// because the edge runs as its own user and nothing in them is secret: the
// domains are in public DNS. A private key is neither, so it gets its own file
// at 0640 rather than dragging the route table's permissions down or pushing
// the key's up (PRD §7.3).
const DefaultBundlePath = "/run/kanea-edge/certs.json"

// BundleName is the published file's name.
const BundleName = "certs.json"

// Bundle is the certificate and challenge material the edge serves.
//
// Challenges live here rather than with the routes because they are the same
// kind of thing: short-lived proof material kanead owns and the edge only
// presents. Keeping them together means one file to publish when an issuance
// starts and one to publish when it finishes.
type Bundle struct {
	// Index is the Store index this projection was built from.
	Index uint64 `json:"index"`
	// Certificates is the full set, replacing whatever was there.
	Certificates []Certificate `json:"certificates,omitempty"`
	// HTTPChallenges answers /.well-known/acme-challenge/<token> during an
	// HTTP-01 validation (PRD §7.3).
	HTTPChallenges []HTTPChallenge `json:"http_challenges,omitempty"`
	// Auth is the R27 verifier material (v1.40), one entry per authenticated
	// service. It rides this bundle rather than routes.json because this is
	// the restricted projection (0640): bcrypt lines, token hashes, and (the
	// one genuinely secret field) a JWT HS256 key.
	Auth []AuthEntry `json:"auth,omitempty"`
}

// Certificate is one issued certificate and its key.
type Certificate struct {
	// Domains are the names this certificate covers, lowercased. A leading
	// "*." entry is a wildcard and matches one label.
	Domains []string `json:"domains"`
	// CertPEM is the leaf followed by any intermediates, in chain order.
	CertPEM string `json:"cert_pem"`
	// KeyPEM is the private key. This is why the bundle is not world-readable.
	KeyPEM string `json:"key_pem"`
	// NotAfter is the leaf's expiry, carried so the edge can report it without
	// parsing and so a stale bundle is recognisable.
	NotAfter time.Time `json:"not_after"`
	// Source is the §7.3 mode that supplied this certificate: acme,
	// self-signed or provided. Carried for the expiry metric's label and for
	// nothing else: the edge does not know the precedence rule that chose it
	// (certsource.Publisher.merged resolves that), and must not learn one.
	//
	// omitempty, and empty is tolerated: a bundle written by a pre-v1.35 kanead
	// carries no source, and refusing to serve TLS over a missing metric label
	// would be a spectacularly bad trade.
	Source string `json:"source,omitempty"`
}

// HTTPChallenge is one pending ACME HTTP-01 response.
type HTTPChallenge struct {
	Token   string `json:"token"`
	KeyAuth string `json:"key_auth"`
}

// ErrInvalidBundle marks a projection the edge cannot serve.
var ErrInvalidBundle = errors.New("edge: invalid certificate bundle")

// Validate checks a bundle before it is written or served.
func (b Bundle) Validate() error {
	for i, c := range b.Certificates {
		if len(c.Domains) == 0 {
			return fmt.Errorf("%w: certificate %d covers no domain", ErrInvalidBundle, i)
		}
		for _, d := range c.Domains {
			if d != strings.ToLower(d) || strings.TrimSpace(d) != d {
				return fmt.Errorf("%w: certificate %d domain %q is not canonical",
					ErrInvalidBundle, i, d)
			}
		}
		// Parsed here rather than trusted: a bundle that loads but cannot be
		// used would leave the edge holding a certificate it silently never
		// serves, which looks exactly like TLS not being configured at all.
		if _, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM)); err != nil {
			return fmt.Errorf("%w: certificate %d (%s): %w",
				ErrInvalidBundle, i, strings.Join(c.Domains, ", "), err)
		}
	}
	for i, ch := range b.HTTPChallenges {
		if ch.Token == "" || ch.KeyAuth == "" {
			return fmt.Errorf("%w: challenge %d is incomplete", ErrInvalidBundle, i)
		}
		if strings.ContainsAny(ch.Token, "/?#") {
			// The token becomes a URL path element. One carrying a separator
			// would answer a path nobody asked about.
			return fmt.Errorf("%w: challenge %d token %q is not a path element",
				ErrInvalidBundle, i, ch.Token)
		}
	}
	return nil
}

// PublishBundle writes the certificate projection.
//
// Same temp-then-rename as the route table, but 0640: this file holds private
// keys. The group is the edge user's, so it can read what it must present
// without anything else on the node being able to.
func PublishBundle(path string, bundle Bundle, gid int) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bundle: %w", err)
	}
	body = append(body, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301; the file, not the dir, is the secret
		return fmt.Errorf("edge dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*"+tempSuffix)
	if err != nil {
		return fmt.Errorf("create temp bundle: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err := os.Remove(tmpName); err != nil && !os.IsNotExist(err) {
			slog.Default().Debug("cannot remove temp bundle", "path", tmpName, "error", err)
		}
	}()

	if err := writeBundleFile(tmp, tmpName, body, gid); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publish bundle: %w", err)
	}
	return nil
}

// writeBundleFile fills, secures and closes the temp file.
//
// The permissions are narrowed *before* the rename, never after: a file that is
// briefly 0644 in a shared directory is a file anyone watching can copy.
func writeBundleFile(tmp *os.File, name string, body []byte, gid int) error {
	defer func() {
		if err := tmp.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			slog.Default().Debug("cannot close temp bundle", "path", name, "error", err)
		}
	}()

	if _, err := tmp.Write(body); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync bundle: %w", err)
	}

	// Group before mode: chown clears the setuid/setgid bits, so doing it after
	// chmod would quietly undo part of what was just set.
	if gid > 0 {
		if err := tmp.Chown(os.Getuid(), gid); err != nil {
			return fmt.Errorf("chown bundle to gid %d: %w", gid, err)
		}
		if err := tmp.Chmod(0o640); err != nil {
			return fmt.Errorf("chmod bundle: %w", err)
		}
	} else if err := tmp.Chmod(0o600); err != nil {
		// No group configured, so nothing but this user may read it. An edge
		// running as another user will fail loudly rather than silently being
		// handed keys it should not have.
		return fmt.Errorf("chmod bundle: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close bundle: %w", err)
	}
	return nil
}

// LoadBundle reads a published certificate projection.
func LoadBundle(path string) (Bundle, error) {
	body, err := os.ReadFile(path) // #nosec G304; the path is operator configuration
	if err != nil {
		return Bundle{}, err
	}
	var bundle Bundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return Bundle{}, fmt.Errorf("%w: %w", ErrInvalidBundle, err)
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

// BundlePath is where the bundle lives under a given directory.
func BundlePath(dir string) string { return filepath.Join(dir, BundleName) }

// expiriesOf turns a bundle into the expiry gauges the metrics collector holds.
//
// One entry per certificate, labelled with its first domain, not one per name
// it covers. A wildcard covering forty subdomains is one thing that expires on
// one date, and forty gauges saying so would make a single renewal look like a
// fleet-wide event.
//
// A certificate from a pre-v1.35 kanead carries no source. It is labelled
// "unknown" rather than dropped: the expiry is the number worth having, and
// withholding it because a label is missing gets the trade backwards.
func expiriesOf(b Bundle) []CertExpiry {
	out := make([]CertExpiry, 0, len(b.Certificates))
	for _, c := range b.Certificates {
		if len(c.Domains) == 0 {
			continue // Validate refuses these; belt and braces before an index
		}
		source := c.Source
		if source == "" {
			source = "unknown"
		}
		out = append(out, CertExpiry{
			CommonName: c.Domains[0],
			Source:     source,
			NotAfter:   c.NotAfter,
		})
	}
	return out
}
