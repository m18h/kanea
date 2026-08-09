package api

import (
	"context"
	"errors"
	"net/http"
)

// PathCerts is the certificate surface (PRD §16.1).
//
// Only the CA certificate is served, and only the certificate. There is no
// route that returns a private key, for the same reason §16.3 gives no tool a
// secrets `get`: the safe design is not one that guards the verb, it is one
// where the verb does not exist.
const PathCerts = "/v1/certs"

// CertificateAuthority hands out this node's self-signed CA certificate, so an
// operator can install it once and have every service on the node be trusted
// (PRD §7.3).
//
// Defined here rather than imported so this package does not depend on
// internal/certsource. There is deliberately no method that returns the key.
type CertificateAuthority interface {
	CACertificate(ctx context.Context) ([]byte, error)
}

// errNoCA is the answer when nothing on this node uses a self-signed
// certificate, so no CA has ever been generated.
//
// A 404 rather than a 503: the resource genuinely does not exist, and the
// message says what would bring it into being.
var errNoCA = errors.New(
	"no service on this node uses tls { mode = \"self-signed\" }, so no CA has been generated")

// handleCACertificate serves the CA certificate an operator installs on their
// devices.
//
// Authenticated like every other route (constraint #7) but not admin-only: this
// certificate is presented in every handshake to every client that trusts it.
// It is public by construction, and treating it as privileged would only make
// the one workflow it exists for harder than it is.
func (s *Server) handleCACertificate(w http.ResponseWriter, r *http.Request) {
	if s.ca == nil {
		writeError(w, http.StatusNotFound, errNoCA)
		return
	}
	pem, err := s.ca.CACertificate(r.Context())
	if err != nil {
		// Any failure to produce one reads the same to a caller: there is no
		// CA to install. The detail is in the daemon's log.
		writeError(w, http.StatusNotFound, errNoCA)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="kanea-ca.crt"`)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(pem); err != nil {
		// The response is already committed; there is nowhere left to report.
		_ = err
	}
}
