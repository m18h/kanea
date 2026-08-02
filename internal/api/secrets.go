package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/kanea-dev/kanea/internal/secrets"
)

// PathSecrets is the secrets surface.
//
// There is deliberately **no read route**. Secrets are write-only over the API
// (PRD §13.3, §16.3): an operator sets a value and sees that it exists, and
// nothing outside the daemon can read one back. Enforced by the route not
// existing rather than by a permission check that could be misconfigured — a
// missing handler cannot be granted to the wrong role.
const PathSecrets = "/v1/secrets"

// MaxSecretBytes bounds a value. Large enough for a certificate chain or an
// SSH key, small enough that the endpoint is not a way to fill the database.
const MaxSecretBytes = 64 << 10

// SecretsResponse lists what exists, without values.
type SecretsResponse struct {
	Secrets []secrets.Info `json:"secrets"`
}

// SecretRequest sets one value.
type SecretRequest struct {
	Value string `json:"value"`
}

// handleListSecrets returns metadata for every secret.
func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil {
		writeError(w, http.StatusServiceUnavailable, errSecretsUnavailable)
		return
	}
	infos, err := s.secrets.List(r.Context(), r.URL.Query().Get("prefix"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if infos == nil {
		infos = []secrets.Info{}
	}
	writeJSON(w, http.StatusOK, SecretsResponse{Secrets: infos})
}

// handlePutSecret creates or replaces one secret.
func (s *Server) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil {
		writeError(w, http.StatusServiceUnavailable, errSecretsUnavailable)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, PathSecrets+"/")
	// The path, never the value: which secret was written is exactly what an
	// audit trail should say, and what it was set to is exactly what it must not
	// (PRD §13.3, §14 A09).
	auditTarget(r, path)
	if path == "" {
		writeError(w, http.StatusBadRequest, errors.New("api: no secret path"))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxSecretBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(body) > MaxSecretBytes {
		writeError(w, http.StatusRequestEntityTooLarge,
			errors.New("api: secret is larger than the limit"))
		return
	}

	var req SecretRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.secrets.Put(r.Context(), path, []byte(req.Value)); err != nil {
		writeError(w, statusForSecretError(err), err)
		return
	}
	// No body: there is nothing to return that is not the secret itself.
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteSecret removes one secret.
func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	if s.secrets == nil {
		writeError(w, http.StatusServiceUnavailable, errSecretsUnavailable)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, PathSecrets+"/")
	auditTarget(r, path)
	if err := s.secrets.Delete(r.Context(), path); err != nil {
		writeError(w, statusForSecretError(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// statusForSecretError maps a store error to a status a client can act on.
func statusForSecretError(err error) int {
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, secrets.ErrInvalidPath):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

var errSecretsUnavailable = errors.New("api: the secrets store is not configured")
