package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/m18h/kanea/internal/auth"
)

// Account management routes (PRD §13.2, §13.3).
const (
	PathUsers  = "/v1/users"
	PathTokens = "/v1/tokens" // #nosec G101: a route, not a credential
)

// Accounts manages users and tokens.
//
// Separate from Authenticator because the two are asked different questions at
// different times: every request authenticates, almost none creates an account.
// Splitting them also keeps the read-only path from holding a handle that can
// mint credentials.
type Accounts interface {
	PutUser(ctx context.Context, name, password string, role auth.Role) error
	Users(ctx context.Context) ([]auth.User, error)
	DeleteUser(ctx context.Context, name string) error
	CreateToken(ctx context.Context, name string, role auth.Role, expires time.Time) (auth.Token, string, error)
	Tokens(ctx context.Context) ([]auth.Token, error)
	RevokeToken(ctx context.Context, id string) error
}

// UsersResponse lists accounts. Password hashes are stripped by the store
// before they get here, so this cannot leak one by forgetting to.
type UsersResponse struct {
	Users []auth.User `json:"users"`
}

// UserRequest creates or replaces one account.
type UserRequest struct {
	Password string    `json:"password"`
	Role     auth.Role `json:"role"`
}

// TokensResponse lists tokens without their hashes.
type TokensResponse struct {
	Tokens []auth.Token `json:"tokens"`
}

// TokenRequest mints a bearer token.
type TokenRequest struct {
	Name string    `json:"name"`
	Role auth.Role `json:"role"`
	// ExpiresIn is a Go duration ("720h"). Empty means no expiry, which the
	// daemon accepts and warns about rather than refusing: a CI token that must
	// not expire mid-release is a real need, and an unexpiring token that is
	// visible in a listing is better than one someone works around.
	ExpiresIn string `json:"expires_in,omitempty"`
}

// TokenResponse carries a newly minted token.
type TokenResponse struct {
	Token auth.Token `json:"token"`
	// Secret is the presented form, returned exactly once. Nothing stores it:
	// a lost token is replaced, not recovered, which is the property that makes
	// a leaked Store harmless (§13.3).
	Secret string `json:"secret"`
}

// handleListUsers lists accounts.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		writeError(w, http.StatusServiceUnavailable, errNoAccounts)
		return
	}
	users, err := s.accounts.Users(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if users == nil {
		users = []auth.User{}
	}
	writeJSON(w, http.StatusOK, UsersResponse{Users: users})
}

// handlePutUser creates or replaces an account.
func (s *Server) handlePutUser(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		writeError(w, http.StatusServiceUnavailable, errNoAccounts)
		return
	}
	name := r.PathValue("name")
	auditTarget(r, name)

	var req UserRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxLoginBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	if err := s.accounts.PutUser(r.Context(), name, req.Password, req.Role); err != nil {
		writeError(w, statusForAuthError(err), err)
		return
	}
	s.log.Info("account written", "user", name, "role", req.Role)
	// No body: everything worth returning is either already known to the caller
	// or is the hash.
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteUser removes an account.
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		writeError(w, http.StatusServiceUnavailable, errNoAccounts)
		return
	}
	name := r.PathValue("name")
	auditTarget(r, name)

	if err := s.accounts.DeleteUser(r.Context(), name); err != nil {
		writeError(w, statusForAuthError(err), err)
		return
	}
	s.log.Info("account removed", "user", name)
	w.WriteHeader(http.StatusNoContent)
}

// handleListTokens lists tokens.
func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		writeError(w, http.StatusServiceUnavailable, errNoAccounts)
		return
	}
	tokens, err := s.accounts.Tokens(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if tokens == nil {
		tokens = []auth.Token{}
	}
	writeJSON(w, http.StatusOK, TokensResponse{Tokens: tokens})
}

// handleCreateToken mints a token and returns its one-time secret.
func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		writeError(w, http.StatusServiceUnavailable, errNoAccounts)
		return
	}
	var req TokenRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxLoginBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	auditTarget(r, req.Name)

	var expires time.Time
	if req.ExpiresIn != "" {
		ttl, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("expires_in: %w", err))
			return
		}
		if ttl <= 0 {
			writeError(w, http.StatusBadRequest, errors.New("expires_in must be positive"))
			return
		}
		expires = time.Now().Add(ttl)
	}

	token, secret, err := s.accounts.CreateToken(r.Context(), req.Name, req.Role, expires)
	if err != nil {
		writeError(w, statusForAuthError(err), err)
		return
	}
	if expires.IsZero() {
		s.log.Warn("minted a token that never expires",
			"token_id", token.ID, "name", token.Name, "role", token.Role)
	}
	// The id is audited, the secret is not: the entry has to be enough to
	// revoke the token later and useless to anyone who reads it.
	auditTarget(r, req.Name+" ("+token.ID+")")
	// The stored hash is what the daemon compares against; a caller has no use
	// for it and every reason not to have it. Listings strip it in the store,
	// and this is the one path that does not go through them.
	token.Hash = ""
	writeJSON(w, http.StatusCreated, TokenResponse{Token: token, Secret: secret})
}

// handleRevokeToken deletes a token by id.
func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		writeError(w, http.StatusServiceUnavailable, errNoAccounts)
		return
	}
	id := r.PathValue("id")
	auditTarget(r, id)

	if err := s.accounts.RevokeToken(r.Context(), id); err != nil {
		writeError(w, statusForAuthError(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var errNoAccounts = errors.New("api: account management is not configured on this daemon")

// statusForAuthError maps an auth error to a status a client can act on.
func statusForAuthError(err error) int {
	switch {
	case errors.Is(err, auth.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, auth.ErrWeakPassword):
		return http.StatusBadRequest
	case errors.Is(err, auth.ErrLastAdmin):
		// A conflict, not a permission problem: the caller is allowed to do
		// this, the platform's state is what refuses.
		return http.StatusConflict
	case err == nil:
		return http.StatusOK
	default:
		// A malformed name or an unknown role is the caller's mistake, and
		// these are the only other things the store rejects.
		return http.StatusBadRequest
	}
}
