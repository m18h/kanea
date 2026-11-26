package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/secrets"
)

// oidcSettings is the provider configuration as auth.oidc in kanea.hcl expresses it.
type oidcSettings struct {
	issuer    string
	clientID  string
	secretRef string
	redirect  string
	scopes    []string
	roleClaim string
	admins    []string
	viewers   []string
}

// buildOIDC constructs the identity provider, or nothing when none is
// configured.
//
// The return is an interface rather than *auth.OIDC on purpose: a typed nil in
// an interface is not nil, and the API decides whether the provider routes
// exist by comparing that interface against nil.
func buildOIDC(ctx context.Context, cfg oidcSettings, store *secrets.Store,
	logger *slog.Logger) (api.Provider, error) {
	if cfg.issuer == "" {
		if cfg.clientID != "" || cfg.secretRef != "" || len(cfg.admins) > 0 {
			// Half-configured is worth saying out loud: someone set the client
			// up and would otherwise find out the provider is off by clicking a
			// sign-in button that is not there.
			logger.Warn("OIDC settings are present but auth.oidc.issuer is not; password login only")
		}
		return nil, nil
	}

	clientSecret, err := resolveSecretRef(ctx, "auth.oidc.client_secret", cfg.secretRef, store)
	if err != nil {
		return nil, err
	}

	provider, err := auth.NewOIDC(ctx, auth.OIDCConfig{
		Issuer:       cfg.issuer,
		ClientID:     cfg.clientID,
		ClientSecret: clientSecret,
		RedirectURL:  cfg.redirect,
		Scopes:       cfg.scopes,
		RoleClaim:    cfg.roleClaim,
		AdminValues:  cfg.admins,
		ViewerValues: cfg.viewers,
		Logger:       logger,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("identity provider configured",
		"issuer", cfg.issuer, "role_claim", cfg.roleClaim,
		"admin_claims", cfg.admins, "viewer_claims", cfg.viewers)
	return provider, nil
}

// resolveSecretRef reads a node config attribute's credential from the
// secrets store, naming the attribute in every refusal so the operator meets
// the R3 rule in front of the line they wrote. Shared by the OIDC client
// secret and the LDAP bind password (v1.47).
//
// A `secret:` reference rather than a literal value, for the reason every
// other credential in Kanea is one (§6.2 R3): a literal in kanea.hcl is
// readable by whoever can read the file, and ends up in its backups and
// history. An empty reference is a public PKCE client, which is a supported
// configuration and not a downgrade.
func resolveSecretRef(ctx context.Context, attr, ref string, store *secrets.Store) (string, error) {
	if ref == "" {
		return "", nil
	}
	if !strings.HasPrefix(ref, secrets.Prefix) {
		return "", fmt.Errorf("%s must be a %s reference, e.g. %sshared/…",
			attr, secrets.Prefix, secrets.Prefix)
	}
	if store == nil {
		return "", fmt.Errorf("cannot resolve %s: the secrets store is unavailable", ref)
	}

	value, err := store.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("%s: %w", attr, err)
	}
	return string(value), nil
}
