package main

// Directory authentication wiring (PRD v1.47, §13.2) — the oidc.go twin.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/secrets"
)

// ldapSettings is what the agent's flags say about the directory.
type ldapSettings struct {
	url          string
	bindDN       string
	bindRef      string // a `secret:` reference, never a literal (R3)
	userBaseDN   string
	userFilter   string
	groupBaseDN  string
	groupFilter  string
	adminGroups  []string
	viewerGroups []string
	caFile       string
}

// configured reports whether any LDAP flag was set.
func (c ldapSettings) configured() bool {
	return c.url != "" || c.bindDN != "" || c.bindRef != "" ||
		c.userBaseDN != "" || c.userFilter != "" ||
		c.groupBaseDN != "" || c.groupFilter != "" ||
		len(c.adminGroups) > 0 || len(c.viewerGroups) > 0 || c.caFile != ""
}

// buildLDAP assembles the verifier, or nil when LDAP is not configured.
//
// Validation is hard and connection is soft, deliberately split (§3.20): a
// config error refuses at startup in front of the operator — the OIDC rule —
// while an unreachable directory is a warning and a serving daemon, because a
// directory outage is weather and must not keep kanead down.
func buildLDAP(
	ctx context.Context, cfg ldapSettings, store *secrets.Store, logger *slog.Logger,
) (*auth.LDAP, error) {
	if cfg.url == "" {
		if cfg.configured() {
			// Half a configuration is worth a line: the operator set LDAP
			// flags and is not getting LDAP.
			logger.Warn("LDAP settings are present but --ldap-url is not; " +
				"password login is local-only")
		}
		return nil, nil
	}

	bindPassword, err := resolveSecretRef(ctx, "--ldap-bind-password", cfg.bindRef, store)
	if err != nil {
		return nil, err
	}
	directory, err := auth.NewLDAP(auth.LDAPConfig{
		URL:          cfg.url,
		BindDN:       cfg.bindDN,
		BindPassword: bindPassword,
		UserBaseDN:   cfg.userBaseDN,
		UserFilter:   cfg.userFilter,
		GroupBaseDN:  cfg.groupBaseDN,
		GroupFilter:  cfg.groupFilter,
		AdminGroups:  cfg.adminGroups,
		ViewerGroups: cfg.viewerGroups,
		CAFile:       cfg.caFile,
		Logger:       logger,
	})
	if err != nil {
		return nil, fmt.Errorf("ldap: %w", err)
	}

	checkCtx, cancel := context.WithTimeout(ctx, ldapStartupCheckTimeout)
	defer cancel()
	if err := directory.CheckConnection(checkCtx); err != nil {
		logger.Warn("the directory is unreachable; LDAP logins will fail until it returns",
			"server", directory.Server(), "error", err)
	} else {
		logger.Info("directory authentication configured",
			"server", directory.Server(), "user_base", cfg.userBaseDN,
			"admin_groups", len(cfg.adminGroups), "viewer_groups", len(cfg.viewerGroups))
	}
	return directory, nil
}

// ldapStartupCheckTimeout bounds the reachability warning's probe, so a
// black-holed directory does not stall startup.
const ldapStartupCheckTimeout = 5 * time.Second

// ldapVerifier adapts the nil case: a nil *auth.LDAP in an auth.PasswordVerifier
// field would be a non-nil interface holding a nil pointer — the buildOIDC
// lesson, applied here.
func ldapVerifier(l *auth.LDAP) auth.PasswordVerifier {
	if l == nil {
		return nil
	}
	return l
}

// ldapServerName names the directory for the audit Detail, or nothing.
func ldapServerName(l *auth.LDAP) string {
	if l == nil {
		return ""
	}
	return l.Server()
}
