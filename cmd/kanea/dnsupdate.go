package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/kanea-dev/kanea/internal/acme"
	"github.com/kanea-dev/kanea/internal/secrets"
)

// dnsUpdateSettings is the DNS-01 solver as the flags express it.
type dnsUpdateSettings struct {
	server    string
	zone      string
	key       string
	secretRef string
	algorithm string
}

// buildDNSSolver constructs the DNS-01 solver, or nothing when none is
// configured.
//
// Returning an interface, and a true nil when disabled: the ACME manager
// decides whether wildcards are possible by comparing it against nil, and a
// typed nil pointer in an interface would tell it the opposite of the truth.
func buildDNSSolver(ctx context.Context, cfg dnsUpdateSettings, store *secrets.Store,
	logger *slog.Logger) (acme.DNSSolver, error) {
	if cfg.server == "" {
		if cfg.key != "" || cfg.secretRef != "" {
			logger.Warn("DNS update credentials are set but --acme-dns-server is not; " +
				"DNS-01 is off and wildcards cannot be issued")
		}
		return nil, nil
	}

	secret, err := resolveTSIGSecret(ctx, cfg.secretRef, store)
	if err != nil {
		return nil, err
	}

	solver, err := acme.NewRFC2136Solver(acme.RFC2136Config{
		Server:        cfg.server,
		Zone:          cfg.zone,
		TSIGKey:       cfg.key,
		TSIGSecret:    secret,
		TSIGAlgorithm: cfg.algorithm,
		Logger:        logger,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("DNS-01 enabled", "server", cfg.server, "zone", cfg.zone, "tsig_key", cfg.key)
	return solver, nil
}

// resolveTSIGSecret reads the update key from the secrets store.
//
// A `secret:` reference for the same reason the OIDC client secret is one
// (§6.2 R3): a TSIG key that can write to a zone can pass an ACME challenge for
// every name in it, and argv is world-readable through /proc.
func resolveTSIGSecret(ctx context.Context, ref string, store *secrets.Store) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("--acme-dns-tsig-secret is required with --acme-dns-server: "+
			"unsigned dynamic updates would let anyone on the network answer a challenge "+
			"(use a %s reference)", secrets.Prefix)
	}
	if !strings.HasPrefix(ref, secrets.Prefix) {
		return "", fmt.Errorf("--acme-dns-tsig-secret must be a %s reference, e.g. %sshared/tsig-key",
			secrets.Prefix, secrets.Prefix)
	}
	if store == nil {
		return "", fmt.Errorf("cannot resolve %s: the secrets store is unavailable", ref)
	}

	value, err := store.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("tsig secret: %w", err)
	}
	return strings.TrimSpace(string(value)), nil
}
