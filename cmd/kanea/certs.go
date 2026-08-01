package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/kanea-dev/kanea/internal/acme"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/store"
)

// certCheckInterval is how often the renewal pass runs.
//
// Twelve hours, against certificates renewed a third of their life before
// expiry — for Let's Encrypt that is a 30-day window, so a node can miss sixty
// consecutive passes and still renew in time. Checking more often would only
// spend rate limit faster when something is wrong.
const certCheckInterval = 12 * time.Hour

// certRetryInterval is how soon a failed pass is retried. Short enough that a
// transient DNS or network problem resolves within the hour, long enough not to
// hammer the CA — whose failed-validation limits are the ones that bite.
const certRetryInterval = 15 * time.Minute

// wildcardThreshold is where PRD §7.3 says per-service certificates stop being
// the right shape. Until the secrets store lands (M5) there is no DNS-01 and
// therefore no wildcard, so crossing it is a warning rather than a switch.
const wildcardThreshold = 20

// runCertificates is kanead's ACME loop: issue what is missing, renew what is
// due, publish the result for the edge.
func runCertificates(ctx context.Context, m *acme.Manager, pub *acme.Publisher,
	st store.Store, baseDomain string, trigger <-chan struct{}, logger *slog.Logger,
) error {
	// Publish immediately, before the first issuance. A restart must put the
	// certificates it already holds back in front of the edge without waiting
	// for the CA to answer — or every kanead restart is a TLS outage.
	if err := syncCertificates(ctx, m, pub, st, baseDomain, logger); err != nil {
		logger.Error("certificate pass failed", "error", err)
	}

	timer := time.NewTimer(certCheckInterval)
	defer timer.Stop()
	for {
		// An apply wakes the loop as well as the timer: a newly exposed service
		// should get its certificate in seconds, not at the next renewal check.
		// Deploying is also exactly when the domain is new and most likely to
		// be misconfigured, which is when an operator is watching.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		case <-trigger:
			// Give the reconciler a moment to publish the route first. Nothing
			// depends on it — challenges are served regardless of routing — but
			// issuing for a service that has not converged wastes an attempt if
			// the deploy is about to fail.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(certTriggerDelay):
			}
		}

		next := certCheckInterval
		if err := syncCertificates(ctx, m, pub, st, baseDomain, logger); err != nil {
			logger.Error("certificate pass failed", "error", err, "retry_in", certRetryInterval)
			next = certRetryInterval
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(next)
	}
}

// certTriggerDelay lets a deploy settle before issuance is attempted.
const certTriggerDelay = 3 * time.Second

// syncCertificates runs one pass.
func syncCertificates(ctx context.Context, m *acme.Manager, pub *acme.Publisher,
	st store.Store, baseDomain string, logger *slog.Logger,
) error {
	requests, err := certRequests(ctx, st, baseDomain, logger)
	if err != nil {
		return err
	}
	if len(requests) > wildcardThreshold {
		logger.Warn("more exposed services than per-service certificates are meant for",
			"services", len(requests), "threshold", wildcardThreshold,
			"detail", "PRD §7.3 switches to a wildcard via DNS-01 here; that needs the "+
				"secrets store (M5). Watch your Let's Encrypt rate limits until then")
	}

	certs, err := m.Sync(ctx, requests)
	if err != nil {
		return err
	}
	if err := pub.SetCertificates(certs); err != nil {
		return fmt.Errorf("publish certificates: %w", err)
	}
	logger.Info("certificates published", "certificates", len(certs), "requested", len(requests))
	return nil
}

// certRequests reads desired state and returns what needs a certificate.
//
// The domains come from the same resolution the route table uses, so a service
// cannot end up with a certificate for a name the edge does not route — which
// would be an issuance that always fails validation.
func certRequests(ctx context.Context, st store.Store, baseDomain string,
	logger *slog.Logger,
) ([]acme.Request, error) {
	services, err := listAllServices(ctx, st)
	if err != nil {
		return nil, err
	}

	var out []acme.Request
	for _, d := range services {
		if d.Expose == nil || !d.Expose.LetsEncrypt {
			continue
		}
		domains := reconciler.EdgeDomains(d, baseDomain)
		if len(domains) == 0 {
			logger.Warn("service asks for a certificate but has no domain",
				"service", d.Project+"/"+d.Service,
				"detail", "declare expose.domains, or set --base-domain")
			continue
		}
		out = append(out, acme.Request{Domains: domains, Service: d.Project + "/" + d.Service})
	}
	return out, nil
}

// listAllServices reads every desired service from the Store.
func listAllServices(ctx context.Context, st store.Store) ([]reconciler.Desired, error) {
	var out []reconciler.Desired
	opts := store.ListOptions{}
	for {
		values, page, err := store.ListValues[reconciler.Desired](ctx, st, store.KindService, opts)
		if err != nil {
			return nil, fmt.Errorf("list services: %w", err)
		}
		out = append(out, values...)
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

// certStoreAdapter maps the ACME manager's needs onto the certs bucket.
type certStoreAdapter struct{ store store.Store }

func (a certStoreAdapter) Get(ctx context.Context, key string) ([]byte, bool, error) {
	rec, err := a.store.Get(ctx, store.KindCert, key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return rec.Value, true, nil
}

func (a certStoreAdapter) Put(ctx context.Context, key string, value []byte) error {
	mut, err := store.PutRawMutation(store.KindCert, key, value)
	if err != nil {
		return err
	}
	_, err = a.store.Apply(ctx, mut)
	return err
}

func (a certStoreAdapter) List(ctx context.Context, prefix string) (map[string][]byte, error) {
	out := map[string][]byte{}
	opts := store.ListOptions{Prefix: prefix}
	for {
		page, err := a.store.List(ctx, store.KindCert, opts)
		if err != nil {
			return nil, err
		}
		for _, rec := range page.Records {
			out[rec.Key] = rec.Value
		}
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

// lookupGID resolves the group the edge runs as, so the certificate bundle can
// be readable by it and by nothing else.
//
// A name that does not resolve is a hard error rather than a fallback to
// owner-only: the operator asked for the edge to be able to read this, and
// silently publishing a file it cannot read would leave TLS mysteriously
// unconfigured.
func lookupGID(name string) (int, error) {
	if name == "" {
		return 0, nil
	}
	if gid, err := strconv.Atoi(name); err == nil {
		return gid, nil
	}
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("edge group %q: %w", name, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return 0, fmt.Errorf("edge group %q has a non-numeric gid %q", name, group.Gid)
	}
	return gid, nil
}

// readCABundle loads an extra CA to trust when talking to the ACME directory.
func readCABundle(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	body, err := os.ReadFile(path) // #nosec G304 — operator configuration
	if err != nil {
		return nil, fmt.Errorf("acme CA bundle: %w", err)
	}
	return body, nil
}

// certificates bundles the two halves of the ACME subsystem.
type certificates struct {
	manager   *acme.Manager
	publisher *acme.Publisher
}

// buildCertificates wires ACME, or returns nil when it is not configured.
//
// Not configured is a legitimate state, not an error: a node serving plaintext
// behind someone else's TLS terminator, or one still being set up, should start
// and work. What it must not do is start *and look configured*, so the reason
// is logged rather than left to be inferred from the absence of certificates.
func buildCertificates(email, directory, caPath, bundlePath, group, verifyURL string,
	st store.Store, logger *slog.Logger,
) (*certificates, error) {
	if email == "" {
		logger.Warn("no --acme-email: no certificates will be obtained",
			"detail", "exposed services are reachable over HTTP only")
		return nil, nil
	}

	gid, err := lookupGID(group)
	if err != nil {
		return nil, err
	}
	if gid == 0 {
		logger.Warn("no --edge-group: the certificate bundle is readable only by this user",
			"detail", "an edge running as another user will not be able to serve TLS")
	}

	publisher, err := acme.NewPublisher(acme.PublisherConfig{
		Path:      bundlePath,
		GID:       gid,
		VerifyURL: verifyURL,
		Logger:    logger,
	})
	if err != nil {
		return nil, err
	}

	caBundle, err := readCABundle(caPath)
	if err != nil {
		return nil, err
	}
	manager, err := acme.New(acme.Config{
		Directory:    directory,
		Email:        email,
		Store:        certStoreAdapter{store: st},
		Solver:       publisher,
		Logger:       logger,
		HTTPClientCA: caBundle,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("ACME enabled", "email", email, "directory", directory, "bundle", bundlePath)
	return &certificates{manager: manager, publisher: publisher}, nil
}
