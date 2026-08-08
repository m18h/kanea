package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/acme"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/store"
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

// runCertificates is kanead's ACME loop: issue what is missing, renew what is
// due, publish the result for the edge.
func runCertificates(ctx context.Context, m *acme.Manager, pub *acme.Publisher,
	st store.Store, baseDomain string, trigger <-chan struct{}, logger *slog.Logger,
	emit func(notify.Event),
) error {
	// What each certificate's issuance time was on the previous pass. A
	// certificate whose IssuedAt moved was obtained during this pass, which is
	// how "issued" and "renewed" are told apart without reaching inside the
	// ACME manager for a callback it does not have.
	seen := map[string]time.Time{}
	// Publish immediately, before the first issuance. A restart must put the
	// certificates it already holds back in front of the edge without waiting
	// for the CA to answer — or every kanead restart is a TLS outage.
	if err := syncCertificates(ctx, m, pub, st, baseDomain, logger, emit, seen); err != nil {
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
		if err := syncCertificates(ctx, m, pub, st, baseDomain, logger, emit, seen); err != nil {
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
	emit func(notify.Event), seen map[string]time.Time,
) error {
	exposures, err := certExposures(ctx, st, baseDomain, logger)
	if err != nil {
		return err
	}
	plan := acme.PlanRequests(exposures, acme.PlanOptions{
		BaseDomain: baseDomain,
		Wildcards:  m.SupportsWildcards(),
	})
	if plan.OverThreshold {
		// The condition §7.3 wants said out loud: past this many certificates a
		// node is spending its weekly Let's Encrypt allowance on redeploys, and
		// the fix — a wildcard — needs a DNS-01 solver nobody has configured.
		logger.Warn("more per-service certificates than Let's Encrypt rate limits are comfortable with",
			"certificates", plan.PerService, "threshold", acme.DefaultWildcardThreshold,
			"detail", "configure --acme-dns-server to switch to per-project wildcards (PRD §7.3)")
	}
	if plan.Wildcard > 0 {
		logger.Info("issuing per-project wildcards",
			"wildcards", plan.Wildcard, "per_service", plan.PerService)
	}

	certs, err := m.Sync(ctx, plan.Requests)
	if err != nil {
		// A renewal that fails is an outage with a date on it, which is why
		// §11 files cert.failed as an error rather than a warning.
		emitCert(emit, notify.EventCertFailed, "", "certificate issuance failed: "+err.Error())
		return err
	}
	emitCertChanges(emit, certs, seen)
	if err := pub.SetCertificates(certs); err != nil {
		return fmt.Errorf("publish certificates: %w", err)
	}
	logger.Info("certificates published", "certificates", len(certs), "requested", len(plan.Requests))
	return nil
}

// emitCertChanges publishes an event for each certificate obtained this pass.
func emitCertChanges(emit func(notify.Event), certs []acme.Certificate, seen map[string]time.Time) {
	if emit == nil {
		return
	}
	for _, cert := range certs {
		if len(cert.Domains) == 0 {
			continue
		}
		primary := cert.Domains[0]
		previous, known := seen[primary]
		seen[primary] = cert.IssuedAt
		if known && !cert.IssuedAt.After(previous) {
			continue // unchanged since the last pass
		}
		// First time this daemon has seen it is "issued"; a later issuance for
		// a name it already held is a renewal. A restart therefore reports the
		// certificates it loads as issued once, which is the honest answer —
		// it does not know what happened before it started.
		name := notify.EventCertIssued
		if known {
			name = notify.EventCertRenewed
		}
		emitCert(emit, name, primary, fmt.Sprintf("%s valid until %s",
			strings.Join(cert.Domains, ", "), cert.NotAfter.Format(time.DateOnly)))
	}
}

// emitCert publishes one certificate event.
//
// Certificates are node-level: a wildcard covers a whole project and an
// exposure can name a domain that belongs to no service, so there is no service
// to attribute one to.
func emitCert(emit func(notify.Event), name, domain, message string) {
	if emit == nil {
		return
	}
	emit(notify.NewEvent(name, "", "", message, time.Now()).WithDetail(domain))
}

// certExposures reads desired state and returns what needs a certificate.
//
// The domains come from the same resolution the route table uses, so a service
// cannot end up with a certificate for a name the edge does not route — which
// would be an issuance that always fails validation.
func certExposures(ctx context.Context, st store.Store, baseDomain string,
	logger *slog.Logger,
) ([]acme.Exposure, error) {
	services, err := listAllServices(ctx, st)
	if err != nil {
		return nil, err
	}

	var out []acme.Exposure
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
		out = append(out, acme.Exposure{
			Service: d.Project + "/" + d.Service,
			Project: d.Project,
			Domains: domains,
			// A declared domain is somebody else's zone; only the generated
			// names of §7.2 can be collapsed into a wildcard.
			Auto: len(d.Expose.Domains) == 0,
		})
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
	dnsSolver acme.DNSSolver, st store.Store, logger *slog.Logger,
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
		DNSSolver:    dnsSolver,
		Logger:       logger,
		HTTPClientCA: caBundle,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("ACME enabled", "email", email, "directory", directory, "bundle", bundlePath,
		"dns01", dnsSolver != nil)
	return &certificates{manager: manager, publisher: publisher}, nil
}
