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
	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/certsource"
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

// certFileCheckInterval is how often the provided-certificate config and the
// files it names are checked for movement.
//
// A minute, because a renewal tool rewrites a certificate without telling
// Kanea, and the gap between "certbot renewed it" and "the edge serves it" is
// time an operator spends looking at an expired certificate. The check hashes a
// handful of small files and a pass only runs when something actually moved, so
// the cost of the poll is not the cost of a pass.
const certFileCheckInterval = time.Minute

// certRetryInterval is how soon a failed pass is retried. Short enough that a
// transient DNS or network problem resolves within the hour, long enough not to
// hammer the CA — whose failed-validation limits are the ones that bite.
const certRetryInterval = 15 * time.Minute

// runCertificates is kanead's certificate loop: obtain what is missing, renew
// what is due, publish the result for the edge (PRD §7.3).
func runCertificates(ctx context.Context, c *certificates, st store.Store,
	baseDomain, nodeDefault string, trigger <-chan struct{}, logger *slog.Logger,
	emit func(notify.Event),
) error {
	// What each certificate's issuance time was on the previous pass. A
	// certificate whose IssuedAt moved was obtained during this pass, which is
	// how "issued" and "renewed" are told apart without reaching inside a
	// source for a callback it does not have.
	seen := map[string]time.Time{}
	// Publish immediately, before the first issuance. A restart must put the
	// certificates it already holds back in front of the edge without waiting
	// for the CA to answer — or every kanead restart is a TLS outage.
	if err := syncCertificates(ctx, c, st, baseDomain, nodeDefault, logger, emit, seen); err != nil {
		logger.Error("certificate pass failed", "error", err)
	}

	timer := time.NewTimer(certCheckInterval)
	defer timer.Stop()

	// A separate, much faster tick for the one source whose material changes
	// without Kanea doing anything. It does not run a pass — it asks whether
	// the files moved, and only then wakes the loop.
	files := time.NewTicker(certFileCheckInterval)
	defer files.Stop()

	for {
		// An apply wakes the loop as well as the timer: a newly exposed service
		// should get its certificate in seconds, not at the next renewal check.
		// Deploying is also exactly when the domain is new and most likely to
		// be misconfigured, which is when an operator is watching.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		case <-files.C:
			if c.provided == nil || !c.provided.Changed() {
				continue
			}
			logger.Info("provided certificates changed on disk", "path", c.provided.Path())
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
		if err := syncCertificates(ctx, c, st, baseDomain, nodeDefault, logger, emit, seen); err != nil {
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

// syncCertificates runs one pass over every configured source.
//
// A source that fails does not stop the others: three origins share one bundle,
// and a registry outage at Let's Encrypt must not withdraw the certificates a
// local CA minted. The pass reports the first error so the loop can back off,
// but only after everything that could publish has.
func syncCertificates(ctx context.Context, c *certificates, st store.Store,
	baseDomain, nodeDefault string, logger *slog.Logger,
	emit func(notify.Event), seen map[string]time.Time,
) error {
	byMode, err := certRequests(ctx, st, baseDomain, nodeDefault, logger)
	if err != nil {
		return err
	}

	var firstErr error
	for _, source := range c.sources {
		mode := source.Mode()
		reqs := byMode[mode]
		res, err := source.Ensure(ctx, reqs)
		if err != nil {
			// The source could not run at all. Leave what it last published in
			// place rather than withdrawing certificates that still work.
			logger.Error("certificate source failed", "mode", mode, "error", err)
			emitCert(emit, notify.EventCertFailed, "",
				string(mode)+" certificates failed: "+err.Error())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, f := range res.Failures {
			logger.Error("cannot obtain a certificate",
				"mode", mode, "service", f.Request.Service,
				"domains", strings.Join(f.Request.Domains, ", "), "error", f.Err)
			emitCert(emit, notify.EventCertFailed, primaryDomain(f.Request.Domains),
				f.Request.Service+": "+f.Err.Error())
			if firstErr == nil {
				firstErr = f.Err
			}
		}
		emitCertChanges(emit, res.Certificates, seen)
		if err := c.publisher.SetCertificates(mode, res.Certificates); err != nil {
			return fmt.Errorf("publish %s certificates: %w", mode, err)
		}
		if len(reqs) > 0 || len(res.Certificates) > 0 {
			logger.Info("certificates published", "mode", mode,
				"certificates", len(res.Certificates), "requested", len(reqs))
		}
	}
	return firstErr
}

// certificateAuthority hands the API a CA source, or an explicit nil.
//
// The explicit nil is the point. A nil *certificates assigned to the interface
// field would be a *non-nil* interface holding a nil pointer, so the API's "is
// one configured" check would answer yes — the trap buildReplication documents
// for api.Backups, and it costs one function to not fall into.
func certificateAuthority(c *certificates) api.CertificateAuthority {
	if c == nil || c.ca == nil {
		return nil
	}
	return c
}

// modeNames lists the certificate sources a flag or a spec may name.
func modeNames() []string {
	out := make([]string, 0, len(certsource.Modes()))
	for _, mode := range certsource.Modes() {
		out = append(out, string(mode))
	}
	return out
}

// primaryDomain is a request's Store key, or "" for a request with no names.
func primaryDomain(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	return domains[0]
}

// acmeSource adapts the ACME manager to the Source seam.
//
// The wildcard collapse lives here rather than in the manager because it is a
// Let's Encrypt rate-limit workaround and not a property of issuance: a CA this
// node owns has no rate limit, so no other source has an equivalent.
type acmeSource struct {
	manager    *acme.Manager
	baseDomain string
	log        *slog.Logger
}

func (a *acmeSource) Mode() certsource.Mode { return certsource.ModeACME }

func (a *acmeSource) Ensure(ctx context.Context, reqs []certsource.Request) (certsource.Result, error) {
	exposures := make([]acme.Exposure, 0, len(reqs))
	for _, req := range reqs {
		exposures = append(exposures, acme.Exposure{
			Service: req.Service,
			Project: req.Project,
			Domains: req.Domains,
			Auto:    req.Auto,
		})
	}
	plan := acme.PlanRequests(exposures, acme.PlanOptions{
		BaseDomain: a.baseDomain,
		Wildcards:  a.manager.SupportsWildcards(),
	})
	if plan.OverThreshold {
		// The condition §7.3 wants said out loud: past this many certificates a
		// node is spending its weekly Let's Encrypt allowance on redeploys, and
		// the fix — a wildcard — needs a DNS-01 solver nobody has configured.
		a.log.Warn("more per-service certificates than Let's Encrypt rate limits are comfortable with",
			"certificates", plan.PerService, "threshold", acme.DefaultWildcardThreshold,
			"detail", "configure --acme-dns-server to switch to per-project wildcards (PRD §7.3)")
	}
	if plan.Wildcard > 0 {
		a.log.Info("issuing per-project wildcards",
			"wildcards", plan.Wildcard, "per_service", plan.PerService)
	}

	certs, err := a.manager.Sync(ctx, plan.Requests)
	if err != nil {
		return certsource.Result{}, err
	}
	return certsource.Result{Certificates: certs}, nil
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

// certRequests reads desired state and groups what needs a certificate by the
// source it asked for (PRD §6.2 R20).
//
// The domains come from the same resolution the route table uses, so a service
// cannot end up with a certificate for a name the edge does not route — which
// would be an issuance that always fails validation.
//
// Every mode gets an entry, including an empty one. A source is called with
// everything it should be holding, and "nothing" is how it learns to let go of
// what it held last pass.
func certRequests(ctx context.Context, st store.Store, baseDomain, nodeDefault string,
	logger *slog.Logger,
) (map[certsource.Mode][]certsource.Request, error) {
	services, err := listAllServices(ctx, st)
	if err != nil {
		return nil, err
	}

	out := map[certsource.Mode][]certsource.Request{}
	for _, mode := range certsource.Modes() {
		out[mode] = nil
	}
	for _, d := range services {
		// One request per route (v1.50): each expose block asks under its own
		// mode, so a service may hold an acme certificate for its public name
		// beside a self-signed one for its LAN name.
		for _, e := range d.AllExposes() {
			mode := certsource.Mode(e.ResolveTLSMode(nodeDefault))
			if mode == "" || mode == certsource.ModePlaintext {
				// Plaintext is a declaration, not a request. There is nothing to
				// obtain, and the edge learns of it from the route table.
				//
				// R28's one warning: a grpc route that *resolved* here (an
				// undeclared mode on a --tls-default plaintext node) can never
				// serve a real gRPC client — the plaintext path is HTTP/1.1. The
				// declared combination is a plan error; this half is a warning
				// because R20 resolves node-side, where plan cannot see.
				if e.Protocol == "grpc" {
					logger.Warn("grpc route resolved to plaintext",
						"service", d.Project+"/"+d.Service,
						"detail", "gRPC clients need TLS+HTTP/2 on :443; declare tls { mode } or change --tls-default")
				}
				continue
			}
			if !mode.Valid() {
				// R20 refuses this at plan time, so reaching here means a record
				// written by a newer CLI or edited by hand. Serving plaintext and
				// saying so beats guessing which source was meant.
				logger.Error("service asks for an unknown TLS mode",
					"service", d.Project+"/"+d.Service, "mode", mode,
					"detail", "it is reachable over HTTP only until this is corrected")
				continue
			}
			domains := reconciler.EdgeDomainsFor(d, e, baseDomain)
			if len(domains) == 0 {
				if e != d.Expose {
					continue // R16 refuses a nameless extra block at plan
				}
				logger.Warn("service asks for a certificate but has no domain",
					"service", d.Project+"/"+d.Service, "mode", mode,
					"detail", "declare expose.domains, or set --base-domain")
				continue
			}
			out[mode] = append(out[mode], certsource.Request{
				Domains: domains,
				Service: d.Project + "/" + d.Service,
				Project: d.Project,
				// A declared domain is somebody else's zone; only the generated
				// names of §7.2 can be collapsed into a wildcard.
				Auto: len(e.Domains) == 0,
				Name: e.TLSName,
			})
		}
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

// The ACME directory aliases an operator writes.
//
// v1.32 defaulted --acme-directory to Let's Encrypt *staging*, so a node that
// was configured entirely correctly served certificates every browser rejects.
// Staging existed to absorb a first-attempt misconfiguration, and
// `--tls-default self-signed` absorbs it better: a certificate that actually
// works once the CA is installed, rather than one that never will.
const (
	DirectoryProduction = "production"
	DirectoryStaging    = "staging"
)

// resolveDirectory turns an alias into a directory URL. Anything else is passed
// through, so a private or test CA is still just a URL.
func resolveDirectory(directory string) string {
	switch directory {
	case DirectoryProduction:
		return acme.LetsEncryptProduction
	case DirectoryStaging:
		return acme.LetsEncryptStaging
	default:
		return directory
	}
}

// certificates is the certificate subsystem: the sources and the one file they
// publish through (PRD §7.3).
type certificates struct {
	sources   []certsource.Source
	publisher *certsource.Publisher
	// ca is the self-signed source, when one is configured. Held separately
	// because `kanea ca show` needs it and the Source seam has no verb for it.
	ca *certsource.SelfSigned
	// provided is the operator's own certificates. Also held separately: it is
	// the only source whose material can change while kanead is not looking,
	// so the loop has to be able to ask it whether anything moved.
	provided *certsource.Provided
}

// CACertificate implements api.CertificateAuthority.
//
// Nil-safe on the field, not on the receiver: a node with no self-signed source
// answers ErrNoCA rather than panicking, and the route turns that into a 404
// that says which mode would have created one.
func (c *certificates) CACertificate(ctx context.Context) ([]byte, error) {
	if c == nil || c.ca == nil {
		return nil, certsource.ErrNoCA
	}
	return c.ca.CACertificate(ctx)
}

// certConfig is everything the certificate subsystem is wired from.
//
// A struct rather than a positional argument list: this used to take ten
// parameters of which six were strings, and adding a source to it means adding
// fields that a caller must not be able to transpose.
type certConfig struct {
	// Email enables ACME. Empty means no ACME at all, which is legitimate.
	Email string
	// Directory is the ACME directory URL.
	Directory string
	// CAPath is a PEM bundle for the ACME server's own certificate, for a
	// private CA in testing.
	CAPath string
	// BundlePath is the projection the edge reads (edge.DefaultBundlePath).
	BundlePath string
	// Group is the edge's group, which the bundle is made readable by.
	Group string
	// VerifyURL is where kanead reaches its own edge to confirm a challenge is
	// being served.
	VerifyURL string
	// BaseDomain is what auto-FQDNs are generated under, and what names the CA
	// when --tls-ca-name is empty.
	BaseDomain string
	// Default is the mode an exposed service gets when its spec declares none
	// (R20). It decides which sources are worth building.
	Default string
	// CAName identifies the self-signed CA in a device's trust list.
	CAName string
	// CertsConfig is the grant file for operator-provided certificates
	// (--tls-certs-config). Empty means the feature does not exist, which is
	// the default.
	CertsConfig string

	DNSSolver acme.DNSSolver
	Store     store.Store
	Logger    *slog.Logger
}

// buildCertificates wires the certificate sources, or returns nil when none of
// them can do anything.
//
// Nothing configured is a legitimate state, not an error: a node serving
// plaintext behind someone else's TLS terminator, or one still being set up,
// should start and work. What it must not do is start *and look configured*, so
// the reason is logged rather than left to be inferred from an absence.
func buildCertificates(cfg certConfig) (*certificates, error) {
	// Refused at startup rather than resolved to something. A typo here would
	// otherwise apply to every service that declares no tls block, and the
	// symptom — plain HTTP everywhere — looks like a DNS problem.
	if !certsource.Mode(cfg.Default).Valid() {
		return nil, fmt.Errorf("--tls-default %q: use one of %s",
			cfg.Default, strings.Join(modeNames(), ", "))
	}

	wantACME := cfg.Email != ""
	// The self-signed source is built whenever a spec could ask for it, which
	// is either explicitly or through the node default. Building it costs
	// nothing until something is issued: the CA is generated on first use, not
	// here (§7.3).
	wantSelfSigned := true

	if !wantACME {
		detail := "exposed services are reachable over HTTP only"
		if cfg.Default == string(certsource.ModeSelfSigned) {
			detail = "services default to self-signed certificates (--tls-default)"
		}
		cfg.Logger.Warn("no --acme-email: no certificates will be obtained from a CA", "detail", detail)
	}
	if cfg.Default == string(certsource.ModeACME) && !wantACME {
		// The commonest misconfiguration: the default asks for ACME and no
		// account exists, so every exposed service silently serves plaintext.
		cfg.Logger.Warn("--tls-default is acme but no --acme-email is set",
			"detail", "every exposed service that does not declare expose.tls will serve plain HTTP")
	}

	gid, err := lookupGID(cfg.Group)
	if err != nil {
		return nil, err
	}
	if gid == 0 {
		cfg.Logger.Warn("no --edge-group: the certificate bundle is readable only by this user",
			"detail", "an edge running as another user will not be able to serve TLS")
	}

	publisher, err := certsource.NewPublisher(certsource.PublisherConfig{
		Path:      cfg.BundlePath,
		GID:       gid,
		VerifyURL: cfg.VerifyURL,
		Logger:    cfg.Logger,
	})
	if err != nil {
		return nil, err
	}

	out := &certificates{publisher: publisher}

	if wantACME {
		caBundle, err := readCABundle(cfg.CAPath)
		if err != nil {
			return nil, err
		}
		directory := resolveDirectory(cfg.Directory)
		if directory == acme.LetsEncryptStaging {
			cfg.Logger.Warn("using the Let's Encrypt staging CA",
				"detail", "its certificates are not publicly trusted; "+
					"for a certificate that works without a public name, use --tls-default self-signed")
		}
		manager, err := acme.New(acme.Config{
			Directory:    directory,
			Email:        cfg.Email,
			Store:        certStoreAdapter{store: cfg.Store},
			Solver:       publisher,
			DNSSolver:    cfg.DNSSolver,
			Logger:       cfg.Logger,
			HTTPClientCA: caBundle,
		})
		if err != nil {
			return nil, err
		}
		out.sources = append(out.sources, &acmeSource{
			manager: manager, baseDomain: cfg.BaseDomain, log: cfg.Logger,
		})
		cfg.Logger.Info("ACME enabled", "email", cfg.Email, "directory", directory,
			"bundle", cfg.BundlePath, "dns01", cfg.DNSSolver != nil)
	}

	provided := certsource.NewProvided(cfg.CertsConfig, cfg.Logger)
	out.provided = provided
	out.sources = append(out.sources, provided)
	switch {
	case provided.Configured():
		cfg.Logger.Info("operator-provided certificates enabled", "config", cfg.CertsConfig)
	case cfg.Default == string(certsource.ModeProvided):
		// The same shape of warning as --tls-default acme with no email: the
		// default asks for a source that cannot produce anything, and the
		// symptom is plain HTTP on every service that declares no tls block.
		cfg.Logger.Warn("--tls-default is provided but no --tls-certs-config is set",
			"detail", "every exposed service that does not declare expose.tls will serve plain HTTP")
	}

	if wantSelfSigned {
		selfSigned, err := certsource.NewSelfSigned(certsource.SelfSignedConfig{
			Store:  certStoreAdapter{store: cfg.Store},
			Name:   caName(cfg),
			Logger: cfg.Logger,
		})
		if err != nil {
			return nil, err
		}
		out.ca = selfSigned
		out.sources = append(out.sources, selfSigned)
	}

	return out, nil
}

// caName is what the self-signed CA is called in a device's trust list.
//
// The operator's own name, else the base domain, else this host — it has to be
// recognisable a year later, when the only context is a list of certificate
// authorities on a phone.
func caName(cfg certConfig) string {
	if cfg.CAName != "" {
		return cfg.CAName
	}
	if cfg.BaseDomain != "" {
		return cfg.BaseDomain
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return ""
}
