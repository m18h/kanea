// Package acme obtains and renews the TLS certificates kanea-edge serves
// (PRD §7.3).
//
// It runs in kanead, never in the edge. Issuance means writing — an account
// key, a certificate, a renewal timestamp — and not writing is the whole
// property that lets the edge run unprivileged with no Store handle (§5.2.6).
// The edge's part is to present what it is handed: this package publishes the
// HTTP-01 response through the same projection the certificates travel in, and
// waits for the edge to actually serve it before asking the CA to look.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/m18h/kanea/internal/certsource"
)

// LetsEncryptProduction and LetsEncryptStaging are the well-known directories.
//
// Staging is not just for CI: its rate limits are far looser, and an operator
// setting Kanea up for the first time will get the DNS wrong at least once
// (PRD §7.3).
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// RenewalFraction is how far into a certificate's life renewal starts, as a
// fraction of its total validity (PRD §7.3: two thirds). For a 90-day Let's
// Encrypt certificate that is day 60, leaving a month of retries before
// anything actually expires.
//
// Deprecated: use certsource.RenewalFraction. Renewal is a property of a
// certificate, not of the CA that signed one.
const RenewalFraction = certsource.RenewalFraction

// Certificate is one issued certificate as Kanea stores it.
//
// The type lives in internal/certsource because expiry, coverage and renewal
// are properties of a certificate rather than of ACME — a self-signed leaf has
// all three and never speaks to a CA. It is aliased here because this package
// stores and returns them, and because an ACME certificate is still a
// certificate.
type Certificate = certsource.Certificate

// Request asks for a certificate covering a set of names.
type Request struct {
	// Domains, lowercased and sorted. The first is the primary and becomes the
	// Store key.
	Domains []string
	// Service is who asked, for logs and events.
	Service string
}

// Solver publishes an HTTP-01 response and confirms it is being served.
//
// The confirmation is the important half. Publishing is asynchronous — the edge
// polls a file — so telling the CA to validate immediately after writing is a
// race, and losing it costs a failed-validation slot that takes an hour to
// clear (PRD §7.3).
type Solver interface {
	// Present publishes the response and returns once the edge is serving it.
	Present(ctx context.Context, domain, token, keyAuth string) error
	// CleanUp withdraws it.
	CleanUp(ctx context.Context, domain, token, keyAuth string) error
}

// Store is the slice of the state store this package needs.
type Store interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Put(ctx context.Context, key string, value []byte) error
	List(ctx context.Context, prefix string) (map[string][]byte, error)
}

// Config configures a Manager.
type Config struct {
	// Directory is the ACME directory URL. Empty means Let's Encrypt staging,
	// which is the safe default: an operator who has not chosen deliberately
	// should not be spending production rate limit.
	Directory string
	// Email is the ACME account contact. Required.
	Email string
	// Store persists the account key and the issued certificates.
	Store Store
	// Solver answers HTTP-01 challenges. Optional when DNSSolver is set.
	Solver Solver
	// DNSSolver answers DNS-01 challenges. Required for a wildcard, which
	// HTTP-01 cannot validate: there is no single host a wildcard resolves to.
	DNSSolver DNSSolver
	// Logger receives progress and failures.
	Logger *slog.Logger
	// Now is injectable for tests.
	Now func() time.Time
	// HTTPClientCA is an optional PEM bundle trusted when talking to the ACME
	// directory. It exists for test CAs (Pebble) and private ACME servers; it
	// is not a way to relax verification.
	HTTPClientCA []byte
}

// Manager issues and renews certificates.
type Manager struct {
	directory string
	email     string
	store     Store
	solver    Solver
	dnsSolver DNSSolver
	log       *slog.Logger
	now       func() time.Time
	caBundle  []byte
}

// ErrNotConfigured marks a manager that cannot issue anything.
var ErrNotConfigured = errors.New("acme: not configured")

// New builds a Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.Email == "" {
		return nil, fmt.Errorf("%w: an account email is required", ErrNotConfigured)
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: a store is required", ErrNotConfigured)
	}
	if cfg.Solver == nil && cfg.DNSSolver == nil {
		return nil, fmt.Errorf("%w: a challenge solver is required", ErrNotConfigured)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Directory == "" {
		cfg.Directory = LetsEncryptStaging
		cfg.Logger.Warn("no ACME directory configured; using the Let's Encrypt staging CA",
			"detail", "certificates will not be publicly trusted; set --acme-directory to go live")
	}
	return &Manager{
		directory: cfg.Directory,
		email:     cfg.Email,
		store:     cfg.Store,
		solver:    cfg.Solver,
		dnsSolver: cfg.DNSSolver,
		log:       cfg.Logger,
		now:       cfg.Now,
		caBundle:  cfg.HTTPClientCA,
	}, nil
}

// certKeyPrefix namespaces issued certificates in the store.
const certKeyPrefix = "cert/"

// Sync makes the stored certificates match the requests: issues what is
// missing, renews what is due, and returns everything currently valid.
//
// One request failing does not stop the others. A single misconfigured domain —
// DNS not pointed at this node yet is the common one — must not block renewal
// of every certificate that is working.
func (m *Manager) Sync(ctx context.Context, requests []Request) ([]Certificate, error) {
	existing, err := m.load(ctx)
	if err != nil {
		return nil, err
	}
	now := m.now()

	var out []Certificate
	wanted := map[string]bool{}

	for _, req := range requests {
		if len(req.Domains) == 0 {
			continue
		}
		key := req.Domains[0]
		wanted[key] = true

		current, have := existing[key]
		switch {
		case have && current.Covers(req.Domains) && !current.NeedsRenewal(now):
			out = append(out, current)
			continue
		case have && current.Covers(req.Domains):
			m.log.Info("certificate is due for renewal",
				"service", req.Service, "domains", req.Domains,
				"not_after", current.NotAfter, "renew_after", current.RenewAfter())
		case have:
			m.log.Info("certificate no longer matches the requested names",
				"service", req.Service, "have", current.Domains, "want", req.Domains)
		default:
			m.log.Info("requesting a certificate", "service", req.Service, "domains", req.Domains)
		}

		issued, err := m.obtain(ctx, req)
		if err != nil {
			m.log.Error("certificate issuance failed",
				"service", req.Service, "domains", req.Domains, "error", err)
			// Keep serving what we have. An expiring certificate is better than
			// no certificate, and the next pass retries.
			if have {
				out = append(out, current)
			}
			continue
		}
		if err := m.save(ctx, issued); err != nil {
			m.log.Error("cannot persist certificate",
				"service", req.Service, "domains", req.Domains, "error", err)
			// It exists at the CA either way, so serve it rather than reissue
			// on the next pass and spend the rate limit twice.
		}
		out = append(out, issued)
	}

	// Certificates for services that no longer exist are kept, not deleted.
	// Reissuing after a service is briefly removed and restored would spend a
	// duplicate-certificate slot, and an unused certificate costs nothing but
	// a few kilobytes until it expires.
	for key, cert := range existing {
		if !wanted[key] && !cert.NotAfter.Before(now) {
			m.log.Debug("keeping a certificate no service currently claims",
				"domains", cert.Domains, "not_after", cert.NotAfter)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

// obtain runs one issuance.
func (m *Manager) obtain(ctx context.Context, req Request) (Certificate, error) {
	client, err := m.client(ctx)
	if err != nil {
		return Certificate{}, err
	}
	if err := m.installSolver(ctx, client, req); err != nil {
		return Certificate{}, err
	}

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: req.Domains,
		Bundle:  true, // leaf + intermediates, which is what a server must send
	})
	if err != nil {
		return Certificate{}, fmt.Errorf("obtain %s: %w", strings.Join(req.Domains, ", "), err)
	}

	leaf, err := leafOf(res.Certificate)
	if err != nil {
		return Certificate{}, err
	}
	return Certificate{
		Domains:   req.Domains,
		CertPEM:   string(res.Certificate),
		KeyPEM:    string(res.PrivateKey),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		IssuedAt:  m.now(),
	}, nil
}

// SupportsWildcards reports whether this manager can issue one.
func (m *Manager) SupportsWildcards() bool { return m.dnsSolver != nil }

// installSolver picks the challenge for a request.
//
// A wildcard forces DNS-01: there is no host for HTTP-01 to reach, because the
// name matches hosts that do not exist yet. Everything else prefers HTTP-01 —
// it needs no credential, it validates in seconds rather than waiting on DNS
// propagation, and it fails in ways an operator can see from the edge's logs.
// Only one provider is installed per issuance, so which challenge was used is a
// decision made here rather than whichever one the CA happened to offer first.
func (m *Manager) installSolver(ctx context.Context, client *lego.Client, req Request) error {
	if requiresDNS(req.Domains) {
		if m.dnsSolver == nil {
			return fmt.Errorf("%w: %s needs a DNS-01 solver (a wildcard cannot be validated over HTTP)",
				ErrNotConfigured, strings.Join(req.Domains, ", "))
		}
		if err := client.Challenge.SetDNS01Provider(m.dnsSolver); err != nil {
			return fmt.Errorf("install dns-01 solver: %w", err)
		}
		return nil
	}
	if m.solver != nil {
		if err := client.Challenge.SetHTTP01Provider(&legoSolver{ctx: ctx, solver: m.solver}); err != nil {
			return fmt.Errorf("install http-01 solver: %w", err)
		}
		return nil
	}
	if err := client.Challenge.SetDNS01Provider(m.dnsSolver); err != nil {
		return fmt.Errorf("install dns-01 solver: %w", err)
	}
	return nil
}

// requiresDNS reports whether any name in a request is a wildcard.
func requiresDNS(domains []string) bool {
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			return true
		}
	}
	return false
}

// leafOf decodes the first certificate in a PEM chain.
func leafOf(chain []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(chain)
	if block == nil {
		return nil, errors.New("acme: issued chain is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("acme: parse issued leaf: %w", err)
	}
	return leaf, nil
}

// legoSolver adapts Kanea's Solver to lego's provider interface.
//
// lego's interface has no context, so the one from the issuing call is carried
// on the struct. That is normally a smell; here it is the only way to make a
// challenge that publishes through a file and waits for another process
// cancellable at all.
type legoSolver struct {
	ctx    context.Context
	solver Solver
}

func (s *legoSolver) Present(domain, token, keyAuth string) error {
	return s.solver.Present(s.ctx, domain, token, keyAuth)
}

func (s *legoSolver) CleanUp(domain, token, keyAuth string) error {
	return s.solver.CleanUp(s.ctx, domain, token, keyAuth)
}

// ---- store ----

func (m *Manager) load(ctx context.Context) (map[string]Certificate, error) {
	raw, err := m.store.List(ctx, certKeyPrefix)
	if err != nil {
		return nil, fmt.Errorf("acme: load certificates: %w", err)
	}
	out := make(map[string]Certificate, len(raw))
	for key, body := range raw {
		var cert Certificate
		if err := decode(body, &cert); err != nil {
			// One unreadable record must not stop every renewal. It will be
			// overwritten by the next issuance for that name.
			m.log.Error("cannot decode stored certificate", "key", key, "error", err)
			continue
		}
		out[cert.Key()] = cert
	}
	return out, nil
}

func (m *Manager) save(ctx context.Context, cert Certificate) error {
	body, err := encode(cert)
	if err != nil {
		return err
	}
	return m.store.Put(ctx, certKeyPrefix+cert.Key(), body)
}

// ---- account ----

// accountKeyStoreKey is where the ACME account key lives.
//
// One account per node, not per certificate: the account is the identity the CA
// rate-limits and the thing that would have to be re-registered after a restore.
const accountKeyStoreKey = "account/key"

// user is lego's view of the ACME account.
type user struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *user) GetEmail() string                        { return u.email }
func (u *user) GetRegistration() *registration.Resource { return u.registration }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

// client builds a registered lego client.
func (m *Manager) client(ctx context.Context) (*lego.Client, error) {
	key, err := m.accountKey(ctx)
	if err != nil {
		return nil, err
	}
	account := &user{email: m.email, key: key}

	cfg := lego.NewConfig(account)
	cfg.CADirURL = m.directory
	cfg.Certificate.KeyType = certcrypto.EC256
	if len(m.caBundle) > 0 {
		client, err := caTrustingClient(m.caBundle)
		if err != nil {
			return nil, err
		}
		cfg.HTTPClient = client
	}

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("acme: client: %w", err)
	}

	// Registration is idempotent at the CA: registering an existing account key
	// returns the existing account. So this runs on every issuance rather than
	// being cached, which also means a restored node re-attaches to its account
	// without a separate recovery step.
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("acme: register account %s: %w", m.email, err)
	}
	account.registration = reg
	return client, nil
}

// accountKey loads the account key, generating one on first use.
func (m *Manager) accountKey(ctx context.Context) (crypto.PrivateKey, error) {
	body, found, err := m.store.Get(ctx, accountKeyStoreKey)
	if err != nil {
		return nil, fmt.Errorf("acme: read account key: %w", err)
	}
	if found {
		var pemText string
		if err := decode(body, &pemText); err != nil {
			return nil, fmt.Errorf("acme: decode account key: %w", err)
		}
		return parseECKey(pemText)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("acme: generate account key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("acme: marshal account key: %w", err)
	}
	text := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	stored, err := encode(text)
	if err != nil {
		return nil, err
	}
	if err := m.store.Put(ctx, accountKeyStoreKey, stored); err != nil {
		// Continuing with an unsaved key would register a second account at the
		// CA on the next start, and accounts are what rate limits attach to.
		return nil, fmt.Errorf("acme: persist account key: %w", err)
	}
	m.log.Info("generated a new ACME account key", "email", m.email, "directory", m.directory)
	return key, nil
}

func parseECKey(text string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("acme: stored account key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("acme: parse account key: %w", err)
	}
	return key, nil
}
