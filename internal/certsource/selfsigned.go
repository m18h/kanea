package certsource

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// SelfSigned issues certificates from a CA this node generated (PRD §7.3).
//
// It exists for the install with no public name: a LAN with wildcard DNS, no
// inbound port 80 for HTTP-01 and no provider credential for DNS-01. The
// operator installs one CA certificate on their devices and every service on
// the node is trusted, which is a working answer where ACME has none.
type SelfSigned struct {
	store Store
	name  string
	log   *slog.Logger
	now   func() time.Time

	mu sync.Mutex
	ca *authority
}

// CAStoreKey is where this node's own CA lives.
//
// In the certs bucket beside the ACME account key, so it travels in the
// encrypted archive and is restored with everything else — no separate backup
// path, no restore ordering, no second permission story (§15.3).
const CAStoreKey = "ca/self-signed"

// selfSignedPrefix namespaces the leaves this source issues.
//
// Beside internal/acme's "cert/" prefix, deliberately never under it: that
// package lists "cert/" to find what it must renew, and would otherwise pick up
// certificates it did not issue and cannot reissue.
const selfSignedPrefix = "selfsigned/"

// CAValidity is how long the CA certificate lasts.
//
// Ten years, because renewing it means reinstalling it on every phone, laptop
// and television in the house. A certificate whose renewal is a manual chore
// across a household does not get to expire on a schedule nobody wrote down.
const CAValidity = 10 * 365 * 24 * time.Hour

// LeafValidity is how long an issued certificate lasts.
//
// Deliberately Let's Encrypt's ninety days rather than the decade we could
// mint: with RenewalFraction that puts renewal at day sixty, so the ordinary
// renewal pass runs this code every two months instead of once a decade. A bug
// in a path exercised twice a year is found while it is still cheap.
const LeafValidity = 90 * 24 * time.Hour

// clockSkewAllowance backdates NotBefore.
//
// A device whose clock is four minutes fast rejects a certificate minted this
// second, and that presents to its owner as "your CA is broken" rather than as
// a clock problem.
const clockSkewAllowance = 5 * time.Minute

// ErrNoCA marks a node that has never issued a self-signed certificate.
var ErrNoCA = errors.New("certsource: this node has no self-signed CA")

// SelfSignedConfig configures the source.
type SelfSignedConfig struct {
	Store Store
	// Name identifies the CA in a device's trust list a year from now. The
	// caller passes --tls-ca-name, else the base domain, else the hostname.
	Name   string
	Logger *slog.Logger
	// Now is injectable so renewal can be tested without waiting sixty days.
	Now func() time.Time
}

// NewSelfSigned builds the source.
func NewSelfSigned(cfg SelfSignedConfig) (*SelfSigned, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: a store is required for self-signed certificates", ErrNotConfigured)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Name == "" {
		cfg.Name = "this node"
	}
	return &SelfSigned{store: cfg.Store, name: cfg.Name, log: cfg.Logger, now: cfg.Now}, nil
}

// Mode identifies this source.
func (s *SelfSigned) Mode() Mode { return ModeSelfSigned }

// Ensure issues what is missing and renews what is due.
//
// The shape is acme.Sync's: load once, keep what still covers its request and
// is not due, mint the rest — and one failure never suppresses the others.
func (s *SelfSigned) Ensure(ctx context.Context, reqs []Request) (Result, error) {
	held, err := s.load(ctx)
	if err != nil {
		return Result{}, err
	}

	var out Result
	now := s.now()
	for _, req := range reqs {
		if len(req.Domains) == 0 {
			continue
		}
		if cert, ok := held[req.Domains[0]]; ok && cert.Covers(req.Domains) && !cert.NeedsRenewal(now) {
			out.Certificates = append(out.Certificates, cert)
			continue
		}
		cert, err := s.issue(ctx, req.Domains, now)
		if err != nil {
			out.Failures = append(out.Failures, Failure{Request: req, Err: err})
			s.log.Error("cannot issue a self-signed certificate",
				"service", req.Service, "domains", strings.Join(req.Domains, ", "), "error", err)
			continue
		}
		out.Certificates = append(out.Certificates, cert)
		s.log.Info("self-signed certificate issued",
			"service", req.Service, "domains", strings.Join(req.Domains, ", "),
			"not_after", cert.NotAfter.Format(time.DateOnly))
	}
	return out, nil
}

// CACertificate returns the CA certificate PEM.
//
// It does not generate one. A GET must not mutate state, and a CA that exists
// because somebody looked is a CA nobody decided to have — generation belongs
// in Ensure, where an actual service asked to be served. Until then this is
// ErrNoCA, and the API turns that into a 404 that says why.
func (s *SelfSigned) CACertificate(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ca, err := s.loadCA(ctx)
	if err != nil {
		return nil, err
	}
	if ca == nil {
		return nil, ErrNoCA
	}
	return []byte(ca.CertPEM), nil
}

// authority is the stored CA: its certificate and its key.
type authority struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`

	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// load reads the leaves this source has already issued.
func (s *SelfSigned) load(ctx context.Context) (map[string]Certificate, error) {
	raw, err := s.store.List(ctx, selfSignedPrefix)
	if err != nil {
		return nil, fmt.Errorf("list self-signed certificates: %w", err)
	}
	out := make(map[string]Certificate, len(raw))
	for key, body := range raw {
		var cert Certificate
		if err := json.Unmarshal(body, &cert); err != nil {
			// One unreadable record must not stop the others from renewing.
			// It will be reissued, which is the repair.
			s.log.Warn("ignoring an unreadable self-signed certificate", "key", key, "error", err)
			continue
		}
		if cert.Key() != "" {
			out[cert.Key()] = cert
		}
	}
	return out, nil
}

// issue mints a leaf for these names and stores it.
func (s *SelfSigned) issue(ctx context.Context, domains []string, now time.Time) (Certificate, error) {
	s.mu.Lock()
	ca, err := s.ensureCA(ctx, now)
	s.mu.Unlock()
	if err != nil {
		return Certificate{}, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Certificate{}, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Certificate{}, err
	}

	notBefore := now.Add(-clockSkewAllowance)
	notAfter := now.Add(LeafValidity)
	// A requested name that parses as an IP becomes an IP SAN, not a DNS SAN —
	// clients match the two differently, and a dashboard reached at a bare
	// address needs the former (PRD v1.61, bind.api_tls). Service domains are
	// DNS-1123 by construction and never take this branch.
	var dnsNames []string
	var ipAddrs []net.IP
	for _, d := range domains {
		if ip := net.ParseIP(d); ip != nil {
			ipAddrs = append(ipAddrs, ip)
			continue
		}
		dnsNames = append(dnsNames, d)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domains[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return Certificate{}, fmt.Errorf("sign leaf: %w", err)
	}
	keyPEM, err := encodeECKey(key)
	if err != nil {
		return Certificate{}, err
	}

	cert := Certificate{
		Domains: domains,
		// The leaf alone. A client that has the CA installed does not need it
		// sent, and one that has not is not helped by receiving it.
		CertPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:    keyPEM,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		IssuedAt:  now,
	}
	body, err := json.Marshal(cert)
	if err != nil {
		return Certificate{}, fmt.Errorf("encode certificate: %w", err)
	}
	if err := s.store.Put(ctx, selfSignedPrefix+cert.Key(), body); err != nil {
		return Certificate{}, fmt.Errorf("store certificate: %w", err)
	}
	return cert, nil
}

// ensureCA returns the node's CA, generating it once if it does not exist.
// The caller holds the lock.
func (s *SelfSigned) ensureCA(ctx context.Context, now time.Time) (*authority, error) {
	ca, err := s.loadCA(ctx)
	if err != nil {
		return nil, err
	}
	if ca != nil {
		return ca, nil
	}
	return s.generateCA(ctx, now)
}

// loadCA reads the CA from the store, or returns nil if there is none.
// The caller holds the lock.
func (s *SelfSigned) loadCA(ctx context.Context) (*authority, error) {
	if s.ca != nil {
		return s.ca, nil
	}
	body, found, err := s.store.Get(ctx, CAStoreKey)
	if err != nil {
		return nil, fmt.Errorf("read the self-signed CA: %w", err)
	}
	if !found {
		return nil, nil
	}
	var stored authority
	if err := json.Unmarshal(body, &stored); err != nil {
		return nil, fmt.Errorf("decode the self-signed CA: %w", err)
	}
	if err := stored.parse(); err != nil {
		return nil, err
	}
	s.ca = &stored
	return s.ca, nil
}

// generateCA mints this node's CA. The caller holds the lock.
func (s *SelfSigned) generateCA(ctx context.Context, now time.Time) (*authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	// The subject key identifier is the SPKI hash, which is what a device's
	// trust UI shows beside the name.
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal CA public key: %w", err)
	}
	sum := sha256.Sum256(spki)

	template := &x509.Certificate{
		SerialNumber: serial,
		// Identifiable in a phone's trust list a year from now, which is the
		// only interface this name has.
		Subject:               pkix.Name{CommonName: "Kanea local CA (" + s.name + ")"},
		NotBefore:             now.Add(-clockSkewAllowance),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		// It signs leaves and nothing else: no intermediate under it.
		MaxPathLenZero: true,
		SubjectKeyId:   sum[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign the CA: %w", err)
	}
	keyPEM, err := encodeECKey(key)
	if err != nil {
		return nil, err
	}

	ca := &authority{
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:  keyPEM,
	}
	body, err := json.Marshal(ca)
	if err != nil {
		return nil, fmt.Errorf("encode the self-signed CA: %w", err)
	}
	if err := s.store.Put(ctx, CAStoreKey, body); err != nil {
		return nil, fmt.Errorf("store the self-signed CA: %w", err)
	}
	if err := ca.parse(); err != nil {
		return nil, err
	}
	s.ca = ca
	s.log.Warn("generated this node's self-signed CA",
		"subject", template.Subject.CommonName,
		"not_after", template.NotAfter.Format(time.DateOnly),
		"detail", "run `kanea ca show` and install it on the devices that will reach these services")
	return ca, nil
}

// parse decodes the stored PEM into the forms signing needs.
func (a *authority) parse() error {
	block, _ := pem.Decode([]byte(a.CertPEM))
	if block == nil {
		return fmt.Errorf("%w: the stored CA certificate is not PEM", ErrNoCA)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse the stored CA certificate: %w", err)
	}
	keyBlock, _ := pem.Decode([]byte(a.KeyPEM))
	if keyBlock == nil {
		return fmt.Errorf("%w: the stored CA key is not PEM", ErrNoCA)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse the stored CA key: %w", err)
	}
	a.cert, a.key = cert, key
	return nil
}

// randomSerial draws a 128-bit certificate serial.
func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

// encodeECKey renders a private key as PEM.
func encodeECKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

// CAInfo describes the CA for `kanea ca info`.
type CAInfo struct {
	Subject     string    `json:"subject"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
}

// DescribeCA summarises a CA certificate PEM.
//
// The fingerprint is SHA-256, colon-separated and upper case, because that is
// the form a device's trust dialog displays and comparing the two by eye is the
// only verification an operator can actually perform.
func DescribeCA(certPEM []byte) (CAInfo, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return CAInfo{}, fmt.Errorf("%w: not PEM", ErrNoCA)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CAInfo{}, fmt.Errorf("parse CA certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, 0, len(sum))
	for _, b := range sum {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return CAInfo{
		Subject:     cert.Subject.CommonName,
		Fingerprint: strings.Join(parts, ":"),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
	}, nil
}
