package certsource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/m18h/kanea/internal/edge"
)

// ErrNotConfigured marks a publisher that cannot be built.
var ErrNotConfigured = errors.New("certsource: not configured")

// Publisher owns the edge's certificate projection: it is the only writer.
//
// It holds every source's certificates and any in-flight HTTP-01 responses,
// because they share one file: a challenge appearing must not drop the
// certificates already being served, and neither must one source publishing.
type Publisher struct {
	path     string
	gid      int
	log      *slog.Logger
	verifier *challengeVerifier

	mu sync.Mutex
	// bySource is each source's current contribution, keyed by mode.
	//
	// Per source, not one flat list. Three sources publish into this file on
	// their own schedules (ACME twice a day, a file-backed source every
	// minute) and any one of them writing the whole set would drop the other
	// two. That bug is the reason this map exists.
	bySource   map[Mode][]Certificate
	challenges map[string]string
	// auth is the R27 verifier material (v1.40): the fourth contribution to
	// the restricted bundle, replaced wholesale by its one writer (the
	// reconciler's projection) the way each certificate source replaces its
	// own slice.
	auth  []edge.AuthEntry
	index uint64
	// last is the bytes of the most recent bundle with its index zeroed, so an
	// unchanged set can be recognised. See write.
	last []byte
}

// mergeOrder is the precedence when two sources hold a certificate for one name.
//
// An operator who put a certificate on this node meant it; a publicly trusted
// certificate beats one only this node's devices trust; self-signed is the
// floor. Collisions are rare by construction (a domain belongs to one service
// (R16) and a service names one mode) so they arrive only through wildcards,
// and the rule exists to be deterministic rather than to be busy.
var mergeOrder = []Mode{ModeSelfSigned, ModeACME, ModeProvided}

// PublisherConfig configures the bundle writer.
type PublisherConfig struct {
	// Path is the bundle file (see edge.DefaultBundlePath).
	Path string
	// GID is the group allowed to read it: the edge user's. Zero makes the
	// file owner-only, which is right when kanead and the edge run as the same
	// user and refuses to hand keys to anyone else when they do not.
	GID int
	// VerifyURL is where kanead reaches its own edge to confirm a challenge is
	// being served. Empty disables the check, which is only safe in tests.
	VerifyURL string
	// VerifyTimeout bounds that confirmation.
	VerifyTimeout time.Duration
	Logger        *slog.Logger
}

// DefaultVerifyURL is the edge's plaintext listener as seen from this node.
const DefaultVerifyURL = "http://127.0.0.1:80"

// DefaultVerifyTimeout bounds the wait for the edge to pick up a challenge.
// Comfortably more than the edge's poll interval, because losing this race
// costs a failed-validation slot at the CA.
const DefaultVerifyTimeout = 30 * time.Second

// NewPublisher builds the bundle writer.
func NewPublisher(cfg PublisherConfig) (*Publisher, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("%w: no certificate bundle path", ErrNotConfigured)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.VerifyTimeout <= 0 {
		cfg.VerifyTimeout = DefaultVerifyTimeout
	}

	p := &Publisher{
		path:       cfg.Path,
		gid:        cfg.GID,
		log:        cfg.Logger,
		bySource:   map[Mode][]Certificate{},
		challenges: map[string]string{},
	}
	if cfg.VerifyURL != "" {
		p.verifier = &challengeVerifier{
			base:    strings.TrimSuffix(cfg.VerifyURL, "/"),
			timeout: cfg.VerifyTimeout,
			log:     cfg.Logger,
		}
	} else {
		cfg.Logger.Warn("ACME challenge self-check is disabled",
			"detail", "a validation may be attempted before the edge is serving the response")
	}
	return p, nil
}

// SetCertificates replaces one source's contribution and republishes.
//
// Per source, never wholesale. A source is called on every pass with everything
// it should be holding, including nothing, so replacing its slice is correct:
// but replacing the *file's* contents from one source would drop the others.
func (p *Publisher) SetCertificates(mode Mode, certs []Certificate) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(certs) == 0 {
		delete(p.bySource, mode)
	} else {
		p.bySource[mode] = append([]Certificate(nil), certs...)
	}
	return p.write()
}

// SetAuth replaces the R27 verifier material and republishes (v1.40).
//
// One writer, wholesale: unlike certificates there is no second source to
// merge with (the reconciler's projection is the only thing that resolves
// the spec's references) so the certificate sources' per-mode discipline
// would be ceremony here. The index still bumps only on a byte change, which
// is what keeps a steady-state reconcile pass from reloading the edge.
func (p *Publisher) SetAuth(entries []edge.AuthEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.auth = append([]edge.AuthEntry(nil), entries...)
	return p.write()
}

// Present publishes an HTTP-01 response and waits for the edge to serve it.
//
// The wait is the point. Publishing is a file write the edge polls for, so
// returning as soon as it is written and letting lego tell the CA to validate
// is a race, and losing it does not merely retry, it spends a
// failed-validation slot that takes an hour to clear (PRD §7.3).
func (p *Publisher) Present(ctx context.Context, domain, token, keyAuth string) error {
	p.mu.Lock()
	p.challenges[token] = keyAuth
	err := p.write()
	p.mu.Unlock()
	if err != nil {
		return fmt.Errorf("publish challenge for %s: %w", domain, err)
	}

	if p.verifier == nil {
		return nil
	}
	return p.verifier.wait(ctx, domain, token, keyAuth)
}

// CleanUp withdraws a challenge response.
func (p *Publisher) CleanUp(_ context.Context, domain, token, _ string) error {
	p.mu.Lock()
	delete(p.challenges, token)
	err := p.write()
	p.mu.Unlock()
	if err != nil {
		// Not worth failing the issuance over: a stale challenge answer is
		// useless to anyone without the matching account key, and the next
		// publish clears it.
		p.log.Warn("cannot withdraw acme challenge", "domain", domain, "token", token, "error", err)
	}
	return nil
}

// write publishes the current state. The caller holds the lock.
func (p *Publisher) write() error {
	bundle := edge.Bundle{Certificates: p.merged(), Auth: p.auth}

	tokens := make([]string, 0, len(p.challenges))
	for token := range p.challenges {
		tokens = append(tokens, token)
	}
	// Sorted so an unchanged set produces an unchanged file, which is what
	// keeps the edge from logging a reload that changed nothing.
	sort.Strings(tokens)
	for _, token := range tokens {
		bundle.HTTPChallenges = append(bundle.HTTPChallenges,
			edge.HTTPChallenge{Token: token, KeyAuth: p.challenges[token]})
	}

	// The index is bumped only when the material actually changed.
	//
	// The edge reloads on a byte difference, so publishing a fresh index over
	// an identical set is a reload of nothing. That is harmless twice a day
	// with ACME alone and becomes a keyring rebuild every minute once a
	// file-backed source is stat-ed at rotation speed.
	body, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshal certificate bundle: %w", err)
	}
	if p.last != nil && bytes.Equal(body, p.last) {
		return nil
	}
	p.last = body
	p.index++
	bundle.Index = p.index
	return edge.PublishBundle(p.path, bundle, p.gid)
}

// merged flattens every source's certificates into what the edge will serve,
// resolving a name claimed twice by mergeOrder. The caller holds the lock.
//
// Resolved here rather than left to the keyring's last-writer-wins means the
// edge never has to know a precedence rule, which is the property that lets a
// fourth source be added without touching it.
func (p *Publisher) merged() []edge.Certificate {
	winner := map[string]Mode{}
	for _, mode := range mergeOrder {
		for _, c := range p.bySource[mode] {
			for _, domain := range c.Domains {
				winner[domain] = mode
			}
		}
	}

	out := []edge.Certificate{}
	for _, mode := range mergeOrder {
		for _, c := range p.bySource[mode] {
			// A certificate keeps only the names it won. One that won none is
			// dropped: publishing a key for names nothing will select is a
			// private key on disk doing no work.
			domains := make([]string, 0, len(c.Domains))
			for _, domain := range c.Domains {
				if winner[domain] == mode {
					domains = append(domains, domain)
				}
			}
			if len(domains) == 0 {
				continue
			}
			out = append(out, edge.Certificate{
				Domains:  domains,
				CertPEM:  c.CertPEM,
				KeyPEM:   c.KeyPEM,
				NotAfter: c.NotAfter,
				Source:   string(mode),
			})
		}
	}
	// Sorted by primary domain so the file is a function of its contents and
	// not of the order sources happened to publish in.
	sort.Slice(out, func(i, j int) bool { return out[i].Domains[0] < out[j].Domains[0] })
	return out
}

// challengeVerifier confirms the edge is serving a challenge response.
type challengeVerifier struct {
	base    string
	timeout time.Duration
	log     *slog.Logger
}

// verifyPollInterval is how often the self-check retries.
const verifyPollInterval = 200 * time.Millisecond

// wait polls the edge until it answers with the expected key authorization.
func (v *challengeVerifier) wait(ctx context.Context, domain, token, keyAuth string) error {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	url := v.base + "/.well-known/acme-challenge/" + token
	client := &http.Client{Timeout: 5 * time.Second}

	var lastErr error
	for {
		if got, err := fetchChallenge(ctx, client, url, domain); err != nil {
			lastErr = err
		} else if got == keyAuth {
			return nil
		} else {
			lastErr = fmt.Errorf("edge answered %q", truncate(got, 64))
		}

		select {
		case <-ctx.Done():
			// Refusing to proceed is deliberate. Asking the CA to validate a
			// challenge we cannot serve ourselves is guaranteed to fail, and
			// failures are the rate limit that hurts.
			return fmt.Errorf("edge is not serving the challenge for %s at %s after %s: %w",
				domain, url, v.timeout, lastErr)
		case <-time.After(verifyPollInterval):
		}
	}
}

// fetchChallenge asks the edge for a challenge response as the CA would.
func fetchChallenge(ctx context.Context, client *http.Client, url, domain string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// The Host header is what makes this the same request the CA will make:
	// the edge routes by host, so checking against 127.0.0.1 would prove
	// nothing about the name being validated.
	req.Host = domain

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Nothing to do about it, and nowhere useful to report it: the
			// answer has already been read.
			_ = err
		}
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("edge answered %d", resp.StatusCode)
	}
	return strings.TrimSpace(string(body)), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
