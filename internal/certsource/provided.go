package certsource

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"

	"github.com/m18h/kanea/internal/edge"
)

// Provided serves certificates an operator put on this node (PRD §7.3, R20).
//
// It is the passthrough model applied to TLS. A spec names a *grant* —
// `tls { mode = "provided", name = "shop" }` — and the mapping from that name
// to a pair of files lives in the node's own config, never in the spec. The
// reason is R17's: GitOps deploys a spec automatically, so anything a spec can
// name, anyone who can push to a synced repository can name, and a spec that
// could name /etc/ssl/private/anything would be choosing which of this
// machine's private keys to serve.
//
// The grant carries an `allow` list of projects for the same reason the
// passthrough grants do, and the default is that the config file does not
// exist.
//
// Nothing here ever falls back to another source. A provided certificate that
// cannot be resolved leaves the service on plaintext, because a silent
// downgrade to a certificate no browser trusts is worse: an interstitial is a
// thing an operator learns to click through, and then clicks through on the day
// it means something.
type Provided struct {
	log *slog.Logger

	mu sync.Mutex
	// path is the config file, empty when the feature is off.
	path string
	// policy is the last config that parsed. A parse failure keeps it, the way
	// edge.Watcher keeps the last good snapshot: a half-saved file must not
	// take working sites down.
	policy   *certPolicy
	loaded   bool
	warned   bool
	lastHash [sha256.Size]byte
}

// certGrant is one configured certificate: two files and who may claim them.
//
// There is no domain list. The names come from the certificate's own SANs,
// read on every pass — a declared list is a second copy that can disagree with
// the certificate, and a configuration that lies about what it serves is worse
// than one that says nothing.
type certGrant struct {
	name      string
	certPath  string
	keyPath   string
	allow     map[string]struct{}
	allowList []string
}

type certPolicy struct {
	grants map[string]certGrant
	// order is the grant names sorted, so a tie between two equally valid
	// candidates is broken the same way on every node and every restart.
	order []string
}

// dns1123Label is the shape a grant name must have, matching what a job spec
// validates a `name` reference as. Held here rather than imported for the
// reason passthrough holds its own copy: a name the config accepts and no spec
// can reference is a grant nobody can use.
var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ErrNoCertificate marks a request no configured certificate satisfies.
var ErrNoCertificate = errors.New("certsource: no configured certificate covers this service")

type hclCertRoot struct {
	Certificates []hclCertificate `hcl:"certificate,block"`
	Remain       hcl.Body         `hcl:",remain"`
}

type hclCertificate struct {
	Name     string    `hcl:"name,label"`
	Cert     string    `hcl:"cert"`
	Key      string    `hcl:"key"`
	Allow    []string  `hcl:"allow"`
	DefRange hcl.Range `hcl:",def_range"`
}

// NewProvided builds the source. An empty path turns the feature off: the
// source still exists and satisfies nothing, which is what makes
// `--tls-default provided` on an unconfigured node an explicit failure per
// service rather than a startup error nobody can act on.
func NewProvided(path string, logger *slog.Logger) *Provided {
	if logger == nil {
		logger = slog.Default()
	}
	return &Provided{path: strings.TrimSpace(path), log: logger, policy: &certPolicy{}}
}

// Mode reports which spec mode this source serves.
func (p *Provided) Mode() Mode { return ModeProvided }

// Configured reports whether an operator pointed this node at a config file.
func (p *Provided) Configured() bool { return p.path != "" }

// Changed reports whether the config or any file it names has moved since the
// last call, so the caller can skip a pass that would produce the same bundle.
//
// It hashes the config source and every certificate and key it names, rather
// than stat-ing them. A renewal tool that writes the same size at the same
// second is not hypothetical — certbot writes then renames, and the mtime it
// leaves is whatever the temporary file had.
//
// It is deliberately a poll and not fsnotify: write-then-rename replaces the
// inode a watch is registered on, which is exactly why internal/edge polls too.
func (p *Provided) Changed() bool {
	if p.path == "" {
		return false
	}
	sum := p.fingerprint()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loaded && sum == p.lastHash {
		return false
	}
	p.lastHash = sum
	p.loaded = true
	return true
}

// fingerprint hashes the config and everything it points at.
//
// An unreadable file contributes its error text, so a certificate that
// disappears and comes back is two changes rather than none.
func (p *Provided) fingerprint() [sha256.Size]byte {
	h := sha256.New()
	// hash.Hash.Write never returns an error, so nothing in here can fail.
	write := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		h.Write([]byte(line))
	}

	src, err := os.ReadFile(p.path) // #nosec G304 — operator-supplied config path
	if err != nil {
		write("config-error:%v\n", err)
		return sum(h)
	}
	h.Write(src)

	// Parse to find the files, but do not report a parse failure here: Ensure
	// is where a bad config is diagnosed, and Changed must still return true
	// so the operator sees the complaint on the pass that follows their edit.
	policy, perr := parseCertPolicy(p.path, src)
	if perr != nil {
		return sum(h)
	}
	for _, name := range policy.order {
		g := policy.grants[name]
		for _, f := range []string{g.certPath, g.keyPath} {
			body, err := os.ReadFile(f) // #nosec G304 — operator-supplied path
			if err != nil {
				write("%s:error:%v\n", f, err)
				continue
			}
			write("%s:", f)
			h.Write(body)
		}
	}
	return sum(h)
}

func sum(h interface{ Sum([]byte) []byte }) [sha256.Size]byte {
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Ensure resolves each request against the configured grants.
//
// The config is re-read on every pass, a deliberate divergence from
// --passthrough-config's load-once: a device grant is a decision, and a
// certificate is a thing with an expiry date that a renewal tool rewrites
// behind Kanea's back.
func (p *Provided) Ensure(_ context.Context, reqs []Request) (Result, error) {
	policy := p.reload()
	var res Result
	for _, req := range reqs {
		cert, err := p.resolve(policy, req)
		if err != nil {
			res.Failures = append(res.Failures, Failure{Request: req, Err: err})
			continue
		}
		res.Certificates = append(res.Certificates, cert)
	}
	return res, nil
}

// reload re-reads the config, keeping the last good one on failure.
func (p *Provided) reload() *certPolicy {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.path == "" {
		return &certPolicy{}
	}
	src, err := os.ReadFile(p.path) // #nosec G304 — operator-supplied config path
	if err == nil {
		var policy *certPolicy
		if policy, err = parseCertPolicy(p.path, src); err == nil {
			p.policy, p.warned = policy, false
			return p.policy
		}
	}
	// Logged once per bad state, like edge.Watcher: a config nobody fixes for a
	// week must not be a log line every minute.
	if !p.warned {
		p.warned = true
		p.log.Error("certificate config unusable; keeping the last one that parsed",
			"path", p.path, "error", err, "grants", len(p.policy.grants))
	}
	return p.policy
}

// resolve picks the certificate for one request.
func (p *Provided) resolve(policy *certPolicy, req Request) (Certificate, error) {
	if p.path == "" {
		return Certificate{}, fmt.Errorf(
			"%w: this node has no --tls-certs-config, so there is no certificate to give it",
			ErrNoCertificate)
	}
	if len(policy.grants) == 0 {
		return Certificate{}, fmt.Errorf("%w: %s defines no certificate blocks",
			ErrNoCertificate, p.path)
	}

	var candidates []certGrant
	for _, name := range policy.order {
		g := policy.grants[name]
		if req.Name != "" && g.name != req.Name {
			continue
		}
		if _, ok := g.allow[req.Project]; !ok {
			continue
		}
		candidates = append(candidates, g)
	}
	if len(candidates) == 0 {
		return Certificate{}, p.noCandidate(policy, req)
	}

	var matched []Certificate
	var names []string
	var lastErr error
	for _, g := range candidates {
		cert, err := loadGrant(g)
		if err != nil {
			lastErr = err
			continue
		}
		if !coversAll(cert.Domains, req.Domains) {
			lastErr = fmt.Errorf("certificate %q covers %s, not %s",
				g.name, strings.Join(cert.Domains, ", "), strings.Join(req.Domains, ", "))
			continue
		}
		matched = append(matched, cert)
		names = append(names, g.name)
	}
	switch len(matched) {
	case 0:
		if lastErr != nil {
			return Certificate{}, lastErr
		}
		return Certificate{}, fmt.Errorf("%w: %s", ErrNoCertificate, req.Service)
	case 1:
		p.warnIfExpired(matched[0], names[0], req)
		return matched[0], nil
	default:
		// Sorted candidate order makes this the same choice every time, which
		// matters more than which one wins — but an operator whose two
		// wildcards both cover a service should be told rather than left to
		// wonder which is being served.
		p.log.Warn("several configured certificates cover this service; using the first by name",
			"service", req.Service, "using", names[0], "also", strings.Join(names[1:], ", "))
		p.warnIfExpired(matched[0], names[0], req)
		return matched[0], nil
	}
}

// noCandidate explains why nothing was even considered, which is almost always
// a missing project in an allow list and is worth naming as that.
func (p *Provided) noCandidate(policy *certPolicy, req Request) error {
	if req.Name != "" {
		g, ok := policy.grants[req.Name]
		if !ok {
			return fmt.Errorf("%w: %s names certificate %q, which %s does not define",
				ErrNoCertificate, req.Service, req.Name, p.path)
		}
		return fmt.Errorf("%w: certificate %q allows %s, not project %q",
			ErrNoCertificate, req.Name, strings.Join(g.allowList, ", "), req.Project)
	}
	return fmt.Errorf("%w: no certificate in %s allows project %q",
		ErrNoCertificate, p.path, req.Project)
}

// warnIfExpired reports an expired certificate and serves it anyway.
//
// Refusing it at midnight turns a stale site into an unreachable one, and an
// operator who has not noticed the expiry will notice the browser long before
// they notice a log line. The event is what tells them; the certificate is what
// keeps the door open until they act.
func (p *Provided) warnIfExpired(cert Certificate, name string, req Request) {
	if time.Now().Before(cert.NotAfter) {
		return
	}
	p.log.Warn("configured certificate has expired; serving it anyway",
		"service", req.Service, "certificate", name, "expired", cert.NotAfter.Format(time.RFC3339))
}

// loadGrant reads and validates one grant's files.
//
// tls.X509KeyPair is the check, not a bare PEM decode: a certificate paired
// with the wrong key is the commonest operator error here, it produces a
// handshake failure with no useful client-side message, and it has to be named
// as itself.
func loadGrant(g certGrant) (Certificate, error) {
	certPEM, err := os.ReadFile(g.certPath) // #nosec G304 — operator-supplied path
	if err != nil {
		return Certificate{}, fmt.Errorf("certificate %q: read cert: %w", g.name, err)
	}
	keyPEM, err := os.ReadFile(g.keyPath) // #nosec G304 — operator-supplied path
	if err != nil {
		return Certificate{}, fmt.Errorf("certificate %q: read key: %w", g.name, err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Certificate{}, fmt.Errorf(
			"certificate %q: %s and %s are not a matching pair: %w",
			g.name, g.certPath, g.keyPath, err)
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return Certificate{}, fmt.Errorf("certificate %q: %w", g.name, err)
		}
	}

	domains := make([]string, 0, len(leaf.DNSNames))
	for _, d := range leaf.DNSNames {
		domains = append(domains, strings.ToLower(strings.TrimSuffix(d, ".")))
	}
	if len(domains) == 0 {
		return Certificate{}, fmt.Errorf(
			"certificate %q (%s) has no subjectAltName DNS entries, so it covers no host; "+
				"a certificate that names hosts only in its subject CN is refused by every "+
				"current browser", g.name, g.certPath)
	}
	sort.Strings(domains)

	return Certificate{
		Domains:   domains,
		CertPEM:   string(certPEM),
		KeyPEM:    string(keyPEM),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		IssuedAt:  leaf.NotBefore,
	}, nil
}

// coversAll reports whether a certificate naming these domains covers every
// name the service needs. It is CoversHost's rule applied to a set, so a
// wildcard certificate satisfies a service without either side knowing a
// filename convention — and it is the edge's own matcher, so a certificate
// this accepts is one the edge will actually select on SNI.
func coversAll(certDomains, want []string) bool {
	if len(want) == 0 {
		return false
	}
	for _, host := range want {
		if !edge.CoversHost(certDomains, host) {
			return false
		}
	}
	return true
}

// parseCertPolicy reads the config file.
func parseCertPolicy(filename string, src []byte) (*certPolicy, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("certsource: %s", diags.Error())
	}
	var root hclCertRoot
	if diags := gohcl.DecodeBody(file.Body, nil, &root); diags.HasErrors() {
		return nil, fmt.Errorf("certsource: %s", diags.Error())
	}

	policy := &certPolicy{grants: make(map[string]certGrant, len(root.Certificates))}
	for _, c := range root.Certificates {
		if !dns1123Label.MatchString(c.Name) {
			return nil, fmt.Errorf(
				"certsource: certificate grant %q is not a DNS-1123 label, so no job spec could reference it",
				c.Name)
		}
		if _, dup := policy.grants[c.Name]; dup {
			return nil, fmt.Errorf("certsource: certificate grant %q is defined twice", c.Name)
		}
		for field, path := range map[string]string{"cert": c.Cert, "key": c.Key} {
			if strings.TrimSpace(path) == "" {
				return nil, fmt.Errorf("certsource: certificate grant %q has no %s path", c.Name, field)
			}
			if !strings.HasPrefix(path, "/") {
				return nil, fmt.Errorf(
					"certsource: certificate grant %q has a relative %s path %q; "+
						"the daemon's working directory is not something a config should depend on",
					c.Name, field, path)
			}
		}
		// A grant naming no project is a config error, not a permissive
		// default — the rule the passthrough grants follow, for the reason
		// R5 gives: cross-project reach is something an operator states.
		if len(c.Allow) == 0 {
			return nil, fmt.Errorf(
				"certsource: certificate grant %q lists no projects in `allow`; "+
					"a grant nobody may claim is not a permissive default", c.Name)
		}
		allow := make(map[string]struct{}, len(c.Allow))
		for _, project := range c.Allow {
			if !dns1123Label.MatchString(project) {
				return nil, fmt.Errorf(
					"certsource: certificate grant %q allows %q, which is not a DNS-1123 label "+
						"and so is not a project name", c.Name, project)
			}
			allow[project] = struct{}{}
		}
		policy.grants[c.Name] = certGrant{
			name: c.Name, certPath: c.Cert, keyPath: c.Key,
			allow: allow, allowList: append([]string(nil), c.Allow...),
		}
	}
	for name := range policy.grants {
		policy.order = append(policy.order, name)
	}
	sort.Strings(policy.order)
	return policy, nil
}

// Path is the config file an operator pointed this node at, for logs.
func (p *Provided) Path() string { return p.path }
