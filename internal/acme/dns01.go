package acme

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// DNSSolver publishes a DNS-01 challenge record.
//
// The shape matches lego's provider interface — no context, because lego's does
// not have one — and it is deliberately the same two calls as the HTTP-01
// Solver: publish, then withdraw.
type DNSSolver interface {
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error
}

// RFC2136Config configures dynamic DNS updates (RFC 2136, TSIG-signed).
//
// RFC 2136 rather than a hosted provider's SDK: it is what BIND, Knot and
// PowerDNS all speak, it needs no vendor library, and the TSIG signing is in
// miekg/dns — which Kanea already carries for its own resolver (§7.1). lego's
// own rfc2136 provider would have worked and pulls in a Kerberos stack for the
// GSS-TSIG case Kanea does not use; a hundred lines here costs less than that
// dependency tail. Hosted providers are a curated list to be added one at a
// time, each weighed against what its SDK drags in.
type RFC2136Config struct {
	// Server is the authoritative nameserver to send updates to, host:port.
	Server string
	// Zone is the zone the updates belong to, e.g. "apps.example.com".
	// Empty means it is derived from the name being challenged.
	Zone string
	// TSIGKey is the key name, TSIGSecret its base64 secret, and TSIGAlgorithm
	// the HMAC to sign with (hmac-sha256 by default).
	TSIGKey       string
	TSIGSecret    string
	TSIGAlgorithm string
	// TTL for the challenge record. Short: it exists for one validation.
	TTL uint32
	// Timeout bounds one update exchange.
	Timeout time.Duration

	Logger *slog.Logger
}

// Defaults for a dynamic-update solver.
const (
	// DefaultChallengeTTL is short because the record lives for one validation
	// and a long TTL only slows the next attempt down.
	DefaultChallengeTTL = 60
	// DefaultUpdateTimeout bounds one exchange with the nameserver.
	DefaultUpdateTimeout = 10 * time.Second
)

// RFC2136Solver answers DNS-01 challenges with dynamic updates.
type RFC2136Solver struct {
	cfg RFC2136Config
	log *slog.Logger
}

// NewRFC2136Solver validates the configuration and returns a solver.
func NewRFC2136Solver(cfg RFC2136Config) (*RFC2136Solver, error) {
	if cfg.Server == "" {
		return nil, errors.New("acme: a DNS update server is required")
	}
	if cfg.TSIGKey == "" || cfg.TSIGSecret == "" {
		// An unsigned update is one anybody on the network can send, and what
		// they can send is a TXT record that passes an ACME challenge for a
		// name they do not own. There is no unauthenticated mode here.
		return nil, errors.New("acme: dynamic DNS updates must be TSIG-signed; " +
			"a key name and secret are required")
	}
	if cfg.TSIGAlgorithm == "" {
		cfg.TSIGAlgorithm = dns.HmacSHA256
	}
	if !strings.HasSuffix(cfg.TSIGAlgorithm, ".") {
		cfg.TSIGAlgorithm += "."
	}
	switch cfg.TSIGAlgorithm {
	case dns.HmacSHA1, dns.HmacSHA224, dns.HmacSHA256, dns.HmacSHA384, dns.HmacSHA512:
	default:
		return nil, fmt.Errorf("acme: unsupported TSIG algorithm %q", cfg.TSIGAlgorithm)
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultChallengeTTL
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultUpdateTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	cfg.TSIGKey = dns.Fqdn(cfg.TSIGKey)
	if cfg.Zone != "" {
		cfg.Zone = dns.Fqdn(cfg.Zone)
	}
	return &RFC2136Solver{cfg: cfg, log: cfg.Logger}, nil
}

// Present adds the challenge TXT record.
func (s *RFC2136Solver) Present(domain, _, keyAuth string) error {
	name, value := challengeRecord(domain, keyAuth)
	record, err := s.txtRecord(name, value)
	if err != nil {
		return err
	}

	msg := s.newUpdate(name)
	msg.Insert([]dns.RR{record})
	if err := s.exchange(msg); err != nil {
		return fmt.Errorf("acme: publish %s: %w", name, err)
	}
	s.log.Debug("published a DNS-01 challenge record", "name", name)
	return nil
}

// CleanUp removes it.
//
// A failure here is reported but is not fatal to issuance: the certificate is
// already obtained by this point, and a stale challenge record is untidy rather
// than dangerous — it authorises nothing on its own.
func (s *RFC2136Solver) CleanUp(domain, _, keyAuth string) error {
	name, value := challengeRecord(domain, keyAuth)
	record, err := s.txtRecord(name, value)
	if err != nil {
		return err
	}

	msg := s.newUpdate(name)
	msg.Remove([]dns.RR{record})
	if err := s.exchange(msg); err != nil {
		return fmt.Errorf("acme: withdraw %s: %w", name, err)
	}
	return nil
}

// newUpdate starts an UPDATE for the zone the name belongs to.
func (s *RFC2136Solver) newUpdate(name string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetUpdate(s.zoneFor(name))
	return msg
}

func (s *RFC2136Solver) txtRecord(name, value string) (dns.RR, error) {
	record, err := dns.NewRR(fmt.Sprintf("%s %d IN TXT %q", name, s.cfg.TTL, value))
	if err != nil {
		return nil, fmt.Errorf("acme: build challenge record: %w", err)
	}
	return record, nil
}

// exchange signs and sends the update.
func (s *RFC2136Solver) exchange(msg *dns.Msg) error {
	client := &dns.Client{
		// TCP: an UPDATE with a TSIG record is easily past 512 bytes, and a
		// truncated update is a failed one.
		Net:     "tcp",
		Timeout: s.cfg.Timeout,
		TsigSecret: map[string]string{
			s.cfg.TSIGKey: s.cfg.TSIGSecret,
		},
	}
	msg.SetTsig(s.cfg.TSIGKey, s.cfg.TSIGAlgorithm, tsigFudge, time.Now().Unix())

	reply, _, err := client.Exchange(msg, s.cfg.Server)
	if err != nil {
		return fmt.Errorf("update %s: %w", s.cfg.Server, err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		// NOTAUTH usually means the key is not permitted for this zone, and
		// REFUSED that the server does not serve it. Both are configuration,
		// and naming the code is what makes them findable.
		return fmt.Errorf("update refused by %s: %s", s.cfg.Server, dns.RcodeToString[reply.Rcode])
	}
	return nil
}

// tsigFudge is the clock skew a signature tolerates, in seconds. 300 is the
// convention; a node whose clock is further out than that has a problem this
// setting should not paper over (`kanea doctor` checks NTP).
const tsigFudge = 300

// zoneFor returns the zone an update belongs to.
func (s *RFC2136Solver) zoneFor(name string) string {
	if s.cfg.Zone != "" {
		return s.cfg.Zone
	}
	// Without a configured zone, assume the challenge name's parent: for
	// `_acme-challenge.web.shop.example.com.` that is `web.shop.example.com.`,
	// which is right when each name is its own zone and wrong otherwise —
	// hence the configuration option, and hence this being the fallback.
	if _, after, found := strings.Cut(name, "."); found {
		return dns.Fqdn(after)
	}
	return dns.Fqdn(name)
}

// challengeRecord returns the record name and value for a challenge.
//
// Both come from lego rather than being recomputed here: the value is a
// specific digest of the key authorization, and the name follows any CNAME the
// operator has delegated the challenge through — a common setup, and one that
// silently fails if the record is published at the un-followed name.
//
// Wildcards land in the same place: the challenge for `*.shop.example.com` is
// published at `_acme-challenge.shop.example.com`, exactly as for the bare
// name, which is why a wildcard and its parent share one authorization.
func challengeRecord(domain, keyAuth string) (name, value string) {
	// The star is stripped here rather than trusted to be absent. A CA strips
	// it before it names the authorization, so lego never passes one — but a
	// solver that would publish `_acme-challenge.*.shop.example.com` if it did
	// is one wrong caller away from writing a record no resolver serves and no
	// validation finds.
	domain = strings.TrimPrefix(domain, "*.")
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return dns.Fqdn(info.EffectiveFQDN), info.Value
}

// ensure the solver satisfies the interface the manager takes.
var _ DNSSolver = (*RFC2136Solver)(nil)
