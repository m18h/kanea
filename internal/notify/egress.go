package notify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Outbound egress rules (PRD §11, §14 A10: server-side request forgery).
//
// A notification target is a URL an operator writes into a job spec, and a job
// spec is not always written by the person who owns the node. Kanea reaching an
// arbitrary URL on request is the definition of SSRF, and the interesting
// targets are exactly the ones a firewall was supposed to protect: the metadata
// service on 169.254.169.254, another project's service on the internal
// network, localhost.
//
// So: **https only, private and link-local destinations refused**, with an
// explicit opt-out for the operator who really is running an internal chat
// server. The check happens at dial time rather than on the hostname, because a
// hostname is not a destination: the same name can resolve to a public address
// when it is validated and a private one when it is connected to, and only the
// address the socket actually goes to is worth checking.

// Errors an egress refusal produces.
var (
	// ErrInsecureScheme means the target is not https.
	ErrInsecureScheme = errors.New("notify: notification targets must use https")
	// ErrPrivateDestination means the address is one this node should not be
	// made to reach on a spec's say-so.
	ErrPrivateDestination = errors.New("notify: destination address is private, " +
		"loopback or link-local")
)

// DefaultEgressTimeout bounds one delivery attempt end to end.
//
// Short, because delivery is best-effort and retried: a channel that takes ten
// seconds to fail is a channel that holds a worker while a fleet is restarting.
const DefaultEgressTimeout = 10 * time.Second

// EgressPolicy decides which destinations a channel may reach.
type EgressPolicy struct {
	// AllowPrivate permits RFC1918, loopback, link-local and unique-local
	// destinations. Off by default; §11 calls this the "explicit opt-out for
	// internal chat servers".
	AllowPrivate bool
	// AllowHTTP permits plain http. Off by default. Separate from AllowPrivate
	// on purpose: an internal Mattermost on a private address is a reasonable
	// thing to allow, and sending a signed payload over cleartext to the
	// public internet is not the same decision at all.
	AllowHTTP bool
}

// CheckURL validates a target before it is ever used.
//
// The scheme check belongs here because it is a property of the URL. The
// address check does *not*: a name that resolves publicly now can resolve to
// 127.0.0.1 later, so that one happens per connection, in the dialer.
func (p EgressPolicy) CheckURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("notify: cannot parse target: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !p.AllowHTTP {
			return nil, fmt.Errorf("%w (%s)", ErrInsecureScheme, redactURL(u))
		}
	default:
		return nil, fmt.Errorf("%w: scheme %q", ErrInsecureScheme, u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("notify: target has no host")
	}
	return u, nil
}

// HTTPClient builds a client that enforces the policy at dial time.
//
// Redirects are refused rather than followed. A target that answers 302 to
// http://169.254.169.254/ would otherwise walk straight past every check above,
// and no notification endpoint worth using needs a redirect.
func (p EgressPolicy) HTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultEgressTimeout
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}

	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("notify: refusing to follow a redirect to %s",
				redactURL(req.URL))
		},
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return p.dial(ctx, dialer, network, addr)
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          8,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   timeout,
			ExpectContinueTimeout: time.Second,
		},
	}
}

// dial connects only to an address the policy allows.
//
// The check is on the resolved address, immediately before the connection, so
// there is no window between validating a name and using it: the DNS rebinding
// attack this whole function exists to close.
func (p EgressPolicy) dial(
	ctx context.Context, dialer *net.Dialer, network, addr string,
) (net.Conn, error) {
	if p.AllowPrivate {
		return dialer.DialContext(ctx, network, addr)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("notify: cannot parse address %q: %w", addr, err)
	}
	ips, err := (&net.Resolver{}).LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("notify: cannot resolve %s: %w", host, err)
	}

	// Every candidate must be acceptable, not just the one that happens to be
	// tried first. A name resolving to both a public and a private address is
	// how a check on "the first result" is bypassed.
	var last error
	for _, ip := range ips {
		if !AllowedIP(ip.IP) {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrPrivateDestination, host, ip.IP)
		}
	}
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		// LookupIPAddr returned no addresses and no error, which should not
		// happen, but returning a nil error with a nil connection would panic
		// in the transport rather than fail the delivery.
		return nil, fmt.Errorf("notify: %s resolved to no usable address", host)
	}
	return nil, last
}

// AllowedIP reports whether an address may be a notification destination.
//
// Everything that is not routable on the public internet is refused: loopback
// (the control plane itself), link-local (cloud metadata, 169.254.169.254 and
// its IPv6 equivalent), private and unique-local ranges (the rest of the
// network this node sits on), multicast, and the unspecified address.
func AllowedIP(ip net.IP) bool {
	switch {
	case ip == nil, ip.IsUnspecified(), ip.IsLoopback(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(), ip.IsMulticast(),
		ip.IsPrivate():
		return false
	}
	// IPv4-mapped IPv6 (::ffff:10.0.0.1) needs no special case: net.IP's
	// predicates normalise through To4(), so IsPrivate, IsLoopback and
	// IsLinkLocalUnicast all answer true for the mapped forms. Verified rather
	// than assumed: TestAllowedIPRefusesEverythingNotPubliclyRoutable covers
	// the mapped forms explicitly, so a Go change here fails a test rather
	// than quietly opening a hole.
	//
	// NAT64 (64:ff9b::/96) does need one. It carries an IPv4 address in its low
	// 32 bits, Go has no notion of the prefix, so a private v4 destination can
	// be written as a v6 address that every predicate above calls public.
	if len(ip) == net.IPv6len && ip[0] == 0x00 && ip[1] == 0x64 &&
		ip[2] == 0xff && ip[3] == 0x9b {
		return AllowedIP(ip[12:16])
	}
	return true
}

// redactURL renders a URL for an error or a log with its credentials and query
// removed.
//
// A notification target is frequently a capability URL: a Slack incoming
// webhook is a secret in path form, and an ntfy topic can be. Logging one in
// full puts a credential in a file that is not the secrets store (R3, §14 A09).
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	b.WriteString(u.Host)
	if u.Path != "" && u.Path != "/" {
		// The first segment only. It says which service this is without
		// carrying the token that follows.
		b.WriteString("/")
		if first, _, found := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/"); found {
			b.WriteString(first)
			b.WriteString("/…")
		} else {
			b.WriteString("…")
		}
	}
	return b.String()
}
