package edge

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/textproto"
	"strings"
	"time"

	"github.com/kanea-dev/kanea/internal/ratelimit"
)

// compiled is a route with its middleware parsed once, at reload, rather than
// once per request.
//
// Parsing CIDRs and durations in the request path would be wasted work on every
// request, but the real reason is failure timing: a malformed rule discovered
// mid-request has no good answer — allow and the control is not enforced, deny
// and a typo takes the service down. Discovered at reload, it is a rejected
// snapshot and the last good table keeps serving.
type compiled struct {
	Route

	allow []netip.Prefix
	deny  []netip.Prefix

	// limit is nil when the service has no rate limit.
	limit *ratelimit.Spec
	// per is what the limit is keyed by: an address, the service, or a header
	// value. It shapes the key the limiter is called with rather than the limit
	// itself, which is why it lives here and not in the Spec.
	per string

	// requestSet and responseSet are pre-canonicalised so the request path does
	// not re-normalise header names.
	requestSet     map[string]string
	requestRemove  []string
	responseSet    map[string]string
	responseRemove []string
}

// compile parses a route's middleware, or reports why it cannot be served.
func compile(r Route) (compiled, error) {
	out := compiled{Route: r}

	if r.IPRestriction != nil {
		var err error
		if out.allow, err = parsePrefixes(r.IPRestriction.Allow); err != nil {
			return compiled{}, fmt.Errorf("%s: ip_restriction.allow: %w", r.Name(), err)
		}
		if out.deny, err = parsePrefixes(r.IPRestriction.Deny); err != nil {
			return compiled{}, fmt.Errorf("%s: ip_restriction.deny: %w", r.Name(), err)
		}
	}

	if r.RateLimit != nil {
		spec, per, err := compileRateLimit(*r.RateLimit)
		if err != nil {
			return compiled{}, fmt.Errorf("%s: rate_limit: %w", r.Name(), err)
		}
		out.limit, out.per = &spec, per
	}

	if h := r.Headers; h != nil {
		var err error
		if out.requestSet, err = canonicalHeaders(h.RequestSet); err != nil {
			return compiled{}, fmt.Errorf("%s: headers.request_set: %w", r.Name(), err)
		}
		if out.responseSet, err = canonicalHeaders(h.ResponseSet); err != nil {
			return compiled{}, fmt.Errorf("%s: headers.response_set: %w", r.Name(), err)
		}
		if out.requestRemove, err = canonicalNames(h.RequestRemove); err != nil {
			return compiled{}, fmt.Errorf("%s: headers.request_remove: %w", r.Name(), err)
		}
		if out.responseRemove, err = canonicalNames(h.ResponseRemove); err != nil {
			return compiled{}, fmt.Errorf("%s: headers.response_remove: %w", r.Name(), err)
		}
	}
	return out, nil
}

func compileRateLimit(rl RateLimit) (ratelimit.Spec, string, error) {
	if rl.Requests <= 0 {
		return ratelimit.Spec{}, "", fmt.Errorf("requests = %d must be positive", rl.Requests)
	}
	if rl.Burst < 0 {
		return ratelimit.Spec{}, "", fmt.Errorf("burst = %d must not be negative", rl.Burst)
	}
	window, err := time.ParseDuration(rl.Window)
	if err != nil {
		return ratelimit.Spec{}, "", fmt.Errorf("window %q: %w", rl.Window, err)
	}
	if window <= 0 {
		return ratelimit.Spec{}, "", fmt.Errorf("window %q must be positive", rl.Window)
	}

	per := strings.TrimSpace(rl.Per)
	if per == "" {
		per = RateLimitPerIP
	}
	switch {
	case per == RateLimitPerIP, per == RateLimitPerService:
	case strings.HasPrefix(per, RateLimitPerHeaderPrefix):
		if name := strings.TrimPrefix(per, RateLimitPerHeaderPrefix); !validHeaderName(name) {
			return ratelimit.Spec{}, "", fmt.Errorf("per %q names an invalid header", rl.Per)
		}
	default:
		return ratelimit.Spec{}, "", fmt.Errorf("per %q must be %q, %q or %q",
			rl.Per, RateLimitPerIP, RateLimitPerService, RateLimitPerHeaderPrefix+"<name>")
	}

	return ratelimit.Spec{Requests: rl.Requests, Window: window, Burst: rl.Burst}, per, nil
}

// Rate limit keys, matching the job spec vocabulary (PRD §7.2.1).
const (
	RateLimitPerIP           = "ip"
	RateLimitPerService      = "service"
	RateLimitPerHeaderPrefix = "header:"
)

// parsePrefixes reads a CIDR list. A bare address is a single host.
func parsePrefixes(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, err := parsePrefix(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, prefix)
	}
	return out, nil
}

func parsePrefix(entry string) (netip.Prefix, error) {
	entry = strings.TrimSpace(entry)
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, err
		}
		// Masked so "10.0.0.5/8" behaves as the /8 it claims to be rather than
		// depending on whether the author normalised it.
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR or an address", entry)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// canonicalHeaders normalises header names so the request path can set them
// without re-normalising, and refuses the ones the edge owns.
func canonicalHeaders(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	for name, value := range in {
		canonical, err := canonicalHeaderName(name)
		if err != nil {
			return nil, err
		}
		out[canonical] = value
	}
	return out, nil
}

func canonicalNames(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(in))
	for _, name := range in {
		canonical, err := canonicalHeaderName(name)
		if err != nil {
			return nil, err
		}
		out = append(out, canonical)
	}
	return out, nil
}

// canonicalHeaderName validates one name and returns its canonical form.
//
// The refusals repeat what R16 already rejects at plan time. That is not
// redundant: the edge serves a file, and a file can be hand-edited or written
// by a future version. A snapshot that could rewrite X-Forwarded-For would
// forge the client identity the middleware above it is keyed on, so the reader
// refuses it rather than trusting the writer.
func canonicalHeaderName(name string) (string, error) {
	if !validHeaderName(name) {
		return "", fmt.Errorf("%q is not a valid header name", name)
	}
	canonical := textproto.CanonicalMIMEHeaderKey(name)
	lower := strings.ToLower(canonical)
	if hopByHop[lower] {
		return "", fmt.Errorf("%q is connection-scoped and belongs to the proxy", name)
	}
	for _, owned := range forwardedHeaders {
		if strings.EqualFold(owned, canonical) {
			return "", fmt.Errorf("%q is set by the edge from the real connection", name)
		}
	}
	return canonical, nil
}

// hopByHop are the connection-scoped headers of RFC 9110 §7.6.1.
var hopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "te": true, "trailer": true,
	"transfer-encoding": true, "upgrade": true,
}

// validHeaderName reports whether s is a legal HTTP field name (RFC 9110
// token). A name holding a colon or a newline is a response-splitting attempt.
func validHeaderName(s string) bool {
	return s != "" && !strings.ContainsAny(s, " \t\r\n:()<>@,;\\\"/[]?={}")
}

// ---- request path ----

// allowsAddress applies the IP restriction. Deny wins over allow, and an empty
// allow list means the world (PRD §7.2.1).
func (c compiled) allowsAddress(addr netip.Addr) bool {
	if !addr.IsValid() {
		// No usable peer address. Refusing is the only safe reading: an
		// address-based control cannot be enforced against an unknown address.
		return len(c.deny) == 0 && len(c.allow) == 0
	}
	for _, prefix := range c.deny {
		if prefix.Contains(addr) {
			return false
		}
	}
	if len(c.allow) == 0 {
		return true
	}
	for _, prefix := range c.allow {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// rateKey is the bucket subject for one request, or "" when the request cannot
// be keyed (a missing header, say) and should not be limited.
func (c compiled) rateKey(r *http.Request, addr netip.Addr) string {
	switch {
	case c.limit == nil:
		return ""
	case c.per == RateLimitPerService:
		return "service"
	case strings.HasPrefix(c.per, RateLimitPerHeaderPrefix):
		name := strings.TrimPrefix(c.per, RateLimitPerHeaderPrefix)
		if value := r.Header.Get(name); value != "" {
			return "h:" + value
		}
		// A request without the header cannot be attributed. Falling back to
		// the address would let a client dodge a per-key limit by omitting the
		// header, so it lands in a shared bucket for exactly that case.
		return "h:"
	default:
		if !addr.IsValid() {
			return ""
		}
		return "a:" + addr.String()
	}
}

// applyRequestHeaders rewrites the outbound request.
//
// Removals run before sets so a spec can replace a header by naming it in
// both, which is the reading that does not depend on ordering luck.
func (c compiled) applyRequestHeaders(h http.Header) {
	for _, name := range c.requestRemove {
		h.Del(name)
	}
	for name, value := range c.requestSet {
		h.Set(name, value)
	}
}

// applyResponseHeaders rewrites the response on its way out.
func (c compiled) applyResponseHeaders(h http.Header) {
	for _, name := range c.responseRemove {
		h.Del(name)
	}
	for name, value := range c.responseSet {
		h.Set(name, value)
	}
}
