package jobspec

import (
	"fmt"
	"net/netip"
	"net/textproto"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/m18h/kanea/internal/certsource"
)

// EdgePortName is the port a route uses when a service declares several
// (PRD §7.2). v1 routes by Host alone, so with more than one candidate there is
// no request attribute left to choose with — the spec has to say.
const EdgePortName = "http"

// MaxDomainLength is the DNS limit on a fully qualified name.
const MaxDomainLength = 253

// RateLimitKeys are the accepted `rate_limit.per` values (PRD §7.2.1).
const (
	RateLimitPerIP      = "ip"
	RateLimitPerService = "service"
	// RateLimitPerHeaderPrefix keys the bucket by a request header, written
	// `per = "header:X-API-Key"`.
	RateLimitPerHeaderPrefix = "header:"
)

// AutoFQDN is the domain a service gets when its expose block omits `domains`
// (PRD §7.2). One wildcard DNS record for the base domain makes every service
// routable without another DNS change.
func AutoFQDN(project, service, baseDomain string) string {
	if baseDomain == "" {
		return ""
	}
	return service + "." + project + "." + strings.Trim(baseDomain, ".")
}

// EdgeDomains returns the hostnames this service answers on, lowercased.
//
// Empty when the service is not exposed — and also when it is exposed with no
// explicit domains and no base domain is known, because then the name cannot be
// computed yet. Callers that must have a name (the agent building routes) pass
// the server's base domain; callers that are only checking a file may not have
// one.
func (s *Service) EdgeDomains(baseDomain string) []string {
	if s.Expose == nil {
		return nil
	}
	if len(s.Expose.Domains) > 0 {
		out := make([]string, 0, len(s.Expose.Domains))
		for _, d := range s.Expose.Domains {
			out = append(out, canonicalDomain(d))
		}
		return out
	}
	if auto := AutoFQDN(s.Project, s.Name, baseDomain); auto != "" {
		return []string{canonicalDomain(auto)}
	}
	return nil
}

// EdgePort returns the port the edge proxies to, or nil if the service does not
// declare a usable one (R16 rejects that at plan time, so a nil here in the
// agent means validation was skipped).
func (s *Service) EdgePort() *Port {
	if s.Network == nil || len(s.Network.Ports) == 0 {
		return nil
	}
	for _, p := range s.Network.Ports {
		if p.Name == EdgePortName {
			return p
		}
	}
	if len(s.Network.Ports) == 1 {
		return s.Network.Ports[0]
	}
	return nil
}

// canonicalDomain is the form used for route lookup and collision detection.
// DNS is case-insensitive, so two services claiming "Shop.example.com" and
// "shop.example.com" are claiming one domain, not two.
func canonicalDomain(d string) string { return strings.ToLower(strings.TrimSpace(d)) }

// validateExpose enforces R16 for one service.
//
// Everything here is checked at plan time because the alternative is a runtime
// failure in a process that is holding public traffic. An ingress control that
// silently fails to apply is worse than one that was never written: the spec
// says the service is restricted, the edge is not restricting it, and nothing
// says so.
func validateExpose(svc *Service) hcl.Diagnostics {
	if svc.Expose == nil {
		return nil
	}
	e := svc.Expose

	var diags hcl.Diagnostics
	diags = append(diags, validateExposePort(svc)...)
	diags = append(diags, validateExposeDomains(svc)...)
	diags = append(diags, validateExposeTLS(svc)...)
	where := fmt.Sprintf("Service %q", svc.Name)
	diags = append(diags, validateIPRestriction(where, e.IPRestriction)...)
	diags = append(diags, validateRateLimit(where, e.RateLimit)...)
	diags = append(diags, validateExposeHeaders(where, e.Headers)...)
	return diags
}

// validateExposePort checks that there is exactly one sensible upstream.
func validateExposePort(svc *Service) hcl.Diagnostics {
	rng := svc.Expose.DefRange

	if svc.Network == nil || len(svc.Network.Ports) == 0 {
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Exposed service declares no port",
			Detail: fmt.Sprintf("Service %q has an expose block but no network { port … }. "+
				"The edge needs somewhere to send the request; an exposed service with no "+
				"port is a route to nowhere.", svc.Name),
			Subject: rng.Ptr(),
		}}
	}
	if svc.EdgePort() != nil {
		return nil
	}

	names := make([]string, 0, len(svc.Network.Ports))
	for _, p := range svc.Network.Ports {
		names = append(names, p.Name)
	}
	return hcl.Diagnostics{{
		Severity: hcl.DiagError,
		Summary:  "Ambiguous exposed port",
		Detail: fmt.Sprintf("Service %q declares ports %s and is exposed, but none is named %q. "+
			"v1 routes by Host alone, so there is nothing in the request left to pick a port with. "+
			"Name the public one %q.",
			svc.Name, strings.Join(quoteAll(names), ", "), EdgePortName, EdgePortName),
		Subject: rng.Ptr(),
	}}
}

// validateExposeDomains checks each declared domain as a hostname.
func validateExposeDomains(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	seen := map[string]bool{}

	for _, raw := range svc.Expose.Domains {
		domain := canonicalDomain(raw)
		if err := checkDomain(domain); err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid domain",
				Detail:   fmt.Sprintf("Service %q: domain %q %s.", svc.Name, raw, err),
				Subject:  svc.Expose.DefRange.Ptr(),
			})
			continue
		}
		if seen[domain] {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate domain",
				Detail:   fmt.Sprintf("Service %q lists domain %q twice.", svc.Name, domain),
				Subject:  svc.Expose.DefRange.Ptr(),
			})
		}
		seen[domain] = true
	}
	return diags
}

// validateExposeTLS enforces R20: a tls block names a certificate source, and
// "provided" is the only one a grant name means anything for.
//
// There is deliberately no warning for an absent tls block. The whole point of
// --tls-default is that a homelabber annotates nothing and still gets a
// certificate, and a warning on every service teaches people to ignore
// warnings — after which the two below stop being read either.
func validateExposeTLS(svc *Service) hcl.Diagnostics {
	t := svc.Expose.TLS
	if t == nil {
		return nil
	}
	rng := t.DefRange
	if rng.Filename == "" {
		rng = svc.Expose.DefRange
	}
	var diags hcl.Diagnostics

	if t.Mode != "" && !certsource.Mode(t.Mode).Valid() {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Unknown TLS mode",
			Detail: fmt.Sprintf("Service %q declares tls mode %q. A mode names where the "+
				"certificate comes from, and this node knows %s.",
				svc.Name, t.Mode, strings.Join(quoteAll(certsourceModeNames()), ", ")),
			Subject: rng.Ptr(),
		})
	}
	if t.Mode != "" && t.LetsEncrypt != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Two TLS spellings",
			Detail: fmt.Sprintf("Service %q sets both `mode` and `letsencrypt`. They are the "+
				"same setting written twice, and picking one for you would mean guessing "+
				"which is stale. Keep `mode`.", svc.Name),
			Subject: rng.Ptr(),
		})
	}
	if t.Name != "" {
		if t.Mode != string(certsource.ModeProvided) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Certificate name without a provided mode",
				Detail: fmt.Sprintf("Service %q names certificate %q, but its tls mode is %s. "+
					"A name selects among the certificates an operator put on this node, "+
					"so it means nothing to a source that issues its own.",
					svc.Name, t.Name, describeMode(t.Mode)),
				Subject: rng.Ptr(),
			})
		}
		diags = append(diags, validateGrant("certificate", svc.Name, t.Name, t.Name, rng)...)
	}

	// The deprecation warnings. `letsencrypt = true` still means what it always
	// meant; `letsencrypt = false` is the one that changed underfoot, so it is
	// the one whose warning has to say what the new silence means.
	if t.LetsEncrypt != nil {
		detail := fmt.Sprintf("Service %q writes `letsencrypt = true`. Write "+
			"`mode = %q` instead; the old spelling still works and will be removed.",
			svc.Name, certsource.ModeACME)
		if !*t.LetsEncrypt {
			detail = fmt.Sprintf("Service %q writes `letsencrypt = false`. Write "+
				"`mode = %q` if you meant plain HTTP: an absent mode does not mean "+
				"no certificate, it means whatever this node's --tls-default is.",
				svc.Name, certsource.ModePlaintext)
		}
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagWarning,
			Summary:  "Deprecated TLS spelling",
			Detail:   detail,
			Subject:  rng.Ptr(),
		})
	}
	return diags
}

// certsourceModeNames lists the modes a spec may name, in a stable order.
func certsourceModeNames() []string {
	modes := certsource.Modes()
	out := make([]string, 0, len(modes))
	for _, m := range modes {
		out = append(out, string(m))
	}
	return out
}

// describeMode names the mode in an error, including the case where the spec
// left it to the node.
func describeMode(mode string) string {
	if mode == "" {
		return "whatever this node defaults to"
	}
	return fmt.Sprintf("%q", mode)
}

// checkDomain reports why a string is not usable as a route hostname.
//
// The rejections are all things that "work" somewhere else and would silently
// never match here: a URL instead of a host, a port suffix, a wildcard.
func checkDomain(d string) error {
	switch {
	case d == "":
		return fmt.Errorf("is empty")
	case len(d) > MaxDomainLength:
		return fmt.Errorf("is longer than the %d-character DNS limit", MaxDomainLength)
	case strings.Contains(d, "://"):
		return fmt.Errorf("looks like a URL; write the hostname alone")
	case strings.Contains(d, "/"):
		return fmt.Errorf("contains a path; v1 routes by host only, so paths never match")
	case strings.Contains(d, ":"):
		return fmt.Errorf("contains a port; the edge always listens on 80 and 443")
	case strings.Contains(d, "*"):
		return fmt.Errorf("is a wildcard; routes name one host each (a wildcard " +
			"certificate is a separate thing — see the acme config)")
	case strings.HasSuffix(d, "."):
		return fmt.Errorf("has a trailing dot; write it as it appears in a Host header")
	}

	for _, label := range strings.Split(d, ".") {
		if err := checkDomainLabel(label); err != nil {
			return fmt.Errorf("has an invalid label %q: %w", label, err)
		}
	}
	return nil
}

func checkDomainLabel(label string) error {
	switch {
	case label == "":
		return fmt.Errorf("labels may not be empty")
	case len(label) > MaxNameLength:
		return fmt.Errorf("labels are at most %d characters", MaxNameLength)
	case label[0] == '-' || label[len(label)-1] == '-':
		return fmt.Errorf("labels may not start or end with '-'")
	}
	for _, r := range label {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return fmt.Errorf("labels hold only letters, digits and '-'")
		}
	}
	return nil
}

// validateIPRestriction checks that every entry parses as a CIDR.
//
// A bare address is accepted and read as a single host, because writing
// "203.0.113.7" and meaning that one host is the obvious intent and turning it
// into a plan error would be pedantry.
func validateIPRestriction(where string, r *IPRestriction) hcl.Diagnostics {
	if r == nil {
		return nil
	}
	var diags hcl.Diagnostics
	for _, list := range []struct {
		field   string
		entries []string
	}{{"allow", r.Allow}, {"deny", r.Deny}} {
		for _, entry := range list.entries {
			if _, err := ParseCIDR(entry); err != nil {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Invalid CIDR",
					Detail: fmt.Sprintf("%s: ip_restriction.%s entry %q is not a CIDR or address: %s.",
						where, list.field, entry, err),
					Subject: r.DefRange.Ptr(),
				})
			}
		}
	}
	return diags
}

// ParseCIDR reads one ip_restriction entry: a prefix ("10.0.0.0/8") or a bare
// address, which becomes a single-host prefix.
func ParseCIDR(entry string) (netip.Prefix, error) {
	entry = strings.TrimSpace(entry)
	if strings.Contains(entry, "/") {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, err
		}
		// Masked so that "10.0.0.5/8" behaves as the /8 it says it is rather
		// than depending on whether the caller normalised it.
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func validateRateLimit(where string, rl *RateLimit) hcl.Diagnostics {
	if rl == nil {
		return nil
	}
	var diags hcl.Diagnostics
	rng := rl.DefRange

	if rl.Requests <= 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid rate limit",
			Detail: fmt.Sprintf("%s: rate_limit.requests = %d; it must be positive. "+
				"To refuse all traffic use ip_restriction, which says so plainly.",
				where, rl.Requests),
			Subject: rng.Ptr(),
		})
	}
	if rl.Burst < 0 {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid rate limit",
			Detail:   fmt.Sprintf("%s: rate_limit.burst = %d; it must not be negative.", where, rl.Burst),
			Subject:  rng.Ptr(),
		})
	}

	switch window, err := ParseDuration(rl.Window); {
	case rl.Window == "":
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Rate limit has no window",
			Detail: fmt.Sprintf("%s: rate_limit needs a window (\"1m\", \"10s\"). "+
				"A request count without a period does not describe a rate.", where),
			Subject: rng.Ptr(),
		})
	case err != nil:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid duration",
			Detail:   fmt.Sprintf("%s: rate_limit.window = %q: %s.", where, rl.Window, err),
			Subject:  rng.Ptr(),
		})
	case window == 0:
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid rate limit",
			Detail:   fmt.Sprintf("%s: rate_limit.window is zero.", where),
			Subject:  rng.Ptr(),
		})
	}

	diags = append(diags, validateRateLimitKey(where, rl)...)
	return diags
}

// validateRateLimitKey checks `per`. An unrecognised key would otherwise fall
// back to some default and rate-limit the wrong thing — which looks like it is
// working until the day it matters.
func validateRateLimitKey(where string, rl *RateLimit) hcl.Diagnostics {
	per := strings.TrimSpace(rl.Per)
	switch {
	case per == "", per == RateLimitPerIP, per == RateLimitPerService:
		return nil
	case strings.HasPrefix(per, RateLimitPerHeaderPrefix):
		name := strings.TrimPrefix(per, RateLimitPerHeaderPrefix)
		if !validHeaderName(name) {
			return hcl.Diagnostics{{
				Severity: hcl.DiagError,
				Summary:  "Invalid rate limit key",
				Detail: fmt.Sprintf("%s: rate_limit.per = %q names an invalid header %q.",
					where, rl.Per, name),
				Subject: rl.DefRange.Ptr(),
			}}
		}
		return nil
	default:
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid rate limit key",
			Detail: fmt.Sprintf("%s: rate_limit.per = %q. Use %q, %q, or %q.",
				where, rl.Per, RateLimitPerIP, RateLimitPerService, RateLimitPerHeaderPrefix+"<name>"),
			Subject: rl.DefRange.Ptr(),
		}}
	}
}

// hopByHopHeaders are connection-scoped and belong to the proxy, not to the
// service behind it (RFC 9110 §7.6.1). Rewriting them from a spec breaks
// framing, keep-alive, or the WebSocket upgrade.
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// edgeOwnedHeaders carry the edge's statement about who the client is. A spec
// that could set them would be forging the identity that ip_restriction, rate
// limiting and every access log downstream are keyed on (PRD §14, A01).
var edgeOwnedHeaders = map[string]bool{
	"forwarded":         true,
	"x-forwarded-for":   true,
	"x-forwarded-host":  true,
	"x-forwarded-port":  true,
	"x-forwarded-proto": true,
	"x-real-ip":         true,
}

func validateExposeHeaders(where string, h *Headers) hcl.Diagnostics {
	if h == nil {
		return nil
	}
	var diags hcl.Diagnostics
	rng := h.DefRange

	check := func(field, name string) {
		if !validHeaderName(name) {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid header name",
				Detail: fmt.Sprintf("%s: headers.%s names %q, which is not a valid HTTP header.",
					where, field, name),
				Subject: rng.Ptr(),
			})
			return
		}
		lower := strings.ToLower(name)
		if hopByHopHeaders[lower] {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Header belongs to the proxy",
				Detail: fmt.Sprintf("%s: headers.%s names %q, a connection-scoped header the "+
					"edge manages. Rewriting it breaks request framing or the WebSocket upgrade.",
					where, field, name),
				Subject: rng.Ptr(),
			})
			return
		}
		if edgeOwnedHeaders[lower] {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Header belongs to the edge",
				Detail: fmt.Sprintf("%s: headers.%s names %q. The edge sets it from the real "+
					"connection; a spec that could set it would be forging the client identity that "+
					"ip_restriction, rate limits and your access logs all read.",
					where, field, name),
				Subject: rng.Ptr(),
			})
		}
	}

	for _, name := range sortedKeys(h.RequestSet) {
		check("request_set", name)
	}
	for _, name := range h.RequestRemove {
		check("request_remove", name)
	}
	for _, name := range sortedKeys(h.ResponseSet) {
		check("response_set", name)
	}
	for _, name := range h.ResponseRemove {
		check("response_remove", name)
	}
	return diags
}

// validateExposedDomains rejects two services claiming one domain (R16).
//
// This is a whole-set check rather than a per-service one because that is the
// only level it exists at: each spec is individually fine, and the collision is
// between them. Left to the edge it would be last-writer-wins, which is a
// routing table that depends on map iteration order.
func validateExposedDomains(spec *Spec) hcl.Diagnostics {
	type claim struct {
		service string
		project string
		rng     hcl.Range
	}
	var diags hcl.Diagnostics
	claimed := map[string]claim{}

	for _, svc := range spec.Services {
		if svc.Expose == nil {
			continue
		}
		for _, domain := range svc.EdgeDomains(spec.BaseDomain) {
			if first, taken := claimed[domain]; taken {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Domain claimed twice",
					Detail: fmt.Sprintf("Domain %q is claimed by %s/%s and by %s/%s (%s). "+
						"One host reaches one service.",
						domain, first.project, first.service, svc.Project, svc.Name, first.rng),
					Subject: svc.Expose.DefRange.Ptr(),
				})
				continue
			}
			claimed[domain] = claim{service: svc.Name, project: svc.Project, rng: svc.Expose.DefRange}
		}
	}
	return diags
}

// validHeaderName reports whether s is a legal HTTP field name (RFC 9110
// token). textproto's canonicaliser rejects anything with a delimiter, which is
// exactly the check wanted here — a header name with a colon or a newline in it
// is a response-splitting attempt.
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	return textproto.CanonicalMIMEHeaderKey(s) != "" &&
		!strings.ContainsAny(s, " \t\r\n:()<>@,;\\\"/[]?={}")
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}
