package edge

import (
	"crypto/tls"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The labelled families (PRD §9.1.1). What they must get right is cardinality:
// every dimension here is chosen by somebody other than Kanea, and the whole
// design rests on none of them being able to grow this map without bound.

func TestMethodIsFoldedToTheAllowlist(t *testing.T) {
	m := NewMetrics()

	// r.Method is a token from the request line and Go's server accepts an
	// arbitrary one, so this dimension is attacker-chosen. Nine known methods
	// and one overflow is the entire range it may take.
	for _, method := range []string{"GET", "POST", "PROPFIND", "\x00weird", "MKCOL"} {
		m.Observe(Observation{
			Service: "shop/web", Status: 200, Method: method,
			Protocol: ProtocolHTTP, Duration: time.Millisecond,
		})
	}

	body := render(t, m)
	for _, want := range []struct{ method, count string }{
		{"GET", "1"},
		{"POST", "1"},
		{"OTHER", "3"},
	} {
		got := sample(t, body, fmt.Sprintf(
			`kanea_edge_service_requests_total{service="shop/web",code="200",method=%q,protocol="http"}`,
			want.method))
		if got != want.count {
			t.Errorf("method %s = %s, want %s", want.method, got, want.count)
		}
	}
	if strings.Contains(body, "PROPFIND") || strings.Contains(body, "MKCOL") {
		t.Error("a method outside the allowlist reached a label")
	}
}

func TestStatusCodeIsExactAndOutOfRangeFolds(t *testing.T) {
	m := NewMetrics()
	// Exact, so a dashboard written against Traefik's code="502" matches.
	m.Observe(Observation{Service: "shop/web", Status: 502, Method: "GET", Protocol: ProtocolHTTP})
	// Not a status any upstream can return. ServeHTTP's contract does not stop
	// a handler passing it, and it must not become a series of its own.
	m.Observe(Observation{Service: "shop/web", Status: 9001, Method: "GET", Protocol: ProtocolHTTP})

	body := render(t, m)
	if got := sample(t, body,
		`kanea_edge_service_requests_total{service="shop/web",code="502",method="GET",protocol="http"}`); got != "1" {
		t.Errorf("502 = %s, want 1", got)
	}
	if strings.Contains(body, `code="9001"`) {
		t.Error("an out-of-range status became its own series")
	}
}

func TestPerServiceCardinalityCapFoldsAndCounts(t *testing.T) {
	m := NewMetrics()

	// Far past the ceiling. Codes are upstream-chosen, so "ordinary operation
	// stays under the cap" is not a guarantee: a service answering a distinct
	// status per request is what this exists to survive.
	for code := 200; code < 200+maxSeriesPerService*3; code++ {
		m.Observe(Observation{
			Service: "shop/web", Status: code, Method: "GET",
			Protocol: ProtocolHTTP, Duration: time.Millisecond,
		})
	}

	m.mu.RLock()
	held := len(m.services["shop/web"].labelled)
	m.mu.RUnlock()
	if held > maxSeriesPerService {
		t.Errorf("service holds %d series, past the %d cap", held, maxSeriesPerService)
	}

	body := render(t, m)
	// The overflow series exists and holds everything past the cap...
	overflow := sample(t, body,
		`kanea_edge_service_requests_total{service="shop/web",code="other",method="OTHER",protocol="other"}`)
	if overflow == "0" {
		t.Error("nothing folded into the overflow series")
	}
	// ...and the fold is visible. A cap nobody can see is indistinguishable
	// from a leak, which is why scaling.Metrics counts its drops too.
	if got := sample(t, body, "kanea_edge_series_dropped_total"); got == "0" {
		t.Error("series were folded but the drop counter stayed at zero")
	}

	// The aggregate family is unaffected by the cap: it has one series per
	// service and counts every request regardless of how it was labelled.
	if got := sample(t, body, `kanea_edge_requests_total{service="shop/web"}`); got != "120" {
		t.Errorf("aggregate requests = %s, want 120: the cap must not lose a request", got)
	}
}

func TestRetainSweepsTheLabelledFamiliesToo(t *testing.T) {
	m := NewMetrics()
	for code := 200; code < 220; code++ {
		m.Observe(Observation{
			Service: "shop/gone", Status: code, Method: "GET", Protocol: ProtocolHTTP,
		})
	}
	m.TCPAccepted("shop/gone", EntrypointForPort(5432))

	m.Retain(map[string]bool{"shop/web": true})

	// A service's labelled map holds up to maxSeriesPerService entries, so a
	// route table that churns without this leaks forty series per departure
	// rather than one.
	if body := render(t, m); strings.Contains(body, "shop/gone") {
		t.Fatalf("labelled or tcp series survived the service leaving the table:\n%s", body)
	}
}

func TestTLSAndProtocolAreRecorded(t *testing.T) {
	m := NewMetrics()
	m.Observe(Observation{
		Service: "shop/web", Status: 200, Method: "GET", Protocol: ProtocolHTTPS,
		TLSVersion: tls.VersionName(tls.VersionTLS13),
		TLSCipher:  tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256),
	})
	m.Observe(Observation{Service: "shop/web", Status: 101, Method: "GET", Protocol: ProtocolWebsocket})

	body := render(t, m)
	if got := sample(t, body,
		`kanea_edge_service_requests_tls_total{service="shop/web",tls_version="TLS 1.3",tls_cipher="TLS_AES_128_GCM_SHA256"}`); got != "1" {
		t.Errorf("tls series = %s, want 1", got)
	}
	// A websocket upgrade is its own protocol. Without it every upgraded
	// connection reads as a plain 200 that happened to take a long time.
	if got := sample(t, body,
		`kanea_edge_service_requests_total{service="shop/web",code="101",method="GET",protocol="websocket"}`); got != "1" {
		t.Errorf("websocket series = %s, want 1", got)
	}
	// A plaintext request contributes no TLS series at all rather than one
	// labelled with an empty version.
	if strings.Contains(body, `tls_version=""`) {
		t.Error("a plaintext request produced a TLS series")
	}
}

func TestBytesAreCounted(t *testing.T) {
	m := NewMetrics()
	m.Observe(Observation{
		Service: "shop/web", Status: 200, Method: "POST", Protocol: ProtocolHTTP,
		RequestBytes: 512, ResponseBytes: 4096,
	})
	m.Observe(Observation{
		Service: "shop/web", Status: 200, Method: "POST", Protocol: ProtocolHTTP,
		RequestBytes: 512, ResponseBytes: 4096,
	})

	body := render(t, m)
	if got := sample(t, body, `kanea_edge_service_requests_bytes_total{service="shop/web"}`); got != "1024" {
		t.Errorf("request bytes = %s, want 1024", got)
	}
	if got := sample(t, body, `kanea_edge_service_responses_bytes_total{service="shop/web"}`); got != "8192" {
		t.Errorf("response bytes = %s, want 8192", got)
	}
}

func TestEntrypointCountsAreSeparateFromServices(t *testing.T) {
	m := NewMetrics()
	m.Observe(Observation{
		Service: "shop/web", Entrypoint: EntrypointWebSecure,
		Status: 200, Method: "GET", Protocol: ProtocolHTTPS,
	})
	m.Observe(Observation{
		Service: "shop/api", Entrypoint: EntrypointWebSecure,
		Status: 500, Method: "GET", Protocol: ProtocolHTTPS,
	})
	m.Observe(Observation{
		Service: "shop/web", Entrypoint: EntrypointWeb,
		Status: 200, Method: "GET", Protocol: ProtocolHTTP,
	})

	body := render(t, m)
	// An entrypoint aggregates across services: "is anything on :443 failing"
	// is a question no per-service series answers on its own.
	if got := sample(t, body,
		`kanea_edge_entrypoint_requests_total{entrypoint="websecure",code="200"}`); got != "1" {
		t.Errorf("websecure 200 = %s, want 1", got)
	}
	if got := sample(t, body,
		`kanea_edge_entrypoint_requests_total{entrypoint="websecure",code="500"}`); got != "1" {
		t.Errorf("websecure 500 = %s, want 1", got)
	}
	if got := sample(t, body,
		`kanea_edge_entrypoint_requests_total{entrypoint="web",code="200"}`); got != "1" {
		t.Errorf("web 200 = %s, want 1", got)
	}
}

func TestConnectionGaugeNeverGoesNegative(t *testing.T) {
	m := NewMetrics()
	// Two atomics moved from different goroutines: a close racing an open can
	// read below zero, and a negative connection count makes a graph look
	// broken rather than busy.
	m.ConnClosed(EntrypointWeb)
	m.ConnClosed(EntrypointWeb)

	if got := sample(t, render(t, m),
		`kanea_edge_entrypoint_open_connections{entrypoint="web"}`); got != "0" {
		t.Errorf("open connections = %s, want 0", got)
	}
}

func TestCertificateExpiryIsPublishedPerCertificateNotPerName(t *testing.T) {
	expiry := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	bundle := Bundle{Certificates: []Certificate{{
		// A wildcard covering many names is one thing that expires on one
		// date. One gauge per name would make a single renewal look like a
		// fleet-wide event.
		Domains:  []string{"*.shop.example.com", "a.shop.example.com", "b.shop.example.com"},
		NotAfter: expiry,
		Source:   "acme",
	}}}

	m := NewMetrics()
	m.SetCertificates(expiriesOf(bundle))

	body := render(t, m)
	got := sample(t, body,
		`kanea_edge_tls_certs_not_after{cn="*.shop.example.com",source="acme"}`)
	if got != fmt.Sprintf("%d", expiry.Unix()) {
		t.Errorf("expiry = %s, want %d", got, expiry.Unix())
	}
	if strings.Count(body, "kanea_edge_tls_certs_not_after{") != 1 {
		t.Errorf("one certificate produced more than one gauge:\n%s", body)
	}
}

func TestACertificateWithNoSourceIsStillPublished(t *testing.T) {
	// A bundle written by a pre-v1.35 kanead carries no source. The expiry is
	// the number worth having, and withholding it over a missing label gets
	// the trade backwards.
	m := NewMetrics()
	m.SetCertificates(expiriesOf(Bundle{Certificates: []Certificate{{
		Domains: []string{"shop.example.com"}, NotAfter: time.Unix(1800000000, 0),
	}}}))

	if got := sample(t, render(t, m),
		`kanea_edge_tls_certs_not_after{cn="shop.example.com",source="unknown"}`); got != "1800000000" {
		t.Errorf("expiry = %s, want 1800000000", got)
	}
}

func TestReloadOutcomesAreCountedSeparately(t *testing.T) {
	m := NewMetrics()
	at := time.Unix(1700000000, 0)
	m.Reloaded(true, at)
	m.Reloaded(false, at.Add(time.Second))
	m.Reloaded(false, at.Add(2*time.Second))

	body := render(t, m)
	if got := sample(t, body, `kanea_edge_config_reloads_total{result="success"}`); got != "1" {
		t.Errorf("successes = %s, want 1", got)
	}
	if got := sample(t, body, `kanea_edge_config_reloads_total{result="failure"}`); got != "2" {
		t.Errorf("failures = %s, want 2", got)
	}
	// The timestamp tracks the last *success*: a failing reload leaves it
	// where it was, which is what makes "routing froze at 14:02" readable.
	if got := sample(t, body, "kanea_edge_config_last_reload_success"); got != "1700000000" {
		t.Errorf("last success = %s, want 1700000000", got)
	}
}

func TestLabelValuesAreEscaped(t *testing.T) {
	// A certificate's common name is not Kanea's to choose. Everything else
	// here is DNS-1123 by the time it arrives, but this one is only as
	// well-behaved as whoever issued the certificate.
	m := NewMetrics()
	m.SetCertificates([]CertExpiry{{
		CommonName: `we"ird\name` + "\n", Source: "provided", NotAfter: time.Unix(1, 0),
	}})

	body := render(t, m)
	if strings.Contains(body, "\ncn=") || strings.Count(body, "kanea_edge_tls_certs_not_after{") != 1 {
		t.Errorf("a label value broke out of its quoting:\n%s", body)
	}
	if !strings.Contains(body, `cn="we\"ird\\name\n"`) {
		t.Errorf("label was not escaped as the exposition format defines:\n%s", body)
	}
}

func TestUTF8LabelValuesTravelAsThemselves(t *testing.T) {
	// %q would render these as \u escapes, which Prometheus does not unescape:
	// the label would come back as literal backslash-u text.
	m := NewMetrics()
	m.SetCertificates([]CertExpiry{{
		CommonName: "möbel.example.com", Source: "acme", NotAfter: time.Unix(1, 0),
	}})

	if body := render(t, m); !strings.Contains(body, `cn="möbel.example.com"`) {
		t.Errorf("a non-ASCII label was escaped:\n%s", body)
	}
}

// TestLabelledFootprintAtTargetScale bounds what the collector costs at §21's
// service count with every per-service ceiling saturated.
//
// The cap is the only thing that makes this bounded (codes come from
// upstreams and methods from clients) so it needs a measurement of its own,
// the way scaling.Metrics has TestFootprintAtTargetScale.
func TestLabelledFootprintAtTargetScale(t *testing.T) {
	if testing.Short() {
		t.Skip("footprint measurement is slow")
	}
	const services = 500

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	m := NewMetrics()
	for s := range services {
		name := fmt.Sprintf("proj%d/svc%d", s/10, s)
		for i := range maxSeriesPerService {
			m.Observe(Observation{
				Service: name, Entrypoint: EntrypointWebSecure,
				Status: 200 + i, Method: "GET", Protocol: ProtocolHTTPS,
				Duration: time.Millisecond,
			})
		}
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	used := after.HeapAlloc - before.HeapAlloc

	// §21 budgets the edge's labelled term at roughly 4 MiB fully saturated.
	// The ceiling here is generous against allocator variation; what it is
	// really asserting is the order of magnitude, because an unbounded map
	// would miss it by a factor of thousands rather than a few percent.
	const budget = 24 << 20
	if used > budget {
		t.Errorf("labelled families used %d MiB at %d services, over the %d MiB budget",
			used>>20, services, budget>>20)
	}
	t.Logf("%d services × %d series: %d KiB", services, maxSeriesPerService, used>>10)

	// Keep it alive to the measurement.
	runtime.KeepAlive(m)
}

// TestExpositionIsWellFormed is a structural check standing in for promtool.
//
// It is hand-written for the reason the collector is: pulling
// prometheus/common in to parse our own output would put a dependency tail
// behind `make security` for a check that is a dozen lines. What it catches is
// the class that actually bites: a family whose samples disagree about their
// label keys, which is how one metric name at two cardinalities double-counts,
// and a sample with no TYPE, which Prometheus reads as untyped and will not
// rate().
func TestExpositionIsWellFormed(t *testing.T) {
	m := NewMetrics()
	m.Observe(Observation{
		Service: "shop/web", Entrypoint: EntrypointWebSecure, Status: 200,
		Method: "GET", Protocol: ProtocolHTTPS, Duration: time.Millisecond,
		RequestBytes: 1, ResponseBytes: 2, TLSVersion: "TLS 1.3", TLSCipher: "X",
	})
	m.Refused("shop/web", ReasonRateLimit)
	m.TCPAccepted("home/db", EntrypointForPort(5432))
	m.TCPRefused("home/db", EntrypointForPort(5432), ReasonNodeLimit)
	m.SetCertificates([]CertExpiry{{CommonName: "a.example.com", Source: "acme", NotAfter: time.Unix(1, 0)}})
	m.Reloaded(true, time.Unix(1, 0))

	typed := map[string]bool{}
	labelKeys := map[string]string{}

	for line := range strings.SplitSeq(render(t, m), "\n") {
		if line == "" {
			continue
		}
		if after, ok := strings.CutPrefix(line, "# TYPE "); ok {
			typed[strings.Fields(after)[0]] = true
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}

		name, keys := familyAndKeys(t, line)
		// A histogram's _bucket/_sum/_count share their family's TYPE, and
		// _bucket carries an extra `le`. Normalise both away.
		base := name
		for _, suffix := range []string{"_bucket", "_sum", "_count"} {
			if trimmed, ok := strings.CutSuffix(base, suffix); ok && typed[trimmed] {
				base = trimmed
				keys = strings.ReplaceAll(keys, ",le", "")
				break
			}
		}
		if !typed[base] {
			t.Errorf("sample %q has no TYPE: Prometheus reads it as untyped and rate() will not work", name)
			continue
		}
		if seen, ok := labelKeys[base]; ok && seen != keys {
			t.Errorf("family %s has two label sets, %q and %q; one name at two "+
				"cardinalities double-counts under sum()", base, seen, keys)
			continue
		}
		labelKeys[base] = keys
	}

	// A sanity floor, so a render that emitted nothing would not pass by
	// vacuously satisfying every rule above.
	if len(typed) < 15 {
		t.Errorf("only %d families were declared; the exposition looks truncated", len(typed))
	}
}

// familyAndKeys splits a sample line into its metric name and its label keys.
func familyAndKeys(t *testing.T, line string) (name, keys string) {
	t.Helper()
	open := strings.Index(line, "{")
	if open < 0 {
		return strings.Fields(line)[0], ""
	}
	end := strings.LastIndex(line, "}")
	if end < open {
		t.Fatalf("unterminated label set: %q", line)
	}
	var out []string
	for _, pair := range splitLabels(line[open+1 : end]) {
		key, _, _ := strings.Cut(pair, "=")
		out = append(out, key)
	}
	return line[:open], strings.Join(out, ",")
}

// splitLabels splits a label set on commas that are outside quotes, because a
// value may contain one.
func splitLabels(s string) []string {
	var out []string
	var start, depth int
	for i, r := range s {
		switch r {
		case '"':
			depth ^= 1
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}
