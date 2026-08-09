package edge

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Prometheus exposition rendering for the edge's counters (PRD §9.1.1).
//
// The same format containerd's endpoint uses, so kanead scrapes both with one
// parser rather than inventing a projection file for what is already a solved
// wire format.
//
// It lives apart from metrics.go because the two have different reasons to
// change: the collector changes when the edge learns to measure something new,
// and this changes when the wire format or a metric's name does. A name here is
// a public promise (§9.1.1) and renaming one breaks every dashboard written
// against it, which is a different kind of edit from adding a counter.

// escapeLabelValue escapes a value for the exposition format.
//
// Explicitly, rather than with %q. A Go-quoted string escapes non-ASCII as
// \xNN and \uNNNN, and Prometheus does not unescape either — a certificate
// whose common name is not ASCII would render as a label no scraper reads back
// correctly. The format defines exactly three escapes and this emits exactly
// those, leaving UTF-8 to travel as itself.
func escapeLabelValue(s string) string {
	if !strings.ContainsAny(s, `\"`+"\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// label renders one name="value" pair.
func label(name, value string) string {
	return name + `="` + escapeLabelValue(value) + `"`
}

// snapshot is a consistent view of the collector, taken under one lock.
//
// Rendering holds no lock: the maps are copied here (pointers, not counters),
// and the atomics behind them are read lock-free afterwards. A render that held
// the lock would block every request on the node for the duration of a scrape.
type snapshot struct {
	services    []namedService
	entrypoints []namedEntrypoint
	tcp         []namedTCP
	certs       []CertExpiry
}

type namedService struct {
	name string
	m    *serviceMetrics
}

type namedEntrypoint struct {
	name string
	m    *entrypointMetrics
}

type namedTCP struct {
	key tcpKey
	m   *tcpMetrics
}

func (m *Metrics) snapshot() snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s := snapshot{
		services:    make([]namedService, 0, len(m.services)),
		entrypoints: make([]namedEntrypoint, 0, len(m.entrypoints)),
		tcp:         make([]namedTCP, 0, len(m.tcp)),
		certs:       append([]CertExpiry(nil), m.certs...),
	}
	for name, sm := range m.services {
		s.services = append(s.services, namedService{name: name, m: sm})
	}
	for name, ep := range m.entrypoints {
		s.entrypoints = append(s.entrypoints, namedEntrypoint{name: name, m: ep})
	}
	for key, t := range m.tcp {
		s.tcp = append(s.tcp, namedTCP{key: key, m: t})
	}

	sort.Slice(s.services, func(i, j int) bool { return s.services[i].name < s.services[j].name })
	sort.Slice(s.entrypoints, func(i, j int) bool { return s.entrypoints[i].name < s.entrypoints[j].name })
	sort.Slice(s.tcp, func(i, j int) bool {
		if s.tcp[i].key.service != s.tcp[j].key.service {
			return s.tcp[i].key.service < s.tcp[j].key.service
		}
		return s.tcp[i].key.entrypoint < s.tcp[j].key.entrypoint
	})
	sort.Slice(s.certs, func(i, j int) bool {
		if s.certs[i].CommonName != s.certs[j].CommonName {
			return s.certs[i].CommonName < s.certs[j].CommonName
		}
		return s.certs[i].Source < s.certs[j].Source
	})
	return s
}

// WriteTo renders the Prometheus exposition format.
func (m *Metrics) WriteTo(w io.Writer) (int64, error) {
	s := m.snapshot()
	out := &printer{w: w}

	m.writeAggregate(out, s)
	m.writeLabelled(out, s)
	m.writeEntrypoints(out, s)
	m.writeTCP(out, s)
	m.writePlatform(out, s)

	return out.n, out.err
}

// writeAggregate renders the family the autoscaler's scraper differences
// (internal/scaling.EdgeScraper). Its names and labels are a contract: the
// scraper keys on them by string, and a rename here silently stops every
// scaling rule on the node.
func (m *Metrics) writeAggregate(out *printer, s snapshot) {
	out.line("# HELP kanea_edge_requests_total Requests proxied to a service.")
	out.line("# TYPE kanea_edge_requests_total counter")
	for _, svc := range s.services {
		out.printf("kanea_edge_requests_total{%s} %d\n",
			label("service", svc.name), svc.m.requests.Load())
	}

	out.line("# HELP kanea_edge_request_duration_ms Request duration histogram.")
	out.line("# TYPE kanea_edge_request_duration_ms histogram")
	for _, svc := range s.services {
		l := label("service", svc.name)
		for b, bound := range latencyBounds {
			out.printf("kanea_edge_request_duration_ms_bucket{%s,le=\"%g\"} %d\n",
				l, bound, svc.m.buckets[b].Load())
		}
		out.printf("kanea_edge_request_duration_ms_bucket{%s,le=\"+Inf\"} %d\n",
			l, svc.m.buckets[len(latencyBounds)].Load())
		out.printf("kanea_edge_request_duration_ms_sum{%s} %d\n", l, svc.m.durationSum.Load())
		out.printf("kanea_edge_request_duration_ms_count{%s} %d\n", l, svc.m.requests.Load())
	}

	out.line("# HELP kanea_edge_errors_total Responses with a 5xx status.")
	out.line("# TYPE kanea_edge_errors_total counter")
	for _, svc := range s.services {
		out.printf("kanea_edge_errors_total{%s} %d\n",
			label("service", svc.name), svc.m.errors.Load())
	}

	out.line("# HELP kanea_edge_refused_total Requests rejected by ingress middleware.")
	out.line("# TYPE kanea_edge_refused_total counter")
	for _, svc := range s.services {
		for _, reason := range sortedCounterKeys(&svc.m.mu, svc.m.refused) {
			out.printf("kanea_edge_refused_total{%s,%s} %d\n",
				label("service", svc.name), label("reason", reason),
				loadCounter(&svc.m.mu, svc.m.refused, reason))
		}
	}
}

// writeLabelled renders the {code,method,protocol} family.
//
// Named kanea_edge_service_* rather than sharing kanea_edge_requests_total with
// the aggregate above: one metric name at two label cardinalities double-counts
// under any sum() a user writes, because this is the same traffic already
// counted once. The prefix is Traefik's, deliberately.
func (m *Metrics) writeLabelled(out *printer, s snapshot) {
	out.line("# HELP kanea_edge_service_requests_total Requests by status, method and protocol.")
	out.line("# TYPE kanea_edge_service_requests_total counter")
	for _, svc := range s.services {
		for _, k := range svc.m.sortedLabelKeys() {
			series := svc.m.seriesAt(k)
			if series == nil {
				continue
			}
			out.printf("kanea_edge_service_requests_total{%s} %d\n",
				labelSetFor(svc.name, k), series.requests.Load())
		}
	}

	out.line("# HELP kanea_edge_service_request_duration_ms Request duration by status, method and protocol.")
	out.line("# TYPE kanea_edge_service_request_duration_ms histogram")
	for _, svc := range s.services {
		for _, k := range svc.m.sortedLabelKeys() {
			series := svc.m.seriesAt(k)
			if series == nil {
				continue
			}
			l := labelSetFor(svc.name, k)
			for b, bound := range latencyBounds {
				out.printf("kanea_edge_service_request_duration_ms_bucket{%s,le=\"%g\"} %d\n",
					l, bound, series.buckets[b].Load())
			}
			out.printf("kanea_edge_service_request_duration_ms_bucket{%s,le=\"+Inf\"} %d\n",
				l, series.buckets[len(latencyBounds)].Load())
			out.printf("kanea_edge_service_request_duration_ms_sum{%s} %d\n", l, series.durationSum.Load())
			out.printf("kanea_edge_service_request_duration_ms_count{%s} %d\n", l, series.requests.Load())
		}
	}

	out.line("# HELP kanea_edge_service_requests_bytes_total Request body bytes received.")
	out.line("# TYPE kanea_edge_service_requests_bytes_total counter")
	for _, svc := range s.services {
		out.printf("kanea_edge_service_requests_bytes_total{%s} %d\n",
			label("service", svc.name), svc.m.requestBytes.Load())
	}

	out.line("# HELP kanea_edge_service_responses_bytes_total Response body bytes sent.")
	out.line("# TYPE kanea_edge_service_responses_bytes_total counter")
	for _, svc := range s.services {
		out.printf("kanea_edge_service_responses_bytes_total{%s} %d\n",
			label("service", svc.name), svc.m.responseBytes.Load())
	}

	out.line("# HELP kanea_edge_service_requests_tls_total Requests by TLS version and cipher.")
	out.line("# TYPE kanea_edge_service_requests_tls_total counter")
	for _, svc := range s.services {
		svc.m.mu.RLock()
		keys := make([]tlsKey, 0, len(svc.m.tls))
		for k := range svc.m.tls {
			keys = append(keys, k)
		}
		svc.m.mu.RUnlock()
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].version != keys[j].version {
				return keys[i].version < keys[j].version
			}
			return keys[i].cipher < keys[j].cipher
		})
		for _, k := range keys {
			out.printf("kanea_edge_service_requests_tls_total{%s,%s,%s} %d\n",
				label("service", svc.name), label("tls_version", k.version),
				label("tls_cipher", k.cipher), loadCounter(&svc.m.mu, svc.m.tls, k))
		}
	}

	// In flight, not "open connections". The handler sees requests, and with
	// keep-alive those are not the same thing — one connection carries many.
	// Only the entrypoint gauge below counts connections, because ConnState is
	// the only place a connection is actually visible. Naming this one
	// open_connections to match Traefik would be naming it after a quantity it
	// does not measure.
	out.line("# HELP kanea_edge_service_requests_in_flight Requests currently being proxied to a service.")
	out.line("# TYPE kanea_edge_service_requests_in_flight gauge")
	for _, svc := range s.services {
		out.printf("kanea_edge_service_requests_in_flight{%s} %d\n",
			label("service", svc.name), clampGauge(svc.m.inFlight.Load()))
	}
}

func (m *Metrics) writeEntrypoints(out *printer, s snapshot) {
	out.line("# HELP kanea_edge_entrypoint_requests_total Requests by entrypoint and status.")
	out.line("# TYPE kanea_edge_entrypoint_requests_total counter")
	for _, ep := range s.entrypoints {
		for _, code := range sortedCounterKeys(&ep.m.mu, ep.m.requests) {
			out.printf("kanea_edge_entrypoint_requests_total{%s,%s} %d\n",
				label("entrypoint", ep.name), label("code", code),
				loadCounter(&ep.m.mu, ep.m.requests, code))
		}
	}

	out.line("# HELP kanea_edge_entrypoint_open_connections Connections open on an entrypoint.")
	out.line("# TYPE kanea_edge_entrypoint_open_connections gauge")
	for _, ep := range s.entrypoints {
		out.printf("kanea_edge_entrypoint_open_connections{%s} %d\n",
			label("entrypoint", ep.name), clampGauge(ep.m.open.Load()))
	}
}

// writeTCP renders published-port counters (§7.2.2). Before v1.35 this surface
// had none at all.
func (m *Metrics) writeTCP(out *printer, s snapshot) {
	out.line("# HELP kanea_edge_tcp_connections_total Connections accepted on a published TCP port.")
	out.line("# TYPE kanea_edge_tcp_connections_total counter")
	for _, t := range s.tcp {
		out.printf("kanea_edge_tcp_connections_total{%s} %d\n",
			tcpLabels(t.key), t.m.connections.Load())
	}

	out.line("# HELP kanea_edge_tcp_active_connections Connections currently relayed.")
	out.line("# TYPE kanea_edge_tcp_active_connections gauge")
	for _, t := range s.tcp {
		out.printf("kanea_edge_tcp_active_connections{%s} %d\n",
			tcpLabels(t.key), clampGauge(t.m.active.Load()))
	}

	out.line("# HELP kanea_edge_tcp_refused_total Connections refused before being relayed.")
	out.line("# TYPE kanea_edge_tcp_refused_total counter")
	for _, t := range s.tcp {
		for _, reason := range sortedCounterKeys(&t.m.mu, t.m.refused) {
			out.printf("kanea_edge_tcp_refused_total{%s,%s} %d\n",
				tcpLabels(t.key), label("reason", reason),
				loadCounter(&t.m.mu, t.m.refused, reason))
		}
	}

	out.line("# HELP kanea_edge_tcp_bytes_in_total Bytes relayed from client to upstream.")
	out.line("# TYPE kanea_edge_tcp_bytes_in_total counter")
	for _, t := range s.tcp {
		out.printf("kanea_edge_tcp_bytes_in_total{%s} %d\n", tcpLabels(t.key), t.m.bytesIn.Load())
	}

	out.line("# HELP kanea_edge_tcp_bytes_out_total Bytes relayed from upstream to client.")
	out.line("# TYPE kanea_edge_tcp_bytes_out_total counter")
	for _, t := range s.tcp {
		out.printf("kanea_edge_tcp_bytes_out_total{%s} %d\n", tcpLabels(t.key), t.m.bytesOut.Load())
	}
}

// writePlatform renders the edge's own health: certificates, reloads, and the
// cardinality drop counter.
func (m *Metrics) writePlatform(out *printer, s snapshot) {
	out.line("# HELP kanea_edge_tls_certs_not_after Certificate expiry, in unix seconds.")
	out.line("# TYPE kanea_edge_tls_certs_not_after gauge")
	for _, c := range s.certs {
		out.printf("kanea_edge_tls_certs_not_after{%s,%s} %d\n",
			label("cn", c.CommonName), label("source", c.Source), c.NotAfter.Unix())
	}

	out.line("# HELP kanea_edge_config_reloads_total Projection reload attempts.")
	out.line("# TYPE kanea_edge_config_reloads_total counter")
	out.printf("kanea_edge_config_reloads_total{result=\"success\"} %d\n", m.reloadOK.Load())
	out.printf("kanea_edge_config_reloads_total{result=\"failure\"} %d\n", m.reloadFail.Load())

	out.line("# HELP kanea_edge_config_last_reload_success Last successful reload, in unix seconds.")
	out.line("# TYPE kanea_edge_config_last_reload_success gauge")
	out.printf("kanea_edge_config_last_reload_success %d\n", m.lastReloadUnix.Load())

	out.line("# HELP kanea_edge_series_dropped_total Label combinations folded at the per-service cap.")
	out.line("# TYPE kanea_edge_series_dropped_total counter")
	out.printf("kanea_edge_series_dropped_total %d\n", m.dropped.Load())
}

// labelSetFor renders a labelled series' full label set.
func labelSetFor(service string, k labelKey) string {
	return label("service", service) + "," + label("code", k.code) + "," +
		label("method", k.method) + "," + label("protocol", k.protocol)
}

func tcpLabels(k tcpKey) string {
	return label("service", k.service) + "," + label("entrypoint", k.entrypoint)
}

// sortedLabelKeys returns a service's labelled combinations in a stable order,
// so an unchanged service renders byte-identically on every scrape.
func (m *serviceMetrics) sortedLabelKeys() []labelKey {
	m.mu.RLock()
	keys := make([]labelKey, 0, len(m.labelled))
	for k := range m.labelled {
		keys = append(keys, k)
	}
	m.mu.RUnlock()

	sort.Slice(keys, func(i, j int) bool {
		if keys[i].code != keys[j].code {
			return keys[i].code < keys[j].code
		}
		if keys[i].method != keys[j].method {
			return keys[i].method < keys[j].method
		}
		return keys[i].protocol < keys[j].protocol
	})
	return keys
}

func (m *serviceMetrics) seriesAt(k labelKey) *labelledSeries {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.labelled[k]
}

// sortedCounterKeys lists a small counter map's keys in a stable order.
func sortedCounterKeys(mu *sync.RWMutex, m map[string]*atomic.Uint64) []string {
	mu.RLock()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	mu.RUnlock()
	sort.Strings(keys)
	return keys
}

// loadCounter reads one counter out of a guarded map.
func loadCounter[K comparable](mu *sync.RWMutex, m map[K]*atomic.Uint64, key K) uint64 {
	mu.RLock()
	c, ok := m[key]
	mu.RUnlock()
	if !ok {
		return 0
	}
	return c.Load()
}

// clampGauge floors a connection gauge at zero.
//
// Open-connection tracking is two atomics moved from different goroutines — a
// close racing an open can read transiently negative. A negative connection
// count is not a measurement anyone can act on, and it makes a Prometheus graph
// look broken rather than busy.
func clampGauge(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// printer writes the exposition and holds the first failure.
//
// One place that checks the error, rather than fifty call sites each checking a
// write that cannot usefully fail differently: once the response is broken,
// every later line is broken the same way, and the caller has already sent the
// header so it cannot answer with a status either way.
type printer struct {
	w   io.Writer
	n   int64
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	n, err := fmt.Fprintf(p.w, format, args...)
	p.n += int64(n)
	p.err = err
}

func (p *printer) line(s string) { p.printf("%s\n", s) }
