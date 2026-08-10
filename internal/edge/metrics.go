package edge

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// L7 metrics (PRD §9.1, §9.1.1).
//
// The edge is the **primary autoscaling signal for exposed services**: it is
// already in the request path, so counting there costs nothing extra. It
// covers north-south; east-west is the datapath's own map counters (§9.1).
//
// What is published is **cumulative counters**, never a rate or a percentile.
// The edge does not know the scrape interval, does not know how many scrapers
// there are, and must not hold a window that a missed scrape would silently
// reset. kanead differences two readings, which is the same thing it does with
// containerd's CPU counter, and a missed scrape becomes a wider interval rather
// than a lost measurement.
//
// # Two families, and why they have different names
//
// §9.1.1 splits this surface in two. The **aggregate** family — one series per
// service — is the autoscaler's input and is differenced into the in-memory
// rings. The **labelled** family carries `{code,method,protocol}` and is
// retained verbatim by the exporter, never differenced.
//
// They are deliberately spelled with *different metric names*
// (`kanea_edge_requests_total` versus `kanea_edge_service_requests_total`)
// rather than as one name at two label cardinalities. One name carrying both
// would double-count under any `sum()` a user writes and would make
// `promtool check metrics` complain — the aggregate is the same traffic already
// counted once. The labelled names follow Traefik's `_service_`/`_entrypoint_`
// shape, which is the vocabulary someone arriving from it already has.

// latencyBounds are the histogram's upper edges in milliseconds.
//
// Log-spaced, and denser where a decision gets made: `p95_latency_ms` targets
// in the hundreds are what a real scaling rule is written against (§6.1), so
// resolution there is worth more than resolution at 10 ms or at 30 s. The last
// bucket is unbounded, because a request that takes a minute still has to be
// counted somewhere.
var latencyBounds = []float64{1, 2, 5, 10, 25, 50, 100, 200, 400, 800, 1500, 3000, 10000}

// Entrypoint names. Kanea's entrypoints are the two well-known listeners plus
// one per published port (§7.2.2); the set comes from the Store, never from
// anything a client sends.
const (
	// EntrypointWeb is the :80 listener. The name is Traefik's, because an
	// operator migrating a dashboard should not have to relearn it.
	EntrypointWeb = "web"
	// EntrypointWebSecure is the :443 listener.
	EntrypointWebSecure = "websecure"
)

// EntrypointForPort names a published listener's entrypoint (§7.2.2).
func EntrypointForPort(port int) string { return fmt.Sprintf("port-%d", port) }

// Request protocols, derived from the connection rather than read from
// r.Proto: the request line is the client's to write, and a label taken from it
// is a label the client chooses. A closed four-value set (§9.1.1): with the
// nine-method allowlist and lazily created codes, it sits far under
// maxSeriesPerService, and grpc requires the route marker AND the wire to
// agree, so no client can mint the fourth value on an unmarked route.
const (
	ProtocolHTTP      = "http"
	ProtocolHTTPS     = "https"
	ProtocolWebsocket = "websocket"
	// ProtocolGRPC is a request on an R28-marked route that is gRPC on the
	// wire: negotiated HTTP/2 + the application/grpc content type (v1.41).
	ProtocolGRPC = "grpc"
)

// Refusal reasons. A closed set, so no cap is needed on this dimension —
// and separate series because they are separate operator problems: an
// ip_restriction refusal is policy working, a rate_limit refusal is capacity.
const (
	ReasonIPRestriction = "ip_restriction"
	ReasonRateLimit     = "rate_limit"
	// ReasonListenerLimit is a published listener's own max_conns (§7.2.2).
	ReasonListenerLimit = "listener_limit"
	// ReasonNodeLimit is the node-wide --max-published-conns ceiling.
	ReasonNodeLimit = "node_limit"
	// ReasonNoBackends is a udp datagram with nowhere to go (v1.42): the
	// service is starting or scaled to zero, and UDP has no way to tell the
	// client, so the operator's counter is the only witness.
	ReasonNoBackends = "no_backends"
)

// methodOther is where a method outside the RFC set folds.
//
// r.Method is a token from the request line and Go's server accepts an
// arbitrary one, so this dimension is attacker-chosen and cannot be passed
// through. Nine known methods plus one overflow is the whole range.
const methodOther = "OTHER"

// normalizeMethod folds a request method into the allowlist.
//
// A switch rather than a map: it is on the per-request path, and it needs no
// lock, no hashing and no allocation.
func normalizeMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace:
		return method
	default:
		return methodOther
	}
}

// maxSeriesPerService caps the labelled combinations one service may hold.
//
// Codes are upstream-chosen and methods are allowlisted, so the product is
// bounded in ordinary operation — but "ordinary" is not a guarantee, and a
// service that answers a different status per request would otherwise grow this
// map forever. Past the cap everything folds into one overflow series and the
// drop is counted, which is the discipline scaling.Metrics already applies at
// MaxSeries: a cap nobody can see is indistinguishable from a leak.
// It is the ceiling on the *whole* map, and the overflow series occupies one of
// its slots — so a service holds at most maxSeriesPerService-1 distinct
// combinations plus the fold. A cap that admitted N and then added an N+1th for
// the overflow would be a cap that is quietly one larger than it says.
const maxSeriesPerService = 40

// overflowKey is the single series every combination past the cap folds into.
var overflowKey = labelKey{code: "other", method: methodOther, protocol: "other"}

// labelKey is one labelled series within a service.
type labelKey struct {
	code     string
	method   string
	protocol string
}

// tlsKey is one handshake shape. Bounded by the versions and suites the edge
// is configured to accept, so it needs no cap.
type tlsKey struct {
	version string
	cipher  string
}

// tcpKey identifies one published TCP or UDP listener (§7.2.2). The udp
// family reuses it: the key is (service, entrypoint) either way, and the two
// families live in separate maps.
type tcpKey struct {
	service    string
	entrypoint string
}

// labelledSeries is one {code,method,protocol} combination's counters.
type labelledSeries struct {
	requests atomic.Uint64
	// timed counts only the observations that entered the histogram. A hijacked
	// connection is counted in requests but never timed (§9.1.1), and a
	// histogram's _count must equal its +Inf bucket — so the two need separate
	// counters.
	timed atomic.Uint64
	// buckets are cumulative counts per latency bound, plus one overflow.
	buckets []atomic.Uint64
	// durationSum is milliseconds, for a mean that does not need the histogram.
	durationSum atomic.Uint64
}

func newLabelledSeries() *labelledSeries {
	return &labelledSeries{buckets: make([]atomic.Uint64, len(latencyBounds)+1)}
}

// observe records one request into a labelled series. A hijacked connection's
// "duration" is its session lifetime, not a latency, so it skips the histogram
// (timed=false) while still being counted.
func (s *labelledSeries) observe(ms float64, timed bool) {
	s.requests.Add(1)
	if !timed {
		return
	}
	s.timed.Add(1)
	s.durationSum.Add(uint64(ms))

	// Cumulative buckets: bucket i counts everything at or below bound i, which
	// is what `le` means in the exposition format and what makes a percentile
	// computable from a difference of two scrapes.
	idx := sort.SearchFloat64s(latencyBounds, ms)
	for i := idx; i < len(s.buckets); i++ {
		s.buckets[i].Add(1)
	}
}

// serviceMetrics is one service's counters.
//
// The first block is the aggregate family and is what the autoscaler's scraper
// reads; it is unchanged from before §9.1.1 and must stay that way. Everything
// below it is the labelled family, which no scraper differences.
type serviceMetrics struct {
	requests atomic.Uint64
	// timed counts observations that entered the histogram — see
	// labelledSeries.timed for why it is separate from requests.
	timed       atomic.Uint64
	buckets     []atomic.Uint64
	durationSum atomic.Uint64
	// errors counts 5xx responses: the signal that a service is failing rather
	// than merely busy, which are opposite scaling decisions.
	errors atomic.Uint64

	requestBytes  atomic.Uint64
	responseBytes atomic.Uint64
	// inFlight is a gauge, so it decrements — hence Int64. It can be
	// transiently negative under a racing decrement and is clamped at render.
	//
	// Requests, not connections: the handler never sees a connection, and with
	// keep-alive one connection carries many requests.
	inFlight atomic.Int64

	mu sync.RWMutex
	// labelled is the {code,method,protocol} family, capped.
	labelled map[labelKey]*labelledSeries
	tls      map[tlsKey]*atomic.Uint64
	// refused counts requests the middleware rejected before an upstream saw
	// them, by reason. They are not load on the service and must not scale it up.
	refused map[string]*atomic.Uint64
}

func newServiceMetrics() *serviceMetrics {
	return &serviceMetrics{
		buckets:  make([]atomic.Uint64, len(latencyBounds)+1),
		labelled: map[labelKey]*labelledSeries{},
		tls:      map[tlsKey]*atomic.Uint64{},
		refused:  map[string]*atomic.Uint64{},
	}
}

// observeAggregate records into the unlabelled family the scraper reads.
// timed=false counts the request (and any 5xx) without touching the latency
// histogram — a hijacked connection's duration is its session lifetime, and
// one long WebSocket would otherwise dominate the p95 the autoscaler reads.
func (m *serviceMetrics) observeAggregate(ms float64, status int, timed bool) {
	m.requests.Add(1)
	if status >= 500 {
		m.errors.Add(1)
	}
	if !timed {
		return
	}
	m.timed.Add(1)
	m.durationSum.Add(uint64(ms))
	idx := sort.SearchFloat64s(latencyBounds, ms)
	for i := idx; i < len(m.buckets); i++ {
		m.buckets[i].Add(1)
	}
}

// seriesFor returns the labelled series for a key, folding to the overflow
// series once the cap is reached. It reports whether a combination was dropped.
func (m *serviceMetrics) seriesFor(key labelKey) (*labelledSeries, bool) {
	m.mu.RLock()
	s, ok := m.labelled[key]
	m.mu.RUnlock()
	if ok {
		return s, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Re-check: two requests for a new combination race here, and the loser
	// must use the winner's counters rather than replacing them.
	if s, ok = m.labelled[key]; ok {
		return s, false
	}
	// -1 reserves the slot the overflow series will take, so the map never
	// exceeds the stated ceiling.
	if len(m.labelled) >= maxSeriesPerService-1 {
		if s, ok = m.labelled[overflowKey]; ok {
			return s, true
		}
		s = newLabelledSeries()
		m.labelled[overflowKey] = s
		return s, true
	}
	s = newLabelledSeries()
	m.labelled[key] = s
	return s, false
}

// counterIn fetches or creates a counter in one of the small closed-set maps.
func counterIn[K comparable](mu *sync.RWMutex, m map[K]*atomic.Uint64, key K) *atomic.Uint64 {
	mu.RLock()
	c, ok := m[key]
	mu.RUnlock()
	if ok {
		return c
	}
	mu.Lock()
	defer mu.Unlock()
	if c, ok = m[key]; ok {
		return c
	}
	c = &atomic.Uint64{}
	m[key] = c
	return c
}

// entrypointMetrics is one listener's counters (§9.1.1).
type entrypointMetrics struct {
	open atomic.Int64

	mu sync.RWMutex
	// requests is keyed by status code. Bounded by the same cap as a service's
	// labelled family, for the same reason.
	requests map[string]*atomic.Uint64
}

func newEntrypointMetrics() *entrypointMetrics {
	return &entrypointMetrics{requests: map[string]*atomic.Uint64{}}
}

// tcpMetrics is one published TCP listener's counters (§7.2.2).
//
// These had no coverage at all before v1.35, which is why `ErrTooManyConns`
// carried a comment saying it existed "so the refusal is countable" while
// nothing counted it.
type tcpMetrics struct {
	connections atomic.Uint64
	active      atomic.Int64
	bytesIn     atomic.Uint64
	bytesOut    atomic.Uint64

	mu      sync.RWMutex
	refused map[string]*atomic.Uint64
}

func newTCPMetrics() *tcpMetrics {
	return &tcpMetrics{refused: map[string]*atomic.Uint64{}}
}

// udpMetrics is one published UDP listener's counters (v1.42, §7.2.2).
//
// Sessions, not connections — a udp "connection" is an entry in the relay's
// table — and expiries are counted separately from ordinary closes, because a
// session cap or an aggressive expiry that nobody can see is indistinguishable
// from packet loss.
type udpMetrics struct {
	sessions atomic.Uint64
	active   atomic.Int64
	expired  atomic.Uint64
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64

	mu      sync.RWMutex
	refused map[string]*atomic.Uint64
}

func newUDPMetrics() *udpMetrics {
	return &udpMetrics{refused: map[string]*atomic.Uint64{}}
}

// CertExpiry is one certificate in the bundle the edge is serving (§7.3).
//
// Published as a gauge of the expiry instant rather than of a remaining
// duration: a duration is only true at the moment it is scraped, and a stale
// sample of one reads as a certificate that is still fine.
type CertExpiry struct {
	// CommonName is what the certificate is for.
	CommonName string
	// Source is the §7.3 mode that supplied it: acme, self-signed, provided.
	Source string
	// NotAfter is when it stops being valid.
	NotAfter time.Time
}

// Metrics collects the edge's request, connection and platform counters.
type Metrics struct {
	mu          sync.RWMutex
	services    map[string]*serviceMetrics
	entrypoints map[string]*entrypointMetrics
	tcp         map[tcpKey]*tcpMetrics
	udp         map[tcpKey]*udpMetrics
	certs       []CertExpiry

	dropped        atomic.Uint64
	reloadOK       atomic.Uint64
	reloadFail     atomic.Uint64
	lastReloadUnix atomic.Int64
}

// NewMetrics builds an empty collector.
func NewMetrics() *Metrics {
	return &Metrics{
		services:    map[string]*serviceMetrics{},
		entrypoints: map[string]*entrypointMetrics{},
		tcp:         map[tcpKey]*tcpMetrics{},
		udp:         map[tcpKey]*udpMetrics{},
	}
}

// Observation is one completed HTTP request.
//
// A struct rather than ten positional arguments: every field here is a label or
// a measurement, and a call site that transposed two strings would produce a
// metric that is wrong in a way no compiler and no test would notice.
type Observation struct {
	// Service is the route's project/service name.
	Service string
	// Entrypoint is the listener the request arrived on.
	Entrypoint string
	// Status is the response status code.
	Status int
	// Method is the request method, folded through the allowlist here.
	Method string
	// Protocol is http, https, websocket or grpc.
	Protocol string
	// Duration is the time spent in the upstream call.
	Duration time.Duration
	// Hijacked marks a connection that was upgraded and taken over. It is
	// counted as a request but excluded from the latency histograms: ServeHTTP
	// returns when the session ends, so its "duration" is a lifetime, and one
	// long WebSocket would poison the p95 the autoscaler reads (§9.1.1).
	Hijacked bool
	// RequestBytes and ResponseBytes are the body bytes actually moved.
	RequestBytes  int64
	ResponseBytes int64
	// TLSVersion and TLSCipher are empty on a plaintext connection.
	TLSVersion string
	TLSCipher  string
}

// Observe records one completed request.
func (m *Metrics) Observe(o Observation) {
	if o.Service == "" {
		return
	}
	ms := float64(o.Duration.Microseconds()) / 1000
	code := statusLabel(o.Status)

	sm := m.service(o.Service)
	sm.observeAggregate(ms, o.Status, !o.Hijacked)

	if o.RequestBytes > 0 {
		sm.requestBytes.Add(uint64(o.RequestBytes))
	}
	if o.ResponseBytes > 0 {
		sm.responseBytes.Add(uint64(o.ResponseBytes))
	}

	protocol := o.Protocol
	if protocol == "" {
		protocol = ProtocolHTTP
	}
	series, dropped := sm.seriesFor(labelKey{
		code: code, method: normalizeMethod(o.Method), protocol: protocol,
	})
	series.observe(ms, !o.Hijacked)
	if dropped {
		m.dropped.Add(1)
	}

	if o.TLSVersion != "" {
		counterIn(&sm.mu, sm.tls, tlsKey{version: o.TLSVersion, cipher: o.TLSCipher}).Add(1)
	}

	if o.Entrypoint != "" {
		ep := m.entrypoint(o.Entrypoint)
		ep.mu.RLock()
		full := len(ep.requests) >= maxSeriesPerService
		ep.mu.RUnlock()
		if full {
			code = overflowKey.code
		}
		counterIn(&ep.mu, ep.requests, code).Add(1)
	}
}

// Refused records a request the middleware rejected, by reason.
//
// Counted separately and never as a request: a service being hammered by
// blocked addresses is not a service under load, and scaling it up would spend
// capacity on traffic the edge is already dropping.
func (m *Metrics) Refused(service, reason string) {
	if service == "" {
		return
	}
	sm := m.service(service)
	counterIn(&sm.mu, sm.refused, reason).Add(1)
}

// ConnOpened and ConnClosed move the per-entrypoint connection gauge. They are
// driven from http.Server's ConnState hook, which is the only place that sees
// a connection rather than a request.
func (m *Metrics) ConnOpened(entrypoint string) {
	if entrypoint != "" {
		m.entrypoint(entrypoint).open.Add(1)
	}
}

// ConnClosed is ConnOpened's pair.
func (m *Metrics) ConnClosed(entrypoint string) {
	if entrypoint != "" {
		m.entrypoint(entrypoint).open.Add(-1)
	}
}

// RequestStarted and RequestFinished move the per-service in-flight gauge.
//
// Paired around the upstream call, so the gauge answers "how many requests is
// this service handling right now" — the number that distinguishes a service
// that is slow from one that is merely busy.
func (m *Metrics) RequestStarted(service string) {
	if service != "" {
		m.service(service).inFlight.Add(1)
	}
}

// RequestFinished is RequestStarted's pair.
func (m *Metrics) RequestFinished(service string) {
	if service != "" {
		m.service(service).inFlight.Add(-1)
	}
}

// TCPAccepted records an accepted connection on a published TCP listener.
func (m *Metrics) TCPAccepted(service, entrypoint string) {
	t := m.tcpCounters(service, entrypoint)
	t.connections.Add(1)
	t.active.Add(1)
}

// TCPClosed records a finished connection and the bytes it moved.
func (m *Metrics) TCPClosed(service, entrypoint string, bytesIn, bytesOut int64) {
	t := m.tcpCounters(service, entrypoint)
	t.active.Add(-1)
	if bytesIn > 0 {
		t.bytesIn.Add(uint64(bytesIn))
	}
	if bytesOut > 0 {
		t.bytesOut.Add(uint64(bytesOut))
	}
}

// TCPRefused records a connection turned away before it was relayed.
func (m *Metrics) TCPRefused(service, entrypoint, reason string) {
	t := m.tcpCounters(service, entrypoint)
	counterIn(&t.mu, t.refused, reason).Add(1)
}

// UDPSessionOpened records a new session on a published UDP listener (v1.42).
func (m *Metrics) UDPSessionOpened(service, entrypoint string) {
	u := m.udpCounters(service, entrypoint)
	u.sessions.Add(1)
	u.active.Add(1)
}

// UDPSessionClosed records a finished session, the bytes it moved, and whether
// the idle expiry (rather than an upstream error or a shutdown) ended it.
func (m *Metrics) UDPSessionClosed(service, entrypoint string, bytesIn, bytesOut int64, expired bool) {
	u := m.udpCounters(service, entrypoint)
	u.active.Add(-1)
	if expired {
		u.expired.Add(1)
	}
	if bytesIn > 0 {
		u.bytesIn.Add(uint64(bytesIn))
	}
	if bytesOut > 0 {
		u.bytesOut.Add(uint64(bytesOut))
	}
}

// UDPRefused records a datagram that was denied a session.
func (m *Metrics) UDPRefused(service, entrypoint, reason string) {
	u := m.udpCounters(service, entrypoint)
	counterIn(&u.mu, u.refused, reason).Add(1)
}

// SetCertificates replaces the certificate expiry gauges.
//
// Wholesale, unlike certsource.Publisher's per-source merge: the edge reads one
// finished bundle and has no idea which source contributed what beyond the
// label each entry carries. A partial update here would strand an expiry gauge
// for a certificate that is no longer being served.
func (m *Metrics) SetCertificates(certs []CertExpiry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs = append([]CertExpiry(nil), certs...)
}

// Reloaded records a projection reload attempt (§9.1.1).
//
// Both outcomes are counted. "The route never went live" and "the route is
// wrong" are different problems that look identical from outside, and the
// reload counter is what separates them.
func (m *Metrics) Reloaded(ok bool, at time.Time) {
	if ok {
		m.reloadOK.Add(1)
		m.lastReloadUnix.Store(at.Unix())
		return
	}
	m.reloadFail.Add(1)
}

// Forget drops a service's counters when it leaves the route table.
func (m *Metrics) Forget(service string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.services, service)
	for key := range m.tcp {
		if key.service == service {
			delete(m.tcp, key)
		}
	}
	for key := range m.udp {
		if key.service == service {
			delete(m.udp, key)
		}
	}
}

// Retain drops every service not in the given set, which is how the collector
// follows a reloaded route table without leaking the services it dropped.
//
// It sweeps the labelled families with them. A service's labelled map can hold
// maxSeriesPerService entries, so a route table that churns without this would
// leak forty series per departed service rather than one.
func (m *Metrics) Retain(keep map[string]bool) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	dropped := 0
	for service := range m.services {
		if !keep[service] {
			delete(m.services, service)
			dropped++
		}
	}
	for key := range m.tcp {
		if !keep[key.service] {
			delete(m.tcp, key)
		}
	}
	for key := range m.udp {
		if !keep[key.service] {
			delete(m.udp, key)
		}
	}
	return dropped
}

// RetainEntrypoints drops every entrypoint not in the given set, so a published
// port that is withdrawn stops being reported.
func (m *Metrics) RetainEntrypoints(keep map[string]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name := range m.entrypoints {
		if !keep[name] {
			delete(m.entrypoints, name)
		}
	}
}

func (m *Metrics) service(name string) *serviceMetrics {
	m.mu.RLock()
	sm, ok := m.services[name]
	m.mu.RUnlock()
	if ok {
		return sm
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Re-check: two requests for a new service race here, and the loser must
	// use the winner's counters rather than replacing them.
	if sm, ok = m.services[name]; ok {
		return sm
	}
	sm = newServiceMetrics()
	m.services[name] = sm
	return sm
}

func (m *Metrics) entrypoint(name string) *entrypointMetrics {
	m.mu.RLock()
	ep, ok := m.entrypoints[name]
	m.mu.RUnlock()
	if ok {
		return ep
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if ep, ok = m.entrypoints[name]; ok {
		return ep
	}
	ep = newEntrypointMetrics()
	m.entrypoints[name] = ep
	return ep
}

func (m *Metrics) tcpCounters(service, entrypoint string) *tcpMetrics {
	key := tcpKey{service: service, entrypoint: entrypoint}

	m.mu.RLock()
	t, ok := m.tcp[key]
	m.mu.RUnlock()
	if ok {
		return t
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok = m.tcp[key]; ok {
		return t
	}
	t = newTCPMetrics()
	m.tcp[key] = t
	return t
}

func (m *Metrics) udpCounters(service, entrypoint string) *udpMetrics {
	key := tcpKey{service: service, entrypoint: entrypoint}

	m.mu.RLock()
	u, ok := m.udp[key]
	m.mu.RUnlock()
	if ok {
		return u
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok = m.udp[key]; ok {
		return u
	}
	u = newUDPMetrics()
	m.udp[key] = u
	return u
}

// statusLabel renders a status code for the `code` label.
//
// Exact, so a dashboard written against Traefik's `code="502"` matches. A
// status outside the valid range cannot come from an upstream response, but
// ServeHTTP's contract does not enforce that, so it folds rather than becoming
// a series named after whatever an upstream handler passed to WriteHeader.
func statusLabel(status int) string {
	if status < 100 || status > 599 {
		return overflowKey.code
	}
	return fmt.Sprintf("%d", status)
}
