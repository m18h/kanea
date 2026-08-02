package acme_test

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/kanea-dev/kanea/internal/acme"
)

const (
	testTSIGKey    = "kanea-update."
	testTSIGSecret = "c2VjcmV0LWtleS1mb3ItdGVzdGluZy1vbmx5" // base64, test-only
)

// updateServer is a nameserver that accepts TSIG-signed dynamic updates and
// records them. It exists because the interesting part of the solver is what
// goes on the wire — a mocked client would assert the code against itself.
type updateServer struct {
	addr string

	mu      sync.Mutex
	added   []dns.RR
	removed []dns.RR
	// verified records whether the last update carried a valid signature.
	verified bool
	// rcode overrides the reply, so a refusal can be tested.
	rcode int
}

func newUpdateServer(t *testing.T) *updateServer {
	t.Helper()

	s := &updateServer{rcode: dns.RcodeSuccess}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &dns.Server{
		Listener:   listener,
		TsigSecret: map[string]string{testTSIGKey: testTSIGSecret},
		Handler:    dns.HandlerFunc(s.handle),
		// miekg/dns refuses UPDATE with NOTIMP by default, which is the right
		// default for a resolver — Kanea's own (§7.1) keeps it, so nobody can
		// write records into the internal zone. A nameserver that accepts
		// dynamic updates has to opt in, and so does this stand-in for one.
		MsgAcceptFunc: func(dh dns.Header) dns.MsgAcceptAction {
			if opcode := int(dh.Bits>>11) & 0xF; opcode == dns.OpcodeUpdate {
				return dns.MsgAccept
			}
			return dns.DefaultMsgAcceptFunc(dh)
		},
	}
	go func() {
		// The listener is closed by Shutdown; a serve error after that is the
		// shutdown itself.
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Logf("shutdown: %v", err)
		}
	})

	s.addr = listener.Addr().String()
	return s
}

func (s *updateServer) handle(w dns.ResponseWriter, req *dns.Msg) {
	// TsigStatus is nil only when the signature verified against the shared
	// secret; an unsigned or wrongly-signed update lands here with an error.
	signed := req.IsTsig() != nil && w.TsigStatus() == nil
	if !signed {
		// What a real nameserver does with an update it cannot authenticate,
		// and the behaviour the solver has to surface rather than assume the
		// record landed.
		reply := new(dns.Msg)
		reply.SetRcode(req, dns.RcodeNotAuth)
		_ = w.WriteMsg(reply)
		return
	}

	s.mu.Lock()
	s.verified = signed
	for _, rr := range req.Ns {
		// A deletion is expressed as a record with class NONE (RFC 2136 §2.5.4);
		// anything else in the update section is an addition.
		if rr.Header().Class == dns.ClassNONE {
			s.removed = append(s.removed, rr)
		} else {
			s.added = append(s.added, rr)
		}
	}
	rcode := s.rcode
	s.mu.Unlock()

	reply := new(dns.Msg)
	reply.SetRcode(req, rcode)
	reply.SetTsig(testTSIGKey, dns.HmacSHA256, tsigFudgeSeconds, time.Now().Unix())
	if err := w.WriteMsg(reply); err != nil {
		return
	}
}

// tsigFudgeSeconds is the skew a signature tolerates, matching the solver's.
const tsigFudgeSeconds = 300

func (s *updateServer) snapshot() (added, removed []dns.RR, verified bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]dns.RR(nil), s.added...), append([]dns.RR(nil), s.removed...), s.verified
}

func newSolver(t *testing.T, server *updateServer, adjust ...func(*acme.RFC2136Config)) *acme.RFC2136Solver {
	t.Helper()
	cfg := acme.RFC2136Config{
		Server:     server.addr,
		Zone:       "apps.example.com.",
		TSIGKey:    testTSIGKey,
		TSIGSecret: testTSIGSecret,
	}
	for _, apply := range adjust {
		apply(&cfg)
	}
	solver, err := acme.NewRFC2136Solver(cfg)
	if err != nil {
		t.Fatalf("NewRFC2136Solver: %v", err)
	}
	return solver
}

func TestDNS01PublishesASignedChallengeRecord(t *testing.T) {
	server := newUpdateServer(t)
	solver := newSolver(t, server)

	if err := solver.Present("web.shop.apps.example.com", "token", "key-authorization"); err != nil {
		t.Fatalf("Present: %v", err)
	}

	added, _, verified := server.snapshot()
	if !verified {
		// An unsigned update is one anyone on the network can send, and what
		// they can send is a passing ACME challenge for a name they do not own.
		t.Fatal("the update was not TSIG-verified")
	}
	if len(added) != 1 {
		t.Fatalf("added %d records, want 1", len(added))
	}
	txt, ok := added[0].(*dns.TXT)
	if !ok {
		t.Fatalf("record = %T, want TXT", added[0])
	}
	if got := txt.Hdr.Name; got != "_acme-challenge.web.shop.apps.example.com." {
		t.Errorf("name = %q, want the _acme-challenge name", got)
	}
	if len(txt.Txt) != 1 || txt.Txt[0] == "" {
		t.Errorf("value = %v, want the key authorization digest", txt.Txt)
	}
	// The digest, never the key authorization itself.
	if strings.Contains(txt.Txt[0], "key-authorization") {
		t.Errorf("the raw key authorization was published: %q", txt.Txt[0])
	}
}

func TestDNS01WildcardUsesTheParentName(t *testing.T) {
	server := newUpdateServer(t)
	solver := newSolver(t, server)

	// A wildcard's challenge lives at the parent's `_acme-challenge` name —
	// the same place the bare name's does, which is why one authorization
	// covers both and why the star must not reach the record name.
	if err := solver.Present("*.shop.apps.example.com", "token", "key-auth"); err != nil {
		t.Fatalf("Present: %v", err)
	}

	added, _, _ := server.snapshot()
	if len(added) != 1 {
		t.Fatalf("added %d records, want 1", len(added))
	}
	if got := added[0].Header().Name; got != "_acme-challenge.shop.apps.example.com." {
		t.Fatalf("name = %q; a star in a record name is not a name any resolver serves", got)
	}
}

func TestDNS01CleanUpRemovesTheRecord(t *testing.T) {
	server := newUpdateServer(t)
	solver := newSolver(t, server)

	if err := solver.Present("web.shop.apps.example.com", "token", "key-auth"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := solver.CleanUp("web.shop.apps.example.com", "token", "key-auth"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	_, removed, _ := server.snapshot()
	if len(removed) != 1 {
		t.Fatalf("removed %d records, want 1", len(removed))
	}
	if got := removed[0].Header().Name; got != "_acme-challenge.web.shop.apps.example.com." {
		t.Errorf("removed %q", got)
	}
}

func TestDNS01ReportsARefusal(t *testing.T) {
	server := newUpdateServer(t)
	// REFUSED is what a server answers for a zone it does not serve — the
	// second most common misconfiguration after a key that is not permitted.
	server.rcode = dns.RcodeRefused
	solver := newSolver(t, server)

	err := solver.Present("web.shop.apps.example.com", "token", "key-auth")
	if err == nil {
		t.Fatal("a refused update was reported as success")
	}
	// Naming the code is what makes the misconfiguration findable.
	if !strings.Contains(err.Error(), "REFUSED") {
		t.Errorf("err = %v, want the rcode named", err)
	}
}

func TestDNS01RejectsAWrongKey(t *testing.T) {
	server := newUpdateServer(t)
	solver := newSolver(t, server, func(cfg *acme.RFC2136Config) {
		cfg.TSIGSecret = "d3Jvbmctc2VjcmV0LWZvci10ZXN0aW5nLW9ubHk="
	})

	// The server refuses the signature; the point is that the solver surfaces
	// it rather than assuming the record landed.
	if err := solver.Present("web.shop.apps.example.com", "token", "key-auth"); err == nil {
		t.Fatal("an update signed with the wrong key was reported as success")
	}
}

func TestNewRFC2136SolverRefusesAnUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  acme.RFC2136Config
	}{
		{"no server", acme.RFC2136Config{TSIGKey: "k", TSIGSecret: "s"}},
		{"no key", acme.RFC2136Config{Server: "127.0.0.1:53", TSIGSecret: "s"}},
		{"no secret", acme.RFC2136Config{Server: "127.0.0.1:53", TSIGKey: "k"}},
		{"unknown algorithm", acme.RFC2136Config{
			Server: "127.0.0.1:53", TSIGKey: "k", TSIGSecret: "s", TSIGAlgorithm: "hmac-md4",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := acme.NewRFC2136Solver(tc.cfg); err == nil {
				t.Fatal("an unusable or unsigned configuration was accepted")
			}
		})
	}
}
