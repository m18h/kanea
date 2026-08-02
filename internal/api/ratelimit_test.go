package api_test

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/auth"
	"github.com/kanea-dev/kanea/internal/ratelimit"
)

// tightLimits makes both tiers small enough to exhaust in a test without
// making the test about how fast it can send requests.
func tightLimits(public, authenticated int) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) {
		cfg.PublicLimit = &ratelimit.Spec{Requests: public, Window: time.Minute}
		cfg.AuthLimit = &ratelimit.Spec{Requests: authenticated, Window: time.Minute}
	}
}

func TestPublicRoutesAreRateLimited(t *testing.T) {
	h := newAuthHarness(t, tightLimits(3, 100))

	for i := range 3 {
		resp, body := h.do(t, h.request(t, http.MethodGet, api.PathHealth, nil))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d = %d, want 200: %s", i, resp.StatusCode, body)
		}
	}

	resp, body := h.do(t, h.request(t, http.MethodGet, api.PathHealth, nil))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429: %s", resp.StatusCode, body)
	}
	// A client that is told to come back needs to be told when, or it comes
	// back immediately and is refused again.
	retry := resp.Header.Get("Retry-After")
	if retry == "" {
		t.Fatal("no Retry-After on a 429")
	}
	if seconds, err := strconv.Atoi(retry); err != nil || seconds < 0 {
		t.Errorf("Retry-After = %q, want a non-negative number of seconds", retry)
	}
}

func TestLoginIsBoundedBeforeItCostsAnything(t *testing.T) {
	h := newAuthHarness(t, tightLimits(2, 100))

	// Login is the expensive public route — bcrypt by design — so the limiter
	// has to refuse it before the password is ever checked (§14, A07).
	for range 2 {
		h.do(t, h.request(t, http.MethodPost, api.PathLogin,
			api.LoginRequest{User: adminUser, Password: "wrong"}))
	}
	resp, body := h.do(t, h.request(t, http.MethodPost, api.PathLogin,
		api.LoginRequest{User: adminUser, Password: adminPass}))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 even for a correct password: %s", resp.StatusCode, body)
	}
}

func TestTheTwoTiersHaveSeparateBuckets(t *testing.T) {
	h := newAuthHarness(t, tightLimits(2, 100))
	token := h.token(t, auth.RoleAdmin)

	// Exhaust the public tier from this address.
	for range 3 {
		h.do(t, h.request(t, http.MethodGet, api.PathHealth, nil))
	}

	// An authenticated request from the same address is unaffected: otherwise
	// anyone who can reach the daemon could lock out its operator by spending
	// the shared allowance.
	req := h.request(t, http.MethodGet, api.PathServices, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated request = %d, want 200: %s", resp.StatusCode, body)
	}
}

func TestAuthenticatedRequestsAreRateLimitedToo(t *testing.T) {
	h := newAuthHarness(t, tightLimits(100, 3))
	token := h.token(t, auth.RoleAdmin)

	authGet := func() int {
		req := h.request(t, http.MethodGet, api.PathServices, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, _ := h.do(t, req)
		return resp.StatusCode
	}
	for i := range 3 {
		if got := authGet(); got != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i, got)
		}
	}
	// A valid credential is not a licence to hammer: the limit is looser, not
	// absent.
	if got := authGet(); got != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", got)
	}
}

func TestSocketCallersAreNotRateLimited(t *testing.T) {
	// The CLI is the local root of §13.1, and every socket caller shares one
	// meaningless source address — a limit there would throttle `kanea ps` in a
	// loop against nothing.
	h := newHarness(t, tightLimits(1, 1))
	for i := range 20 {
		if status, body := h.raw(t, http.MethodGet, api.PathHealth); status != http.StatusOK {
			t.Fatalf("socket request %d = %d: %s", i, status, body)
		}
	}
}

func TestRateLimitRefusalIsCounted(t *testing.T) {
	h := newAuthHarness(t, tightLimits(1, 100))
	before := api.RateLimited()

	for range 3 {
		h.do(t, h.request(t, http.MethodGet, api.PathHealth, nil))
	}
	if api.RateLimited() <= before {
		t.Fatal("refusals are not counted; the condition would be invisible")
	}
}

func TestRateLimitCanBeDisabled(t *testing.T) {
	// An explicitly invalid spec turns a tier off. It is a deliberate decision
	// rather than an accident of a zero value, which takes the defaults.
	h := newAuthHarness(t, func(cfg *api.ServerConfig) {
		cfg.PublicLimit = &ratelimit.Spec{}
	})
	for i := range 50 {
		if resp, body := h.do(t, h.request(t, http.MethodGet, api.PathHealth, nil)); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d = %d with limits off: %s", i, resp.StatusCode, body)
		}
	}
}
