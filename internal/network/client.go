package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultSocketPath is where cilium-agent listens (PRD §5.2.5).
const DefaultSocketPath = "/var/run/cilium/cilium.sock"

// Errors callers branch on.
var (
	// ErrEndpointNotFound means the agent knows no endpoint for that alloc.
	ErrEndpointNotFound = errors.New("network: endpoint not found")
	// ErrAgentUnavailable means the agent socket could not be reached at all —
	// distinct from an error *from* the agent, because it is the signal that
	// cilium-agent is down rather than that the request was wrong.
	ErrAgentUnavailable = errors.New("network: cilium agent unavailable")
)

// client speaks the cilium-agent REST API over its unix socket.
//
// It is hand-written against the four calls Kanea needs, with plain net/http
// and only the response fields we consume. Importing github.com/cilium/cilium
// for its generated client is not an option: that module requires the whole
// Kubernetes client graph, which AGENTS.md constraint #10 forbids outright, and
// it would drag a large CVE surface behind release gates that are meant to stay
// clean (§14). Four stable GET/PATCH calls do not justify that trade.
//
// Everything the agent *writes* — services, policies — arrives through watched
// files instead (lb.go, policy.go); the writable REST APIs were removed in
// Cilium 1.18 (M0 spike ①).
type client struct {
	http *http.Client
	sock string
}

// newClient builds a client bound to one agent socket. It does not dial: a
// constructor that fails because the agent is not up yet would make kanead's
// start order depend on cilium-agent's. Use Health for that check.
func newClient(sock string, timeout time.Duration) *client {
	if sock == "" {
		sock = DefaultSocketPath
	}
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	return &client{
		sock: sock,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", sock)
				},
				// One agent, one socket: a large pool buys nothing and a leaked
				// idle connection per attach would be a slow resource leak.
				MaxIdleConns:    2,
				IdleConnTimeout: 30 * time.Second,
			},
		},
	}
}

// DefaultRequestTimeout bounds every agent call. Nothing here may block the
// reconcile loop indefinitely: an agent that is regenerating endpoints under
// load answers slowly, and a hung call would stall every other alloc's attach.
const DefaultRequestTimeout = 30 * time.Second

// do performs one API call, decoding a 2xx JSON body into out when out != nil.
// The status code is returned even for errors, because the caller's retry
// decision depends on it (5xx is a race worth retrying, 4xx is our bug).
func (c *client) do(ctx context.Context, method, path string, body, out any) (code int, msg string, err error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, "", fmt.Errorf("encode %s %s: %w", method, path, err)
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, "http://cilium/v1"+path, rdr)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// A dial failure is the agent being down; anything else is in-flight.
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			return 0, "", fmt.Errorf("%w at %s: %w", ErrAgentUnavailable, c.sock, err)
		}
		return 0, "", fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	// Bound the body: a wedged agent must not be able to exhaust kanead's heap.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("read %s %s: %w", method, path, err)
	}
	if resp.StatusCode >= 300 || out == nil {
		return resp.StatusCode, strings.TrimSpace(string(raw)), nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return resp.StatusCode, "", fmt.Errorf("decode %s %s: %w", method, path, err)
	}
	return resp.StatusCode, "", nil
}

// maxResponseBytes caps a single agent reply. The largest thing we read is the
// endpoint list, a few KiB per endpoint at the target scale of §21.
const maxResponseBytes = 32 << 20

// ---- endpoints ----

// endpoint is the slice of Cilium's endpoint model Kanea consumes.
type endpoint struct {
	ID     int64 `json:"id"`
	Status struct {
		ExternalIdentifiers struct {
			ContainerID string `json:"container-id"`
		} `json:"external-identifiers"`
		Identity struct {
			ID     int64    `json:"id"`
			Labels []string `json:"labels"`
		} `json:"identity"`
		Networking struct {
			Addressing []struct {
				IPv4 string `json:"ipv4"`
				IPv6 string `json:"ipv6"`
			} `json:"addressing"`
			InterfaceName string `json:"interface-name"`
		} `json:"networking"`
		State string `json:"state"`
	} `json:"status"`
}

func (e *endpoint) ipv4() string {
	for _, a := range e.Status.Networking.Addressing {
		if a.IPv4 != "" {
			return a.IPv4
		}
	}
	return ""
}

// ready reports whether the endpoint carries a real security identity — one
// allocated from the kvstore rather than a reserved one.
//
// Identities below MinAllocatedIdentity are reserved, and `reserved:init` in
// particular is policy-enforced deny in *both* directions. An endpoint that
// still holds it is not merely unlabelled: its workload is cut off from the
// network entirely (M0 spike ①).
func (e *endpoint) ready() bool {
	return e.Status.Identity.ID >= MinAllocatedIdentity &&
		e.Status.State == endpointStateReady &&
		!hasLabel(e.Status.Identity.Labels, initLabel)
}

// MinAllocatedIdentity is the first non-reserved Cilium security identity.
const MinAllocatedIdentity = 256

const (
	endpointStateReady = "ready"
	// initLabel marks an endpoint whose identity has not been resolved. Traffic
	// to and from it is denied.
	initLabel = "reserved:init"
)

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// endpointByAlloc looks up the endpoint the CNI plugin created for an alloc.
// The container id is the lookup key the plugin records.
func (c *client) endpointByAlloc(ctx context.Context, allocID string) (*endpoint, error) {
	var out endpoint
	code, msg, err := c.do(ctx, http.MethodGet, "/endpoint/container-id:"+allocID, nil, &out)
	switch {
	case err != nil:
		return nil, err
	case code == http.StatusNotFound:
		return nil, fmt.Errorf("%w: alloc %s", ErrEndpointNotFound, allocID)
	case code != http.StatusOK:
		return nil, fmt.Errorf("get endpoint %s: %d %s", allocID, code, msg)
	}
	return &out, nil
}

// endpoints lists every endpoint the agent knows, Kanea's and everyone else's.
func (c *client) endpoints(ctx context.Context) ([]endpoint, error) {
	var out []endpoint
	code, msg, err := c.do(ctx, http.MethodGet, "/endpoint", nil, &out)
	switch {
	case err != nil:
		return nil, err
	// An agent with no endpoints answers 404 rather than an empty list.
	case code == http.StatusNotFound:
		return nil, nil
	case code != http.StatusOK:
		return nil, fmt.Errorf("list endpoints: %d %s", code, msg)
	}
	return out, nil
}

// setIdentityLabels replaces an endpoint's identity labels, which is what turns
// a freshly created (and therefore isolated) endpoint into a member of its
// project.
//
// It must be this call. `PATCH /endpoint/{id}/labels` looks like the right one
// and is not: it *merges* custom labels and leaves `reserved:init` in place, so
// the endpoint stays under init policy and its traffic keeps being dropped.
// `PATCH /endpoint/{id}` replaces the identity label set. `state` is a required
// field of the request body — without it the agent answers 422 (M0 spike ①).
//
// Retries are not defensive: the call lands while the endpoint CNI just created
// is still regenerating, and the agent then answers 500 "error while
// regenerating endpoint" — about one attach in eight during the spike. A 4xx is
// a malformed request, which retrying cannot fix.
func (c *client) setIdentityLabels(ctx context.Context, allocID string, labels []string, retry backoff) error {
	body := map[string]any{"labels": labels, "state": "waiting-for-identity"}

	var lastErr error
	for attempt := range retry.attempts() {
		code, msg, err := c.do(ctx, http.MethodPatch, "/endpoint/container-id:"+allocID, body, nil)
		switch {
		case err != nil:
			lastErr = err
			if errors.Is(err, ErrAgentUnavailable) {
				return err // the agent is down; retrying here just burns the budget
			}
		case code == http.StatusOK:
			return nil
		case code < 500:
			return fmt.Errorf("set labels on %s: %d %s", allocID, code, msg)
		default:
			lastErr = fmt.Errorf("set labels on %s: %d %s", allocID, code, msg)
		}

		if err := retry.wait(ctx, attempt); err != nil {
			return errors.Join(lastErr, err)
		}
	}
	return fmt.Errorf("set labels on %s after %d attempts: %w", allocID, retry.attempts(), lastErr)
}

// health reports whether the agent answers at all.
func (c *client) health(ctx context.Context) error {
	code, msg, err := c.do(ctx, http.MethodGet, "/healthz", nil, nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("cilium health: %d %s", code, msg)
	}
	return nil
}

// backoff is a bounded retry schedule.
type backoff struct {
	// Attempts is the total number of tries, not the number of retries.
	Attempts int
	// Step is multiplied by the attempt number: 300ms, 600ms, 900ms…
	Step time.Duration
}

// defaultBackoff covers the endpoint-regeneration window observed in spike ①
// (~2.6 s total) without stalling a reconcile pass.
var defaultBackoff = backoff{Attempts: 6, Step: 300 * time.Millisecond}

func (b backoff) attempts() int {
	if b.Attempts <= 0 {
		return defaultBackoff.Attempts
	}
	return b.Attempts
}

func (b backoff) step() time.Duration {
	if b.Step <= 0 {
		return defaultBackoff.Step
	}
	return b.Step
}

// wait sleeps before the next attempt, honouring cancellation.
func (b backoff) wait(ctx context.Context, attempt int) error {
	timer := time.NewTimer(time.Duration(attempt+1) * b.step())
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
