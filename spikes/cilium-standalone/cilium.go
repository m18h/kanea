package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// The agent API is spoken over the unix socket with plain net/http and
// hand-written structs on purpose: importing github.com/cilium/cilium as a Go
// module drags in the whole Kubernetes client graph, which AGENTS.md constraint
// #10 forbids. Only the fields Kanea actually needs are modelled here.

type ciliumClient struct{ http *http.Client }

func newCiliumClient() *ciliumClient {
	return &ciliumClient{http: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", ciliumSock)
			},
		},
	}}
}

// do performs an API call and, when out != nil and the response is 2xx,
// decodes the JSON body into it. The HTTP status is always returned.
func (c *ciliumClient) do(ctx context.Context, method, path string, body, out any) (int, string, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, "", err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://cilium/v1"+path, rdr)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	if resp.StatusCode >= 300 || out == nil {
		return resp.StatusCode, strings.TrimSpace(string(raw)), nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return resp.StatusCode, string(raw), fmt.Errorf("decode %s %s: %w", method, path, err)
	}
	return resp.StatusCode, "", nil
}

// ---- endpoints ----

type epModel struct {
	ID     int64 `json:"id"`
	Status struct {
		ExternalIdentifiers struct {
			ContainerID     string `json:"container-id"`
			CNIAttachmentID string `json:"cni-attachment-id"`
		} `json:"external-identifiers"`
		Identity struct {
			ID     int64    `json:"id"`
			Labels []string `json:"labels"`
		} `json:"identity"`
		Networking struct {
			Addressing []struct {
				IPv4 string `json:"ipv4"`
			} `json:"addressing"`
			InterfaceName string `json:"interface-name"`
		} `json:"networking"`
		State  string `json:"state"`
		Labels struct {
			Realized struct {
				User []string `json:"user"`
			} `json:"realized"`
			SecurityRelevant []string `json:"security-relevant"`
		} `json:"labels"`
		Policy struct {
			Realized struct {
				PolicyEnabled string `json:"policy-enabled"`
			} `json:"realized"`
		} `json:"policy"`
	} `json:"status"`
}

func (e *epModel) ipv4() string {
	for _, a := range e.Status.Networking.Addressing {
		if a.IPv4 != "" {
			return a.IPv4
		}
	}
	return ""
}

func (c *ciliumClient) endpoints(ctx context.Context) ([]epModel, error) {
	var out []epModel
	code, msg, err := c.do(ctx, http.MethodGet, "/endpoint", nil, &out)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET /endpoint: %d %s", code, msg)
	}
	return out, nil
}

// endpointByContainer looks an endpoint up by the identifier the CNI plugin
// records — this is how Kanea will map alloc -> endpoint.
func (c *ciliumClient) endpointByContainer(ctx context.Context, id string) (*epModel, error) {
	var out epModel
	code, msg, err := c.do(ctx, http.MethodGet, "/endpoint/container-id:"+id, nil, &out)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET endpoint container-id:%s: %d %s", id, code, msg)
	}
	return &out, nil
}

// setIdentityLabels gives the endpoint its security identity.
//
// The Cilium CNI plugin hardcodes an empty label set in its
// EndpointChangeRequest and only forwards K8S_POD_* CNI args, so an endpoint
// created by CNI starts with reserved:init — and init endpoints are policy
// enforced (deny) in both directions. An agent API call is therefore mandatory,
// and it must be this one:
//
//   - PATCH /endpoint/{id} REPLACES the identity labels (source "any"), which
//     drops reserved:init and lifts init enforcement. `state` is a required
//     field of EndpointChangeRequest (HTTP 422, code 602, without it).
//   - PATCH /endpoint/{id}/labels only merges *custom* labels; reserved:init
//     survives and the endpoint stays under init policy.
//
// It is retried: the call lands while the endpoint created by CNI ADD is still
// regenerating, and the agent then answers 500 "error while regenerating
// endpoint" — observed on roughly 1 in 8 attaches here. Kanea must treat this
// as retryable, not as an attach failure.
func (c *ciliumClient) setIdentityLabels(ctx context.Context, containerID string, lbls []string) error {
	body := map[string]any{"labels": lbls, "state": "waiting-for-identity"}
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		code, msg, err := c.do(ctx, http.MethodPatch, "/endpoint/container-id:"+containerID, body, nil)
		switch {
		case err != nil:
			lastErr = err
		case code == http.StatusOK:
			return nil
		default:
			lastErr = fmt.Errorf("PATCH endpoint %s: %d %s", containerID, code, msg)
			if code < 500 {
				return lastErr // 4xx is our bug, not a race
			}
		}
		time.Sleep(time.Duration(attempt+1) * 300 * time.Millisecond)
	}
	return lastErr
}

// waitIdentity polls until the endpoint has a real (non-init) security identity.
func (c *ciliumClient) waitIdentity(ctx context.Context, containerID string, timeout time.Duration) (*epModel, error) {
	deadline := time.Now().Add(timeout)
	var last *epModel
	for time.Now().Before(deadline) {
		ep, err := c.endpointByContainer(ctx, containerID)
		if err == nil {
			last = ep
			// Reserved identities are < 256; anything above comes from the
			// kvstore. reserved:init must be gone, else init policy still denies.
			if ep.Status.Identity.ID >= 256 && ep.Status.State == "ready" &&
				!containsAny(ep.Status.Identity.Labels, "reserved:init") {
				return ep, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if last != nil {
		return last, fmt.Errorf("endpoint %s: identity %d state %q labels %v after %v",
			containerID, last.Status.Identity.ID, last.Status.State,
			last.Status.Identity.Labels, timeout)
	}
	return nil, fmt.Errorf("endpoint %s never appeared", containerID)
}

// ---- services (eBPF load balancing) ----

type frontendAddress struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

type backendAddress struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	State  string `json:"state,omitempty"`
	Weight *int   `json:"weight,omitempty"`
}

type serviceFlags struct {
	Type      string `json:"type,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type serviceSpec struct {
	ID               int64            `json:"id"`
	FrontendAddress  frontendAddress  `json:"frontend-address"`
	BackendAddresses []backendAddress `json:"backend-addresses"`
	Flags            *serviceFlags    `json:"flags,omitempty"`
}

// Only GET remains in 1.18+: the frontend/backend model below is what the agent
// reports back, not something Kanea can write (see lb.go).

type serviceModel struct {
	Spec   serviceSpec `json:"spec"`
	Status struct {
		Realized serviceSpec `json:"realized"`
	} `json:"status"`
}

func (c *ciliumClient) services(ctx context.Context) ([]serviceModel, error) {
	var out []serviceModel
	code, msg, err := c.do(ctx, http.MethodGet, "/service", nil, &out)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET /service: %d %s", code, msg)
	}
	return out, nil
}

// ---- policy ----

// Writes are gone in 1.18+: PUT/DELETE /policy return 405 and even GET is
// deprecated. Policy now enters the agent through --static-cnp-path (policy.go);
// the revision below is how the spike confirms a file was actually loaded.

type policyModel struct {
	Revision int64  `json:"revision"`
	Policy   string `json:"policy"`
}

func (c *ciliumClient) policyRevision(ctx context.Context) (int64, error) {
	var out policyModel
	code, msg, err := c.do(ctx, http.MethodGet, "/policy", nil, &out)
	if err != nil {
		return 0, err
	}
	if code != http.StatusOK {
		return 0, fmt.Errorf("GET /policy: %d %s", code, msg)
	}
	return out.Revision, nil
}
