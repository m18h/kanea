package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cilium 1.18 removed the writable service API (PUT/DELETE /v1/service/{id}).
// The supported non-k8s replacement is --lb-state-file: a JSON/YAML file the
// agent watches, holding Kubernetes-*shaped* Service and EndpointSlice objects
// (schema only — no API server, no CRDs, no client-go). GET /v1/service remains
// read-only and is used here to verify what the agent programmed.
const lbStateFile = "/var/run/cilium/lb-state.json"

type objectMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type lbPort struct {
	Name       string `json:"name"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	TargetPort int    `json:"targetPort"`
}

type lbService struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		Type      string   `json:"type"`
		ClusterIP string   `json:"clusterIP,omitempty"`
		Ports     []lbPort `json:"ports"`
	} `json:"spec"`
}

type endpointConditions struct {
	Ready       bool `json:"ready"`
	Serving     bool `json:"serving"`
	Terminating bool `json:"terminating"`
}

type endpointEntry struct {
	Addresses  []string           `json:"addresses"`
	Conditions endpointConditions `json:"conditions"`
}

type endpointPort struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type lbEndpointSlice struct {
	Metadata    objectMeta      `json:"metadata"`
	AddressType string          `json:"addressType"`
	Endpoints   []endpointEntry `json:"endpoints"`
	Ports       []endpointPort  `json:"ports"`
}

type lbState struct {
	Services  []lbService       `json:"services"`
	Endpoints []lbEndpointSlice `json:"endpoints"`
}

// webService builds the state file contents for one service with the given
// backend IPs — the shape Kanea's reconciler would emit per project/service.
func webService(backendIPs ...string) lbState {
	var svc lbService
	svc.Metadata = objectMeta{Name: "web", Namespace: "shop"}
	svc.Spec.Type = "ClusterIP"
	svc.Spec.ClusterIP = serviceVIP
	svc.Spec.Ports = []lbPort{{Name: "http", Port: servicePort, Protocol: "TCP", TargetPort: backendPort}}

	slice := lbEndpointSlice{
		Metadata: objectMeta{
			Name:      "web-allocs",
			Namespace: "shop",
			Labels:    map[string]string{"kubernetes.io/service-name": "web"},
		},
		AddressType: "IPv4",
		Ports:       []endpointPort{{Name: "http", Port: backendPort, Protocol: "TCP"}},
	}
	for _, ip := range backendIPs {
		slice.Endpoints = append(slice.Endpoints, endpointEntry{
			Addresses:  []string{ip},
			Conditions: endpointConditions{Ready: true, Serving: true},
		})
	}
	return lbState{Services: []lbService{svc}, Endpoints: []lbEndpointSlice{slice}}
}

// writeLBState swaps the state file in atomically. The agent watches it with
// fsnotify, so a partially written file must never be observable — Cilium's own
// test data documents rename-into-place as the required production pattern.
func writeLBState(state lbState) error {
	b, err := json.MarshalIndent(state, "", " ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(lbStateFile), ".lb-state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, lbStateFile)
}

// phaseLB answers: can Kanea program eBPF service load balancing without k8s,
// and does it work east-west (alloc -> VIP) and from the host (kanea-edge -> VIP)?
func phaseLB(ctx context.Context, e *env) error {
	fmt.Println("\n── service load balancing without k8s (--lb-state-file) ──")

	web1, web2, client := e.allocs[idWeb1], e.allocs[idWeb2], e.allocs[idClient]
	for _, r := range []*running{web1, web2} {
		if err := waitHTTP(ctx, client, r, 20*time.Second); err != nil {
			return err
		}
	}

	err := timed("write lb-state.json (2 backends, atomic rename)", func() error {
		return writeLBState(webService(web1.IP, web2.IP))
	})
	if err != nil {
		check("service programmed without k8s", false, err.Error())
		return nil
	}

	frontend, backends, waitErr := waitService(ctx, e, 2, 20*time.Second)
	check("service programmed from the state file and realized by the agent",
		waitErr == nil, fmt.Sprintf("frontend=%s backends=%d err=%v", frontend, backends, waitErr))
	if waitErr != nil {
		return nil
	}

	// --- east-west LB: alloc -> VIP ---
	hits, err := hitVIPFromAlloc(ctx, client, "lb1", 20)
	check("east-west LB spreads across both backends (Maglev)",
		err == nil && hits[idWeb1] > 0 && hits[idWeb2] > 0,
		fmt.Sprintf("%s=%d %s=%d err=%d", idWeb1, hits[idWeb1], idWeb2, hits[idWeb2], hits["ERR"]))

	// --- host -> VIP: the kanea-edge path (needs socket LB / KPR) ---
	hostHits := map[string]int{}
	for i := 0; i < 10; i++ {
		body, err := hostGet(ctx, fmt.Sprintf("http://%s:%d/", serviceVIP, servicePort))
		if err != nil {
			hostHits["ERR"]++
			continue
		}
		hostHits[strings.TrimSpace(body)]++
	}
	check("host -> service VIP works (kanea-edge north-south path)",
		hostHits["ERR"] == 0 && hostHits[idWeb1]+hostHits[idWeb2] == 10,
		fmt.Sprintf("%s=%d %s=%d err=%d", idWeb1, hostHits[idWeb1], idWeb2, hostHits[idWeb2], hostHits["ERR"]))

	// --- backend removal converges (what happens when an alloc dies) ---
	if err := writeLBState(webService(web1.IP)); err != nil {
		check("backend removal accepted", false, err.Error())
	} else {
		_, _, waitErr = waitService(ctx, e, 1, 15*time.Second)
		hits, err = hitVIPFromAlloc(ctx, client, "lb2", 10)
		check("backend removal converges (all traffic to the survivor)",
			waitErr == nil && err == nil && hits[idWeb1] == 10 && hits[idWeb2] == 0,
			fmt.Sprintf("%s=%d %s=%d err=%d", idWeb1, hits[idWeb1], idWeb2, hits[idWeb2], hits["ERR"]))
	}

	// --- deletion removes the frontend ---
	if err := writeLBState(lbState{}); err != nil {
		check("service deletion accepted", false, err.Error())
	} else {
		gone := waitNoService(ctx, e, 15*time.Second)
		hits, _ = hitVIPFromAlloc(ctx, client, "lb3", 3)
		check("emptying the state file removes the frontend",
			gone && hits["ERR"] == 3,
			fmt.Sprintf("frontend gone=%v, requests after delete: err=%d", gone, hits["ERR"]))
	}

	// Reinstate both backends for the later phases.
	_ = writeLBState(webService(web1.IP, web2.IP))
	_, _, _ = waitService(ctx, e, 2, 15*time.Second)
	return nil
}

// waitService polls the read-only service API until the VIP is programmed with
// the expected number of backends.
func waitService(ctx context.Context, e *env, wantBackends int, timeout time.Duration) (string, int, error) {
	deadline := time.Now().Add(timeout)
	frontend, backends := "", -1
	for time.Now().Before(deadline) {
		svcs, err := e.cil.services(ctx)
		if err == nil {
			for _, s := range svcs {
				r := s.Status.Realized
				if r.FrontendAddress.IP != serviceVIP {
					continue
				}
				frontend = fmt.Sprintf("%s:%d", r.FrontendAddress.IP, r.FrontendAddress.Port)
				backends = len(r.BackendAddresses)
				if backends == wantBackends {
					return frontend, backends, nil
				}
			}
		}
		settle(300 * time.Millisecond)
	}
	return frontend, backends, fmt.Errorf("service %s never reached %d backends (last: %q/%d)",
		serviceVIP, wantBackends, frontend, backends)
}

func waitNoService(ctx context.Context, e *env, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		svcs, err := e.cil.services(ctx)
		if err == nil {
			found := false
			for _, s := range svcs {
				if s.Status.Realized.FrontendAddress.IP == serviceVIP {
					found = true
				}
			}
			if !found {
				return true
			}
		}
		settle(300 * time.Millisecond)
	}
	return false
}

// hitVIPFromAlloc issues n requests to the service VIP from inside an alloc and
// tallies which backend answered.
func hitVIPFromAlloc(ctx context.Context, from *running, execID string, n int) (map[string]int, error) {
	script := fmt.Sprintf("for i in $(seq %d); do wget -q -T 2 -O - http://%s:%d/ || echo ERR; done",
		n, serviceVIP, servicePort)
	out, _, err := execIn(ctx, from, execID, "sh", "-c", script)
	hits := map[string]int{}
	for _, line := range strings.Fields(out) {
		hits[line]++
	}
	return hits, err
}

func hostGet(ctx context.Context, url string) (string, error) {
	c := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// waitHTTP blocks until `target` serves HTTP to `from`.
func waitHTTP(ctx context.Context, from, target *running, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://%s:%d/", target.IP, backendPort)
	for i := 0; time.Now().Before(deadline); i++ {
		body, code, err := wgetFrom(ctx, from, fmt.Sprintf("wait-%s-%d", target.ID, i), url)
		if err == nil && code == 0 && strings.Contains(body, target.ID) {
			return nil
		}
		settle(300 * time.Millisecond)
	}
	return fmt.Errorf("%s never served HTTP within %v", target.ID, timeout)
}
