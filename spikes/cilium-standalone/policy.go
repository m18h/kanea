package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cilium 1.18 also removed the writable policy API (PUT/DELETE /v1/policy; even
// GET is deprecated). The supported non-k8s replacement is --static-cnp-path: a
// watched directory of CiliumNetworkPolicy YAML files. A file with an empty
// metadata.namespace is treated as clusterwide, which is what Kanea wants —
// its endpoints have no k8s namespace labels for a namespaced CNP to match.
const (
	policyDir      = "/var/run/cilium/policies"
	isolationFile  = "kanea-spike-shop-isolation.yaml"
	dnsPolicyFile  = "kanea-spike-dns.yaml"
	policySettleFn = 3 * time.Second
)

// projectIsolationPolicy is PRD §7.1's default: the project is an isolation
// boundary — ingress only from the same project.
const projectIsolationPolicy = `apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: kanea-spike-shop-isolation
spec:
  endpointSelector:
    matchLabels:
      any:project: shop
  ingress:
    - fromEndpoints:
        - matchLabels:
            any:project: shop
`

// writePolicy installs a policy file atomically. The watcher reacts to fsnotify
// events, so a half-written file must never be visible: the temp file is
// deliberately not named *.yaml (the watcher ignores other extensions) and is
// renamed into place. File names must be DNS-1123 subdomains.
func writePolicy(name, body string) error {
	if err := os.MkdirAll(policyDir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(policyDir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(policyDir, name))
}

func removePolicy(name string) error {
	err := os.Remove(filepath.Join(policyDir, name))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// phasePolicy answers: can Kanea impose per-project isolation on a standalone
// Cilium, and is it actually enforced by the datapath?
func phasePolicy(ctx context.Context, e *env) error {
	fmt.Println("\n── network policy without k8s (--static-cnp-path) ──")

	web1, client, other := e.allocs[idWeb1], e.allocs[idClient], e.allocs[idOther]
	webURL := fmt.Sprintf("http://%s:%d/", web1.IP, backendPort)

	// Baseline: with no policy, cross-project traffic is allowed.
	body, code, _ := wgetFrom(ctx, other, "pre-deny", webURL)
	check("baseline: cross-project reachable before policy",
		code == 0 && strings.Contains(body, idWeb1), oneLine(body))

	revBefore, _ := e.cil.policyRevision(ctx)
	err := timed("install CCNP yaml (atomic rename into watched dir)", func() error {
		return writePolicy(isolationFile, projectIsolationPolicy)
	})
	if err != nil {
		check("policy installed without k8s", false, err.Error())
		return nil
	}
	settle(policySettleFn)
	revAfter, _ := e.cil.policyRevision(ctx)
	check("policy loaded by the agent (no CRDs, no API server)", revAfter > revBefore,
		fmt.Sprintf("policy revision %d -> %d", revBefore, revAfter))

	// --- enforcement ---
	body, code, _ = wgetFrom(ctx, client, "allow", webURL)
	check("intra-project traffic still allowed (client -> web)",
		code == 0 && strings.Contains(body, idWeb1), oneLine(body))

	body, code, _ = wgetFrom(ctx, other, "deny", webURL)
	check("cross-project traffic denied (other -> web)",
		code != 0 && !strings.Contains(body, idWeb1),
		fmt.Sprintf("exit=%d out=%q", code, oneLine(body)))

	if ep, err := e.cil.endpointByContainer(ctx, idWeb1); err == nil {
		enabled := ep.Status.Policy.Realized.PolicyEnabled
		check("enforcement visible on the endpoint model",
			enabled == "ingress" || enabled == "both",
			fmt.Sprintf("policy-enabled=%q identity=%d", enabled, ep.Status.Identity.ID))
	}

	// The host endpoint must stay healthy: policy must never lock out the node.
	if eps, err := e.cil.endpoints(ctx); err == nil {
		hostOK := false
		for _, ep := range eps {
			if containsAny(ep.Status.Identity.Labels, "reserved:host") && ep.Status.State == "ready" {
				hostOK = true
			}
		}
		check("host endpoint healthy under policy", hostOK, "reserved:host state=ready")
	}

	// --- removing the file withdraws the policy ---
	if err := removePolicy(isolationFile); err != nil {
		check("policy removal accepted", false, err.Error())
	} else {
		settle(policySettleFn)
		body, code, _ = wgetFrom(ctx, other, "post-delete", webURL)
		check("deleting the file withdraws the policy",
			code == 0 && strings.Contains(body, idWeb1), oneLine(body))
	}

	return nil
}

func truncate(s string, n int) string {
	s = oneLine(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
