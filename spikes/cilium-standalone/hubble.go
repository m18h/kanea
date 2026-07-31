package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// dnsVisibilityPolicy routes the alloc's DNS through Cilium's standalone DNS
// proxy (PRD §7.1 lists this as the alternative to Kanea's built-in resolver).
// Any egress rule makes egress default-deny for the selected endpoint, so the
// rule also re-allows in-cluster traffic.
const dnsVisibilityPolicy = `apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: kanea-spike-dns
spec:
  endpointSelector:
    matchLabels:
      any:service: client
  egress:
    - toEndpoints:
        - {}
    - toCIDRSet:
        - cidr: 1.1.1.1/32
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
          rules:
            dns:
              - matchPattern: "*"
    - toFQDNs:
        - matchPattern: "*"
`

// phaseHubble answers: does Hubble produce Prometheus metrics without a k8s
// ConfigMap, and does it observe policy drops and L7 DNS?
func phaseHubble(ctx context.Context, e *env) error {
	fmt.Println("\n── hubble metrics without k8s ──")

	web1, client, other := e.allocs[idWeb1], e.allocs[idClient], e.allocs[idOther]
	webURL := fmt.Sprintf("http://%s:%d/", web1.IP, backendPort)

	// Generate traffic that must show up as flows and as drops.
	_, _, _ = wgetFrom(ctx, client, "hb-allow", webURL)
	if err := writePolicy(isolationFile, projectIsolationPolicy); err != nil {
		return err
	}
	settle(policySettleFn)
	_, _, _ = wgetFrom(ctx, other, "hb-deny", webURL)
	settle(2 * time.Second)

	text, err := scrape(ctx, hubbleMetricsURL)
	check("hubble metrics endpoint serves Prometheus text (no k8s)",
		err == nil && strings.Contains(text, "hubble_"),
		fmt.Sprintf("%s -> %d bytes", hubbleMetricsURL, len(text)))
	if err != nil {
		return nil
	}

	flows := metricSum(text, "hubble_flows_processed_total")
	check("flows observed", flows > 0, fmt.Sprintf("hubble_flows_processed_total=%.0f", flows))

	drops := metricSum(text, "hubble_drop_total")
	check("policy drops observed (cross-project request)", drops > 0,
		fmt.Sprintf("hubble_drop_total=%.0f", drops))

	tcp := metricSum(text, "hubble_tcp_flags_total")
	info("other configured metric families",
		fmt.Sprintf("hubble_tcp_flags_total=%.0f hubble_port_distribution_total=%.0f",
			tcp, metricSum(text, "hubble_port_distribution_total")))

	// --- L7 DNS visibility through the standalone DNS proxy ---
	if err := writePolicy(dnsPolicyFile, dnsVisibilityPolicy); err != nil {
		check("DNS visibility policy installed", false, err.Error())
	} else {
		settle(policySettleFn)
		out, code, _ := execIn(ctx, client, "dns", "nslookup", "one.one.one.one", "1.1.1.1")
		resolved := code == 0 && strings.Contains(out, "1.1.1.1")
		settle(2 * time.Second)
		text, _ = scrape(ctx, hubbleMetricsURL)
		dns := metricSum(text, "hubble_dns_queries_total")
		check("DNS proxied and observed at L7 (hubble_dns_queries_total)",
			resolved && dns > 0,
			fmt.Sprintf("resolved=%v hubble_dns_queries_total=%.0f out=%q", resolved, dns, truncate(out, 60)))
	}

	_ = removePolicy(isolationFile)
	_ = removePolicy(dnsPolicyFile)
	return nil
}

func scrape(ctx context.Context, url string) (string, error) {
	c := &http.Client{Timeout: 10 * time.Second}
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
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return string(b), fmt.Errorf("GET %s: %d", url, resp.StatusCode)
	}
	return string(b), nil
}

// metricSum totals every sample of a Prometheus metric family.
func metricSum(text, name string) float64 {
	var sum float64
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, name) {
			continue
		}
		rest := line[len(name):]
		if rest != "" && rest[0] != '{' && rest[0] != ' ' {
			continue // different family with the same prefix
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil {
			sum += v
		}
	}
	return sum
}
