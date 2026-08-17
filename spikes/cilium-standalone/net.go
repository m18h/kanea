package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Alloc ids double as CNI container ids; keep them >= 5 chars (see cniRuntime).
const (
	idWeb1   = "spike-web-1"
	idWeb2   = "spike-web-2"
	idClient = "spike-client"
	idOther  = "spike-other"
)

// projectLabels is the identity label set Kanea would give an alloc.
//
// The k8s namespace label is not decoration: Cilium's policy translation
// (pkg/k8s/apis/cilium.io/utils) rewrites every fromEndpoints/toEndpoints
// selector. A clusterwide policy gets "k8s:io.kubernetes.pod.namespace Exists"
// injected ("only match Cilium-managed k8s endpoints"), and a namespaced policy
// gets "k8s:io.kubernetes.pod.namespace=<ns>". Endpoints without that label
// therefore match no peer selector at all: every rule silently denies. Mapping
// project -> namespace label makes Kanea's projects work with the same policy
// semantics every Cilium user already relies on.
func projectLabels(project, service string) []string {
	return []string{
		"kanea=true",
		"project=" + project,
		"service=" + service,
		"k8s:io.kubernetes.pod.namespace=" + project,
	}
}

// phaseNet answers: can our own process attach a containerd workload to Cilium
// without k8s, give it a security identity, and get east-west + egress traffic?
func phaseNet(ctx context.Context, e *env) error {
	fmt.Println("── attach: netns -> CNI ADD -> labels -> identity -> task ──")

	img, err := ensureImage(ctx, e.client)
	if err != nil {
		return fmt.Errorf("image %s: %w", imageRef, err)
	}

	specs := []alloc{
		{ID: idWeb1, Labels: projectLabels("shop", "web"), Cmd: httpdCmd(idWeb1)},
		{ID: idWeb2, Labels: projectLabels("shop", "web"), Cmd: httpdCmd(idWeb2)},
		{ID: idClient, Labels: projectLabels("shop", "client"), Cmd: []string{"sleep", "infinity"}},
		{ID: idOther, Labels: projectLabels("other", "probe"), Cmd: []string{"sleep", "infinity"}},
	}
	for _, a := range specs {
		spec := a
		if err := timed("attach "+spec.ID, func() error {
			_, err := setupAlloc(ctx, e, img, spec)
			return err
		}); err != nil {
			return err
		}
	}

	web1, web2 := e.allocs[idWeb1], e.allocs[idWeb2]
	client, other := e.allocs[idClient], e.allocs[idOther]

	// --- endpoints exist and are addressable by container id ---
	eps, err := e.cil.endpoints(ctx)
	if err != nil {
		return err
	}
	byContainer := map[string]epModel{}
	for _, ep := range eps {
		if cid := ep.Status.ExternalIdentifiers.ContainerID; cid != "" {
			byContainer[cid] = ep
		}
	}
	found, ipsMatch := 0, true
	for _, r := range e.allocs {
		ep, ok := byContainer[r.ID]
		if !ok {
			ipsMatch = false
			continue
		}
		found++
		if ep.ipv4() != r.IP {
			ipsMatch = false
		}
	}
	check("CNI ADD created one Cilium endpoint per alloc", found == 4,
		fmt.Sprintf("%d/4 endpoints, lookup key = external-identifiers.container-id", found))
	check("endpoint IPv4 matches the CNI result", ipsMatch,
		fmt.Sprintf("%s=%s %s=%s", idWeb1, web1.IP, idClient, client.IP))

	// --- labels + identity (the part the CNI plugin cannot do) ---
	epWeb1 := byContainer[idWeb1]
	wantLabels := []string{
		"unspec:kanea=true", "unspec:project=shop", "unspec:service=web",
		"k8s:io.kubernetes.pod.namespace=shop",
	}
	gotLabels := epWeb1.Status.Identity.Labels
	check("identity labels set via agent API replace reserved:init",
		equalSets(gotLabels, wantLabels), strings.Join(gotLabels, " "))

	check("identity allocated from the etcd kvstore (not reserved:init)",
		web1.Identity >= 256 && client.Identity >= 256,
		fmt.Sprintf("web=%d client=%d other=%d", web1.Identity, client.Identity, other.Identity))
	check("identical labels share one identity; different labels differ",
		web1.Identity == web2.Identity && web1.Identity != client.Identity,
		fmt.Sprintf("web-1=%d web-2=%d client=%d", web1.Identity, web2.Identity, client.Identity))

	check("no residual init enforcement once labels are set",
		epWeb1.Status.Policy.Realized.PolicyEnabled == "none",
		fmt.Sprintf("%s policy-enabled=%q (init endpoints report \"both\")",
			idWeb1, epWeb1.Status.Policy.Realized.PolicyEnabled))

	// --- the workload actually sees the pre-wired netns ---
	out, code, err := execIn(ctx, client, "ip-addr", "ip", "addr", "show", "dev", "eth0")
	check("workload joins the pre-created netns (eth0 + IP present)",
		err == nil && code == 0 && strings.Contains(out, client.IP),
		fmt.Sprintf("expected %s in %q", client.IP, oneLine(out)))

	// --- east-west + egress ---
	// httpd needs a moment to bind; retry so a startup race cannot be mistaken
	// for a datapath failure.
	waitErr := waitHTTP(ctx, client, web1, 15*time.Second)
	body, code, err := wgetFrom(ctx, client, "ew", fmt.Sprintf("http://%s:%d/", web1.IP, backendPort))
	check("east-west: client -> web-1 (eBPF datapath, no policy yet)",
		waitErr == nil && err == nil && code == 0 && strings.Contains(body, idWeb1),
		fmt.Sprintf("%s wait=%v exec=%v exit=%d", oneLine(body), waitErr, err, code))

	_, code, _ = execIn(ctx, client, "egress", "nc", "-z", "-w", "3", "1.1.1.1", "80")
	check("north-south: alloc -> internet (masquerade)", code == 0, "1.1.1.1:80")

	return nil
}

// wgetFrom fetches a URL from inside an alloc using BusyBox wget.
func wgetFrom(ctx context.Context, r *running, execID, url string) (string, uint32, error) {
	return execIn(ctx, r, execID, "wget", "-q", "-T", "3", "-O", "-", url)
}

func equalSets(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}

func containsAny(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func oneLine(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(s), "\n", " | "))
}

func settle(d time.Duration) { time.Sleep(d) }
