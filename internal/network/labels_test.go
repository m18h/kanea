package network

import (
	"slices"
	"testing"
)

func TestIdentityLabels(t *testing.T) {
	got := IdentityLabels("shop", "web")
	want := []string{
		"k8s:io.kubernetes.pod.namespace=shop",
		"kanea=true",
		"project=shop",
		"service=web",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("IdentityLabels = %v, want %v", got, want)
	}
}

// The namespace label is the difference between "policies work" and "every rule
// silently denies everything" (M0 spike ①), and the alloc id must stay out of
// the set or Cilium mints one identity per alloc. Both are easy to break in a
// refactor and neither fails loudly, so they get their own test.
func TestIdentityLabelsInvariants(t *testing.T) {
	labels := IdentityLabels("shop", "web")

	if !slices.Contains(labels, LabelNamespace+"=shop") {
		t.Errorf("identity labels must carry %s=<project>: %v", LabelNamespace, labels)
	}
	for _, l := range labels {
		if _, value, _ := splitLabel(l); value == "shop-web-0" {
			t.Errorf("identity labels must not contain the alloc id: %v", labels)
		}
	}
	if len(labels) != 4 {
		t.Errorf("unexpected label count %d: %v", len(labels), labels)
	}
}

func TestIdentityLabelsAreStable(t *testing.T) {
	// Two calls must produce byte-identical sets, or every attach looks like a
	// label change to the agent and forces an identity re-resolution.
	if !slices.Equal(IdentityLabels("shop", "web"), IdentityLabels("shop", "web")) {
		t.Fatal("IdentityLabels is not deterministic")
	}
}

func TestSplitLabel(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		key, value string
		ok         bool
	}{
		{name: "plain", raw: "project=shop", key: "project", value: "shop", ok: true},
		{name: "source prefix", raw: "unspec:project=shop", key: "project", value: "shop", ok: true},
		{
			name: "dotted key keeps its dots", raw: "k8s:io.kubernetes.pod.namespace=shop",
			key: "io.kubernetes.pod.namespace", value: "shop", ok: true,
		},
		{name: "empty value", raw: "project=", key: "project", value: "", ok: true},
		{name: "no separator", raw: "reserved:init", ok: false},
		{name: "empty", raw: "", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, value, ok := splitLabel(tc.raw)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && (key != tc.key || value != tc.value) {
				t.Fatalf("= (%q, %q), want (%q, %q)", key, value, tc.key, tc.value)
			}
		})
	}
}

func TestServiceRefFrom(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		want   ServiceRef
		ok     bool
	}{
		{
			name: "kanea endpoint as the agent reports it",
			// Exactly the label set spike ① observed coming back.
			labels: []string{
				"k8s:io.kubernetes.pod.namespace=shop", "unspec:kanea=true",
				"unspec:project=shop", "unspec:service=web",
			},
			want: ServiceRef{Project: "shop", Service: "web"}, ok: true,
		},
		{
			name:   "cilium's own host endpoint",
			labels: []string{"reserved:host"},
		},
		{
			name:   "another tool's endpoint",
			labels: []string{"unspec:app=grafana", "unspec:project=shop"},
		},
		{
			name:   "managed but incomplete",
			labels: []string{"unspec:kanea=true", "unspec:project=shop"},
		},
		{
			name:   "kanea label present but false",
			labels: []string{"unspec:kanea=false", "unspec:project=shop", "unspec:service=web"},
		},
		{name: "no labels"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := serviceRefFrom(tc.labels)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("= %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestValidateLabelValue(t *testing.T) {
	for _, bad := range []string{"", "a=b", "a:b", "a b", "a,b"} {
		if err := validateLabelValue("project", bad); err == nil {
			t.Errorf("validateLabelValue(%q) = nil, want error", bad)
		}
	}
	if err := validateLabelValue("project", "shop-eu"); err != nil {
		t.Errorf("validateLabelValue(shop-eu) = %v, want nil", err)
	}
}
