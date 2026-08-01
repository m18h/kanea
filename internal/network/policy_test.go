package network

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func testPolicyWriter(t *testing.T) (*Cilium, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := New(Config{PolicyDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, dir
}

// projectPolicies builds the plain per-project input, with no extra edges.
func projectPolicies(names ...string) []ProjectPolicy {
	out := make([]ProjectPolicy, 0, len(names))
	for _, n := range names {
		out = append(out, ProjectPolicy{Project: n})
	}
	return out
}

func policyFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

func TestSyncPoliciesWritesOnePerProject(t *testing.T) {
	c, dir := testPolicyWriter(t)

	if err := c.SyncPolicies(t.Context(), projectPolicies("shop", "blog")); err != nil {
		t.Fatalf("SyncPolicies: %v", err)
	}
	want := []string{"kanea-blog-isolation.yaml", "kanea-shop-isolation.yaml"}
	if got := policyFiles(t, dir); !slices.Equal(got, want) {
		t.Fatalf("files = %v, want %v", got, want)
	}
}

// The document is written as JSON with a .yaml extension — YAML is a superset,
// and the agent's decoder accepts it. Verified against Cilium 1.19.6.
func TestPolicyDocumentShape(t *testing.T) {
	c, dir := testPolicyWriter(t)
	if err := c.SyncPolicies(t.Context(), projectPolicies("shop")); err != nil {
		t.Fatalf("SyncPolicies: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "kanea-shop-isolation.yaml"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	var doc policyDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("policy file is not valid JSON: %v\n%s", err, raw)
	}

	if doc.APIVersion != "cilium.io/v2" || doc.Kind != kindClusterwide {
		t.Errorf("apiVersion/kind = %q/%q", doc.APIVersion, doc.Kind)
	}
	// The selector source must be "any:": Kanea's labels come back from the
	// agent with source `unspec`, and a bare selector defaults to matching k8s
	// labels — which would match nothing.
	if got := doc.Spec.EndpointSelector.MatchLabels["any:project"]; got != "shop" {
		t.Errorf("endpointSelector any:project = %q, want shop", got)
	}
	if len(doc.Spec.Ingress) != 2 {
		t.Fatalf("ingress rules = %d, want 2 (intra-project, host)", len(doc.Spec.Ingress))
	}
	if got := doc.Spec.Ingress[0].FromEndpoints[0].MatchLabels["any:project"]; got != "shop" {
		t.Errorf("fromEndpoints any:project = %q, want shop", got)
	}
	if !slices.Contains(doc.Spec.Ingress[1].FromEntities, entityHost) {
		t.Errorf("ingress must admit the host entity (kanea-edge): %+v", doc.Spec.Ingress[1])
	}
	// Any egress rule at all would flip that direction to default-deny and cut
	// off every outbound call a workload makes.
	if len(doc.Spec.Egress) != 0 {
		t.Errorf("default policy must not restrict egress: %+v", doc.Spec.Egress)
	}
}

// Rewriting an unchanged file is visible to the agent as a policy change and
// costs an endpoint regeneration for nothing.
func TestSyncPoliciesIsIdempotent(t *testing.T) {
	c, dir := testPolicyWriter(t)
	path := filepath.Join(dir, "kanea-shop-isolation.yaml")

	if err := c.SyncPolicies(t.Context(), projectPolicies("shop")); err != nil {
		t.Fatalf("first sync: %v", err)
	}

	// Back-date the file rather than comparing timestamps taken microseconds
	// apart: a rewrite landing inside one clock tick would otherwise look
	// identical to no write at all.
	backdated := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, backdated, backdated); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if err := c.SyncPolicies(t.Context(), projectPolicies("shop")); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !info.ModTime().Equal(backdated) {
		t.Errorf("unchanged policy was rewritten (mtime %v, want %v)", info.ModTime(), backdated)
	}
}

// A changed policy must actually be written, or the idempotency check above
// would be satisfied by a writer that never writes anything.
func TestSyncPoliciesWritesWhenContentChanges(t *testing.T) {
	c, dir := testPolicyWriter(t)
	path := filepath.Join(dir, "kanea-shop-isolation.yaml")

	if err := c.SyncPolicies(t.Context(), projectPolicies("shop")); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}

	if err := c.SyncPolicies(t.Context(), projectPolicies("shop")); err != nil {
		t.Fatalf("resync: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(raw) == "{}\n" {
		t.Error("drifted policy file was not repaired")
	}
}

func TestSyncPoliciesWithdrawsDeletedProjects(t *testing.T) {
	c, dir := testPolicyWriter(t)

	if err := c.SyncPolicies(t.Context(), projectPolicies("shop", "blog")); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := c.SyncPolicies(t.Context(), projectPolicies("shop")); err != nil {
		t.Fatalf("resync: %v", err)
	}
	if got := policyFiles(t, dir); !slices.Equal(got, []string{"kanea-shop-isolation.yaml"}) {
		t.Fatalf("files = %v, want only shop", got)
	}
}

func TestSyncPoliciesWithNoProjectsClearsEverything(t *testing.T) {
	c, dir := testPolicyWriter(t)
	if err := c.SyncPolicies(t.Context(), projectPolicies("shop")); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := c.SyncPolicies(t.Context(), nil); err != nil {
		t.Fatalf("resync: %v", err)
	}
	if got := policyFiles(t, dir); len(got) != 0 {
		t.Fatalf("files = %v, want none", got)
	}
}

// The directory is Kanea's, but "I did not expect this file" is a bad reason to
// delete something from a directory where a wrong move crashes the agent.
func TestSyncPoliciesLeavesForeignFilesAlone(t *testing.T) {
	c, dir := testPolicyWriter(t)
	foreign := filepath.Join(dir, "operator-debug.yaml")
	if err := os.WriteFile(foreign, []byte("# hand-written\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := c.SyncPolicies(t.Context(), nil); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign policy file was removed: %v", err)
	}
}

// The watcher reacts to fsnotify events and would happily load a half-written
// document — and a half-written document is a dead agent, not a rejected one.
// The temp file must therefore not carry the watched extension.
func TestSyncPoliciesLeavesNoVisibleTempFiles(t *testing.T) {
	c, dir := testPolicyWriter(t)
	if err := c.SyncPolicies(t.Context(), projectPolicies("shop")); err != nil {
		t.Fatalf("sync: %v", err)
	}
	for _, name := range policyFiles(t, dir) {
		if strings.HasSuffix(name, ".tmp") {
			t.Errorf("temp file %q left behind", name)
		}
		if strings.HasPrefix(name, ".") && strings.HasSuffix(name, policyFileSuffix) {
			t.Errorf("temp file %q carries the watched extension", name)
		}
	}
}

// Validation is not belt-and-braces here. The agent calls Fatal on a document
// it cannot translate — on fsnotify events *and* on the startup directory scan
// — so a bad file is a crash loop, not a rejected import (M0 spike ①).
func TestPolicyValidation(t *testing.T) {
	valid := func() policyDocument { return projectIsolationPolicy("shop") }

	tests := []struct {
		name string
		doc  func() policyDocument
		want string
	}{
		{name: "valid", doc: valid},
		{
			name: "empty endpointSelector selects the whole node",
			doc: func() policyDocument {
				d := valid()
				d.Spec.EndpointSelector = endpointSelector{}
				return d
			},
			want: "every endpoint on the node",
		},
		{
			name: "ingress rule with no peers denies silently",
			doc: func() policyDocument {
				d := valid()
				d.Spec.Ingress = []ingressRule{{}}
				return d
			},
			want: "selects no peers",
		},
		{
			name: "name that the watcher would ignore",
			doc: func() policyDocument {
				d := valid()
				d.Metadata.Name = "Kanea_Shop"
				return d
			},
			want: "DNS-1123",
		},
		{
			name: "empty name",
			doc: func() policyDocument {
				d := valid()
				d.Metadata.Name = ""
				return d
			},
			want: "empty name",
		},
		{
			name: "selector value that would corrupt the document",
			doc: func() policyDocument {
				d := valid()
				d.Spec.EndpointSelector.MatchLabels["any:project"] = "shop: evil"
				return d
			},
			want: "unusable value",
		},
		{
			name: "wrong kind",
			doc: func() policyDocument {
				d := valid()
				d.Kind = "NetworkPolicy"
				return d
			},
			want: "kind",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.doc().validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("validate = %v, want nil", err)
			case tc.want == "":
			case err == nil:
				t.Fatalf("validate = nil, want an error mentioning %q", tc.want)
			case !strings.Contains(err.Error(), tc.want):
				t.Fatalf("validate = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

// A project name that is not a DNS-1123 label must be refused before the file
// is written, not after — jobspec R1 already guarantees it, and this is the
// assertion that the guarantee still holds by the time it reaches the datapath.
func TestSyncPoliciesRejectsBadProjectNameWithoutWriting(t *testing.T) {
	c, dir := testPolicyWriter(t)

	err := c.SyncPolicies(t.Context(), projectPolicies("Shop Evil"))
	if err == nil {
		t.Fatal("SyncPolicies = nil, want an error")
	}
	if got := policyFiles(t, dir); len(got) != 0 {
		t.Fatalf("a rejected policy still reached the directory: %v", got)
	}
}

func TestValidateDNS1123(t *testing.T) {
	good := []string{"kanea-shop-isolation", "a", "shop.eu", "a-b-c", "x9"}
	bad := []string{"", "Shop", "shop_eu", "-shop", "shop-", "shop/eu", strings.Repeat("a", 254)}

	for _, s := range good {
		if err := validateDNS1123(s); err != nil {
			t.Errorf("validateDNS1123(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range bad {
		if err := validateDNS1123(s); err == nil {
			t.Errorf("validateDNS1123(%q) = nil, want error", s)
		}
	}
}

// The whole point of R14: a peer in another project gets its own document,
// selecting only the service that asked for it.
func TestSyncPoliciesWritesServiceAllowlist(t *testing.T) {
	c, dir := testPolicyWriter(t)

	err := c.SyncPolicies(t.Context(), []ProjectPolicy{{
		Project: "shop",
		Services: []ServicePolicy{{
			Service:   "api",
			AllowFrom: []ServiceRef{{Project: "analytics", Service: "collector"}},
		}},
	}})
	if err != nil {
		t.Fatalf("SyncPolicies: %v", err)
	}

	want := []string{"kanea-shop-api-allow.yaml", "kanea-shop-isolation.yaml"}
	if got := policyFiles(t, dir); !slices.Equal(got, want) {
		t.Fatalf("files = %v, want %v", got, want)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "kanea-shop-api-allow.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc policyDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	// The subject is one service, not the whole project.
	sel := doc.Spec.EndpointSelector.MatchLabels
	if sel["any:project"] != "shop" || sel["any:service"] != "api" {
		t.Errorf("endpointSelector = %v, want just shop/api", sel)
	}
	if len(doc.Spec.Ingress) != 1 || len(doc.Spec.Ingress[0].FromEndpoints) != 1 {
		t.Fatalf("ingress = %+v, want one peer", doc.Spec.Ingress)
	}
	peer := doc.Spec.Ingress[0].FromEndpoints[0].MatchLabels
	if peer["any:project"] != "analytics" || peer["any:service"] != "collector" {
		t.Errorf("peer selector = %v, want analytics/collector", peer)
	}
	// An egress rule here would flip that direction to default-deny for the
	// selected service — a spec author must not be able to do that by accident.
	if len(doc.Spec.Egress) != 0 {
		t.Errorf("allow policy must not touch egress: %+v", doc.Spec.Egress)
	}
}

// The safety property that makes it acceptable for a job spec to influence
// policy at all: the isolation document is untouched, so the extra edges can
// only ever union on top of it.
func TestServiceAllowlistDoesNotAlterProjectIsolation(t *testing.T) {
	c, dir := testPolicyWriter(t)
	isolation := filepath.Join(dir, "kanea-shop-isolation.yaml")

	if err := c.SyncPolicies(t.Context(), projectPolicies("shop")); err != nil {
		t.Fatalf("sync: %v", err)
	}
	before, err := os.ReadFile(isolation)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	err = c.SyncPolicies(t.Context(), []ProjectPolicy{{
		Project: "shop",
		Services: []ServicePolicy{{
			Service:   "api",
			AllowFrom: []ServiceRef{{Project: "analytics", Service: "collector"}},
		}},
	}})
	if err != nil {
		t.Fatalf("resync: %v", err)
	}

	after, err := os.ReadFile(isolation)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(before) != string(after) {
		t.Error("adding a service allowlist changed the project isolation policy")
	}
}

// Removing allow_from from a spec must withdraw the edge, not leave it behind.
func TestSyncPoliciesWithdrawsServiceAllowlist(t *testing.T) {
	c, dir := testPolicyWriter(t)

	err := c.SyncPolicies(t.Context(), []ProjectPolicy{{
		Project: "shop",
		Services: []ServicePolicy{{
			Service:   "api",
			AllowFrom: []ServiceRef{{Project: "analytics", Service: "collector"}},
		}},
	}})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := c.SyncPolicies(t.Context(), projectPolicies("shop")); err != nil {
		t.Fatalf("resync: %v", err)
	}

	if got := policyFiles(t, dir); !slices.Equal(got, []string{"kanea-shop-isolation.yaml"}) {
		t.Fatalf("files = %v, want the allow policy withdrawn", got)
	}
}

// An allowlist that names nothing would switch ingress enforcement on for the
// service while permitting no peers — silent, total denial. validate catches it.
func TestServiceAllowPolicyWithNoPeersIsRejected(t *testing.T) {
	doc := serviceAllowPolicy("shop", ServicePolicy{Service: "api"})

	err := doc.validate()
	if err == nil || !strings.Contains(err.Error(), "selects no peers") {
		t.Fatalf("validate = %v, want a refusal", err)
	}
}
