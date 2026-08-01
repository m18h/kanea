package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultPolicyDir is the agent's --static-cnp-path (PRD §5.2.5).
const DefaultPolicyDir = "/var/run/cilium/policies"

// policyFilePrefix scopes every file Kanea writes — and, more importantly,
// every file Kanea is willing to delete. The PRD gives Kanea exclusive
// ownership of this directory, but "I did not expect this file" is a bad reason
// to remove something from a directory where a wrong move crashes the agent.
const policyFilePrefix = "kanea-"

// Policy documents are written as JSON with a .yaml extension.
//
// That is not a hack: YAML is a superset of JSON, and Cilium's directory
// watcher decodes YAML, so a JSON document parses identically. It buys two
// things that matter here. First, encoding/json is in the standard library, so
// no YAML dependency enters a project whose release gates are CVE scans.
// Second, and the real reason: a generated document can never be malformed by
// its own content. There is no indentation to get wrong and no string that can
// break out of its context — and a malformed file in this directory is fatal to
// cilium-agent, not merely rejected (M0 spike ①).
const policyFileSuffix = ".yaml"

// Cilium policy API constants.
const (
	policyAPIVersion = "cilium.io/v2"
	// kindClusterwide is used rather than the namespaced CiliumNetworkPolicy
	// because Kanea has no Kubernetes namespaces to put a CNP in. A document
	// with an empty metadata.namespace is treated as clusterwide anyway.
	kindClusterwide = "CiliumClusterwideNetworkPolicy"
	// entityHost is the node itself. kanea-edge is a host process, not a
	// container, so it cannot carry a Cilium endpoint identity — `host` *is*
	// the edge proxy's identity as far as policy is concerned (PRD §7.1).
	entityHost = "host"
)

// policyDocument is a CiliumClusterwideNetworkPolicy.
//
// Only the fields Kanea generates are modelled. Everything is a typed struct
// rather than a template, so the document's shape is decided by the compiler
// and the only variable parts are label values.
type policyDocument struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   policyMetadata `json:"metadata"`
	Spec       policySpec     `json:"spec"`
}

type policyMetadata struct {
	Name string `json:"name"`
}

type policySpec struct {
	// EndpointSelector picks the endpoints this policy governs.
	EndpointSelector endpointSelector `json:"endpointSelector"`
	// Ingress lists what may reach them. A non-empty list turns ingress
	// enforcement on for the selected endpoints; anything not matched is denied.
	Ingress []ingressRule `json:"ingress,omitempty"`
	// Egress is deliberately absent from the default policy. Adding *any*
	// egress rule switches that direction to default-deny, which would break
	// every outbound call a workload makes — PRD §7.1 scopes the default policy
	// to inbound only.
	Egress []egressRule `json:"egress,omitempty"`
}

type endpointSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

type ingressRule struct {
	FromEndpoints []endpointSelector `json:"fromEndpoints,omitempty"`
	FromEntities  []string           `json:"fromEntities,omitempty"`
}

type egressRule struct {
	ToEndpoints []endpointSelector `json:"toEndpoints,omitempty"`
	ToEntities  []string           `json:"toEntities,omitempty"`
}

// selectorSource is the label-source prefix used in policy selectors.
//
// "any" matters. Kanea's labels come back from the agent with source `unspec`,
// and a selector written without a source defaults to matching `k8s:` — which
// would match nothing. `any:` matches regardless of source.
const selectorSource = "any:"

// ProjectPolicy is everything Kanea needs to write for one project.
type ProjectPolicy struct {
	Project string
	// Services carries only the services that declare an ingress allowlist;
	// the rest are covered by the project isolation policy alone.
	Services []ServicePolicy
}

// ServicePolicy is one service's explicit ingress allowlist (PRD §6.2 R14).
type ServicePolicy struct {
	Service string
	// AllowFrom names the peers permitted to reach this service.
	AllowFrom []ServiceRef
}

// serviceSelector matches one service's endpoints.
func serviceSelector(project, service string) endpointSelector {
	return endpointSelector{MatchLabels: map[string]string{
		selectorSource + LabelManaged: "true",
		selectorSource + LabelProject: project,
		selectorSource + LabelService: service,
	}}
}

// serviceAllowPolicy builds the extra ingress edges a service asked for.
//
// It is a separate document from the project isolation policy because a
// CiliumClusterwideNetworkPolicy carries exactly one endpointSelector, and this
// one selects a single service rather than the whole project.
//
// Being separate is also what makes it safe. Cilium unions ingress rules across
// every policy selecting an endpoint, so this document can only ever *add*
// reachability — there is no way for a job spec to weaken the project's
// default-deny boundary by writing something here.
func serviceAllowPolicy(project string, svc ServicePolicy) policyDocument {
	peers := make([]endpointSelector, 0, len(svc.AllowFrom))
	for _, peer := range svc.AllowFrom {
		peers = append(peers, serviceSelector(peer.Project, peer.Service))
	}
	return policyDocument{
		APIVersion: policyAPIVersion,
		Kind:       kindClusterwide,
		Metadata:   policyMetadata{Name: allowPolicyName(project, svc.Service)},
		Spec: policySpec{
			EndpointSelector: serviceSelector(project, svc.Service),
			Ingress:          []ingressRule{{FromEndpoints: peers}},
		},
	}
}

func allowPolicyName(project, service string) string {
	return policyFilePrefix + project + "-" + service + "-allow"
}

func allowPolicyFileName(project, service string) string {
	return allowPolicyName(project, service) + policyFileSuffix
}

// projectSelector matches every Kanea endpoint in one project.
func projectSelector(project string) endpointSelector {
	return endpointSelector{MatchLabels: map[string]string{
		selectorSource + LabelManaged: "true",
		selectorSource + LabelProject: project,
	}}
}

// projectIsolationPolicy builds PRD §7.1's default: the project is an isolation
// boundary. Ingress is allowed from the same project and from the node (the
// edge proxy); everything else is denied. Egress is left unrestricted.
func projectIsolationPolicy(project string) policyDocument {
	return policyDocument{
		APIVersion: policyAPIVersion,
		Kind:       kindClusterwide,
		Metadata:   policyMetadata{Name: policyName(project)},
		Spec: policySpec{
			EndpointSelector: projectSelector(project),
			Ingress: []ingressRule{
				{FromEndpoints: []endpointSelector{projectSelector(project)}},
				{FromEntities: []string{entityHost}},
			},
		},
	}
}

func policyName(project string) string { return policyFilePrefix + project + "-isolation" }

func policyFileName(project string) string { return policyName(project) + policyFileSuffix }

// SyncPolicies makes the policy directory match the given set of projects.
//
// It writes what is missing or changed, removes what is no longer wanted, and
// leaves everything else alone. Rewriting an unchanged file would be visible to
// the agent as a policy change and cost an endpoint regeneration for nothing,
// so "no drift" really does mean no writes.
func (c *Cilium) SyncPolicies(_ context.Context, projects []ProjectPolicy) error {
	if err := os.MkdirAll(c.policyDir, 0o700); err != nil {
		return fmt.Errorf("policy dir: %w", err)
	}

	wanted := make(map[string][]byte, len(projects))
	for _, project := range projects {
		body, err := renderPolicy(projectIsolationPolicy(project.Project))
		if err != nil {
			return fmt.Errorf("policy for project %s: %w", project.Project, err)
		}
		wanted[policyFileName(project.Project)] = body

		for _, svc := range project.Services {
			if len(svc.AllowFrom) == 0 {
				continue
			}
			body, err := renderPolicy(serviceAllowPolicy(project.Project, svc))
			if err != nil {
				return fmt.Errorf("policy for service %s/%s: %w", project.Project, svc.Service, err)
			}
			wanted[allowPolicyFileName(project.Project, svc.Service)] = body
		}
	}

	existing, err := c.listPolicyFiles()
	if err != nil {
		return err
	}

	// Remove first. A project that is going away should lose its policy before
	// anything else changes, and removing a file the agent has already loaded
	// cannot fail the way writing one can.
	for _, name := range existing {
		if _, keep := wanted[name]; keep {
			continue
		}
		if err := os.Remove(filepath.Join(c.policyDir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale policy %s: %w", name, err)
		}
		c.log.Info("withdrew network policy", "file", name)
	}

	for _, name := range sortedKeys(wanted) {
		changed, err := c.writePolicyIfChanged(name, wanted[name])
		if err != nil {
			return err
		}
		if changed {
			c.log.Info("installed network policy", "file", name)
		}
	}
	return nil
}

// renderPolicy validates and serialises one document.
//
// Validation runs before anything touches the filesystem, because the failure
// mode on the other side is not a rejected policy — the agent calls Fatal on a
// document it cannot translate, and does it again on the next startup scan, so
// a bad file is a crash loop (M0 spike ①). Everything here is therefore checked
// even though the inputs are already DNS-1123 names by the time they arrive.
func renderPolicy(doc policyDocument) ([]byte, error) {
	if err := doc.validate(); err != nil {
		return nil, err
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode policy: %w", err)
	}
	return append(body, '\n'), nil
}

// validate rejects a document the agent would choke on.
func (d policyDocument) validate() error {
	switch {
	case d.APIVersion != policyAPIVersion:
		return fmt.Errorf("policy: apiVersion %q, want %q", d.APIVersion, policyAPIVersion)
	case d.Kind != kindClusterwide:
		return fmt.Errorf("policy: kind %q, want %q", d.Kind, kindClusterwide)
	case d.Metadata.Name == "":
		return fmt.Errorf("policy: empty name")
	}
	if err := validateDNS1123(d.Metadata.Name); err != nil {
		return fmt.Errorf("policy name: %w", err)
	}
	// An empty endpointSelector is not a harmless no-op: it selects *every*
	// endpoint on the node, including reserved:host. Combined with an ingress
	// list this is how a generated policy locks the operator out of their own
	// node, which PRD §5.2.5 calls out as a thing that must never happen.
	if len(d.Spec.EndpointSelector.MatchLabels) == 0 {
		return fmt.Errorf("policy %s: empty endpointSelector would select every endpoint on the node",
			d.Metadata.Name)
	}
	for key, value := range d.Spec.EndpointSelector.MatchLabels {
		if err := validateSelectorLabel(key, value); err != nil {
			return fmt.Errorf("policy %s endpointSelector: %w", d.Metadata.Name, err)
		}
	}
	for i, rule := range d.Spec.Ingress {
		if len(rule.FromEndpoints) == 0 && len(rule.FromEntities) == 0 {
			// An ingress rule with no peers allows nothing while still switching
			// enforcement on — silent, total denial for the selected endpoints.
			return fmt.Errorf("policy %s ingress[%d]: rule selects no peers", d.Metadata.Name, i)
		}
		for _, sel := range rule.FromEndpoints {
			for key, value := range sel.MatchLabels {
				if err := validateSelectorLabel(key, value); err != nil {
					return fmt.Errorf("policy %s ingress[%d]: %w", d.Metadata.Name, i, err)
				}
			}
		}
	}
	return nil
}

func validateSelectorLabel(key, value string) error {
	switch {
	case key == "":
		return fmt.Errorf("empty selector label key")
	case value == "":
		return fmt.Errorf("selector label %q has an empty value", key)
	case strings.ContainsAny(value, ":= \t\n"):
		return fmt.Errorf("selector label %q has an unusable value %q", key, value)
	}
	return nil
}

// validateDNS1123 checks a subdomain-shaped name. Cilium's directory watcher
// ignores files whose names are not DNS-1123 subdomains, which would make a
// policy silently absent rather than loudly broken.
func validateDNS1123(s string) error {
	if s == "" || len(s) > 253 {
		return fmt.Errorf("%q is not a DNS-1123 subdomain", s)
	}
	for i := range len(s) {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
		case ch == '-' || ch == '.':
			if i == 0 || i == len(s)-1 {
				return fmt.Errorf("%q is not a DNS-1123 subdomain", s)
			}
		default:
			return fmt.Errorf("%q is not a DNS-1123 subdomain", s)
		}
	}
	return nil
}

// writePolicyIfChanged writes a policy file atomically, skipping the write when
// the content already matches. It reports whether it wrote.
//
// The temp file deliberately does not end in .yaml: the watcher reacts to
// fsnotify events and would otherwise try to load a half-written document, and
// a half-written document is a dead agent.
func (c *Cilium) writePolicyIfChanged(name string, body []byte) (bool, error) {
	final := filepath.Join(c.policyDir, name)
	// #nosec G304 — name is policyName()+".yaml", and renderPolicy has already
	// put that name through validateDNS1123, which admits neither '/' nor '..'.
	// The path cannot escape the policy directory.
	if current, err := os.ReadFile(final); err == nil && bytes.Equal(current, body) {
		return false, nil
	}

	tmp := filepath.Join(c.policyDir, "."+name+".tmp")
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return false, fmt.Errorf("write policy %s: %w", name, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		// Leaving a stray temp file behind is harmless — the watcher ignores it
		// — but it would confuse the next operator to look in this directory.
		if rmErr := os.Remove(tmp); rmErr != nil && !os.IsNotExist(rmErr) {
			return false, fmt.Errorf("install policy %s: %w (and temp file left behind: %w)", name, err, rmErr)
		}
		return false, fmt.Errorf("install policy %s: %w", name, err)
	}
	return true, nil
}

// listPolicyFiles returns the policy files Kanea owns, by prefix.
func (c *Cilium) listPolicyFiles() ([]string, error) {
	entries, err := os.ReadDir(c.policyDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read policy dir %s: %w", c.policyDir, err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, policyFilePrefix) || !strings.HasSuffix(name, policyFileSuffix) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
