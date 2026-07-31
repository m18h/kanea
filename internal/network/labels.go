package network

import (
	"fmt"
	"sort"
	"strings"
)

// Identity label keys. These are what Cilium hashes into a security identity,
// and therefore what every policy selector matches on.
const (
	// LabelManaged marks an endpoint as Kanea's, so a policy can address all
	// managed workloads without enumerating projects.
	LabelManaged = "kanea"
	// LabelProject is the isolation boundary (PRD §7.1).
	LabelProject = "project"
	// LabelService names the service within its project.
	LabelService = "service"
	// LabelNamespace is the k8s-shaped namespace label. It is not optional and
	// it is not vestigial: Cilium rewrites every fromEndpoints/toEndpoints
	// selector to also require this label, so an endpoint without it matches no
	// peer selector at all — every rule silently denies everything (M0 spike ①).
	// Project ≡ namespace in Cilium's policy semantics.
	LabelNamespace = "k8s:io.kubernetes.pod.namespace"
)

// IdentityLabels are the labels an alloc's endpoint carries.
//
// The alloc id is deliberately absent. Cilium allocates one security identity
// per distinct label set, so including a per-alloc label would mint an identity
// for every alloc — filling the kvstore, multiplying policy map entries, and
// making a scale-out reprogram the datapath instead of reusing an identity. All
// allocs of a service share one identity, which is what makes "allow service A
// to reach service B" a single rule rather than a cross product. Per-alloc
// addressing comes from the endpoint's container id (DNS, §7.1), not identity.
//
// The result is sorted so an unchanged service produces a byte-identical label
// set on every attach — the agent then has nothing to re-resolve.
func IdentityLabels(project, service string) []string {
	labels := []string{
		LabelManaged + "=true",
		LabelProject + "=" + project,
		LabelService + "=" + service,
		LabelNamespace + "=" + project,
	}
	sort.Strings(labels)
	return labels
}

// ServiceRef identifies the service an endpoint belongs to.
type ServiceRef struct {
	Project string
	Service string
}

// String renders the canonical "project/service" form used in logs and keys.
func (r ServiceRef) String() string { return r.Project + "/" + r.Service }

// serviceRefFrom reads the project and service back out of an endpoint's
// realized identity labels, or reports false if this is not a Kanea endpoint.
//
// The agent returns labels with their source prefixed ("unspec:project=shop"),
// and the prefix is not part of what we wrote, so it is stripped before
// matching. Cilium's own labels (reserved:host, reserved:health) and any
// endpoint another tool created fall out as "not ours" — which matters, because
// this is what decides whether Kanea will program LB backends for an endpoint.
func serviceRefFrom(labels []string) (ServiceRef, bool) {
	var ref ServiceRef
	managed := false

	for _, raw := range labels {
		key, value, ok := splitLabel(raw)
		if !ok {
			continue
		}
		switch key {
		case LabelManaged:
			managed = value == "true"
		case LabelProject:
			ref.Project = value
		case LabelService:
			ref.Service = value
		}
	}
	if !managed || ref.Project == "" || ref.Service == "" {
		return ServiceRef{}, false
	}
	return ref, true
}

// splitLabel parses "source:key=value" or "key=value" into key and value.
//
// The namespace label is the reason this is not a plain strings.Cut on ":": its
// key legitimately contains dots and its source prefix is "k8s", so
// "k8s:io.kubernetes.pod.namespace=shop" must split into
// ("io.kubernetes.pod.namespace", "shop") — the prefix goes, the dotted key
// stays whole.
func splitLabel(raw string) (key, value string, ok bool) {
	key, value, ok = strings.Cut(raw, "=")
	if !ok {
		return "", "", false
	}
	if source, rest, found := strings.Cut(key, ":"); found {
		_ = source
		key = rest
	}
	return key, value, true
}

// validateLabelValue rejects values that would corrupt the label set. Project
// and service names are DNS-1123 labels by the time they reach here (jobspec
// R1), so this is a last-line assertion rather than the real gate — but the
// consequence of a bad value is an endpoint that matches no policy, which fails
// silently and denies traffic. Cheap to check, expensive to debug.
func validateLabelValue(kind, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("network: empty %s name", kind)
	case strings.ContainsAny(value, "=:;, \t\n"):
		return fmt.Errorf("network: %s name %q contains a character that is not valid in a label", kind, value)
	}
	return nil
}
