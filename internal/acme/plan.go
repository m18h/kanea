package acme

import (
	"sort"
	"strings"
)

// DefaultWildcardThreshold is how many per-service certificates a node issues
// before it switches to wildcards (PRD §7.3).
//
// The number comes from Let's Encrypt's limits, not from taste: 50 certificates
// per registered domain per week, and every redeploy that changes a name spends
// one. Twenty leaves room for the churn a real week contains.
const DefaultWildcardThreshold = 20

// Exposure is one exposed service's names, as the route table resolved them.
type Exposure struct {
	// Service is "project/service", for logs and events.
	Service string
	Project string
	// Domains are the names the edge routes for this service.
	Domains []string
	// Auto reports whether Domains are the generated FQDNs of §7.2 rather than
	// operator-declared custom domains. Only generated names can be collapsed
	// into a wildcard: a custom domain is somebody else's zone, and Kanea has
	// no standing to ask for `*.` of it.
	Auto bool
}

// PlanOptions shapes the issuance plan.
type PlanOptions struct {
	// BaseDomain is the suffix generated FQDNs are built under.
	BaseDomain string
	// Wildcards reports whether a DNS-01 solver is configured. Without one a
	// wildcard cannot be issued at all: HTTP-01 cannot validate a name that
	// does not resolve to one host.
	Wildcards bool
	// Threshold overrides DefaultWildcardThreshold.
	Threshold int
}

// Plan is what Plan decided, so the caller can log and alert on it rather than
// this package reaching for a logger.
type Plan struct {
	Requests []Request
	// PerService and Wildcard count what kind of certificate was planned.
	PerService int
	Wildcard   int
	// OverThreshold is set when there are more per-service certificates than
	// the threshold allows and nothing could be done about it, which today
	// means DNS-01 is not configured. It is the condition §7.3 wants said
	// loudly rather than discovered as a rate-limit rejection.
	OverThreshold bool
}

// PlanRequests decides what certificates to ask for.
//
// The rule, from §7.3: per-service certificates while there are few, wildcards
// once there are many. The switch exists because Let's Encrypt counts
// certificates per registered domain per week, and a node with fifty services
// redeploying twice a day walks into that limit: at which point *nothing*
// issues, including the renewal of a certificate already in production.
//
// The wildcard is per project, not per node: the generated names of §7.2 are
// `service.project.<base>`, and a wildcard covers exactly one label. A
// `*.<base>` certificate would not match a single one of them.
func PlanRequests(exposures []Exposure, opts PlanOptions) Plan {
	threshold := opts.Threshold
	if threshold <= 0 {
		threshold = DefaultWildcardThreshold
	}

	// Custom domains are never collapsed, so they are counted but not eligible.
	var custom []Exposure
	autoByProject := map[string][]Exposure{}
	for _, e := range exposures {
		if len(e.Domains) == 0 {
			continue
		}
		if e.Auto && opts.BaseDomain != "" {
			autoByProject[e.Project] = append(autoByProject[e.Project], e)
			continue
		}
		custom = append(custom, e)
	}

	total := len(custom)
	for _, group := range autoByProject {
		total += len(group)
	}

	plan := Plan{}
	// Below the threshold, per-service is simpler and needs no DNS credential.
	// A wildcard is the answer to a scale problem, not an improvement in itself:
	// it puts one key in front of every service in a project, so it is worth
	// having only once the alternative is a rate limit.
	collapse := opts.Wildcards && total > threshold

	for _, e := range custom {
		plan.Requests = append(plan.Requests, Request{Domains: e.Domains, Service: e.Service})
		plan.PerService++
	}

	projects := make([]string, 0, len(autoByProject))
	for project := range autoByProject {
		projects = append(projects, project)
	}
	sort.Strings(projects)

	for _, project := range projects {
		group := autoByProject[project]
		if !collapse {
			for _, e := range group {
				plan.Requests = append(plan.Requests, Request{Domains: e.Domains, Service: e.Service})
				plan.PerService++
			}
			continue
		}
		suffix := project + "." + strings.Trim(opts.BaseDomain, ".")
		plan.Requests = append(plan.Requests, Request{
			// The bare name is included alongside the wildcard: `*.shop.example`
			// does not match `shop.example`, and a project-level route on the
			// parent name is a reasonable thing to add later without reissuing.
			Domains: []string{"*." + suffix, suffix},
			Service: project + " (wildcard)",
		})
		plan.Wildcard++
	}

	plan.OverThreshold = total > threshold && !collapse
	return plan
}
