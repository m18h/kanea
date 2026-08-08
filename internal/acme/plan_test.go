package acme_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/acme"
)

// autoExposures builds n generated-FQDN services in one project.
func autoExposures(project string, n int, base string) []acme.Exposure {
	out := make([]acme.Exposure, 0, n)
	for i := range n {
		service := fmt.Sprintf("svc%02d", i)
		out = append(out, acme.Exposure{
			Service: project + "/" + service,
			Project: project,
			Domains: []string{service + "." + project + "." + base},
			Auto:    true,
		})
	}
	return out
}

func TestPlanKeepsPerServiceCertificatesBelowTheThreshold(t *testing.T) {
	plan := acme.PlanRequests(autoExposures("shop", 3, "apps.example.com"),
		acme.PlanOptions{BaseDomain: "apps.example.com", Wildcards: true})

	if plan.Wildcard != 0 {
		t.Fatalf("wildcards = %d, want none for three services", plan.Wildcard)
	}
	if plan.PerService != 3 || len(plan.Requests) != 3 {
		t.Fatalf("plan = %+v, want three per-service requests", plan)
	}
}

func TestPlanSwitchesToWildcardsPastTheThreshold(t *testing.T) {
	exposures := append(
		autoExposures("shop", 15, "apps.example.com"),
		autoExposures("blog", 10, "apps.example.com")...,
	)
	plan := acme.PlanRequests(exposures,
		acme.PlanOptions{BaseDomain: "apps.example.com", Wildcards: true})

	// Two projects, two certificates — instead of 25 that would spend half a
	// week's Let's Encrypt allowance on one deploy.
	if plan.Wildcard != 2 || plan.PerService != 0 {
		t.Fatalf("plan = %+v, want two wildcards", plan)
	}
	if plan.OverThreshold {
		t.Error("OverThreshold is set even though the wildcard switch handled it")
	}

	var names []string
	for _, req := range plan.Requests {
		names = append(names, strings.Join(req.Domains, " "))
	}
	// One label per star: `*.apps.example.com` would not match
	// `web.shop.apps.example.com`, which is exactly the shape §7.2 generates.
	want := []string{
		"*.blog.apps.example.com blog.apps.example.com",
		"*.shop.apps.example.com shop.apps.example.com",
	}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("request[%d] = %q, want %q", i, names[i], w)
		}
	}
}

func TestPlanWarnsInsteadOfSwitchingWithoutDNS01(t *testing.T) {
	plan := acme.PlanRequests(autoExposures("shop", 25, "apps.example.com"),
		acme.PlanOptions{BaseDomain: "apps.example.com", Wildcards: false})

	if plan.Wildcard != 0 {
		t.Fatalf("a wildcard was planned with no DNS-01 solver: %+v", plan)
	}
	if !plan.OverThreshold {
		t.Fatal("OverThreshold is not set; the operator would find out from a rate-limit rejection")
	}
	if plan.PerService != 25 {
		t.Fatalf("per-service = %d, want all 25 still requested", plan.PerService)
	}
}

func TestPlanNeverCollapsesACustomDomain(t *testing.T) {
	exposures := append(
		autoExposures("shop", 25, "apps.example.com"),
		acme.Exposure{
			Service: "shop/www",
			Project: "shop",
			Domains: []string{"shop.example.co.uk"},
			Auto:    false,
		},
	)
	plan := acme.PlanRequests(exposures,
		acme.PlanOptions{BaseDomain: "apps.example.com", Wildcards: true})

	// A custom domain is somebody else's zone; Kanea has no standing to ask a
	// CA for `*.` of it, and the operator did not ask for that either.
	var found bool
	for _, req := range plan.Requests {
		for _, domain := range req.Domains {
			if domain == "shop.example.co.uk" {
				found = true
			}
			if strings.HasPrefix(domain, "*.") && strings.Contains(domain, "co.uk") {
				t.Fatalf("a custom domain was collapsed into a wildcard: %q", domain)
			}
		}
	}
	if !found {
		t.Fatal("the custom domain lost its certificate")
	}
	if plan.PerService != 1 || plan.Wildcard != 1 {
		t.Fatalf("plan = %+v, want the custom domain kept and the rest collapsed", plan)
	}
}

func TestPlanIgnoresServicesWithNoDomains(t *testing.T) {
	plan := acme.PlanRequests([]acme.Exposure{{Service: "shop/web", Project: "shop"}},
		acme.PlanOptions{BaseDomain: "apps.example.com", Wildcards: true})
	if len(plan.Requests) != 0 {
		t.Fatalf("requests = %+v, want none", plan.Requests)
	}
}

func TestPlanIsDeterministic(t *testing.T) {
	exposures := append(
		autoExposures("zulu", 12, "apps.example.com"),
		autoExposures("alpha", 12, "apps.example.com")...,
	)
	opts := acme.PlanOptions{BaseDomain: "apps.example.com", Wildcards: true}

	// Map iteration order must not reach the request list: a plan that changes
	// order between passes looks like a change to anything comparing them.
	first := acme.PlanRequests(exposures, opts)
	for range 5 {
		next := acme.PlanRequests(exposures, opts)
		for i := range first.Requests {
			if next.Requests[i].Domains[0] != first.Requests[i].Domains[0] {
				t.Fatalf("plan order changed between passes: %q then %q",
					first.Requests[i].Domains[0], next.Requests[i].Domains[0])
			}
		}
	}
}

func TestPlanThresholdIsConfigurable(t *testing.T) {
	plan := acme.PlanRequests(autoExposures("shop", 3, "apps.example.com"),
		acme.PlanOptions{BaseDomain: "apps.example.com", Wildcards: true, Threshold: 2})
	if plan.Wildcard != 1 {
		t.Fatalf("plan = %+v, want the lowered threshold to trigger", plan)
	}
}
