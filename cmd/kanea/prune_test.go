package main

import (
	"strings"
	"testing"
)

// TestPruneScopeRefusals covers the two combinations that would turn
// --remove-orphans into a node-wide delete, and the one that has nothing to be
// authoritative over.
//
// The selector case is the dangerous one: selectors filter the desired state
// before it is sent, so `kanea run app.hcl shop/web --remove-orphans` would
// otherwise mean "delete everything in shop except web".
func TestPruneScopeRefusals(t *testing.T) {
	sel := []selector{{raw: "shop/web", project: "shop", service: "web"}}

	for _, tc := range []struct {
		name     string
		declared []string
		sels     []selector
		image    string
		want     string
	}{
		{"a selector cannot be authoritative", []string{"shop"}, sel, "", "cannot be combined with a selector"},
		{"--image declares no project", nil, nil, "nginx:1.27", "needs a spec file"},
		{"a spec with no project block", nil, nil, "", "no project block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pruneScope(true, tc.declared, tc.sels, tc.image)
			if err == nil {
				t.Fatal("accepted a scope that could not be honest")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestPruneIsOffUnlessAskedFor is the regression guard for the invariant this
// feature bends: an apply is additive, and nothing absent from the request is
// ever pruned unless the request says so.
func TestPruneIsOffUnlessAskedFor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sels  []selector
		image string
	}{
		{"a plain apply", nil, ""},
		{"with a selector", []selector{{raw: "shop", project: "shop"}}, ""},
		{"with --image", nil, "nginx:1.27"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// removeOrphans=false: none of these may produce a scope, and none
			// may error, because the flag is what asks for the behaviour.
			scope, err := pruneScope(false, []string{"shop"}, tc.sels, tc.image)
			if err != nil {
				t.Fatalf("err = %v, want none: the flag was not passed", err)
			}
			if scope != nil {
				t.Errorf("scope = %v, want nil: an apply prunes nothing unless asked", scope)
			}
		})
	}
}

func TestPruneScopeIsTheDeclaredProjects(t *testing.T) {
	scope, err := pruneScope(true, []string{"shop", "data"}, nil, "")
	if err != nil {
		t.Fatalf("pruneScope: %v", err)
	}
	if len(scope) != 2 || scope[0] != "shop" || scope[1] != "data" {
		t.Errorf("scope = %v, want the spec's project blocks", scope)
	}
}
