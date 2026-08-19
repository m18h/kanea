package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestTheAgentWiresEveryOptionalReconcilerDependency reads agent.go and asserts
// that the reconciler.Config it builds populates the fields whose zero value
// silently disables a documented feature.
//
// This exists because of a bug no unit test could catch. reconciler.Config
// gained a Secrets field, the reconciler used it for registry credentials, env
// `secret:` refs and R27 route auth, and cmd/kanea never passed one — so on
// every real node those three features failed with "no secret store is
// configured" while the store itself was healthy. Every reconciler test sets
// cfg.Secrets on its own harness, which is exactly why the package's tests were
// green: they proved the reconciler works when wired, and nothing proved the
// daemon wires it.
//
// Reading the source is unusual and is the point: the defect is in the
// composite literal, not in any function's behaviour, so there is nothing else
// to assert against.
func TestTheAgentWiresEveryOptionalReconcilerDependency(t *testing.T) {
	// Each of these is nil-tolerant by design, and each nil turns off
	// something an operator asked for in a spec.
	required := map[string]string{
		"Secrets":     "registry credentials, env secret: refs and route auth all fail their alloc",
		"Passthrough": "every device and socket grant is refused",
		"Mounts":      "nfs, smb and s3 volumes never mount",
		"Breaker":     "the reconciler has no circuit breaker",
		"Emit":        "no notification is ever published",
		"VolumeUsage": "volume budgets are never measured",
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "agent.go", nil, 0)
	if err != nil {
		t.Fatalf("parse agent.go: %v", err)
	}

	found := map[string]bool{}
	var seen bool
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Config" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "reconciler" {
			return true
		}
		seen = true
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok {
				found[key.Name] = true
			}
		}
		return false
	})

	if !seen {
		t.Fatal("no reconciler.Config literal in agent.go; this test can no longer see what it guards")
	}
	for field, consequence := range required {
		if !found[field] {
			t.Errorf("agent.go builds reconciler.Config without %s: %s", field, consequence)
		}
	}
}
