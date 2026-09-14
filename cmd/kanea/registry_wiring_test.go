package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The internal registry's wiring guards (§5.2.14), in agent_wiring_test.go's
// source-reading pattern: the defect this catches lives in composite
// literals, not in any function's behaviour. A registry that serves but that
// no build ever targets - or a pipeline stack with no registry seam - is
// invisible in dev, because every package test wires its own harness, and
// fatal on the first real node whose spec omits build.target.

// literalFields collects the field names set in every `pkg.typeName{...}`
// literal in the given file. The bool reports whether any literal was seen.
func literalFields(t *testing.T, filename, pkg, typeName string) (map[string]bool, bool) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	found := map[string]bool{}
	var seen bool
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != typeName {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); !ok || ident.Name != pkg {
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
	return found, seen
}

func TestTheDaemonWiresTheRegistryItself(t *testing.T) {
	required := map[string]string{
		"Addr":    "the registry binds the zero address and New refuses to start",
		"Dir":     "the registry has nowhere to store blobs and New refuses to start",
		"Allowed": "every push is refused: a nil bound fails closed, so no build can ever land",
		"Logger":  "refusals and sweeps happen silently",
	}
	found, seen := literalFields(t, "registry.go", "registry", "Config")
	if !seen {
		t.Fatal("no registry.Config literal in registry.go; this test can no longer see what it guards")
	}
	for field, consequence := range required {
		if !found[field] {
			t.Errorf("registry.go builds registry.Config without %s: %s", field, consequence)
		}
	}
}

func TestTheAgentHandsTheRegistryToThePipelines(t *testing.T) {
	found, seen := literalFields(t, "agent.go", "", "pipelineSettings")
	if !seen {
		// pipelineSettings is package-local, so the literal's type is a bare
		// ident rather than a selector; walk again for that shape.
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "agent.go", nil, 0)
		if err != nil {
			t.Fatalf("parse agent.go: %v", err)
		}
		found = map[string]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if ident, ok := lit.Type.(*ast.Ident); !ok || ident.Name != "pipelineSettings" {
				return true
			}
			seen = true
			for _, elt := range lit.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok {
						found[key.Name] = true
					}
				}
			}
			return false
		})
	}
	if !seen {
		t.Fatal("no pipelineSettings literal in agent.go; this test can no longer see what it guards")
	}
	if !found["registry"] {
		t.Error("agent.go builds pipelineSettings without registry: " +
			"every omitted build.target is refused even though the registry is serving")
	}
}

func TestBuildPipelinesForwardsTheRegistryToBothHalves(t *testing.T) {
	// Both halves, because they fail differently: without the ServiceConfig
	// seam the omitted target is refused at request assembly, and without the
	// RunnerConfig seam a composed target reaches the build with no
	// credential to push it.
	for typeName, consequence := range map[string]string{
		"RunnerConfig":  "an internal-target build has no push credential and fails at the registry",
		"ServiceConfig": "an omitted build.target is refused even though the registry is serving",
	} {
		found, seen := literalFields(t, "pipelines.go", "gitops", typeName)
		if !seen {
			t.Fatalf("no gitops.%s literal in pipelines.go; this test can no longer see what it guards", typeName)
		}
		if !found["Registry"] {
			t.Errorf("pipelines.go builds gitops.%s without Registry: %s", typeName, consequence)
		}
	}
}
