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
// `secret:` refs and R27 route auth, and cmd/kanea never passed one - so on
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
		// R33's node default. Its zero value happens to behave like the
		// historical default, which is exactly why a missing wire here would
		// be invisible: `images { pull_policy = "never" }` would be accepted,
		// logged, and then quietly ignored on every pull.
		"DefaultPullPolicy": "the images stanza and --image-pull-policy are silently ignored",
		// R35's plain-file tree. Its zero value is not a working default: a
		// service declaring any file fails its alloc, and the failure would be
		// a daemon-wiring bug wearing a spec error's clothes.
		"PlainFilesDir": "every service that declares a config file fails to start",
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

// TestTheAgentWiresTheAPIServersOptionalDependencies is the same guard over
// api.ServerConfig. Every field here is nil-tolerant by design (the route
// answers 503), which is exactly what makes a missing wire invisible in dev:
// the api package's own tests set their fakes, and only this literal decides
// what a real node gets.
func TestTheAgentWiresTheAPIServersOptionalDependencies(t *testing.T) {
	required := map[string]string{
		"Upgrader":      "the dashboard's check-and-upgrade answers 503 on every node (PRD v1.107)",
		"HostInspector": "the dashboard's updates view answers 503 on every node (PRD v1.108)",
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
		if !ok || sel.Sel.Name != "ServerConfig" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "api" {
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
		t.Fatal("no api.ServerConfig literal in agent.go; this test can no longer see what it guards")
	}
	for field, consequence := range required {
		if !found[field] {
			t.Errorf("agent.go builds api.ServerConfig without %s: %s", field, consequence)
		}
	}
}

// TestTheAgentWiresTheBuildEgressIdentity is the same source-reading guard
// over datapath.Config (v1.105's half of recurring rule: every optional
// daemon dependency is wired in cmd/kanea, pinned by a test that reads the
// source). Each zero here is a working node with a silently open hole: the
// build-egress rules key on these and simply do not exist without them,
// which no test of the datapath package can notice, since its tests set
// their own Config.
func TestTheAgentWiresTheBuildEgressIdentity(t *testing.T) {
	required := map[string]string{
		"BuildEgressUID":   "the metadata drop for build traffic never exists",
		"BuildSubUIDStart": "a Dockerfile USER step's subuid traffic escapes the drop",
		"BuildSubUIDCount": "a Dockerfile USER step's subuid traffic escapes the drop",
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
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "datapath" {
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
		t.Fatal("no datapath.Config literal in agent.go; this test can no longer see what it guards")
	}
	for field, consequence := range required {
		if !found[field] {
			t.Errorf("agent.go builds datapath.Config without %s: %s", field, consequence)
		}
	}
}
