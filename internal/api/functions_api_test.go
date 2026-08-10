package api_test

// GET /v1/functions (v1.39) and the R25 apply-boundary checks.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/functions"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
)

// fakeInvoker serves fixed counters.
type fakeInvoker struct {
	stats   map[string]functions.Stats
	dropped int64
}

func (f fakeInvoker) Snapshot() map[string]functions.Stats { return f.stats }
func (f fakeInvoker) Dropped() int64                       { return f.dropped }

func desiredFunction(project, service string) reconciler.Desired {
	return reconciler.Desired{
		Project: project, Service: service, Count: 1,
		Image:   "example.com/" + service + ":1",
		Runtime: runtime.RuntimeWasmtime,
		Function: &reconciler.FunctionMeta{
			HTTP:   true,
			Events: []reconciler.EventTrigger{{On: []string{"deploy.failed"}}},
			Crons:  []reconciler.CronTrigger{{Schedule: "0 3 * * *", Path: "/nightly"}},
		},
		Ports:     []reconciler.Port{{Name: "http", Container: 8080}},
		Expose:    &reconciler.Expose{Port: 8080},
		Resources: runtime.Resources{CPUMillis: 100, MemoryBytes: 64 << 20, PidsLimit: 256},
	}
}

func TestListFunctionsFiltersOnTheMarker(t *testing.T) {
	h := newHarness(t, func(cfg *api.ServerConfig) {
		cfg.Invoker = fakeInvoker{
			stats: map[string]functions.Stats{
				"shop/resize": {Invocations: 12, Failures: 1, LastInvoked: time.Now()},
			},
		}
	})
	h.putDesired(t, desiredFunction("shop", "resize"))
	h.putService(t, "shop", "web", 2) // an ordinary service: must not appear

	resp, err := h.client.Functions(context.Background())
	if err != nil {
		t.Fatalf("functions: %v", err)
	}
	if len(resp.Functions) != 1 {
		t.Fatalf("functions = %d, want 1 (the marker filter)", len(resp.Functions))
	}
	fn := resp.Functions[0]
	if fn.Service != "resize" || fn.Runtime != runtime.RuntimeWasmtime {
		t.Errorf("view = %+v", fn)
	}
	if !fn.HTTP || len(fn.Events) != 1 || len(fn.Crons) != 1 {
		t.Errorf("triggers did not survive: %+v", fn)
	}
	if fn.Invoker == nil || fn.Invoker.Invocations != 12 {
		t.Errorf("invoker counters missing: %+v", fn.Invoker)
	}
	if fn.MemoryBytes != 64<<20 {
		t.Errorf("memory cap = %d", fn.MemoryBytes)
	}
	// No datapath sample in this harness: the rate must be absent, never zero.
	if fn.InvocationsPerMinute != nil {
		t.Errorf("rate = %v, want absent with no sample", *fn.InvocationsPerMinute)
	}
}

// The R25 boundary at apply: a record that bypassed the parser is refused
// here, exactly as R22's port policy is.
func TestApplyRefusesWhatR25Refuses(t *testing.T) {
	h := newHarness(t)

	// An unknown runtime name.
	bad := desiredFunction("shop", "fn")
	bad.Runtime = "io.containerd.kata.v2"
	_, err := h.client.Apply(context.Background(), []reconciler.Desired{bad}, nil)
	if err == nil || !strings.Contains(err.Error(), "runtime") {
		t.Fatalf("an unknown runtime applied: %v", err)
	}

	// An exec probe on a wasm service.
	probed := desiredFunction("shop", "fn")
	probed.Check = &reconciler.HealthCheck{Type: reconciler.HealthExec, Command: []string{"/check"}}
	_, err = h.client.Apply(context.Background(), []reconciler.Desired{probed}, nil)
	if err == nil || !strings.Contains(err.Error(), "exec") {
		t.Fatalf("an exec check on a wasm service applied: %v", err)
	}
}
