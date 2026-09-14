package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/store"
)

func openTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return st
}

func TestBuildRegistryOffIsSupported(t *testing.T) {
	st := openTestStore(t)
	logger := slog.New(slog.DiscardHandler)

	// "off" itself, and the buildkit coupling: a node that cannot build has
	// no reason to hold a listener open.
	for _, tc := range []struct{ addr, buildkit string }{
		{"off", "unix:///run/kanea/buildkitd.sock"},
		{"127.0.0.1:0", "off"},
	} {
		reg, seam, err := buildRegistry(tc.addr, tc.buildkit, t.TempDir(), st, logger)
		if err != nil || reg != nil || seam.Addr != "" {
			t.Errorf("buildRegistry(%q, %q) = (%v, %+v, %v), want off",
				tc.addr, tc.buildkit, reg, seam, err)
		}
	}
}

// TestBuildRegistryBoundsPushesToDeclaredPipelines exercises the Allowed
// closure buildRegistry actually wires - through the served registry, not a
// reimplementation - against the same Store record the sync loop polls.
func TestBuildRegistryBoundsPushesToDeclaredPipelines(t *testing.T) {
	st := openTestStore(t)
	reg, seam, err := buildRegistry("127.0.0.1:0", "unix:///run/kanea/buildkitd.sock",
		t.TempDir(), st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("buildRegistry: %v", err)
	}
	if reg == nil || seam.Addr != reg.Addr() || seam.PushAuth == nil {
		t.Fatalf("seam = %+v; want the bound address and a push credential", seam)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- reg.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	if _, err := store.PutValue(context.Background(), st, store.KindProject, "shop",
		gitops.Config{
			Project: "shop",
			Builds:  map[string]gitops.BuildSpec{"web": {Context: "."}},
		}); err != nil {
		t.Fatalf("put config: %v", err)
	}

	var pushCfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(seam.PushAuth(), &pushCfg); err != nil {
		t.Fatalf("push credential: %v", err)
	}
	auth := "Basic " + pushCfg.Auths[seam.Addr].Auth

	client := &http.Client{Timeout: 5 * time.Second}
	post := func(repo string) int {
		req, err := http.NewRequest(http.MethodPost,
			"http://"+seam.Addr+"/v2/"+repo+"/blobs/uploads/", nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		req.Header.Set("Authorization", auth)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", repo, err)
		}
		defer resp.Body.Close() //nolint:errcheck // a test response
		return resp.StatusCode
	}

	if got := post("shop/web"); got != http.StatusAccepted {
		t.Errorf("push to the declared pipeline = %d, want 202", got)
	}
	for _, repo := range []string{"shop/api", "other/web"} {
		if got := post(repo); got != http.StatusForbidden {
			t.Errorf("push to undeclared %s = %d, want 403", repo, got)
		}
	}
}
