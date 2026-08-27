package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/reconciler"
)

// TestLogsContainerFlagAfterServiceReachesTheServer pins the whole path from
// argv to query string: `kanea logs shop/api -c migrate` - the form the README
// teaches - must send ?container=migrate. It did not: flag parsing stopped at
// the positional and silently dropped the rest, so the command answered with
// the task's log and no error.
func TestLogsContainerFlagAfterServiceReachesTheServer(t *testing.T) {
	var container atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case api.PathServices:
			resp := api.ServicesResponse{Services: []api.ServiceView{
				{Desired: reconciler.Desired{Project: "shop", Service: "api", Count: 1}},
			}}
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Error(err)
			}
		case api.PathLogs:
			container.Store(r.URL.Query().Get("container"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	err := runLogs([]string{"shop/api", "-c", "migrate", "--url", srv.URL, "--token", "t"})
	if err != nil {
		t.Fatalf("runLogs: %v", err)
	}
	if got, _ := container.Load().(string); got != "migrate" {
		t.Fatalf("server saw container=%q, want %q", got, "migrate")
	}
}

// A second positional is refused rather than ignored: before parseArgs it was
// where a mis-ordered flag's value landed, invisibly.
func TestLogsRefusesExtraPositionals(t *testing.T) {
	if err := runLogs([]string{"shop/api", "extra"}); err == nil {
		t.Fatal("runLogs accepted a second positional")
	}
}

// TestLogsPreviousReachesARemovedService (PRD v1.101): --previous must work on
// a service that no longer exists - that is half its point - so when the name
// resolves against nothing, the literal project/service passes through and the
// daemon answers from disk. The fake daemon here declares no services at all.
func TestLogsPreviousReachesARemovedService(t *testing.T) {
	var query atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case api.PathServices:
			if err := json.NewEncoder(w).Encode(api.ServicesResponse{}); err != nil {
				t.Error(err)
			}
		case api.PathLogs:
			query.Store(r.URL.Query())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	err := runLogs([]string{"shop/api", "--previous", "--url", srv.URL, "--token", "t"})
	if err != nil {
		t.Fatalf("runLogs: %v", err)
	}
	q, _ := query.Load().(url.Values)
	if q.Get("previous") != "true" || q.Get("project") != "shop" || q.Get("service") != "api" {
		t.Fatalf("server saw %v, want previous=true for shop/api", q)
	}

	// Without --previous the unresolvable name stays an error: the fallback
	// exists for reading what remains, not for typos.
	if err := runLogs([]string{"shop/api", "--url", srv.URL, "--token", "t"}); err == nil {
		t.Fatal("a live query for an unknown service did not error")
	}

	// And a bare service name cannot fall back - the daemon finds files by
	// their full name, so the project must be spelled.
	err = runLogs([]string{"api", "--previous", "--url", srv.URL, "--token", "t"})
	if err == nil || !strings.Contains(err.Error(), "project/service") {
		t.Fatalf("bare-name --previous = %v, want a refusal asking for the full name", err)
	}
}
