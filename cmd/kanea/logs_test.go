package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
