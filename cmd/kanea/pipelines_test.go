package main

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/m18h/kanea/internal/store"
)

// The daemon's own pipeline wiring must construct, not just the gitops
// package's pieces individually. RunnerConfig.WorkDir was required from the
// day the runner landed and this call site never set it, so kanead with
// pipelines enabled (the default) refused to start on every real node while
// every unit test, building its own RunnerConfig, passed. This walks the
// wiring the daemon actually runs.
func TestBuildPipelinesStartsWithDefaults(t *testing.T) {
	st, err := store.Open(store.Options{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	svc, queue, err := buildPipelines(pipelineSettings{
		buildkit: "unix:///run/does-not-need-to-exist/buildkitd.sock",
		logDir:   filepath.Join(t.TempDir(), "builds"),
		store:    st,
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("buildPipelines with default-shaped settings refused: %v", err)
	}
	if svc == nil || queue == nil {
		t.Fatal("buildPipelines returned a nil service or queue with pipelines enabled")
	}

	// And "off" stays a supported configuration: nil everything, no error.
	svc, queue, err = buildPipelines(pipelineSettings{buildkit: "off"}, slog.New(slog.DiscardHandler))
	if err != nil || svc != nil || queue != nil {
		t.Fatalf("buildkit=off = (%v, %v, %v), want (nil, nil, nil)", svc, queue, err)
	}
}
