package api_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/gitops"
)

// fakePipelines stands in for the coordinator. The API's job is routing,
// status mapping and audit; what gitops does with a request is tested there.
type fakePipelines struct {
	mu        sync.Mutex
	runs      []gitops.Run
	logPath   string
	triggered []string
	synced    []string
	delivered int

	triggerErr error
	syncErr    error
	deliverErr error
}

func (f *fakePipelines) List(_ context.Context, _, _ string, _ int) ([]gitops.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs, nil
}

func (f *fakePipelines) Get(_ context.Context, project, service, id string) (gitops.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, run := range f.runs {
		if run.Project == project && run.Service == service && run.ID == id {
			return run, nil
		}
	}
	return gitops.Run{}, gitops.ErrNotFound
}

func (f *fakePipelines) LogPath(gitops.Run) string { return f.logPath }

func (f *fakePipelines) Trigger(
	_ context.Context, project, service string, _ bool, by string,
) (gitops.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.triggerErr != nil {
		return gitops.Run{}, f.triggerErr
	}
	f.triggered = append(f.triggered, project+"/"+service+" by "+by)
	return gitops.Run{
		ID: "01ABCDEF", Project: project, Service: service,
		State: gitops.RunQueued, Trigger: gitops.TriggerManual, TriggeredBy: by,
	}, nil
}

func (f *fakePipelines) Sync(_ context.Context, project, by string) (gitops.SyncResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.syncErr != nil {
		return gitops.SyncResult{}, f.syncErr
	}
	f.synced = append(f.synced, project+" by "+by)
	return gitops.SyncResult{Commit: "abc123", Applied: []string{project + "/web"}}, nil
}

func (f *fakePipelines) Deliver(
	_ context.Context, _ string, _ http.Header, _ []byte,
) (gitops.Delivery, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deliverErr != nil {
		return gitops.Delivery{}, f.deliverErr
	}
	f.delivered++
	return gitops.Delivery{
		Provider: "github", Event: "push",
		Ref: "refs/heads/main", Commit: "abc123def456",
	}, nil
}

func withPipelines(p *fakePipelines) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) { cfg.Pipelines = p }
}

func TestBuildQueuesAndReports202(t *testing.T) {
	fake := &fakePipelines{}
	h := newHarness(t, withPipelines(fake))

	run, err := h.client.Build(context.Background(), "shop", "web", true)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Queued, not built: the response says a run exists to follow, not that a
	// build happened.
	if run.State != gitops.RunQueued || run.ID == "" {
		t.Fatalf("run = %+v", run)
	}
	if len(fake.triggered) != 1 || !strings.HasPrefix(fake.triggered[0], "shop/web") {
		t.Fatalf("triggered = %v", fake.triggered)
	}
}

func TestBuildMapsPipelineErrorsToStatuses(t *testing.T) {
	// A client has to tell "retry in a moment" from "this will never work".
	// A full queue is the former and everything else here is the latter.
	for _, tc := range []struct {
		name      string
		err       error
		want      int
		retryable bool
	}{
		{"queue full", gitops.ErrQueueFull, http.StatusTooManyRequests, true},
		{"no build block", gitops.ErrNoBuild, http.StatusConflict, false},
		{"no source", gitops.ErrNoSource, http.StatusConflict, false},
		{"unknown project", gitops.ErrNotFound, http.StatusNotFound, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakePipelines{triggerErr: tc.err}
			h := newHarness(t, withPipelines(fake))

			_, err := h.client.Build(context.Background(), "shop", "web", true)
			var status *api.StatusError
			if !errors.As(err, &status) {
				t.Fatalf("err = %v, want a *api.StatusError", err)
			}
			if status.Status != tc.want {
				t.Fatalf("status = %d, want %d", status.Status, tc.want)
			}
			if status.Retryable() != tc.retryable {
				t.Fatalf("retryable = %v, want %v", status.Retryable(), tc.retryable)
			}
		})
	}
}

func TestRunLogsAreStreamedAsText(t *testing.T) {
	fake := &fakePipelines{}
	logPath := filepath.Join(t.TempDir(), "build.log")
	if err := os.WriteFile(logPath, []byte("step 1\nstep 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake.logPath = logPath
	fake.runs = []gitops.Run{{
		ID: "01ABCDEF", Project: "shop", Service: "web", State: gitops.RunSucceeded,
	}}
	h := newHarness(t, withPipelines(fake))

	var out strings.Builder
	if err := h.client.BuildLogs(
		context.Background(), "shop", "web", "01ABCDEF", false, &out); err != nil {
		t.Fatalf("BuildLogs: %v", err)
	}
	if !strings.Contains(out.String(), "step 2") {
		t.Fatalf("log = %q", out.String())
	}
}

func TestWebhookIsAcceptedWithoutASession(t *testing.T) {
	// The one route authenticated by something other than §13. A git push comes
	// from a provider, not a person, so it carries a per-project HMAC instead of
	// a session — and it must work with no credential attached.
	fake := &fakePipelines{}
	h := newHarness(t, withPipelines(fake))

	status, _ := h.post(t, api.PathWebhooks+"/shop", `{"ref":"refs/heads/main"}`)
	if status != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", status)
	}
	if fake.delivered != 1 {
		t.Fatalf("delivered = %d, want 1", fake.delivered)
	}
}

func TestWebhookRefusesABadSignature(t *testing.T) {
	fake := &fakePipelines{deliverErr: gitops.ErrBadSignature}
	h := newHarness(t, withPipelines(fake))

	status, body := h.post(t, api.PathWebhooks+"/shop", `{"ref":"refs/heads/main"}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
	// The reason is logged and audited, never returned: a caller guessing a
	// secret learns nothing from the response but the refusal.
	if strings.Contains(body, "signature") {
		t.Fatalf("the response explained the refusal: %s", body)
	}
}

func TestWebhookReplayAnswersSuccess(t *testing.T) {
	// A provider retrying a delivery Kanea already processed must see success.
	// An error would make it retry again, forever, for a push already handled.
	fake := &fakePipelines{deliverErr: gitops.ErrReplayedWebhook}
	h := newHarness(t, withPipelines(fake))

	status, _ := h.post(t, api.PathWebhooks+"/shop", `{"ref":"refs/heads/main"}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
}

func TestPipelineRoutesReport503WithoutABuilder(t *testing.T) {
	// Not configured is not the same as not found. A dashboard has to be able
	// to tell "this daemon has no builder" from "wrong URL".
	h := newHarness(t)

	_, err := h.client.Build(context.Background(), "shop", "web", true)
	var status *api.StatusError
	if !errors.As(err, &status) || status.Status != http.StatusServiceUnavailable {
		t.Fatalf("err = %v, want 503", err)
	}
	// And retryable: the builder may simply not be up yet.
	if !status.Retryable() {
		t.Fatal("503 should be retryable")
	}
}

func TestSyncReportsWhatItApplied(t *testing.T) {
	fake := &fakePipelines{}
	h := newHarness(t, withPipelines(fake))

	result, err := h.client.Sync(context.Background(), "shop")
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if result.Commit != "abc123" || len(result.Applied) != 1 {
		t.Fatalf("result = %+v", result)
	}
	if len(fake.synced) != 1 {
		t.Fatalf("synced = %v", fake.synced)
	}
}

// post sends a body over the harness's socket with no credential attached.
func (h *harness) post(t *testing.T, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, "http://kanead"+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.httpClient().Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(out)
}
