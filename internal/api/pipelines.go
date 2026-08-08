package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/m18h/kanea/internal/audit"
	"github.com/m18h/kanea/internal/auth"
	"github.com/m18h/kanea/internal/gitops"
)

// Pipeline routes (PRD §16.1, §10.2).
const (
	PathPipelines = "/v1/pipelines"
	// PathProjects carries the project-level actions a sync needs.
	PathProjects = "/v1/projects"
	// PathWebhooks receives git push notifications. See handleGitWebhook for
	// why it is the one route with its own authentication mechanism.
	PathWebhooks = "/v1/webhooks/git"
)

// Pipelines is the slice of the gitops package the API needs.
//
// The API can list runs, read their logs, and ask for a build. It cannot run
// one itself: the queue serialises builds, and a handler that built inline
// would hold an HTTP connection for minutes and bypass that serialisation.
type Pipelines interface {
	List(ctx context.Context, project, service string, limit int) ([]gitops.Run, error)
	Get(ctx context.Context, project, service, id string) (gitops.Run, error)
	LogPath(run gitops.Run) string
	// Trigger queues a build and returns the queued run.
	Trigger(ctx context.Context, project, service string, deploy bool, by string) (gitops.Run, error)
	// Sync fetches a project's git source and applies what it finds.
	Sync(ctx context.Context, project, by string) (gitops.SyncResult, error)
	// Deliver handles a validated push webhook.
	Deliver(ctx context.Context, project string, header http.Header, body []byte) (gitops.Delivery, error)
}

// RunsResponse lists pipeline runs.
type RunsResponse struct {
	Runs []gitops.Run `json:"runs"`
}

// BuildRequest asks for a build.
type BuildRequest struct {
	// Deploy pins the produced digest on the service when the build succeeds.
	Deploy bool `json:"deploy"`
}

// SyncResponse reports what a sync did.
type SyncResponse struct {
	Project string   `json:"project"`
	Commit  string   `json:"commit,omitempty"`
	Applied []string `json:"applied,omitempty"`
	Built   []string `json:"built,omitempty"`
	// Held lists services a sync would have changed but did not, because the
	// project requires approval (§10.1).
	Held    []string `json:"held,omitempty"`
	Message string   `json:"message,omitempty"`
}

// handleListRuns lists pipeline runs, newest first.
func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	if s.pipelines == nil {
		writeError(w, http.StatusServiceUnavailable, errNoPipelines)
		return
	}
	q := r.URL.Query()
	limit := 0
	if raw := q.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("limit: %w", err))
			return
		}
		limit = parsed
	}

	runs, err := s.pipelines.List(r.Context(), q.Get("project"), q.Get("service"), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if runs == nil {
		runs = []gitops.Run{}
	}
	writeJSON(w, http.StatusOK, RunsResponse{Runs: runs})
}

// handleGetRun returns one run.
func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	if s.pipelines == nil {
		writeError(w, http.StatusServiceUnavailable, errNoPipelines)
		return
	}
	run, err := s.pipelines.Get(r.Context(),
		r.PathValue("project"), r.PathValue("service"), r.PathValue("run"))
	if err != nil {
		writeError(w, statusForPipelineError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// handleRunLogs streams a build's log.
//
// Plain text, like workload logs, and for the same reason: it goes to a
// terminal or into a `<pre>`, and a human reading a failed build should not
// have to decode anything first.
func (s *Server) handleRunLogs(w http.ResponseWriter, r *http.Request) {
	if s.pipelines == nil {
		writeError(w, http.StatusServiceUnavailable, errNoPipelines)
		return
	}
	run, err := s.pipelines.Get(r.Context(),
		r.PathValue("project"), r.PathValue("service"), r.PathValue("run"))
	if err != nil {
		writeError(w, statusForPipelineError(err), err)
		return
	}

	follow := r.URL.Query().Get("follow") == "true"
	tail, err := newTailer(s.pipelines.LogPath(run), gitops.ShortID(run.ID), 0, false)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("no log for run %s", gitops.ShortID(run.ID)))
		return
	}
	defer func() {
		if cerr := tail.Close(); cerr != nil {
			s.log.Warn("close build log", "run", run.ID, "error", cerr)
		}
	}()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	for {
		n, err := tail.copyTo(w)
		if err != nil {
			return
		}
		if n > 0 && flusher != nil {
			flusher.Flush()
		}
		// A finished run's log will not grow, so following it forever would
		// hold a connection open for nothing.
		if !follow {
			return
		}
		if current, err := s.pipelines.Get(r.Context(), run.Project, run.Service, run.ID); err == nil {
			if current.State.Terminal() {
				return
			}
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(PollInterval):
		}
	}
}

// handleBuild queues a build.
func (s *Server) handleBuild(w http.ResponseWriter, r *http.Request) {
	if s.pipelines == nil {
		writeError(w, http.StatusServiceUnavailable, errNoPipelines)
		return
	}
	project, service := r.PathValue("project"), r.PathValue("service")
	auditTarget(r, project+"/"+service)

	var req BuildRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	by := ""
	if id, ok := auth.FromContext(r.Context()); ok {
		by = id.Subject
	}
	run, err := s.pipelines.Trigger(r.Context(), project, service, req.Deploy, by)
	if err != nil {
		writeError(w, statusForPipelineError(err), err)
		return
	}
	// 202: the run exists and has an id to follow, and the build has not
	// happened yet. 200 would claim it had.
	writeJSON(w, http.StatusAccepted, run)
}

// handleSync fetches a project's git source and applies it.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if s.pipelines == nil {
		writeError(w, http.StatusServiceUnavailable, errNoPipelines)
		return
	}
	project := r.PathValue("project")
	auditTarget(r, project)

	by := ""
	if id, ok := auth.FromContext(r.Context()); ok {
		by = id.Subject
	}
	result, err := s.pipelines.Sync(r.Context(), project, by)
	if err != nil {
		writeError(w, statusForPipelineError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, SyncResponse{
		Project: project, Commit: result.Commit, Applied: result.Applied,
		Built: result.Built, Held: result.Held, Message: result.Message,
	})
}

// handleGitWebhook receives a push notification.
//
// **This is the one route authenticated by something other than §13.** A push
// comes from GitHub, not from a person, so no session or bearer token can
// carry it. It is not unauthenticated: every delivery is verified against a
// per-project shared secret before anything happens, replays are rejected, and
// an unsigned request is refused. But the mechanism is different, so it is
// declared `public` in the route table and does its own authentication here —
// visible rather than buried in a middleware exception.
//
// The body is read to a bound before it is used, because the sender chooses
// its size, and it is passed to the verifier as raw bytes: a payload that has
// been through a decoder is no longer the bytes that were signed.
func (s *Server) handleGitWebhook(w http.ResponseWriter, r *http.Request) {
	if s.pipelines == nil {
		writeError(w, http.StatusServiceUnavailable, errNoPipelines)
		return
	}
	project := r.PathValue("project")

	body, err := io.ReadAll(io.LimitReader(r.Body, gitops.MaxWebhookBody+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("api: cannot read the webhook body"))
		return
	}
	if len(body) > gitops.MaxWebhookBody {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Errorf("api: webhook body is larger than %d bytes", gitops.MaxWebhookBody))
		return
	}

	delivery, err := s.pipelines.Deliver(r.Context(), project, r.Header, body)
	if err != nil {
		status := statusForWebhookError(err)
		// Audited as a security event: a stream of rejected deliveries is
		// someone guessing a secret, and it is the same class of thing as a
		// rejected token.
		s.record(r, audit.Entry{
			Action: "webhook.receive", Target: project, Result: audit.ResultDenied,
			Status: status, Detail: err.Error(),
		}, auth.Identity{Subject: "webhook", Via: "webhook"})
		s.log.Warn("git webhook refused",
			"project", project, "source", sourceOf(r), "error", err)
		writeError(w, status, errRefused)
		return
	}

	s.record(r, audit.Entry{
		Action: "webhook.receive", Target: project, Result: audit.ResultOK,
		Status: http.StatusAccepted,
		Detail: fmt.Sprintf("%s %s %s", delivery.Provider, delivery.Event, shortSHA(delivery.Commit)),
	}, auth.Identity{Subject: string(delivery.Provider), Via: "webhook"})

	// 202 whether or not it was deployable: a ping and a tag push are both
	// legitimate deliveries, and answering them with an error would show a
	// broken webhook in the provider's UI.
	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":   true,
		"deployable": delivery.Deployable(),
		"branch":     delivery.Branch(),
		"commit":     delivery.Commit,
	})
}

var errNoPipelines = errors.New("api: pipelines are not configured on this daemon")

// statusForPipelineError maps a pipeline error to a status.
func statusForPipelineError(err error) int {
	switch {
	case errors.Is(err, gitops.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, gitops.ErrQueueFull):
		// Retryable, and the client should know that rather than treating it
		// as a permanent failure.
		return http.StatusTooManyRequests
	case errors.Is(err, gitops.ErrNoSource), errors.Is(err, gitops.ErrNoBuild):
		return http.StatusConflict
	case errors.Is(err, gitops.ErrNoSpecs), errors.Is(err, gitops.ErrAuthRequired):
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// statusForWebhookError maps a rejected delivery to a status.
func statusForWebhookError(err error) int {
	switch {
	case errors.Is(err, gitops.ErrUnsignedWebhook), errors.Is(err, gitops.ErrBadSignature):
		return http.StatusUnauthorized
	case errors.Is(err, gitops.ErrReplayedWebhook):
		// Already handled, not wrong. A provider retrying a delivery Kanea
		// processed should see success, not an error it will retry again.
		return http.StatusOK
	case errors.Is(err, gitops.ErrWebhookTooOld):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// shortSHA abbreviates a commit for a log line.
func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
