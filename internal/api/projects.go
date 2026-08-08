package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/store"
)

// Project and service-lifecycle routes (PRD §16.1).
//
// A project has no record of its own unless it has a pipeline: it is the
// namespace a service declares itself into (§4.2), so the list is assembled
// from what exists rather than read from a table. That is why there is no
// create route — declaring a service in a project is how a project comes to be,
// and a second way to make one would be a second source of truth about which
// projects exist.

// ProjectSummary describes one project.
type ProjectSummary struct {
	Name string `json:"name"`
	// Services and Allocs are counts rather than lists: this is the overview,
	// and the service list has its own route.
	Services int `json:"services"`
	Allocs   int `json:"allocs"`
	// Running counts allocs the runtime reports as up.
	Running int `json:"running"`
	// Git describes the sync source, if the project has one. It carries the URL
	// and branch and never the credential — auth_ref is a reference to a secret
	// and safe to show, but it is omitted anyway: nothing reading this list
	// needs to know which secret a project uses.
	Git *ProjectGit `json:"git,omitempty"`
	// Notifications names the channels configured for the project, so an
	// operator can see that a project has them without being shown their
	// tokens.
	Notifications []string `json:"notifications,omitempty"`
}

// ProjectGit is a project's sync source, credential-free.
type ProjectGit struct {
	URL    string `json:"url"`
	Branch string `json:"branch,omitempty"`
	Path   string `json:"path,omitempty"`
	// LastCommit and LastSyncAt report what the sync loop last did.
	LastCommit string `json:"last_commit,omitempty"`
	LastSyncAt string `json:"last_sync_at,omitempty"`
}

// ProjectsResponse lists projects.
type ProjectsResponse struct {
	Projects []ProjectSummary `json:"projects"`
}

// handleListProjects assembles the project list.
func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	summaries, err := s.projectSummaries(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, ProjectsResponse{Projects: summaries})
}

// handleGetProject serves one project.
func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("project")
	summaries, err := s.projectSummaries(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	for _, p := range summaries {
		if p.Name == name {
			writeJSON(w, http.StatusOK, p)
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Errorf("api: no such project: %s", name))
}

// projectSummaries builds the list from services, allocs and pipeline configs.
func (s *Server) projectSummaries(r *http.Request) ([]ProjectSummary, error) {
	services, err := listAll[reconciler.Desired](r.Context(), s.store, store.KindService)
	if err != nil {
		return nil, err
	}
	allocs, err := listAll[reconciler.AllocRecord](r.Context(), s.store, store.KindAlloc)
	if err != nil {
		return nil, err
	}
	configs, err := listAll[gitops.Config](r.Context(), s.store, store.KindProject)
	if err != nil {
		return nil, err
	}

	byName := map[string]*ProjectSummary{}
	get := func(name string) *ProjectSummary {
		if existing, ok := byName[name]; ok {
			return existing
		}
		summary := &ProjectSummary{Name: name}
		byName[name] = summary
		return summary
	}

	for _, svc := range services {
		get(svc.Project).Services++
	}
	for _, alloc := range allocs {
		summary := get(alloc.Project)
		summary.Allocs++
		if alloc.State == reconciler.AllocRunning {
			summary.Running++
		}
	}
	// A project with a pipeline but no services yet is still a project: it is
	// the state between `kanea run` on a git source and the first successful
	// sync, and leaving it out would make that window look like a failure.
	for _, cfg := range configs {
		summary := get(cfg.Project)
		if cfg.HasSource() {
			summary.Git = &ProjectGit{
				URL: cfg.Source.URL, Branch: cfg.Source.Branch, Path: cfg.Source.Path,
				LastCommit: cfg.LastCommit,
			}
			if !cfg.LastSyncAt.IsZero() {
				summary.Git.LastSyncAt = cfg.LastSyncAt.UTC().Format(timeFormat)
			}
		}
		summary.Notifications = notificationChannels(cfg)
	}

	out := make([]ProjectSummary, 0, len(byName))
	for _, summary := range byName {
		out = append(out, *summary)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// timeFormat is RFC 3339 in UTC, which is what every other timestamp on this
// API is.
const timeFormat = "2006-01-02T15:04:05Z07:00"

// notificationChannels names a project's configured channels without revealing
// anything about how they authenticate.
func notificationChannels(cfg gitops.Config) []string {
	n := cfg.Notifications
	if n == nil {
		return nil
	}
	// The channel kinds that are configured, which is the same name the
	// dispatcher gives them (`<project>/<kind>`) so a test can be asked for by
	// what this list reports.
	configured := map[string]bool{
		"telegram": n.Telegram != nil,
		"webhook":  n.Webhook != nil,
		"slack":    n.Slack != nil,
		"ntfy":     n.Ntfy != nil,
		"smtp":     n.SMTP != nil,
	}
	var out []string
	for kind, on := range configured {
		if on {
			out = append(out, kind)
		}
	}
	sort.Strings(out)
	return out
}

// ---- restart ----

// handleRestart forces a rolling restart of a service.
//
// It bumps the restart generation and returns; the reconciler does the rest,
// through the same update policy a deploy uses. Nothing here touches a
// container, for the same reason `kanea scale` does not: there is one thing
// that converges state, and a second one would eventually disagree with it.
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	project, service := r.PathValue("project"), r.PathValue("service")
	key := project + "/" + service
	auditTarget(r, key)

	current, _, err := store.GetValue[reconciler.Desired](r.Context(), s.store, store.KindService, key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, fmt.Errorf("api: no such service: %s", key))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	current.Generation++
	mut, err := store.PutMutation(store.KindService, key, current)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	index, err := s.store.Apply(r.Context(), mut)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.wake()
	s.emit(notify.EventDeployStarted, project, service,
		fmt.Sprintf("restart requested (generation %d)", current.Generation))
	s.log.Info("restart requested", "service", key, "generation", current.Generation)
	writeJSON(w, http.StatusOK, ApplyResponse{Applied: []string{key}, Index: index})
}

// ---- notification test ----

// Notifier is the slice of the dispatcher the test route needs.
type Notifier interface {
	Test(project, channel string) []notify.TestResult
}

// TestNotificationResponse reports what each channel did with a test message.
type TestNotificationResponse struct {
	Results []notify.TestResult `json:"results"`
}

// handleTestNotification sends a test message through a project's channels
// (PRD §11 "test action").
//
// It bypasses the filters on purpose. A test exists to answer "is this channel
// wired up" — the credential, the URL, the egress rules, the network — and
// routing it through the same `on` patterns would mean a channel configured for
// `deploy.*` silently ignores the test and reports success either way.
func (s *Server) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	if s.notifier == nil {
		writeError(w, http.StatusServiceUnavailable,
			errors.New("api: no notification channels are configured on this daemon"))
		return
	}
	project := r.PathValue("project")
	channel := r.URL.Query().Get("channel")
	auditTarget(r, strings.TrimSuffix(project+"/"+channel, "/"))

	results := s.notifier.Test(project, channel)
	if len(results) == 0 {
		writeError(w, http.StatusNotFound, fmt.Errorf(
			"api: no notification channel matches project %q channel %q", project, channel))
		return
	}
	writeJSON(w, http.StatusOK, TestNotificationResponse{Results: results})
}
