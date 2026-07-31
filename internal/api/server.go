package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/store"
)

// Store is the slice of the state store the API needs.
type Store interface {
	Get(ctx context.Context, kind store.Kind, key string) (store.Record, error)
	List(ctx context.Context, kind store.Kind, opts store.ListOptions) (store.Page, error)
	Apply(ctx context.Context, muts ...store.Mutation) (uint64, error)
	Index(ctx context.Context) (uint64, error)
}

// ServerConfig configures the API server.
type ServerConfig struct {
	Store  Store
	Logger *slog.Logger
	// Socket is the unix socket path. Defaults to DefaultSocket.
	Socket string
	// Version is reported by the health endpoint.
	Version string
	// LogDir is where per-alloc log files live.
	LogDir string
	// Notify is signalled after a successful apply so the reconciler converges
	// immediately instead of waiting out its interval.
	Notify chan<- struct{}
}

// Server is the control-plane HTTP server.
type Server struct {
	store    Store
	log      *slog.Logger
	socket   string
	version  string
	logDir   string
	notify   chan<- struct{}
	listener net.Listener
	http     *http.Server
}

// NewServer builds the server. It does not listen yet.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("api: store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Socket == "" {
		cfg.Socket = DefaultSocket
	}
	s := &Server{
		store: cfg.Store, log: cfg.Logger, socket: cfg.Socket,
		version: cfg.Version, logDir: cfg.LogDir, notify: cfg.Notify,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathHealth, s.handleHealth)
	mux.HandleFunc("GET "+PathServices, s.handleListServices)
	mux.HandleFunc("PUT "+PathServices, s.handleApply)
	mux.HandleFunc("DELETE "+PathServices+"/{project}/{service}", s.handleDeleteService)
	mux.HandleFunc("GET "+PathAllocs, s.handleListAllocs)
	mux.HandleFunc("GET "+PathLogs, s.handleLogs)

	s.http = &http.Server{
		Handler: mux,
		// Slowloris defence, even on a unix socket: a stuck CLI must not pin a
		// connection forever (PRD §5.2.6 applies the same rule at the edge).
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s, nil
}

// Listen creates the socket. Separate from Serve so the caller can report a
// bind failure before daemonising.
func (s *Server) Listen() error {
	if err := os.MkdirAll(filepath.Dir(s.socket), 0o750); err != nil {
		return fmt.Errorf("api: socket dir: %w", err)
	}
	// A stale socket from a crashed kanead would block binding. Removing it is
	// safe: if another kanead were live, the store's file lock would already
	// have refused us.
	if err := os.Remove(s.socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("api: remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", s.socket)
	if err != nil {
		return fmt.Errorf("api: listen on %s: %w", s.socket, err)
	}
	// 0600: the socket is the authentication boundary in M1.
	if err := os.Chmod(s.socket, 0o600); err != nil {
		return errors.Join(fmt.Errorf("api: chmod socket: %w", err), listener.Close())
	}
	s.listener = listener
	return nil
}

// Serve blocks until the context is cancelled or the server fails.
func (s *Server) Serve(ctx context.Context) error {
	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	s.log.Info("api listening", "socket", s.socket)

	errs := make(chan error, 1)
	go func() {
		if err := s.http.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
			return
		}
		errs <- nil
	}()

	// Removing the socket on the way out keeps the next start clean. A failure
	// is reported, not swallowed: a socket we cannot remove will confuse the
	// next kanead.
	cleanup := func(cause error) error {
		if err := os.Remove(s.socket); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.Join(cause, fmt.Errorf("api: remove socket: %w", err))
		}
		return cause
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return cleanup(s.http.Shutdown(shutdownCtx))
	case err := <-errs:
		return cleanup(err)
	}
}

// ---- handlers ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	index, err := s.store.Index(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, Health{Status: "ok", Version: s.version, StoreIndex: index})
}

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	services, err := listAll[reconciler.Desired](r.Context(), s.store, store.KindService)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sort.Slice(services, func(i, j int) bool {
		if services[i].Project != services[j].Project {
			return services[i].Project < services[j].Project
		}
		return services[i].Service < services[j].Service
	})
	writeJSON(w, http.StatusOK, ServicesResponse{Services: services})
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var req ApplyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	if len(req.Services) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("no services in request"))
		return
	}

	muts := make([]store.Mutation, 0, len(req.Services))
	applied := make([]string, 0, len(req.Services))
	for _, svc := range req.Services {
		if svc.Project == "" || svc.Service == "" {
			writeError(w, http.StatusBadRequest, errors.New("every service needs a project and a name"))
			return
		}
		key := svc.Project + "/" + svc.Service
		mut, err := store.PutMutation(store.KindService, key, svc)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		muts = append(muts, mut)
		applied = append(applied, key)
	}

	// One batch: a multi-service apply lands atomically, so the reconciler never
	// sees half a deploy.
	index, err := s.store.Apply(r.Context(), muts...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.wake()
	s.log.Info("applied services", "services", applied, "index", index)
	writeJSON(w, http.StatusOK, ApplyResponse{Applied: applied, Index: index})
}

func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	service := r.PathValue("service")
	key := project + "/" + service

	if _, err := s.store.Get(r.Context(), store.KindService, key); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, fmt.Errorf("no such service %s", key))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	index, err := s.store.Apply(r.Context(), store.DeleteMutation(store.KindService, key))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.wake()
	s.log.Info("deleted service", "service", key, "index", index)
	writeJSON(w, http.StatusOK, ApplyResponse{Applied: []string{key}, Index: index})
}

func (s *Server) handleListAllocs(w http.ResponseWriter, r *http.Request) {
	allocs, err := listAll[reconciler.AllocRecord](r.Context(), s.store, store.KindAlloc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	project := r.URL.Query().Get("project")
	service := r.URL.Query().Get("service")
	filtered := allocs[:0]
	for _, a := range allocs {
		if project != "" && a.Project != project {
			continue
		}
		if service != "" && a.Service != service {
			continue
		}
		filtered = append(filtered, a)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Key() < filtered[j].Key() })
	writeJSON(w, http.StatusOK, AllocsResponse{Allocs: filtered})
}

// handleLogs streams alloc logs. Output is plain text, not JSON: it goes
// straight to a terminal, and a human tailing logs should not have to decode
// anything.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := LogOptions{
		Project: q.Get("project"),
		Service: q.Get("service"),
		AllocID: q.Get("alloc"),
		Follow:  q.Get("follow") == "true",
	}
	if n, err := strconv.Atoi(q.Get("tail")); err == nil {
		opts.Tail = n
	}

	allocs, err := s.selectAllocs(r.Context(), opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if len(allocs) == 0 {
		writeError(w, http.StatusNotFound, errors.New("no matching allocs"))
		return
	}
	// One alloc keeps the stream unprefixed; several need attribution.
	prefix := len(allocs) > 1

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	tails := make([]*tailer, 0, len(allocs))
	for _, alloc := range allocs {
		path := filepath.Join(s.logDir, alloc.ID+".log")
		t, err := newTailer(path, alloc.ID, opts.Tail, prefix)
		if err != nil {
			// A missing log file is normal for an alloc that never started.
			s.log.Debug("no log file", "alloc", alloc.ID, "error", err)
			continue
		}
		defer func() {
			if cerr := t.Close(); cerr != nil {
				s.log.Warn("close log tailer", "alloc", t.allocID, "error", cerr)
			}
		}()
		tails = append(tails, t)
	}

	for {
		wrote := false
		for _, t := range tails {
			n, err := t.copyTo(w)
			if err != nil {
				return
			}
			wrote = wrote || n > 0
		}
		if wrote && flusher != nil {
			flusher.Flush()
		}
		if !opts.Follow {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(PollInterval):
		}
	}
}

func (s *Server) selectAllocs(ctx context.Context, opts LogOptions) ([]reconciler.AllocRecord, error) {
	allocs, err := listAll[reconciler.AllocRecord](ctx, s.store, store.KindAlloc)
	if err != nil {
		return nil, err
	}
	var out []reconciler.AllocRecord
	for _, a := range allocs {
		switch {
		case opts.AllocID != "":
			if a.ID == opts.AllocID {
				out = append(out, a)
			}
		case opts.Service != "":
			if a.Service == opts.Service && (opts.Project == "" || a.Project == opts.Project) {
				out = append(out, a)
			}
		case opts.Project != "":
			if a.Project == opts.Project {
				out = append(out, a)
			}
		default:
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

// wake nudges the reconciler. Non-blocking: a missed wake-up only means the
// next tick handles it, whereas blocking here would stall the API.
func (s *Server) wake() {
	if s.notify == nil {
		return
	}
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// ---- helpers ----

// listAll pages through a bucket. Reads are bounded per page (store constraint),
// so "list everything" is a loop, not a single unbounded transaction.
func listAll[T any](ctx context.Context, s Store, kind store.Kind) ([]T, error) {
	var out []T
	opts := store.ListOptions{}
	for {
		values, page, err := store.ListValues[T](ctx, s, kind, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, values...)
		if !page.More {
			return out, nil
		}
		opts.After = page.NextAfter
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	// Defence in depth for the M5 browser-facing listener: these responses are
	// never a document, and must never be sniffed as one.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// The header is already written, so an encoding failure cannot change the
	// response — log it rather than pretending to return an error.
	if err := json.NewEncoder(w).Encode(body); err != nil {
		encodeFailures.Add(1)
	}
}

// encodeFailures counts responses that could not be written, so the condition
// is observable rather than silent. It is read by tests and, later, by metrics.
var encodeFailures atomic.Int64

// EncodeFailures reports how many responses failed to encode.
func EncodeFailures() int64 { return encodeFailures.Load() }

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, Error{Error: err.Error()})
}

// trimSocketPrefix is used by the client to render a friendlier target.
func trimSocketPrefix(path string) string {
	return strings.TrimPrefix(path, "unix://")
}
