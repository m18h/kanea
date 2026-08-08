package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/m18h/kanea/internal/notify"
)

// PathEvents serves the notification feed (PRD §11, §12).
const PathEvents = "/v1/events"

// Events is the slice of the notification feed the API needs.
//
// Read-only. An event is something that happened; there is no route to create
// one, because a caller inventing history is not a feature.
type Events interface {
	List(ctx context.Context, project string, limit int) ([]notify.Event, error)
}

// EventsResponse is the feed.
type EventsResponse struct {
	Events []notify.Event `json:"events"`
	// Dropped is how many events the dispatcher could not queue since start.
	// Surfaced rather than hidden: a feed that is quiet because everything is
	// fine and one that is quiet because the queue is full look identical
	// otherwise.
	Dropped int64 `json:"dropped,omitempty"`
}

// handleEvents returns the notification feed, newest first.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.events == nil {
		writeJSON(w, http.StatusOK, EventsResponse{Events: []notify.Event{}})
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		limit = parsed
	}

	events, err := s.events.List(r.Context(), r.URL.Query().Get("project"), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if events == nil {
		events = []notify.Event{}
	}
	resp := EventsResponse{Events: events}
	if s.notifyStats != nil {
		resp.Dropped = s.notifyStats().Dropped
	}
	writeJSON(w, http.StatusOK, resp)
}
