package mcp

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

// The streamable-HTTP transport (PRD §16.3).
//
// Stateless: a POST carries one JSON-RPC message and the response carries its
// reply. There is no session id, no SSE stream and no server-initiated message,
// because nothing this server does needs one — every tool call is a request and
// a response, and the live case has a websocket (§12.1). The specification
// permits exactly this shape, and a session table would be state to expire, to
// bound, and to get wrong.

// PathMCP is where the transport is mounted.
const PathMCP = "/mcp"

// maxMessageBytes bounds one incoming message. A tool call is small; a job spec
// passed to apply_spec is the largest thing that legitimately arrives here, and
// the API's own apply route caps its body at 1 MiB.
const maxMessageBytes = 2 << 20

// HTTPHandler serves the transport.
//
// Authentication is *not* done here. This handler is mounted behind the API's
// route wrapper, so a request that reaches it has already been authenticated,
// rate-limited and — for the routes its tools go on to call — authorized and
// audited. Doing any of that again here would be a second implementation of the
// thing §16.3 exists to avoid having two of.
func (s *Server) HTTPHandler(origins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// DNS rebinding is the attack this closes, and the MCP specification
		// names it: a page on any origin can POST to http://localhost:8600/mcp,
		// and without an Origin check a browser someone left open becomes a
		// client of their control plane. A request with no Origin header is not
		// a browser at all — that is every real MCP client — and is allowed
		// through to the credential check that follows.
		if origin := r.Header.Get("Origin"); origin != "" {
			if !originAllowed(origin, r.Host, origins) {
				s.log.Warn("mcp: refused a cross-origin request",
					"origin", origin, "source", r.RemoteAddr)
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			// Echoed only for an origin that passed, so a browser that is
			// allowed can read the reply and one that is not cannot.
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}

		switch r.Method {
		case http.MethodPost:
			s.serveMessage(w, r)
		case http.MethodGet:
			// The specification's answer for a server that offers no
			// server-initiated stream on this endpoint. A client that wanted one
			// falls back to request/response, which is all it will ever need
			// here.
			http.Error(w, "this server does not open a server-to-client stream",
				http.StatusMethodNotAllowed)
		case http.MethodDelete:
			// Session teardown. There are no sessions, so there is nothing to
			// tear down, and saying so is friendlier than 405.
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// serveMessage handles one POSTed JSON-RPC message.
func (s *Server) serveMessage(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); ct != "" && !isJSON(ct) {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxMessageBytes+1))
	if err != nil {
		http.Error(w, "cannot read the request body", http.StatusBadRequest)
		return
	}
	if len(body) > maxMessageBytes {
		http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
		return
	}

	reply := s.Handle(r.Context(), SessionFromRequest(r), body)
	if reply == nil {
		// A notification. The specification says to answer 202 with no body,
		// which is how a client tells "accepted, no reply coming" from "the
		// server has not answered yet".
		w.WriteHeader(http.StatusAccepted)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// A JSON-RPC error is still a successful HTTP exchange: the transport
	// delivered the message and the server answered it. Mapping protocol errors
	// onto status codes would make a client's HTTP layer swallow replies its
	// JSON-RPC layer needs to see.
	w.WriteHeader(http.StatusOK)
	// #nosec G705 — the reply does reflect request data: JSON-RPC requires the
	// response to echo the request's id verbatim, and that is where the taint
	// comes from. It is safe here and only here because the id was decoded into
	// a json.RawMessage, so it is syntactically valid JSON by the time it is
	// echoed; the whole body is re-encoded by encoding/json; the Content-Type is
	// application/json; and the API's secureHeaders sets X-Content-Type-Options:
	// nosniff on every response, so no browser will interpret it as markup.
	if _, err := w.Write(reply); err != nil {
		s.log.Debug("mcp: cannot write the reply", "error", err)
	}
}

// isJSON reports whether a Content-Type names JSON, ignoring parameters.
func isJSON(contentType string) bool {
	media, _, _ := strings.Cut(contentType, ";")
	return strings.EqualFold(strings.TrimSpace(media), "application/json")
}

// originAllowed applies the same rule the websocket uses (api.checkOrigin):
// same-origin needs no configuration, an allowlisted origin passes, and
// everything else — including every origin when no allowlist is configured — is
// refused.
func originAllowed(origin, host string, allowed []string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		// An Origin that does not parse is not one to give the benefit of the
		// doubt to.
		return false
	}
	if strings.EqualFold(parsed.Host, host) {
		return true
	}
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSuffix(candidate, "/"),
			strings.TrimSuffix(origin, "/")) {
			return true
		}
	}
	return false
}
