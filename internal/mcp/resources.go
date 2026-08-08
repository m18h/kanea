package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Resources (PRD §16.3): the same information the read tools return, addressed
// by URI instead of called by name.
//
// The distinction MCP draws is about who decides. A tool is invoked by the
// model when it judges the call useful; a resource is attached by the *client*,
// usually because a human picked it. Kanea publishes both over the same code
// path, because "the current state of shop/web" should not depend on which of
// them asked.

const uriScheme = "kanea://"

// staticResources are the fixed URIs.
func staticResources() []resourceDescriptor {
	return []resourceDescriptor{
		{
			URI: uriScheme + "projects", Name: "projects",
			Description: "Every project on the node, with counts and git source.",
			MimeType:    "application/json",
		},
		{
			URI: uriScheme + "events", Name: "events",
			Description: "The platform event feed, newest first.",
			MimeType:    "application/json",
		},
		{
			URI: uriScheme + "node/stats", Name: "node stats",
			Description: "Node summary: what is declared, what is running, what is failing.",
			MimeType:    "application/json",
		},
	}
}

// resourceTemplates are the parameterised ones.
func resourceTemplates() []resourceTemplate {
	return []resourceTemplate{
		{
			URITemplate: uriScheme + "projects/{project}/services",
			Name:        "project services",
			Description: "The services a project declares.",
			MimeType:    "application/json",
		},
		{
			URITemplate: uriScheme + "services/{project}/{service}/status",
			Name:        "service status",
			Description: "One service's declared state and its allocs.",
			MimeType:    "application/json",
		},
		{
			URITemplate: uriScheme + "services/{project}/{service}/logs",
			Name:        "service logs",
			Description: "The tail of a service's container logs.",
			MimeType:    "text/plain",
		},
	}
}

// readResource resolves a kanea:// URI.
func (s *Server) readResource(
	ctx context.Context, sess *Session, raw json.RawMessage,
) (any, *rpcError) {
	var params readResourceParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, errorf(codeInvalidParams, "resources/read: %v", err)
	}
	rest, ok := strings.CutPrefix(params.URI, uriScheme)
	if !ok {
		return nil, errorf(codeInvalidParams,
			"unsupported URI %q: resources on this server start with %s", params.URI, uriScheme)
	}
	// A URI is a path and nothing more here. Splitting on "/" and matching the
	// shape explicitly, rather than pattern-matching with a template engine,
	// keeps the set of reachable paths equal to the set written down below.
	parts := strings.Split(strings.Trim(rest, "/"), "/")

	text, mime, err := s.resolve(ctx, sess, parts)
	if err != nil {
		// A URI that names something that does not exist, or that this caller may
		// not see, is about the request; anything else is about the server. The
		// code is what a client uses to decide whether retrying is sensible.
		var status *statusError
		clientFault := errors.As(err, &status) &&
			status.Status >= 400 && status.Status < 500
		if clientFault || errors.Is(err, errNoSuchResource) {
			return nil, errorf(codeInvalidParams, "%v", err)
		}
		return nil, errorf(codeInternalError, "%v", err)
	}
	return readResourceResult{Contents: []resourceContents{
		{URI: params.URI, MimeType: mime, Text: trimTo(text, maxResultBytes)},
	}}, nil
}

// resolve maps a split URI onto a backend read.
func (s *Server) resolve(
	ctx context.Context, sess *Session, parts []string,
) (text, mime string, err error) {
	const jsonMime = "application/json"

	switch {
	case len(parts) == 1 && parts[0] == "projects":
		body, err := s.raw(ctx, sess, pathProjects)
		return body, jsonMime, err

	case len(parts) == 1 && parts[0] == "events":
		body, err := s.raw(ctx, sess, query(pathEvents, "limit", "50"))
		return body, jsonMime, err

	case len(parts) == 2 && parts[0] == "node" && parts[1] == "stats":
		body, err := s.raw(ctx, sess, pathStats)
		return body, jsonMime, err

	case len(parts) == 3 && parts[0] == "projects" && parts[2] == "services":
		result, err := runListServices(ctx, s, sess, arguments{"project": parts[1]})
		return firstText(result), jsonMime, err

	case len(parts) == 4 && parts[0] == "services" && parts[3] == "status":
		return s.serviceStatus(ctx, sess, parts[1], parts[2])

	case len(parts) == 4 && parts[0] == "services" && parts[3] == "logs":
		result, err := runGetLogs(ctx, s, sess, arguments{
			"project": parts[1], "service": parts[2], "tail": defaultLogTail,
		})
		return firstText(result), "text/plain", err

	default:
		return "", "", fmt.Errorf("%w: %s%s", errNoSuchResource, uriScheme, strings.Join(parts, "/"))
	}
}

// errNoSuchResource is a URI this server does not publish.
var errNoSuchResource = errors.New("no resource at")

// serviceStatus is the declared state and the allocs together, because that is
// the question anyone attaching this resource is actually asking: is it running
// what it says it runs.
func (s *Server) serviceStatus(
	ctx context.Context, sess *Session, project, service string,
) (string, string, error) {
	svc, err := s.service(ctx, sess, project, service)
	if err != nil {
		return "", "", err
	}
	var allocs struct {
		Allocs []allocRecord `json:"allocs"`
	}
	path := query(pathAllocs, "project", project, "service", service)
	if err := s.call(ctx, sess, http.MethodGet, path, nil, &allocs); err != nil {
		return "", "", err
	}

	body, err := json.MarshalIndent(map[string]any{
		"declared": svc, "allocs": allocs.Allocs,
	}, "", "  ")
	if err != nil {
		return "", "", err
	}
	return string(body), "application/json", nil
}

// raw fetches a JSON body verbatim, for resources that are exactly one route.
func (s *Server) raw(ctx context.Context, sess *Session, path string) (string, error) {
	var body json.RawMessage
	if err := s.call(ctx, sess, http.MethodGet, path, nil, &body); err != nil {
		return "", err
	}
	// Re-indented: a resource is read by a human as often as by a model.
	var pretty any
	if err := json.Unmarshal(body, &pretty); err != nil {
		return string(body), nil
	}
	indented, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		return string(body), nil
	}
	return string(indented), nil
}

// firstText pulls the text out of a tool result, so a resource can be served by
// the tool that already knows how to produce it.
func firstText(result callToolResult) string {
	if len(result.Content) == 0 {
		return ""
	}
	return result.Content[0].Text
}
