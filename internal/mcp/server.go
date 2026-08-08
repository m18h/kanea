package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"github.com/kanea-dev/kanea/internal/gitops"
	"github.com/kanea-dev/kanea/internal/reconciler"
)

// Server implements the MCP method set over a Backend.
//
// It holds no state about a conversation. MCP has an initialize handshake, but
// nothing this server does depends on having seen it: every request carries its
// own credential and every tool call is independent. That is what lets the
// streamable-HTTP transport answer without sessions — there is nothing for a
// session to hold — and it is why a client that reconnects mid-task loses
// nothing.
type Server struct {
	backend Backend
	log     *slog.Logger
	version string
	// parse turns job-spec source into desired state. Supplied by the binary
	// rather than implemented here, for the same reason gitops takes an Applier:
	// converting a parsed spec into desired state is wiring, and wiring lives in
	// cmd/kanea. Nil leaves plan_spec and apply_spec reporting that they are
	// unavailable, rather than absent — a tool that vanished would look like a
	// version mismatch.
	parse SpecParser
	// tools is the fixed registry, sorted by name.
	tools  []*tool
	byName map[string]*tool
}

// SpecParser turns HCL job-spec source into desired state and pipeline configs.
type SpecParser func(source []byte) ([]reconciler.Desired, []gitops.Config, error)

// Config configures the MCP server.
type Config struct {
	// Backend is how tools reach the platform. Required.
	Backend Backend
	Logger  *slog.Logger
	// Version is reported to clients as the server version.
	Version string
	// ParseSpec backs plan_spec and apply_spec. Optional.
	ParseSpec SpecParser
}

// New builds the server.
func New(cfg Config) (*Server, error) {
	if cfg.Backend == nil {
		return nil, errors.New("mcp: a backend is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}

	s := &Server{
		backend: cfg.Backend, log: cfg.Logger, version: cfg.Version, parse: cfg.ParseSpec,
	}
	s.tools = registry()
	sort.Slice(s.tools, func(i, j int) bool { return s.tools[i].name < s.tools[j].name })
	s.byName = make(map[string]*tool, len(s.tools))
	for _, t := range s.tools {
		if _, dup := s.byName[t.name]; dup {
			return nil, fmt.Errorf("mcp: duplicate tool %q", t.name)
		}
		s.byName[t.name] = t
	}
	return s, nil
}

// Handle processes one JSON-RPC message and returns the reply, or nil for a
// notification, which by specification gets no response at all.
func (s *Server) Handle(ctx context.Context, sess *Session, body []byte) []byte {
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		return encode(failTo(nil, errorf(codeParseError, "malformed JSON-RPC message: %v", err)))
	}
	// The version check is not pedantry: a message that does not say 2.0 was
	// produced by something that is not speaking this protocol, and guessing
	// what it meant is how a parser becomes an attack surface.
	if req.JSONRPC != "2.0" {
		return encode(failTo(req.ID, errorf(codeInvalidRequest,
			"jsonrpc must be \"2.0\", got %q", req.JSONRPC)))
	}

	result, rpcErr := s.dispatch(ctx, sess, req)
	if req.isNotification() {
		// Notifications get no reply, successful or otherwise. An error here is
		// worth a log line and nothing more — there is nobody to tell.
		if rpcErr != nil {
			s.log.Debug("mcp notification failed", "method", req.Method, "error", rpcErr.Message)
		}
		return nil
	}
	if rpcErr != nil {
		return encode(failTo(req.ID, rpcErr))
	}
	return encode(replyTo(req.ID, result))
}

// dispatch routes one method.
func (s *Server) dispatch(ctx context.Context, sess *Session, req request) (any, *rpcError) {
	switch req.Method {
	case methodInitialize:
		return s.initialize(req.Params)

	case methodInitialized:
		// A notification that the client is ready. Nothing to do — this server
		// holds no per-connection state to unblock.
		return nil, nil

	case methodPing:
		// An empty result is the whole protocol here.
		return struct{}{}, nil

	case methodToolsList:
		return s.listTools(ctx, sess), nil

	case methodToolsCall:
		return s.callTool(ctx, sess, req.Params)

	case methodResourcesList:
		return listResourcesResult{Resources: staticResources()}, nil

	case methodResourceTemplates:
		return listTemplatesResult{ResourceTemplates: resourceTemplates()}, nil

	case methodResourcesRead:
		return s.readResource(ctx, sess, req.Params)

	default:
		return nil, errorf(codeMethodNotFound, "unknown method %q", req.Method)
	}
}

// initialize answers the handshake.
func (s *Server) initialize(raw json.RawMessage) (any, *rpcError) {
	var params initializeParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, errorf(codeInvalidParams, "initialize: %v", err)
		}
	}

	// Echo a version the client asked for when it is one we speak, so a client
	// pinned to an older revision is not forced to downgrade its expectations
	// of everything else.
	version := ProtocolVersion
	if supportedVersions[params.ProtocolVersion] {
		version = params.ProtocolVersion
	}
	s.log.Info("mcp client connected",
		"client", params.ClientInfo.Name, "client_version", params.ClientInfo.Version,
		"protocol", version)

	return initializeResult{
		ProtocolVersion: version,
		Capabilities: serverCapabilities{
			Tools:     &toolsCapability{},
			Resources: &resourcesCapability{},
		},
		ServerInfo:   clientInfo{Name: ServerName, Version: s.version},
		Instructions: instructions,
	}, nil
}

// listTools reports the tools this caller may use.
//
// Filtered by role, which takes one extra request to find out who is asking.
// The filter is a courtesy and not a control — the enforcement is the API, which
// refuses the call whether or not it was advertised — but it is a courtesy worth
// the round trip: a model told it can deploy will try to deploy, and a refusal
// it could not have predicted reads as a transient failure worth retrying.
func (s *Server) listTools(ctx context.Context, sess *Session) listToolsResult {
	tier := s.tierFor(ctx, sess)

	out := listToolsResult{Tools: make([]toolDescriptor, 0, len(s.tools))}
	for _, t := range s.tools {
		if t.tier > tier {
			continue
		}
		out.Tools = append(out.Tools, t.describe())
	}
	return out
}

// tierFor asks the API who the caller is and translates the answer into the
// highest tier of tool they could use.
//
// It fails closed. A session lookup that errors means we do not know the role,
// and the safe reading of "I do not know" is the least privileged one.
func (s *Server) tierFor(ctx context.Context, sess *Session) tier {
	var out struct {
		Role string `json:"role"`
	}
	if err := s.call(ctx, sess, "GET", pathSession, nil, &out); err != nil {
		s.log.Debug("mcp: cannot determine the caller's role", "error", err)
		return tierRead
	}
	if out.Role == roleAdmin {
		return tierDestructive
	}
	return tierRead
}

// roleAdmin is the role name the API reports for a caller that may write. It is
// compared as a string rather than imported, so this package does not depend on
// the auth package to speak to the API over HTTP.
const roleAdmin = "admin"

// callTool runs one tool.
func (s *Server) callTool(ctx context.Context, sess *Session, raw json.RawMessage) (any, *rpcError) {
	var params callToolParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, errorf(codeInvalidParams, "tools/call: %v", err)
	}
	t, ok := s.byName[params.Name]
	if !ok {
		// A protocol error rather than a tool error: the client asked for
		// something that does not exist, which is a bug in the client, not a
		// refusal the model should reason about.
		return nil, errorf(codeInvalidParams, "unknown tool %q", params.Name)
	}

	args := arguments(params.Arguments)

	// The confirm gate (§16.3). Enforced here rather than by the API, because it
	// is not an authorization rule — an admin is allowed to delete a project,
	// and the API will let them. It is a rule about *agents*: a destructive
	// action has to be asked for in a way that a model cannot arrive at by
	// pattern-matching a tool name, and that a human reviewing the transcript
	// can see was asked for deliberately.
	if t.tier == tierDestructive && !args.boolean("confirm") {
		return errResult("%s is destructive and was not confirmed. "+
			"Call it again with confirm=true only if the operator has explicitly "+
			"asked for this. It cannot be undone.", t.name), nil
	}

	result, err := t.run(ctx, s, sess, args)
	if err != nil {
		// A tool that failed reports it in the result, so the model sees it.
		// Logged as well, at the level the outcome deserves: a refusal is worth
		// a warning, a missing service is not.
		var status *statusError
		if errors.As(err, &status) && (status.Status == 401 || status.Status == 403) {
			s.log.Warn("mcp tool refused",
				"tool", t.name, "source", sess.source(), "error", err)
		} else {
			s.log.Debug("mcp tool failed", "tool", t.name, "error", err)
		}
		return errResult("%v", err), nil
	}
	return result, nil
}

func (s *Session) source() string {
	if s == nil {
		return ""
	}
	return s.Source
}

// encode renders a response. A response that cannot be encoded is a bug in this
// package rather than anything the caller did, and it still has to produce
// valid JSON-RPC — an unparseable reply would hang a client waiting for one.
func encode(resp response) []byte {
	body, err := json.Marshal(resp)
	if err == nil {
		return body
	}
	// The fallback carries no Result, so the only way it can fail to encode is
	// an id that did not come from a decoded message — which cannot happen, the
	// id being raw JSON this package never constructs. Handled anyway, because
	// returning nothing here hangs a client waiting for a reply.
	fallback, ferr := json.Marshal(failTo(resp.ID,
		errorf(codeInternalError, "cannot encode the response")))
	if ferr != nil {
		return []byte(`{"jsonrpc":"2.0","id":null,` +
			`"error":{"code":-32603,"message":"cannot encode the response"}}`)
	}
	return fallback
}
