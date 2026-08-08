package mcp

import (
	"encoding/json"
	"fmt"
)

// The wire protocol: JSON-RPC 2.0 carrying MCP's method set.
//
// Hand-written rather than taken from an SDK, for the same reason the Cilium
// client is (AGENTS.md): the surface Kanea needs is small and fully specified,
// and a dependency that speaks a protocol on your behalf is a dependency that
// decides what your protocol version is, what your error shapes are, and what
// gets logged. The methods below are the whole of it.

// ProtocolVersion is the MCP revision this server implements.
const ProtocolVersion = "2025-06-18"

// supportedVersions are the revisions a client may ask for and get. A client
// that asks for something else is answered with ProtocolVersion and decides for
// itself whether it can proceed — which is what the specification says to do,
// and is better than refusing a client that would have worked.
var supportedVersions = map[string]bool{
	"2025-06-18": true,
	"2025-03-26": true,
	"2024-11-05": true,
}

// ServerName and ServerVersion identify this implementation to a client.
const ServerName = "kanea"

// MCP method names.
const (
	methodInitialize        = "initialize"
	methodInitialized       = "notifications/initialized"
	methodPing              = "ping"
	methodToolsList         = "tools/list"
	methodToolsCall         = "tools/call"
	methodResourcesList     = "resources/list"
	methodResourceTemplates = "resources/templates/list"
	methodResourcesRead     = "resources/read"
)

// JSON-RPC 2.0 error codes. The first five are the specification's; the MCP
// layer adds none of its own, because a tool that ran and failed reports that
// in its *result* rather than as a protocol error — see callResult.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// request is one incoming JSON-RPC message.
//
// ID is raw because JSON-RPC allows a string, a number or null, and a response
// has to echo back exactly what it was sent — normalising it to a Go type would
// turn 1 into "1" for a client that cares.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// isNotification reports whether the message expects no reply. JSON-RPC says a
// message without an id is a notification, and sending a response to one is a
// protocol violation.
func (r request) isNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

// response is one outgoing JSON-RPC message.
type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcError is a JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("mcp: %s (%d)", e.Message, e.Code) }

func errorf(code int, format string, args ...any) *rpcError {
	return &rpcError{Code: code, Message: fmt.Sprintf(format, args...)}
}

func replyTo(id json.RawMessage, result any) response {
	return response{JSONRPC: "2.0", ID: id, Result: result}
}

func failTo(id json.RawMessage, err *rpcError) response {
	return response{JSONRPC: "2.0", ID: id, Error: err}
}

// ---- initialize ----

type initializeParams struct {
	ProtocolVersion string     `json:"protocolVersion"`
	ClientInfo      clientInfo `json:"clientInfo"`
}

type clientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type initializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    serverCapabilities `json:"capabilities"`
	ServerInfo      clientInfo         `json:"serverInfo"`
	// Instructions are shown to the model as context for the whole server. The
	// safety rules are stated here as well as enforced, because a model that
	// knows a destructive tool needs confirm asks for it rather than discovering
	// the rule by being refused.
	Instructions string `json:"instructions,omitempty"`
}

// serverCapabilities advertises only what this server implements. Prompts,
// sampling, completion and logging are absent rather than declared-and-empty:
// a client that sees the capability will call the method.
type serverCapabilities struct {
	Tools     *toolsCapability     `json:"tools,omitempty"`
	Resources *resourcesCapability `json:"resources,omitempty"`
}

// toolsCapability declares no listChanged: the tool set is fixed at build time,
// so there is never a change to notify about.
type toolsCapability struct{}

// resourcesCapability likewise declares neither subscribe nor listChanged. A
// resource's *contents* change constantly — that is what makes it a resource —
// but the list does not, and Kanea has a websocket for the live case.
type resourcesCapability struct{}

// instructions is the server-level guidance handed to the model at initialize.
const instructions = `Kanea is a single-node container orchestration platform.

Tools are tiered by what they can do. Read tools need the viewer role; tools
that change state need admin; delete_project needs admin and confirm=true.
Authorization is decided by the daemon, not by this server: a refusal is real,
and retrying it will not help.

No tool returns a secret value. Secrets are referenced in specs as
"secret:<project>/<name>" and are write-only over the API.

Prefer plan_spec before apply_spec: it reports what would change without
changing anything.`

// ---- tools ----

// toolDescriptor is one entry in tools/list.
type toolDescriptor struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema inputSchema `json:"inputSchema"`
	Annotations *hints      `json:"annotations,omitempty"`
}

// hints are MCP's tool annotations: advisory statements about what a tool does,
// which a client uses to decide what to confirm with a human. They are hints in
// the strict sense — nothing here is enforcement, and the daemon does not read
// them.
type hints struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    bool   `json:"readOnlyHint,omitempty"`
	DestructiveHint bool   `json:"destructiveHint,omitempty"`
	IdempotentHint  bool   `json:"idempotentHint,omitempty"`
	OpenWorldHint   bool   `json:"openWorldHint"`
}

// inputSchema is the JSON Schema for a tool's arguments.
type inputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
}

type property struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Enum        []string `json:"enum,omitempty"`
	Default     any      `json:"default,omitempty"`
}

func object(props map[string]property, required ...string) inputSchema {
	return inputSchema{Type: "object", Properties: props, Required: required}
}

type listToolsResult struct {
	Tools []toolDescriptor `json:"tools"`
}

type callToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// callToolResult is a tool's answer.
//
// IsError carries a *tool* failure — the platform said no, the service does not
// exist — as a successful JSON-RPC response. That is the specification's design
// and it is the right one: the model is the one that has to react to "you may
// not do that", and a protocol-level error is handled by the client library
// before the model ever sees it.
type callToolResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(text string) callToolResult {
	return callToolResult{Content: []contentBlock{{Type: "text", Text: text}}}
}

func errResult(format string, args ...any) callToolResult {
	return callToolResult{
		Content: []contentBlock{{Type: "text", Text: fmt.Sprintf(format, args...)}},
		IsError: true,
	}
}

// ---- resources ----

type resourceDescriptor struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type resourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type listResourcesResult struct {
	Resources []resourceDescriptor `json:"resources"`
}

type listTemplatesResult struct {
	ResourceTemplates []resourceTemplate `json:"resourceTemplates"`
}

type readResourceParams struct {
	URI string `json:"uri"`
}

type readResourceResult struct {
	Contents []resourceContents `json:"contents"`
}

type resourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text"`
}
