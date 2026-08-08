package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/audit"
	"github.com/kanea-dev/kanea/internal/auth"
	"github.com/kanea-dev/kanea/internal/mcp"
)

// The MCP transport is mounted on this server and its tools call back into it.
// These tests are about that loop: the same auth, the same authorization, the
// same audit trail — §16.3's "no side channels" is a claim about this file.

// withMCP mounts the transport, with its backend pointed at the harness's own
// handler once that exists.
//
// The indirection is the same one the daemon needs and for the same reason: the
// transport is a route on the server whose handler is the transport's backend,
// so one of the two has to be resolved late.
func withMCP(target **httptest.Server) func(*api.ServerConfig) {
	return func(cfg *api.ServerConfig) {
		server, err := mcp.New(mcp.Config{
			Backend: mcp.HandlerBackend{Handler: func() http.Handler {
				if *target == nil {
					return nil
				}
				return (*target).Config.Handler
			}},
			Version: "test",
		})
		if err != nil {
			panic(err)
		}
		cfg.MCP = server.HTTPHandler(nil)
	}
}

// newMCPHarness builds a harness with the transport wired to itself.
func newMCPHarness(t *testing.T) *authHarness {
	t.Helper()
	var target *httptest.Server
	h := newAuthHarness(t, withMCP(&target))
	target = h.server
	return h
}

// rpcCall posts one JSON-RPC message to the transport with the given token.
func rpcCall(t *testing.T, h *authHarness, token, method string, params any) map[string]any {
	t.Helper()
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		body["params"] = params
	}
	req := h.request(t, http.MethodPost, api.PathMCP, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, raw := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s = %d: %s", method, resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("decode reply: %v (%s)", err, raw)
	}
	return out
}

func TestMCPTransportIsNotPublic(t *testing.T) {
	// Deny-by-default applies to MCP like every other route (§14 A01). An agent
	// with no credential must not reach the tool surface at all.
	h := newMCPHarness(t)
	req := h.request(t, http.MethodPost, api.PathMCP,
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	if resp, body := h.do(t, req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated MCP = %d, want 401: %s", resp.StatusCode, body)
	}
}

func TestMCPToolCallIsAuthorizedByTheAPI(t *testing.T) {
	// The tier filter hides a mutating tool from a viewer, but the filter is a
	// courtesy. This is the control: a viewer who calls the tool anyway is
	// refused by the route the tool lands on.
	h := newMCPHarness(t)
	viewer := h.token(t, auth.RoleViewer)

	reply := rpcCall(t, h, viewer, "tools/call", map[string]any{
		"name":      "scale_service",
		"arguments": map[string]any{"project": "shop", "service": "web", "count": 5},
	})
	result, ok := reply["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", reply)
	}
	if isError, _ := result["isError"].(bool); !isError {
		t.Fatalf("a viewer scaled a service through MCP: %v", result)
	}
}

func TestMCPToolCallIsAudited(t *testing.T) {
	// §16.3: every tool call is audit-logged with the token identity. It is not
	// audited by the MCP server — it is audited because the call goes through
	// the same route wrapper the CLI does, under the same identity.
	h := newMCPHarness(t)
	admin := h.token(t, auth.RoleAdmin)

	rpcCall(t, h, admin, "tools/call", map[string]any{
		"name":      "scale_service",
		"arguments": map[string]any{"project": "shop", "service": "web", "count": 1},
	})

	page, err := h.audit.List(context.Background(), audit.Filter{Action: "service.scale"})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(page.Entries) == 0 {
		t.Fatal("an MCP scale left no audit entry")
	}
	entry := page.Entries[0]
	if entry.Actor == "" || entry.Via != string(auth.MethodToken) {
		t.Errorf("the audit entry does not name the token identity: %+v", entry)
	}
	if entry.Target != "shop/web" {
		t.Errorf("target = %q, want shop/web", entry.Target)
	}
}

func TestMCPRespectsTheCallersRoleWhenListingTools(t *testing.T) {
	h := newMCPHarness(t)

	names := func(token string) string {
		reply := rpcCall(t, h, token, "tools/list", nil)
		encoded, err := json.Marshal(reply["result"])
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		return string(encoded)
	}

	if strings.Contains(names(h.token(t, auth.RoleViewer)), "delete_project") {
		t.Error("a viewer was offered delete_project")
	}
	if !strings.Contains(names(h.token(t, auth.RoleAdmin)), "delete_project") {
		t.Error("an admin was not offered delete_project")
	}
}
