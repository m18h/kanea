package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/mcp"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
)

// fakeAPI stands in for kanead. It records what the tools asked for, which is
// the thing worth asserting: a tool that reached the right route with the right
// method has done its job, and whether that route works is the API's own tests.
type fakeAPI struct {
	mu    sync.Mutex
	calls []string
	role  string
	// status overrides the response for a path prefix.
	status map[string]int
}

func newFakeAPI(role string) *fakeAPI {
	return &fakeAPI{role: role, status: map[string]int{}}
}

func (f *fakeAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()

		for prefix, status := range f.status {
			if strings.HasPrefix(r.URL.Path, prefix) {
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "refused"})
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/auth/session":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"subject": "agent", "role": f.role,
			})
		case r.URL.Path == "/v1/services" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"services": []reconciler.Desired{{
					Project: "shop", Service: "web", Count: 2, Image: "nginx:1.27",
					Resources: runtime.Resources{CPUMillis: 100, MemoryBytes: 256 << 20},
				}},
			})
		case r.URL.Path == "/v1/services" && r.Method == http.MethodPut:
			_ = json.NewEncoder(w).Encode(map[string]any{"applied": []string{"shop/web"}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	})
}

func (f *fakeAPI) called(method, path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == method+" "+path {
			return true
		}
	}
	return false
}

func newServer(t *testing.T, api *fakeAPI) *mcp.Server {
	t.Helper()
	handler := api.handler()
	s, err := mcp.New(mcp.Config{
		Backend: mcp.HandlerBackend{Handler: func() http.Handler { return handler }},
		Version: "test",
		ParseSpec: func(source []byte) ([]reconciler.Desired, []gitops.Config, error) {
			return []reconciler.Desired{{
				Project: "shop", Service: "web", Count: 3, Image: string(source),
			}}, nil, nil
		},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return s
}

// rpc sends one message and decodes the reply.
func rpc(t *testing.T, s *mcp.Server, method string, params any) map[string]any {
	t.Helper()
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		body["params"] = params
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	reply := s.Handle(context.Background(), &mcp.Session{}, encoded)
	if reply == nil {
		t.Fatalf("%s produced no reply", method)
	}
	var out map[string]any
	if err := json.Unmarshal(reply, &out); err != nil {
		t.Fatalf("decode reply: %v (%s)", err, reply)
	}
	return out
}

// callTool invokes one tool and returns its content text and error flag.
func callTool(t *testing.T, s *mcp.Server, name string, args map[string]any) (string, bool) {
	t.Helper()
	reply := rpc(t, s, "tools/call", map[string]any{"name": name, "arguments": args})
	if rpcErr, bad := reply["error"]; bad {
		t.Fatalf("%s failed at the protocol level: %v", name, rpcErr)
	}
	result, ok := reply["result"].(map[string]any)
	if !ok {
		t.Fatalf("%s returned no result: %v", name, reply)
	}
	isError, _ := result["isError"].(bool)

	var text strings.Builder
	blocks, _ := result["content"].([]any)
	for _, raw := range blocks {
		block, _ := raw.(map[string]any)
		s, _ := block["text"].(string)
		text.WriteString(s)
	}
	return text.String(), isError
}

func toolNames(t *testing.T, s *mcp.Server) []string {
	t.Helper()
	reply := rpc(t, s, "tools/list", nil)
	result, ok := reply["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/list returned no result: %v", reply)
	}
	tools, _ := result["tools"].([]any)
	out := make([]string, 0, len(tools))
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		name, _ := tool["name"].(string)
		out = append(out, name)
	}
	return out
}

func has(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func TestInitializeNegotiatesTheProtocolVersion(t *testing.T) {
	s := newServer(t, newFakeAPI("admin"))

	// A version this server speaks is echoed, so a client pinned to an older
	// revision is not forced to reinterpret everything else.
	reply := rpc(t, s, "initialize", map[string]any{
		"protocolVersion": "2025-03-26",
		"clientInfo":      map[string]string{"name": "test", "version": "1"},
	})
	result := reply["result"].(map[string]any)
	if got := result["protocolVersion"]; got != "2025-03-26" {
		t.Errorf("protocolVersion = %v, want the client's own", got)
	}

	// One it does not speak gets this server's, and the client decides.
	reply = rpc(t, s, "initialize", map[string]any{"protocolVersion": "1999-01-01"})
	result = reply["result"].(map[string]any)
	if got := result["protocolVersion"]; got != mcp.ProtocolVersion {
		t.Errorf("protocolVersion = %v, want %s", got, mcp.ProtocolVersion)
	}
}

func TestNotificationsGetNoReply(t *testing.T) {
	// JSON-RPC forbids replying to a message with no id. A server that answers
	// anyway desynchronises a client that is counting responses.
	s := newServer(t, newFakeAPI("admin"))
	body := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if reply := s.Handle(context.Background(), &mcp.Session{}, body); reply != nil {
		t.Fatalf("a notification was answered with %s", reply)
	}
}

func TestViewerSeesOnlyReadTools(t *testing.T) {
	names := toolNames(t, newServer(t, newFakeAPI("viewer")))

	for _, want := range []string{"list_services", "get_logs", "get_events"} {
		if !has(names, want) {
			t.Errorf("a viewer cannot see %s", want)
		}
	}
	for _, unwanted := range []string{"apply_spec", "scale_service", "delete_project"} {
		if has(names, unwanted) {
			t.Errorf("a viewer was offered %s", unwanted)
		}
	}
}

func TestAdminSeesEveryTier(t *testing.T) {
	names := toolNames(t, newServer(t, newFakeAPI("admin")))
	for _, want := range []string{"list_services", "apply_spec", "delete_project"} {
		if !has(names, want) {
			t.Errorf("an admin cannot see %s", want)
		}
	}
}

func TestToolListingFailsClosed(t *testing.T) {
	// If the daemon will not say who the caller is, the safe reading of "I do
	// not know" is the least privileged one.
	api := newFakeAPI("admin")
	api.status["/v1/auth/session"] = http.StatusUnauthorized
	names := toolNames(t, newServer(t, api))

	if has(names, "delete_project") {
		t.Error("an unidentifiable caller was offered a destructive tool")
	}
	if !has(names, "list_services") {
		t.Error("an unidentifiable caller was offered nothing at all")
	}
}

func TestDestructiveToolsNeedConfirmation(t *testing.T) {
	api := newFakeAPI("admin")
	s := newServer(t, api)

	text, isError := callTool(t, s, "delete_project", map[string]any{"project": "shop"})
	if !isError {
		t.Fatal("delete_project ran without confirmation")
	}
	if !strings.Contains(text, "confirm=true") {
		t.Errorf("the refusal does not say how to confirm: %s", text)
	}
	// And nothing was deleted: the gate is before the work, not after it.
	if api.called(http.MethodDelete, "/v1/services/shop/web") {
		t.Fatal("delete_project deleted a service before being confirmed")
	}

	if _, isError := callTool(t, s, "delete_project", map[string]any{
		"project": "shop", "confirm": true,
	}); isError {
		t.Fatal("a confirmed delete_project was still refused")
	}
	if !api.called(http.MethodDelete, "/v1/services/shop/web") {
		t.Error("a confirmed delete_project deleted nothing")
	}
}

func TestRefusalsAreReportedAsToolErrorsNotProtocolErrors(t *testing.T) {
	// A model has to see "you may not do that" to react to it. A JSON-RPC error
	// is handled by the client library and never reaches the model.
	api := newFakeAPI("viewer")
	api.status["/v1/services/shop/web/scale"] = http.StatusForbidden
	s := newServer(t, api)

	text, isError := callTool(t, s, "scale_service", map[string]any{
		"project": "shop", "service": "web", "count": 5,
	})
	if !isError {
		t.Fatal("a forbidden scale was reported as success")
	}
	if !strings.Contains(text, "not permitted") {
		t.Errorf("the refusal does not read as one: %s", text)
	}
}

func TestUnknownToolIsAProtocolError(t *testing.T) {
	// The other side of the same rule: a tool that does not exist is a bug in
	// the client, not something for the model to reason about.
	s := newServer(t, newFakeAPI("admin"))
	reply := rpc(t, s, "tools/call", map[string]any{"name": "rm_rf", "arguments": map[string]any{}})
	if _, bad := reply["error"]; !bad {
		t.Fatalf("an unknown tool produced a result: %v", reply)
	}
}

func TestScaleRejectsANegativeCount(t *testing.T) {
	api := newFakeAPI("admin")
	s := newServer(t, api)
	if _, isError := callTool(t, s, "scale_service", map[string]any{
		"project": "shop", "service": "web", "count": -1,
	}); !isError {
		t.Fatal("a negative replica count was accepted")
	}
	if api.called(http.MethodPost, "/v1/services/shop/web/scale") {
		t.Error("a negative count still reached the daemon")
	}
}

func TestStopScalesToZeroRatherThanDeleting(t *testing.T) {
	// The declaration has to survive a stop, or bringing the service back means
	// re-applying a spec the operator may not have.
	api := newFakeAPI("admin")
	s := newServer(t, api)
	if _, isError := callTool(t, s, "stop_service", map[string]any{
		"project": "shop", "service": "web",
	}); isError {
		t.Fatal("stop_service failed")
	}
	if !api.called(http.MethodPost, "/v1/services/shop/web/scale") {
		t.Error("stop_service did not scale")
	}
	if api.called(http.MethodDelete, "/v1/services/shop/web") {
		t.Error("stop_service deleted the service")
	}
}

func TestPlanSpecChangesNothing(t *testing.T) {
	api := newFakeAPI("admin")
	s := newServer(t, api)

	text, isError := callTool(t, s, "plan_spec", map[string]any{"spec": "nginx:1.28"})
	if isError {
		t.Fatalf("plan_spec failed: %s", text)
	}
	if !strings.Contains(text, "update shop/web") {
		t.Errorf("the plan does not describe the change: %s", text)
	}
	if api.called(http.MethodPut, "/v1/services") {
		t.Fatal("plan_spec applied the spec")
	}
}

func TestApplySpecApplies(t *testing.T) {
	api := newFakeAPI("admin")
	s := newServer(t, api)
	if _, isError := callTool(t, s, "apply_spec", map[string]any{"spec": "nginx:1.28"}); isError {
		t.Fatal("apply_spec failed")
	}
	if !api.called(http.MethodPut, "/v1/services") {
		t.Error("apply_spec applied nothing")
	}
}

func TestNoToolReadsASecret(t *testing.T) {
	// §16.3: secrets are write-only over the API and no tool returns one. The
	// enforcement is that the secrets routes are not reachable from any tool —
	// this test is what keeps that true as tools are added.
	names := toolNames(t, newServer(t, newFakeAPI("admin")))
	for _, name := range names {
		if strings.Contains(name, "secret") {
			t.Errorf("tool %q touches secrets; §16.3 lists no secret tools", name)
		}
	}
}

func TestArgumentsSurviveModelSloppiness(t *testing.T) {
	// A model sends numbers as strings often enough that strict decoding would
	// fail calls that were perfectly clear.
	api := newFakeAPI("admin")
	s := newServer(t, api)
	if _, isError := callTool(t, s, "scale_service", map[string]any{
		"project": "shop", "service": "web", "count": "3",
	}); isError {
		t.Fatal("a count sent as a string was rejected")
	}
	if !api.called(http.MethodPost, "/v1/services/shop/web/scale") {
		t.Error("the scale never reached the daemon")
	}
}

func TestGetServiceNamesTheAlternativesWhenItMisses(t *testing.T) {
	// A model that misremembers a name should get the correction, not a bare
	// "not found" it can only respond to by guessing again.
	s := newServer(t, newFakeAPI("admin"))
	text, isError := callTool(t, s, "get_service", map[string]any{
		"project": "shop", "service": "wbe",
	})
	if !isError {
		t.Fatal("a missing service was reported as found")
	}
	if !strings.Contains(text, "web") {
		t.Errorf("the error does not name what does exist: %s", text)
	}
}

func TestResourcesResolve(t *testing.T) {
	s := newServer(t, newFakeAPI("admin"))
	reply := rpc(t, s, "resources/read", map[string]any{"uri": "kanea://projects"})
	if _, bad := reply["error"]; bad {
		t.Fatalf("kanea://projects did not resolve: %v", reply["error"])
	}

	reply = rpc(t, s, "resources/read", map[string]any{"uri": "kanea://nope"})
	if _, bad := reply["error"]; !bad {
		t.Fatal("an unknown resource URI resolved")
	}
}

// ---- transport ----

func TestHTTPTransportRefusesAForeignOrigin(t *testing.T) {
	// DNS rebinding: without this, a page left open in a browser is a client of
	// the operator's control plane.
	s := newServer(t, newFakeAPI("admin"))
	handler := s.HTTPHandler([]string{"https://kanea.example.com"})

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("a foreign origin got %d, want %d", rec.Code, http.StatusForbidden)
	}

	// An allowlisted one passes.
	req = httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Origin", "https://kanea.example.com")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("an allowed origin got %d, want %d", rec.Code, http.StatusOK)
	}

	// And a request with no Origin at all — every real MCP client — passes.
	req = httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("a non-browser client got %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHTTPTransportAnswersANotificationWith202(t *testing.T) {
	s := newServer(t, newFakeAPI("admin"))
	req := httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	rec := httptest.NewRecorder()
	s.HTTPHandler(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
	if body := rec.Body.String(); body != "" {
		t.Errorf("a notification was answered with a body: %q", body)
	}
}

func TestHTTPTransportCapsTheMessageSize(t *testing.T) {
	s := newServer(t, newFakeAPI("admin"))
	huge := strings.Repeat("a", 3<<20)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(huge))
	rec := httptest.NewRecorder()
	s.HTTPHandler(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestStdioTransportRoundTrips(t *testing.T) {
	s := newServer(t, newFakeAPI("admin"))
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	var out strings.Builder

	if err := s.ServeStdio(context.Background(), in, &out); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	// Two replies, not three: the notification in the middle gets none.
	if len(lines) != 2 {
		t.Fatalf("got %d replies, want 2:\n%s", len(lines), out.String())
	}
	for _, line := range lines {
		var reply map[string]any
		if err := json.Unmarshal([]byte(line), &reply); err != nil {
			t.Fatalf("reply is not JSON: %v (%s)", err, line)
		}
		if reply["jsonrpc"] != "2.0" {
			t.Errorf("reply is not JSON-RPC 2.0: %s", line)
		}
	}
}

func TestMalformedMessageIsAnswered(t *testing.T) {
	// A client waiting for a reply must get one, or it hangs.
	s := newServer(t, newFakeAPI("admin"))
	reply := s.Handle(context.Background(), &mcp.Session{}, []byte(`{not json`))
	if reply == nil {
		t.Fatal("a malformed message got no reply")
	}
	var out map[string]any
	if err := json.Unmarshal(reply, &out); err != nil {
		t.Fatalf("the error reply is itself malformed: %v", err)
	}
	if _, bad := out["error"]; !bad {
		t.Errorf("a malformed message was accepted: %s", reply)
	}
}
