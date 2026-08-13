package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/auth"
)

// GET /v1/vars (R30, v1.63): authenticated, any role — variables are never
// secrets, and a viewer planning a spec needs the node's defaults.

func TestVarsRequiresAuthentication(t *testing.T) {
	h := newAuthHarness(t)
	resp, body := h.do(t, h.request(t, http.MethodGet, api.PathVars, nil))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET %s = %d, want 401: %s", api.PathVars, resp.StatusCode, body)
	}
}

func TestVarsServesTheNodeStanzaToAViewer(t *testing.T) {
	h := newAuthHarness(t, func(cfg *api.ServerConfig) {
		cfg.NodeVars = map[string]string{"domain": "home.lan", "replicas": "3"}
	})
	req := h.request(t, http.MethodGet, api.PathVars, nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", api.PathVars, resp.StatusCode, body)
	}
	var out struct {
		Variables map[string]string `json:"variables"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Variables["domain"] != "home.lan" || out.Variables["replicas"] != "3" {
		t.Errorf("variables = %v", out.Variables)
	}
}

func TestVarsWithNoStanzaIsAnEmptyMapNotNull(t *testing.T) {
	h := newAuthHarness(t)
	req := h.request(t, http.MethodGet, api.PathVars, nil)
	req.Header.Set("Authorization", "Bearer "+h.token(t, auth.RoleViewer))
	resp, body := h.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", api.PathVars, resp.StatusCode, body)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(out["variables"]) == "null" {
		t.Error(`"variables" is null; an absent stanza must serve {}`)
	}
}
