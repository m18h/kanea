package api

import (
	"context"
	"net/http"
)

// The node's shared spec variables (PRD §6.2 R30, v1.63): the `variables { }`
// stanza from /etc/kanea/kanea.hcl, served read-only so client-side parses
// (`kanea plan`/`run`, MCP's spec tools) resolve the same defaults the
// server-side parses read from the loaded nodeconfig. Variables are never
// secrets: that is R30's stated contract, which is what makes an
// any-authenticated-caller read the right tier.

// PathVars is the node-variables route.
const PathVars = "/v1/vars"

// handleVars serves the node's variables stanza. Static after startup: the
// file is load-once (§15.1), so there is nothing to reload or lock.
func (s *Server) handleVars(w http.ResponseWriter, _ *http.Request) {
	vars := s.nodeVars
	if vars == nil {
		vars = map[string]string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"variables": vars})
}

// Vars reads the node's shared spec variables (R30).
func (c *Client) Vars(ctx context.Context) (map[string]string, error) {
	var out struct {
		Variables map[string]string `json:"variables"`
	}
	if err := c.do(ctx, http.MethodGet, PathVars, nil, &out); err != nil {
		return nil, err
	}
	return out.Variables, nil
}
