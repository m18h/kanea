// Package api implements the HTTPS REST + WebSocket API server: management
// API, dashboard assets (go:embed), ACME HTTP-01 challenges, Git webhooks,
// and the MCP endpoint. Auth is deny-by-default on every route (PRD §5.2.1,
// §13, §14, §16).
package api
