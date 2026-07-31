// Package mcp implements the Model Context Protocol server (PRD §16.3):
// streamable-HTTP transport on the API server and stdio via "kanea mcp".
// Tool tiers: read (viewer), mutate (admin), destructive (admin + confirm).
// Secrets are write-only via tools; every call is audited. No side channels
// around the API auth/authz/rate-limit pipeline.
package mcp
