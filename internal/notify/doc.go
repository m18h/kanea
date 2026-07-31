// Package notify implements notification channels (webhook HMAC-signed,
// Telegram, Slack/Discord, SMTP, ntfy) with event filtering, storm
// coalescing/digests, per-channel rate limits, and SSRF egress rules
// (https-only, RFC1918/link-local blocked by default). Delivery never blocks
// the control plane. (PRD §11.)
package notify
