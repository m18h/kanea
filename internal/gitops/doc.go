// Package gitops implements Git-backed projects (poll + HMAC-validated push
// webhooks with replay protection) and the kaniko pipeline runner (rootless
// builds as containerd tasks, push-only registry creds, build secrets via
// mounted files, .git never in context). (PRD §10.)
package gitops
