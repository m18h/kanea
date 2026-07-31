// Package jobspec defines the HCL v2 job-spec schema, parsing, and validation
// (rules R1–R10, PRD §6.2): DNS-1123 names, project-scoped secret references,
// image-only services, service references & dependency edges, spec_version
// gating. Validation errors must carry file/line diagnostics.
// Keep the PRD §6.1 examples valid — they are golden tests.
package jobspec
