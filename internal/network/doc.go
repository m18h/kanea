// Package network holds the driver-neutral networking vocabulary: the
// Service, Backend, ProjectPolicy and Attachment types the reconciler speaks to
// whatever datapath is behind its interfaces, and the embedded internal DNS
// (authoritative for the internal zone only, capped forwarding for everything
// else). The datapath itself is internal/datapath (PRD v1.36, §5.2.5); this
// package knows what a service is, not how one is programmed. No Kubernetes
// dependencies, ever. (PRD §7.)
package network
