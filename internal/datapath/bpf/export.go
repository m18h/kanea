// Package bpf carries the Kanea datapath's eBPF programs (PRD v1.36 §5.2.5):
// the C sources (kanea.c, headers.h) and the committed bpf2go output compiled
// from them.
//
// The generated kanea_bpfel.* / kanea_bpfeb.* artifacts are produced under a
// digest-pinned toolchain container by `make bpf` — never by `go generate`,
// and never by hand. `go build` needs no clang; the target node needs no BTF
// (no CO-RE, no vmlinux.h — the programs read only UAPI context types). The
// `bpf-verify` CI job regenerates and diffs, so editing a generated file by
// hand is a CI failure, not a code path.
//
// This file is hand-written: the exported face of the generated (unexported)
// loader. bpf-verify diffs only the generated artifacts, so it is ordinary
// code.
package bpf

import "github.com/cilium/ebpf"

// Program names in the object, as internal/datapath's loader looks them up.
// The map names live in dpmap, which is the map contract's home.
const (
	ProgConnect4      = "kanea_connect4"
	ProgToContainer   = "kanea_to_container"
	ProgFromContainer = "kanea_from_container"
)

// LoadSpec returns the embedded CollectionSpec for the datapath object of the
// build's byte order.
func LoadSpec() (*ebpf.CollectionSpec, error) { return loadKanea() }
