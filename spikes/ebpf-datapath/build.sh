#!/bin/sh
# Compile the spike's BPF object on the node (clang/llvm required there).
# No bpf2go on purpose: for throwaway code, loading bpf/spike.o at runtime
# with ebpf.LoadCollectionSpec removes the whole generate step.
set -eu
cd "$(dirname "$0")"

CLANG=${CLANG:-clang}

# -g is required: the .maps section is BTF-defined.
# -target bpf on an LE host emits bpfel, which is what headers.h assumes.
"$CLANG" -O2 -g -Wall -Werror -target bpf -c bpf/spike.c -o bpf/spike.o
echo "built bpf/spike.o"
