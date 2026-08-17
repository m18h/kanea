#!/usr/bin/env bash
# Builds testdata/hello.wasm: a wasi-http hello server for the spike.
#
# Two toolchains are tried, either is fine:
#   - cargo + cargo-component (rust, the reference wasi-http producer)
#   - tinygo (go syntax, wasip2 target)
#
# The module must serve GET / with any 2xx on port 8080, and SHOULD serve
# GET /hog by allocating without bound (the memory-cap check needs a way to
# ask for pressure).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p testdata

if command -v cargo >/dev/null && cargo component --version >/dev/null 2>&1; then
  if [ ! -d testdata/hello-rs ]; then
    cargo component new --lib testdata/hello-rs --target wasi:http/proxy 2>/dev/null ||
      cargo component new testdata/hello-rs
  fi
  echo "edit testdata/hello-rs to serve / and /hog, then:"
  echo "  (cd testdata/hello-rs && cargo component build --release)"
  echo "  cp testdata/hello-rs/target/wasm32-wasip2/release/*.wasm testdata/hello.wasm"
  exit 0
fi

if command -v tinygo >/dev/null; then
  cat > testdata/hello.go <<'EOF'
package main

import (
	"net/http"
)

var hog [][]byte

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello from wasm\n"))
	})
	// The memory-cap check: allocate until the cgroup kills us.
	http.HandleFunc("/hog", func(w http.ResponseWriter, _ *http.Request) {
		for {
			hog = append(hog, make([]byte, 1<<20))
		}
	})
	_ = http.ListenAndServe(":8080", nil)
}
EOF
  tinygo build -target=wasip2 -o testdata/hello.wasm testdata/hello.go
  echo "built testdata/hello.wasm (tinygo, wasip2)"
  exit 0
fi

echo "need cargo-component or tinygo to build a wasi-http module" >&2
exit 1
