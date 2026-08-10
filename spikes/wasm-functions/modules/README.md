# Spike modules (reproducible with plain Rust/rustup)

The spike's `build-module.sh` documents tinygo/cargo-component; these are the
plain-Rust equivalents actually used for the 2026-08-10 run (see ../REPORT.md).
wasm is arch-neutral, so build anywhere:

    rustup target add wasm32-wasip1 wasm32-wasip2

    # idle + hog (one binary, "hog" mode via argv)
    (cd idle-hog && cargo build --release --target wasm32-wasip1)
    cp idle-hog/target/wasm32-wasip1/release/app.wasm ../testdata/hello.wasm   # idle
    # (rebuild is unnecessary; the same binary hogs when given argv "hog")
    cp idle-hog/target/wasm32-wasip1/release/app.wasm ../testdata/hog.wasm

    # wasi-http (Rust >=1.82 emits a component for wasm32-wasip2 directly)
    (cd hello-http && cargo build --release --target wasm32-wasip2)
    cp hello-http/target/wasm32-wasip2/release/hellohttp.wasm ../testdata/hello.wasm

Then ../mkimage-host.sh and ../mkimage-hog.sh package them as host-platform
scratch images (REPORT.md finding 2).
