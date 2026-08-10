#!/usr/bin/env bash
# Packages testdata/hello.wasm as the scratch OCI image the functions feature
# ships modules in (PRD v1.39: FROM scratch + module + ENTRYPOINT), and
# imports it into containerd via ctr — the exact layout EnsureImage pulls.
set -euo pipefail
cd "$(dirname "$0")"

SOCKET="${SOCKET:-/run/kanea/containerd.sock}"
CTR="${CTR:-/usr/local/lib/kanea/bin/ctr}"
REF="${REF:-registry.local/spike/hello-wasm:1}"
NS="${NS:-kanea-spike-wasm}"

[ -f testdata/hello.wasm ] || { echo "run ./build-module.sh first" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The rootfs layer: exactly one file.
mkdir -p "$work/rootfs"
cp testdata/hello.wasm "$work/rootfs/app.wasm"
tar -C "$work/rootfs" -czf "$work/layer.tar.gz" app.wasm

# docker save-compatible archive is the simplest thing ctr imports; build the
# OCI form with a config that carries the entrypoint runwasi executes.
layer_sha=$(sha256sum "$work/layer.tar.gz" | cut -d' ' -f1)
diff_sha=$(gzip -dc "$work/layer.tar.gz" | sha256sum | cut -d' ' -f1)

cat > "$work/config.json" <<EOF
{
  "architecture": "wasm",
  "os": "wasip2",
  "config": { "Entrypoint": ["/app.wasm"] },
  "rootfs": { "type": "layers", "diff_ids": ["sha256:${diff_sha}"] }
}
EOF
# NOTE: runwasi also accepts linux/<arch> scratch images, which is what Kanea
# ships. If the wasip2 platform is refused by the import, flip architecture/os
# to your host's ("amd64"/"linux") and record the finding in REPORT.md —
# that IS one of the spike's questions (OCI wasm artifact vs scratch image).
config_sha=$(sha256sum "$work/config.json" | cut -d' ' -f1)

mkdir -p "$work/oci/blobs/sha256"
cp "$work/layer.tar.gz" "$work/oci/blobs/sha256/${layer_sha}"
cp "$work/config.json" "$work/oci/blobs/sha256/${config_sha}"

manifest() {
  cat <<EOF
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:${config_sha}",
    "size": $(stat -c%s "$work/config.json")
  },
  "layers": [{
    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
    "digest": "sha256:${layer_sha}",
    "size": $(stat -c%s "$work/layer.tar.gz")
  }]
}
EOF
}
manifest > "$work/manifest.json"
manifest_sha=$(sha256sum "$work/manifest.json" | cut -d' ' -f1)
cp "$work/manifest.json" "$work/oci/blobs/sha256/${manifest_sha}"

cat > "$work/oci/index.json" <<EOF
{
  "schemaVersion": 2,
  "manifests": [{
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:${manifest_sha}",
    "size": $(stat -c%s "$work/manifest.json"),
    "annotations": { "org.opencontainers.image.ref.name": "${REF}" }
  }]
}
EOF
echo '{"imageLayoutVersion": "1.0.0"}' > "$work/oci/oci-layout"

tar -C "$work/oci" -cf "$work/image.tar" .
sudo "$CTR" -a "$SOCKET" -n "$NS" images import --all-platforms "$work/image.tar"
echo "imported ${REF} into namespace ${NS}"
