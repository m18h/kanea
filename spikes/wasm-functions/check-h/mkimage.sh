#!/usr/bin/env bash
# Packages a wasm module as the scratch OCI image the functions feature ships
# modules in (PRD v1.39: FROM scratch + module + ENTRYPOINT) and imports it
# straight into kanead's own containerd namespace.
#
# This is ../mkimage-host.sh with the two things that made it spike-only turned
# into arguments:
#
#   the architecture, which was hard-coded arm64. It must be the NODE's, not
#   the module's — REPORT.md finding 2: a module ships as a host-platform
#   (linux/<arch>) image, never wasm/wasip2, because containerd's default
#   matcher (which EnsureImage uses, with no special case) will not unpack a
#   wasm-platform image.
#
#   the namespace, which was the spike's own. For a real kanead run it has to
#   be the per-project namespace runtime.Namespace(project) computes, because
#   that is where EnsureImage looks — and EnsureImage returns early when the
#   image is already present, so importing here means the registry.local ref
#   never has to resolve. That is what makes check H runnable on a node with
#   no registry.
#
#     ./mkimage.sh --wasm ../testdata/hello.wasm --project checkh
#     ./mkimage.sh --wasm m.wasm --project p --arch amd64 --ref registry.local/p/m:2
set -euo pipefail
cd "$(dirname "$0")"

die() { printf 'mkimage: %s\n' "$*" >&2; exit 1; }

WASM="../testdata/hello.wasm"
PROJECT=""
ARCH=""
REF=""
SOCKET="${SOCKET:-/run/kanea/containerd.sock}"
CTR="${CTR:-/usr/local/lib/kanea/bin/ctr}"
NS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --wasm)      WASM="$2"; shift 2 ;;
    --project)   PROJECT="$2"; shift 2 ;;
    --arch)      ARCH="$2"; shift 2 ;;
    --ref)       REF="$2"; shift 2 ;;
    --namespace) NS="$2"; shift 2 ;;
    --socket)    SOCKET="$2"; shift 2 ;;
    --ctr)       CTR="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -f "$WASM" ] || die "no module at ${WASM} — build one first (see ../modules/README.md)"
[ -n "$PROJECT" ] || [ -n "$NS" ] || die "need --project (or an explicit --namespace)"

# runtime.Namespace(project) is "kanea-<project>"; restated rather than
# imported because a shell script cannot call Go, and pinned by the check
# driver, which fails loudly if the image is not found where kanead looks.
NS="${NS:-kanea-${PROJECT}}"
REF="${REF:-registry.local/${PROJECT}/hello-http:1}"

# The node's architecture, because the image is host-platform. uname -m speaks
# a different dialect than OCI does.
if [ -z "$ARCH" ]; then
  case "$(uname -m)" in
    x86_64)          ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) die "unrecognised machine $(uname -m); pass --arch" ;;
  esac
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The rootfs layer: exactly one file.
mkdir -p "$work/rootfs"
cp "$WASM" "$work/rootfs/app.wasm"
tar -C "$work/rootfs" -czf "$work/layer.tar.gz" app.wasm

layer_sha=$(sha256sum "$work/layer.tar.gz" | cut -d' ' -f1)
diff_sha=$(gzip -dc "$work/layer.tar.gz" | sha256sum | cut -d' ' -f1)

cat > "$work/config.json" <<EOF
{
  "architecture": "${ARCH}",
  "os": "linux",
  "config": { "Entrypoint": ["/app.wasm"] },
  "rootfs": { "type": "layers", "diff_ids": ["sha256:${diff_sha}"] }
}
EOF
config_sha=$(sha256sum "$work/config.json" | cut -d' ' -f1)

mkdir -p "$work/oci/blobs/sha256"
cp "$work/layer.tar.gz" "$work/oci/blobs/sha256/${layer_sha}"
cp "$work/config.json" "$work/oci/blobs/sha256/${config_sha}"

cat > "$work/manifest.json" <<EOF
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
printf 'imported %s (linux/%s) into namespace %s\n' "$REF" "$ARCH" "$NS"
