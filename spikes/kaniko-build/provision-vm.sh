#!/usr/bin/env bash
# provision-vm.sh — one-time setup for spike ④ (image builds as containerd tasks)
# on the kanea-spike OrbStack VM (Ubuntu 24.04 arm64).
#
# Sets up a local OCI registry with basic auth (so push credentials are exercised
# the way PRD §10.2 describes) and pulls the three candidate builders:
#   kaniko   v1.24.0  — the PRD's incumbent; upstream repo is ARCHIVED (read-only)
#   buildkit v0.32.0  — actively maintained, rootless image
#   buildah  v1.43.1  — actively maintained, chroot isolation available
# Idempotent. Spike-only, nothing ships.
set -euo pipefail

KANIKO_IMAGE="gcr.io/kaniko-project/executor:v1.24.0"
BUILDKIT_IMAGE="docker.io/moby/buildkit:v0.32.0-rootless"
BUILDAH_IMAGE="quay.io/buildah/stable:v1.43.1"
REGISTRY_IMAGE="docker.io/library/registry:3"

REG_USER="kanea"
REG_PASS="kaneabuild"
REG_ADDR="127.0.0.1:5000"
CTR_NS="kanea-spike-build"
BK_USER="kanea-buildkit"
WORKDIR="/var/lib/kanea-spike-build"

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

command -v containerd >/dev/null || { echo "containerd missing: run spike ② provision-vm.sh first" >&2; exit 1; }

say "base packages (htpasswd)"
sudo apt-get update -qq
sudo apt-get install -y -qq apache2-utils curl ca-certificates >/dev/null

say "registry credentials + auth file"
sudo mkdir -p "$WORKDIR"/{auth,registry-data,context,cache}
sudo htpasswd -Bbc "$WORKDIR/auth/htpasswd" "$REG_USER" "$REG_PASS" 2>/dev/null
# docker config.json — the shape every builder expects for registry auth. In
# Kanea this is materialised from the secret store (PRD §12), never on disk.
AUTH_B64="$(printf '%s:%s' "$REG_USER" "$REG_PASS" | base64 -w0)"
sudo tee "$WORKDIR/auth/config.json" >/dev/null <<EOF
{"auths":{"${REG_ADDR}":{"auth":"${AUTH_B64}"}}}
EOF
sudo chmod 0600 "$WORKDIR/auth/config.json" "$WORKDIR/auth/htpasswd"

say "build context (Dockerfile + a file to copy)"
sudo tee "$WORKDIR/context/Dockerfile" >/dev/null <<'EOF'
# Multi-stage on purpose: exercises layer caching and a RUN that touches the
# filesystem as root, which is where rootless builders differ.
FROM docker.io/library/alpine:3.21 AS base
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
COPY payload.txt /opt/payload.txt
RUN echo "built-by-kanea-spike" > /opt/marker.txt && chown app /opt/marker.txt

FROM docker.io/library/alpine:3.21
COPY --from=base /opt/marker.txt /opt/marker.txt
COPY --from=base /opt/payload.txt /opt/payload.txt
USER 10001
ENTRYPOINT ["/bin/sh", "-c", "cat /opt/marker.txt /opt/payload.txt"]
EOF
sudo tee "$WORKDIR/context/payload.txt" >/dev/null <<'EOF'
payload-v1
EOF
# Containerfile contexts: Kanea must accept either filename (Podman/buildah use
# Containerfile, Docker uses Dockerfile), so both the lone-Containerfile case and
# the both-present precedence case are exercised.
sudo mkdir -p "$WORKDIR/context-containerfile" "$WORKDIR/context-both"
sudo cp "$WORKDIR/context/payload.txt" "$WORKDIR/context-containerfile/payload.txt"
sudo cp "$WORKDIR/context/Dockerfile" "$WORKDIR/context-containerfile/Containerfile"
sudo cp "$WORKDIR/context/payload.txt" "$WORKDIR/context-both/payload.txt"
sudo tee "$WORKDIR/context-both/Containerfile" >/dev/null <<'EOF'
FROM docker.io/library/alpine:3.21
RUN echo containerfile-wins > /opt/which.txt
ENTRYPOINT ["/bin/cat", "/opt/which.txt"]
EOF
sudo tee "$WORKDIR/context-both/Dockerfile" >/dev/null <<'EOF'
FROM docker.io/library/alpine:3.21
RUN echo dockerfile-wins > /opt/which.txt
ENTRYPOINT ["/bin/cat", "/opt/which.txt"]
EOF

# A deliberately broken context for the error-surfacing check.
sudo mkdir -p "$WORKDIR/context-bad"
sudo tee "$WORKDIR/context-bad/Dockerfile" >/dev/null <<'EOF'
FROM docker.io/library/alpine:3.21
RUN exit 17
EOF

say "registry as a containerd task (host network, basic auth, $REG_ADDR)"
sudo ctr -n "$CTR_NS" images pull "$REGISTRY_IMAGE" >/dev/null
sudo tee /usr/local/bin/kanea-spike-registry-run >/dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec /usr/local/bin/ctr -n ${CTR_NS} run --rm --net-host \\
  --mount type=bind,src=${WORKDIR}/registry-data,dst=/var/lib/registry,options=rbind:rw \\
  --mount type=bind,src=${WORKDIR}/auth,dst=/auth,options=rbind:ro \\
  --env REGISTRY_AUTH=htpasswd \\
  --env REGISTRY_AUTH_HTPASSWD_REALM="kanea-spike" \\
  --env REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \\
  --env REGISTRY_HTTP_ADDR=${REG_ADDR} \\
  --env REGISTRY_STORAGE_DELETE_ENABLED=true \\
  ${REGISTRY_IMAGE} kanea-spike-registry
EOF
sudo chmod 0755 /usr/local/bin/kanea-spike-registry-run
sudo tee /etc/systemd/system/kanea-spike-registry.service >/dev/null <<'EOF'
[Unit]
Description=OCI registry for the kanea build spike
After=containerd.service
Requires=containerd.service

[Service]
ExecStartPre=-/usr/local/bin/ctr -n kanea-spike-build task kill -s SIGKILL kanea-spike-registry
ExecStartPre=-/usr/local/bin/ctr -n kanea-spike-build container rm kanea-spike-registry
ExecStart=/usr/local/bin/kanea-spike-registry-run
ExecStopPost=-/usr/local/bin/ctr -n kanea-spike-build container rm kanea-spike-registry
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable kanea-spike-registry >/dev/null
sudo systemctl restart kanea-spike-registry

for _ in $(seq 30); do
  curl -fsS -u "${REG_USER}:${REG_PASS}" "http://${REG_ADDR}/v2/" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS -u "${REG_USER}:${REG_PASS}" "http://${REG_ADDR}/v2/" >/dev/null && echo "  registry healthy (auth required)"
# Prove auth is actually enforced, else the push test would be meaningless.
code="$(curl -s -o /dev/null -w '%{http_code}' "http://${REG_ADDR}/v2/")"
[ "$code" = "401" ] && echo "  unauthenticated request -> 401 (auth enforced)" || { echo "  registry is NOT enforcing auth ($code)" >&2; exit 1; }

say "pull builder images"
for img in "$KANIKO_IMAGE" "$BUILDKIT_IMAGE" "$BUILDAH_IMAGE"; do
  echo "  $img"
  sudo ctr -n "$CTR_NS" images pull --platform linux/arm64 "$img" >/dev/null
done
sudo ctr -n "$CTR_NS" images ls | awk 'NR==1 || /kaniko|buildkit|buildah|registry/ {print "  " $1 "  " $3}'

say "rootless buildkitd as a host service (the daemon path)"
# BuildKit's native shape is a daemon, and its rootless mode runs as an
# unprivileged host user via rootlesskit — no privileged container per build.
# Binaries are extracted from the same digest-pinned image used for the task form.
sudo apt-get install -y -qq uidmap >/dev/null
id -u "$BK_USER" >/dev/null 2>&1 || sudo useradd --create-home --shell /usr/sbin/nologin "$BK_USER"
grep -q "^${BK_USER}:" /etc/subuid || sudo usermod --add-subuids 200000-265535 --add-subgids 200000-265535 "$BK_USER"
echo "  subuid: $(grep "^${BK_USER}:" /etc/subuid)  subgid: $(grep "^${BK_USER}:" /etc/subgid)"

mnt="$(mktemp -d)"
sudo ctr -n "$CTR_NS" images mount --rw "$BUILDKIT_IMAGE" "$mnt" >/dev/null
for bin in buildkitd buildctl rootlesskit buildkit-runc buildctl-daemonless.sh; do
  for src in "usr/bin/$bin" "usr/local/bin/$bin"; do
    if [ -f "$mnt/$src" ]; then sudo install -m 0755 "$mnt/$src" "/usr/local/bin/$bin"; echo "  $bin <- /$src"; break; fi
  done
done
sudo ctr -n "$CTR_NS" images unmount "$mnt" >/dev/null || true
rmdir "$mnt" 2>/dev/null || true

# Registry credentials for the daemon user (buildctl reads them client-side, but
# the daemon does the push, so both need the config).
sudo mkdir -p "/home/${BK_USER}/.docker" "/home/${BK_USER}/run"
sudo cp "$WORKDIR/auth/config.json" "/home/${BK_USER}/.docker/config.json"
sudo chown -R "${BK_USER}:${BK_USER}" "/home/${BK_USER}"
sudo chmod 0600 "/home/${BK_USER}/.docker/config.json"

sudo tee /etc/systemd/system/kanea-spike-buildkitd.service >/dev/null <<EOF
[Unit]
Description=rootless buildkitd for the kanea build spike
After=network-online.target
Wants=network-online.target

[Service]
User=${BK_USER}
Environment=HOME=/home/${BK_USER}
Environment=XDG_RUNTIME_DIR=/run/${BK_USER}
Environment=PATH=/usr/local/bin:/usr/bin:/bin
RuntimeDirectory=${BK_USER}
RuntimeDirectoryMode=0750
# --net=host keeps the node's loopback reachable (the registry lives there).
# The socket must live OUTSIDE the copy-up'd /run: rootlesskit replaces /run with
# a namespace-private tmpfs, so a socket under it is invisible to clients on the
# host. \$HOME is shared, so the socket goes there.
ExecStart=/usr/local/bin/rootlesskit --net=host --copy-up=/etc --copy-up=/run \
  /usr/local/bin/buildkitd --addr unix:///home/${BK_USER}/run/buildkitd.sock
Restart=always
RestartSec=3
Delegate=yes
# PRD §10.2 build isolation: with a daemon the cap is collective, not per build.
MemoryMax=2G
CPUQuota=200%

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable kanea-spike-buildkitd >/dev/null
sudo systemctl restart kanea-spike-buildkitd

ok=0
for _ in $(seq 60); do
  # `sudo test`: the daemon's home is 0750, so an unprivileged shell cannot
  # even stat the socket. kanead runs as root, so this matches production.
  if sudo test -S "/home/${BK_USER}/run/buildkitd.sock" && \
     sudo buildctl --addr "unix:///home/${BK_USER}/run/buildkitd.sock" debug workers >/dev/null 2>&1; then
    ok=1; break
  fi
  sleep 1
done
if [ "$ok" != 1 ]; then
  echo "  buildkitd did not create its socket; last log lines:" >&2
  sudo journalctl -u kanea-spike-buildkitd -n 25 --no-pager >&2
  exit 1
fi
echo "  socket: /home/${BK_USER}/run/buildkitd.sock"
echo "  daemon uid: $(ps -o user= -p "$(pgrep -f "buildkitd --addr" | head -1)")"

say "provisioning complete"
