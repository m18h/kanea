#!/usr/bin/env bash
# provision-vm.sh: one-time setup of the kanea-spike OrbStack VM
# (Ubuntu 24.04 arm64): containerd 2.3.3, runc 1.5.1, CNI plugins 1.9.1, Go 1.26.5.
# All downloads checksum-verified. Idempotent. Spike-only, nothing ships.
set -euo pipefail

CONTAINERD_VERSION="2.3.3"
RUNC_VERSION="1.5.1"
CNI_VERSION="1.9.1"
# No Go toolchain: spike code cross-compiles on macOS (GOOS=linux GOARCH=arm64).
ARCH="$(dpkg --print-architecture)" # arm64

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

say "base packages"
sudo apt-get update -qq
sudo apt-get install -y -qq curl jq iptables iproute2 ca-certificates >/dev/null

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT; cd "$tmp"

verify() { # verify <file> <sha256-file>; normalizes "hash\n" and "hash  file\n"
  printf '%s  %s\n' "$(awk '{print $1}' "$2")" "$1" | sha256sum -c - >/dev/null \
    && echo "  sha256 OK: $1" || { echo "  SHA256 MISMATCH: $1" >&2; exit 1; }
}

say "containerd $CONTAINERD_VERSION (static)"
sudo systemctl stop containerd 2>/dev/null || true # binary may be in use on re-runs
curl -fsSLO "https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-static-${CONTAINERD_VERSION}-linux-${ARCH}.tar.gz"
curl -fsSLO "https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-static-${CONTAINERD_VERSION}-linux-${ARCH}.tar.gz.sha256sum"
verify "containerd-static-${CONTAINERD_VERSION}-linux-${ARCH}.tar.gz" "containerd-static-${CONTAINERD_VERSION}-linux-${ARCH}.tar.gz.sha256sum"
mkdir x && tar -C x -xzf "containerd-static-${CONTAINERD_VERSION}-linux-${ARCH}.tar.gz"
sudo cp -R x/bin/* /usr/local/bin/

if ! command -v runc >/dev/null 2>&1; then
  say "runc $RUNC_VERSION"
  curl -fsSLo "runc.${ARCH}" "https://github.com/opencontainers/runc/releases/download/v${RUNC_VERSION}/runc.${ARCH}"
  curl -fsSLo runc.sha256sum "https://github.com/opencontainers/runc/releases/download/v${RUNC_VERSION}/runc.sha256sum"
  grep "  runc\.${ARCH}$" runc.sha256sum | sha256sum -c - >/dev/null \
    && echo "  sha256 OK: runc.${ARCH}" || { echo "  SHA256 MISMATCH: runc" >&2; exit 1; }
  sudo install -m 0755 "runc.${ARCH}" /usr/local/sbin/runc
fi

say "containerd systemd unit + config (metrics on 127.0.0.1:1338, CRI disabled)"
sudo tee /etc/systemd/system/containerd.service >/dev/null <<'EOF'
[Unit]
Description=containerd container runtime
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/containerd
Delegate=yes
KillMode=process
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF
sudo mkdir -p /etc/containerd/conf.d
containerd config default | sudo tee /etc/containerd/config.toml >/dev/null
# config v4: Prometheus listener lives under the server metrics plugin; conf.d import overrides it.
sudo tee /etc/containerd/conf.d/90-kanea-spike.toml >/dev/null <<'EOF'
[plugins.'io.containerd.server.v1.metrics']
  address = '127.0.0.1:1338'
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now containerd
sudo systemctl restart containerd

say "CNI plugins $CNI_VERSION"
curl -fsSLO "https://github.com/containernetworking/plugins/releases/download/v${CNI_VERSION}/cni-plugins-linux-${ARCH}-v${CNI_VERSION}.tgz"
curl -fsSLO "https://github.com/containernetworking/plugins/releases/download/v${CNI_VERSION}/cni-plugins-linux-${ARCH}-v${CNI_VERSION}.tgz.sha256"
verify "cni-plugins-linux-${ARCH}-v${CNI_VERSION}.tgz" "cni-plugins-linux-${ARCH}-v${CNI_VERSION}.tgz.sha256"
sudo mkdir -p /opt/cni/bin
sudo tar -C /opt/cni/bin -xzf "cni-plugins-linux-${ARCH}-v${CNI_VERSION}.tgz"
sudo mkdir -p /etc/cni/net.d /var/lib/cni/networks

say "sysctl + modules for bridge CNI"
sudo modprobe overlay br_netfilter 2>/dev/null || true
sudo tee /etc/sysctl.d/90-kanea-spike.conf >/dev/null <<'EOF'
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-ip6tables = 0
EOF
sudo sysctl --system -q >/dev/null

say "smoke checks"
containerd --version
runc --version | head -1
sudo ctr version | head -2
echo "metrics endpoint: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:1338/v1/metrics)"
say "provisioning complete"
