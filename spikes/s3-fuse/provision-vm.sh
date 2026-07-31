#!/usr/bin/env bash
# provision-vm.sh — one-time setup for spike ③ (S3 FUSE drivers) on the
# kanea-spike OrbStack VM (Ubuntu 24.04 arm64).
#
# Installs a local MinIO as the S3 endpoint plus the three candidate drivers:
#   s3fs        (apt)                       — the FUSE veteran, full POSIX-ish semantics
#   rclone      (upstream .deb)             — `rclone mount`, VFS cache modes
#   mount-s3    (AWS mountpoint-s3, .deb)   — replaces goofys: goofys' last release is
#                                             v0.24.0 (Apr 2020) and ships amd64 only,
#                                             so it cannot run on Kanea's arm64 target.
# Idempotent. Spike-only, nothing ships. No real cloud credentials are used.
set -euo pipefail

RCLONE_VERSION="1.74.4"
ARCH="$(dpkg --print-architecture)" # arm64
S3_ENDPOINT="http://127.0.0.1:9000"
BUCKET="kanea-spike"
ACCESS_KEY="kaneaspike"
SECRET_KEY="kaneaspikesecret"

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

say "base packages (fuse3, s3fs)"
sudo apt-get update -qq
sudo apt-get install -y -qq fuse3 s3fs curl ca-certificates >/dev/null

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT; cd "$tmp"

if ! command -v rclone >/dev/null 2>&1; then
  say "rclone $RCLONE_VERSION (upstream .deb — noble ships 1.60)"
  curl -fsSLO "https://github.com/rclone/rclone/releases/download/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-${ARCH}.deb"
  curl -fsSLO "https://github.com/rclone/rclone/releases/download/v${RCLONE_VERSION}/SHA256SUMS"
  grep " rclone-v${RCLONE_VERSION}-linux-${ARCH}.deb$" SHA256SUMS | sed 's|\*||' | sha256sum -c - >/dev/null \
    && echo "  sha256 OK: rclone" || { echo "  SHA256 MISMATCH: rclone" >&2; exit 1; }
  sudo apt-get install -y -qq "./rclone-v${RCLONE_VERSION}-linux-${ARCH}.deb" >/dev/null
fi

if ! command -v mount-s3 >/dev/null 2>&1; then
  say "mountpoint-s3 (AWS, latest)"
  curl -fsSLo mount-s3.deb "https://s3.amazonaws.com/mountpoint-s3-release/latest/${ARCH}/mount-s3.deb"
  sudo apt-get install -y -qq ./mount-s3.deb >/dev/null
fi

if ! command -v minio >/dev/null 2>&1; then
  say "minio server + mc client"
  curl -fsSLo minio "https://dl.min.io/server/minio/release/linux-${ARCH}/minio"
  curl -fsSLo mc "https://dl.min.io/client/mc/release/linux-${ARCH}/mc"
  sudo install -m 0755 minio /usr/local/bin/minio
  sudo install -m 0755 mc /usr/local/bin/mc
fi

say "minio systemd unit (127.0.0.1:9000, single node)"
sudo mkdir -p /var/lib/kanea-spike-minio
sudo tee /etc/systemd/system/kanea-spike-minio.service >/dev/null <<EOF
[Unit]
Description=MinIO S3 endpoint for the kanea s3-fuse spike
After=network-online.target
Wants=network-online.target

[Service]
Environment=MINIO_ROOT_USER=${ACCESS_KEY}
Environment=MINIO_ROOT_PASSWORD=${SECRET_KEY}
ExecStart=/usr/local/bin/minio server /var/lib/kanea-spike-minio --address 127.0.0.1:9000 --console-address 127.0.0.1:9001
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now kanea-spike-minio
sudo systemctl restart kanea-spike-minio

for _ in $(seq 30); do
  curl -fsS "${S3_ENDPOINT}/minio/health/live" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "${S3_ENDPOINT}/minio/health/live" >/dev/null && echo "  minio healthy"

say "bucket + credentials"
mc alias set kaneaspike "$S3_ENDPOINT" "$ACCESS_KEY" "$SECRET_KEY" >/dev/null
mc mb --ignore-existing "kaneaspike/${BUCKET}" >/dev/null
# Credential files, each in the format its driver expects. Spike-only creds;
# a real deployment sources these from the Kanea secret store (PRD §12).
printf '%s:%s\n' "$ACCESS_KEY" "$SECRET_KEY" | sudo tee /etc/kanea-spike-s3fs.passwd >/dev/null
sudo chmod 0600 /etc/kanea-spike-s3fs.passwd
sudo mkdir -p /root/.config/rclone
sudo tee /root/.config/rclone/rclone.conf >/dev/null <<EOF
[kaneaspike]
type = s3
provider = Minio
env_auth = false
access_key_id = ${ACCESS_KEY}
secret_access_key = ${SECRET_KEY}
endpoint = ${S3_ENDPOINT}
region = us-east-1
force_path_style = true
EOF
sudo chmod 0600 /root/.config/rclone/rclone.conf
sudo mkdir -p /root/.aws
sudo tee /root/.aws/credentials >/dev/null <<EOF
[default]
aws_access_key_id = ${ACCESS_KEY}
aws_secret_access_key = ${SECRET_KEY}
EOF
sudo chmod 0600 /root/.aws/credentials

say "unprivileged mount helper user (PRD §8) + fuse user_allow_other"
id -u kanea-s3 >/dev/null 2>&1 || sudo useradd --system --home-dir /home/kanea-s3 --no-create-home --shell /usr/sbin/nologin kanea-s3
# allow_other is what lets root-run containerd traverse a helper-owned mount.
grep -q '^user_allow_other' /etc/fuse.conf 2>/dev/null || echo user_allow_other | sudo tee -a /etc/fuse.conf >/dev/null
# Same credentials, readable by the helper user.
sudo install -o kanea-s3 -g kanea-s3 -m 0600 /etc/kanea-spike-s3fs.passwd /etc/kanea-spike-s3fs-unpriv.passwd
sudo mkdir -p /home/kanea-s3/.config/rclone /home/kanea-s3/.aws
sudo cp /root/.config/rclone/rclone.conf /home/kanea-s3/.config/rclone/rclone.conf
sudo cp /root/.aws/credentials /home/kanea-s3/.aws/credentials
sudo chown -R kanea-s3:kanea-s3 /home/kanea-s3
sudo chmod -R go-rwx /home/kanea-s3

say "mount points"
sudo mkdir -p /mnt/kanea-s3fs /mnt/kanea-rclone /mnt/kanea-mounts3

say "versions"
s3fs --version | head -1
rclone version | head -1
mount-s3 --version | head -1
minio --version | head -1
say "provisioning complete"
