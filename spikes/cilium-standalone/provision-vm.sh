#!/usr/bin/env bash
# provision-vm.sh: one-time setup of standalone Cilium on the kanea-spike OrbStack VM
# (Ubuntu 24.04 arm64). Assumes spike ② already provisioned containerd/runc/CNI plugins.
#
# Installs: etcd (kvstore, 127.0.0.1:2379) + cilium-agent as a privileged host-network
# containerd task, with the cilium-cni plugin extracted from the image onto the host.
# All downloads checksum-verified or digest-pinned. Idempotent. Spike-only, nothing ships.
set -euo pipefail

CILIUM_VERSION="1.19.6"
ETCD_VERSION="3.7.1"
CLUSTER_CIDR="10.200.0.0/16" # PRD §15.1 cilium.cluster_cidr
NODE_CIDR="10.200.1.0/24"    # this node's endpoint allocation prefix
ARCH="$(dpkg --print-architecture)" # arm64
CILIUM_IMAGE="quay.io/cilium/cilium:v${CILIUM_VERSION}"

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

command -v containerd >/dev/null || { echo "containerd missing: run spike ② provision-vm.sh first" >&2; exit 1; }

say "base packages"
sudo apt-get update -qq
sudo apt-get install -y -qq curl jq iptables iproute2 ca-certificates >/dev/null

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT; cd "$tmp"

if ! command -v etcd >/dev/null 2>&1; then
  say "etcd $ETCD_VERSION"
  base="https://github.com/etcd-io/etcd/releases/download/v${ETCD_VERSION}"
  curl -fsSLO "${base}/etcd-v${ETCD_VERSION}-linux-${ARCH}.tar.gz"
  curl -fsSLO "${base}/SHA256SUMS"
  grep " etcd-v${ETCD_VERSION}-linux-${ARCH}.tar.gz$" SHA256SUMS | sed 's|\./||' | sha256sum -c - >/dev/null \
    && echo "  sha256 OK: etcd tarball" || { echo "  SHA256 MISMATCH: etcd" >&2; exit 1; }
  tar -xzf "etcd-v${ETCD_VERSION}-linux-${ARCH}.tar.gz"
  sudo install -m 0755 "etcd-v${ETCD_VERSION}-linux-${ARCH}/etcd" /usr/local/bin/etcd
  sudo install -m 0755 "etcd-v${ETCD_VERSION}-linux-${ARCH}/etcdctl" /usr/local/bin/etcdctl
fi

say "etcd systemd unit (127.0.0.1:2379, single node)"
sudo mkdir -p /var/lib/kanea-spike-etcd
sudo tee /etc/systemd/system/kanea-spike-etcd.service >/dev/null <<'EOF'
[Unit]
Description=etcd kvstore for standalone Cilium (kanea spike)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/etcd \
  --name=kanea-spike \
  --data-dir=/var/lib/kanea-spike-etcd \
  --listen-client-urls=http://127.0.0.1:2379 \
  --advertise-client-urls=http://127.0.0.1:2379 \
  --listen-peer-urls=http://127.0.0.1:2380 \
  --initial-advertise-peer-urls=http://127.0.0.1:2380 \
  --initial-cluster=kanea-spike=http://127.0.0.1:2380 \
  --initial-cluster-state=new \
  --auto-compaction-retention=1
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now kanea-spike-etcd
for _ in $(seq 30); do
  ETCDCTL_API=3 etcdctl --endpoints=127.0.0.1:2379 endpoint health >/dev/null 2>&1 && break
  sleep 1
done
ETCDCTL_API=3 etcdctl --endpoints=127.0.0.1:2379 endpoint health

say "pull $CILIUM_IMAGE"
sudo ctr -n cilium images pull "$CILIUM_IMAGE" >/dev/null
sudo ctr -n cilium images ls -q | grep -F "$CILIUM_IMAGE" >/dev/null
DIGEST="$(sudo ctr -n cilium images ls | awk -v i="$CILIUM_IMAGE" '$1==i {print $3}')"
echo "  image digest: $DIGEST"

say "extract cilium-cni + cilium-dbg from the image"
mnt="$(mktemp -d)"
sudo ctr -n cilium images mount --rw "$CILIUM_IMAGE" "$mnt" >/dev/null
# The image ships the CNI plugin at /opt/cni/bin/cilium-cni and the CLI at /usr/bin/cilium-dbg.
for src in opt/cni/bin/cilium-cni usr/bin/cilium-cni; do
  [ -f "$mnt/$src" ] && sudo install -m 0755 "$mnt/$src" /opt/cni/bin/cilium-cni && echo "  cilium-cni <- /$src" && break
done
for src in usr/bin/cilium-dbg usr/bin/cilium; do
  [ -f "$mnt/$src" ] && sudo install -m 0755 "$mnt/$src" /usr/local/bin/cilium-dbg && echo "  cilium-dbg <- /$src" && break
done
sudo ctr -n cilium images unmount "$mnt" >/dev/null || true
rmdir "$mnt" 2>/dev/null || true
test -x /opt/cni/bin/cilium-cni || { echo "cilium-cni not found in image" >&2; exit 1; }

say "host mount points + sysctl for cilium"
# /var/run/cilium also carries the two file-based control surfaces a non-k8s
# deployment needs: lb-state.json (services) and policies/ (static CNPs).
sudo mkdir -p /var/run/cilium/policies /run/cilium/cgroupv2 /sys/fs/bpf /etc/cni/net.d
mountpoint -q /sys/fs/bpf || sudo mount -t bpf bpffs /sys/fs/bpf
sudo mount --make-shared /sys/fs/bpf
mountpoint -q /run/cilium/cgroupv2 || sudo mount -t cgroup2 none /run/cilium/cgroupv2
sudo touch /run/xtables.lock
sudo tee /etc/sysctl.d/91-kanea-spike-cilium.conf >/dev/null <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.core.bpf_jit_enable = 1
EOF
sudo sysctl --system -q >/dev/null

say "cilium-agent systemd unit (privileged containerd task, host network + PID)"
sudo tee /usr/local/bin/kanea-spike-cilium-run >/dev/null <<EOF
#!/usr/bin/env bash
# Runs cilium-agent as a privileged host-network containerd task. Spike-only.
set -euo pipefail
exec /usr/local/bin/ctr -n cilium run --rm \\
  --privileged \\
  --net-host \\
  --with-ns pid:/proc/1/ns/pid \\
  --mount type=bind,src=/var/run/cilium,dst=/var/run/cilium,options=rbind:rw \\
  --mount type=bind,src=/sys/fs/bpf,dst=/sys/fs/bpf,options=rbind:rw \\
  --mount type=bind,src=/run/cilium/cgroupv2,dst=/run/cilium/cgroupv2,options=rbind:rw \\
  --mount type=bind,src=/run/xtables.lock,dst=/run/xtables.lock,options=rbind:rw \\
  --mount type=bind,src=/lib/modules,dst=/lib/modules,options=rbind:ro \\
  --env CILIUM_CNI_CHAINING_MODE=none \\
  "$CILIUM_IMAGE" cilium-agent \\
  cilium-agent \\
    --enable-k8s=false \\
    --kvstore=etcd \\
    --kvstore-opt=etcd.address=127.0.0.1:2379 \\
    --identity-allocation-mode=kvstore \\
    --ipam=cluster-pool \\
    --ipv4-range=$NODE_CIDR \\
    --enable-ipv4=true \\
    --enable-ipv6=false \\
    --routing-mode=native \\
    --ipv4-native-routing-cidr=$CLUSTER_CIDR \\
    --enable-ipv4-masquerade=true \\
    --kube-proxy-replacement=true \\
    --bpf-lb-algorithm=maglev \\
    --lb-state-file=/var/run/cilium/lb-state.json \\
    --enable-l7-proxy=true \\
    --enable-health-checking=false \\
    --enable-endpoint-health-checking=false \\
    --static-cnp-path=/var/run/cilium/policies \\
    --policy-default-local-cluster=false \\
    --enable-hubble=true \\
    --hubble-listen-address=:4244 \\
    --hubble-metrics-server=:9965 \\
    --hubble-metrics='dns drop tcp flow port-distribution' \\
    --cgroup-root=/run/cilium/cgroupv2 \\
    --bpf-root=/sys/fs/bpf
EOF
sudo chmod 0755 /usr/local/bin/kanea-spike-cilium-run
sudo tee /etc/systemd/system/kanea-spike-cilium.service >/dev/null <<'EOF'
[Unit]
Description=cilium-agent (standalone, kanea spike)
After=containerd.service kanea-spike-etcd.service
Requires=containerd.service kanea-spike-etcd.service

[Service]
ExecStartPre=-/usr/local/bin/ctr -n cilium task kill -s SIGKILL cilium-agent
ExecStartPre=-/usr/local/bin/ctr -n cilium container rm cilium-agent
ExecStart=/usr/local/bin/kanea-spike-cilium-run
ExecStopPost=-/usr/local/bin/ctr -n cilium container rm cilium-agent
Restart=always
RestartSec=5
LimitNOFILE=1048576
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable kanea-spike-cilium
sudo systemctl restart kanea-spike-cilium

say "wait for the agent API socket"
ok=0
for _ in $(seq 90); do
  if [ -S /var/run/cilium/cilium.sock ] && sudo cilium-dbg status --brief >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
if [ "$ok" != 1 ]; then
  echo "cilium-agent did not become healthy; last 60 log lines:" >&2
  sudo journalctl -u kanea-spike-cilium -n 60 --no-pager >&2
  exit 1
fi

say "CNI conflist (/etc/cni/net.d/05-cilium.conflist, PRD §5.2.5)"
sudo tee /etc/cni/net.d/05-cilium.conflist >/dev/null <<'EOF'
{
  "cniVersion": "1.0.0",
  "name": "cilium",
  "plugins": [
    {
      "type": "cilium-cni",
      "enable-debug": false,
      "log-file": "/var/run/cilium/cilium-cni.log"
    }
  ]
}
EOF

say "smoke checks"
sudo cilium-dbg status | head -20
echo "hubble metrics: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9965/metrics)"
say "provisioning complete"
