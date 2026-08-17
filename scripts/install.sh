#!/usr/bin/env bash
# Kanea installer (PRD §5.2.12).
#
# It does three things and stops: fetch the binary, verify it, and hand over to
# `kanea init`. It generates no keys and starts nothing: those are decisions
# with consequences, and a script that made them for you would be making them at
# the moment you understand the node least.
#
# The runtime is not among them. `kanea init` installs containerd, runc and
# buildkitd at versions the binary pins (PRD §5.2.12) and enforces a version
# matrix, so they are not a prerequisite list you assemble by hand. The network
# layer needs no component at all: the eBPF datapath's programs are compiled
# into the kanea binary itself (§5.2.5).
#
# Run it with bash, not sh: `set -o pipefail` is not POSIX, and the checksum
# check below is a pipeline whose *first* command is the one that can fail.
#
#     curl -fsSL https://m18h.github.io/kanea/install.sh | sudo bash
set -euo pipefail

REPO="${KANEA_REPO:-m18h/kanea}"
VERSION="${KANEA_VERSION:-latest}"
PREFIX="${KANEA_PREFIX:-/usr/local/bin}"

die() { printf 'install: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }
need curl
need tar
need install

# Kanea is a Linux platform: containerd, cgroups v2, netns and eBPF are all
# Linux. Said here rather than discovered after a download.
[ "$(uname -s)" = "Linux" ] || die "kanead runs on Linux (found $(uname -s))"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

if [ "$VERSION" = "latest" ]; then
  # Resolved from the redirect GitHub already serves, rather than from the JSON
  # API: parsing that needs jq, which is not on a minimal Debian or Amazon Linux
  # image, so the one-liner this script exists to be would fail on its first
  # step, on exactly the bare node it is meant for. The redirect also has no
  # unauthenticated rate limit.
  VERSION="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPO}/releases/latest")" ||
    die "cannot reach https://github.com/${REPO}/releases/latest"
  VERSION="${VERSION##*/}"
  # A repository with no release redirects to /releases, and the tag would come
  # back as the literal "releases", which composes into a plausible-looking
  # archive name and a 404 nobody can read. Checked here instead.
  case "$VERSION" in
    v*) ;;
    *) die "no published release found for ${REPO} (set KANEA_VERSION to pin one)" ;;
  esac
fi

ARCHIVE="kanea_${VERSION#v}_linux_${ARCH}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"

# An existing binary makes this an upgrade, and the ending below changes with
# it: a node that is already initialised needs a restart in the right order,
# not a second key ceremony.
OLD_VERSION=""
if [ -x "${PREFIX}/kanea" ]; then
  OLD_VERSION="$("${PREFIX}/kanea" version 2>/dev/null | awk '{print $2}')" || OLD_VERSION=""
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -n "$OLD_VERSION" ] && [ "$OLD_VERSION" = "$VERSION" ]; then
  note "kanea ${VERSION} is already installed; reinstalling it"
elif [ -n "$OLD_VERSION" ]; then
  note "Upgrading kanea ${OLD_VERSION} -> ${VERSION} (linux/${ARCH})"
else
  note "Downloading kanea ${VERSION} (linux/${ARCH})"
fi
curl -fsSL "${BASE}/${ARCHIVE}" -o "${WORK}/${ARCHIVE}"

# Checksum verification is not optional and there is no flag to skip it. A
# binary that is about to run as root on this node, with access to every
# container and every secret, is not something to install on the strength of a
# TLS connection alone.
note "Verifying the checksum"
curl -fsSL "${BASE}/checksums.txt" -o "${WORK}/checksums.txt"
(
  cd "$WORK"
  if command -v sha256sum >/dev/null 2>&1; then
    grep " ${ARCHIVE}\$" checksums.txt | sha256sum -c - >/dev/null
  else
    grep " ${ARCHIVE}\$" checksums.txt | shasum -a 256 -c - >/dev/null
  fi
) || die "checksum mismatch: do not run this binary"

# Signature verification, when cosign is present. Not required, because
# requiring it would mean every installer needs cosign; strongly preferred,
# because a checksum file fetched from the same place as the binary proves only
# that the two agree.
if command -v cosign >/dev/null 2>&1; then
  note "Verifying the signature"
  curl -fsSL "${BASE}/checksums.txt.sig" -o "${WORK}/checksums.txt.sig" 2>/dev/null || true
  curl -fsSL "${BASE}/checksums.txt.pem" -o "${WORK}/checksums.txt.pem" 2>/dev/null || true
  if [ -s "${WORK}/checksums.txt.sig" ]; then
    cosign verify-blob \
      --certificate "${WORK}/checksums.txt.pem" \
      --signature "${WORK}/checksums.txt.sig" \
      --certificate-identity-regexp "https://github.com/${REPO}/" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      "${WORK}/checksums.txt" >/dev/null 2>&1 || die "signature verification failed"
    note "Signature verified"
  else
    note "No signature published for ${VERSION}; checksum only"
  fi
else
  note "cosign not found; checksum verified but signature not checked"
fi

tar -xzf "${WORK}/${ARCHIVE}" -C "$WORK"
install -m 0755 "${WORK}/kanea" "${PREFIX}/kanea"
note "Installed ${PREFIX}/kanea"

# The upgrade ending. The new binary is on disk but the old one is still the
# one running; `kanea upgrade` owns the restart order (PRD §15.4): back up,
# drain and restart the edge, then kanead, which runs any state migrations.
# Workloads are untouched throughout (KillMode=process).
if [ -n "$OLD_VERSION" ]; then
  cat <<'UPGRADE'

The running daemons are still on the old binary. Next:

    sudo kanea upgrade

It backs up, drains and restarts kanea-edge, then restarts kanead, which
runs any state migrations. Running workloads are untouched throughout.

(Next time, `sudo kanea upgrade` alone is the whole upgrade: it downloads
and verifies the release itself before restarting anything.)

If the release notes mention changed systemd units, regenerate them too;
`kanea upgrade` deliberately never rewrites units:

    sudo kanea init      # idempotent: key, accounts and settings are kept
    sudo systemctl daemon-reload

Host components (containerd, runc, buildkitd) are pinned by the new binary;
`sudo kanea install --dry-run` shows whether any of them need to move, and
`sudo kanea doctor` confirms the node agrees with the version matrix.
UPGRADE
  exit 0
fi

cat <<'NEXT'

Next:

  1. Run:

         sudo kanea init

     It checks the node, installs the runtime (containerd, runc and rootless
     buildkitd, at pinned versions), runs the master-key ceremony and writes
     the systemd units.

     Have somewhere to record the key before you start: it is shown once,
     and without it every backup is unreadable.

     Nothing already on the node is touched: Kanea's containerd installs under
     its own prefix on its own socket, so a box that ran Docker yesterday runs
     it tomorrow. `kanea install --list` shows the pinned versions first, and
     `--dry-run` verifies every download without writing anything.

  2. Then:

         sudo systemctl daemon-reload
         sudo systemctl enable --now kanead
         sudo kanea user add --role admin <name>

     To use the CLI without sudo, join the kanea group and log in again;
     membership is root-equivalent, exactly like docker's:

         sudo usermod -aG kanea <user>

No egress on that node? Build a bundle on a machine that has some, carry it
across, and install from it; the same verification either way:

    kanea bundle create --arch amd64 -o kanea-bundle.tar.gz   # connected
    sudo kanea init --bundle kanea-bundle.tar.gz              # air-gapped

Read the disaster-recovery runbook before you need it:

    https://github.com/m18h/kanea/blob/main/docs/DR_RUNBOOK.md
NEXT
