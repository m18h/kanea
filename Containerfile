# The Kanea CLI as a container image (PRD §5.2.12, v1.88).
#
# This is the CLI half and nothing more, the line v1.60 drew for Homebrew: it is
# for the pipeline that deploys to a node, not for the node. `plan`, `run`,
# `deploy`, `ps`, `logs`, `secret` and the rest of the remote surface (§16.2)
# work here against KANEA_URL/KANEA_TOKEN; `plan`'s parse-and-validate half needs
# no daemon at all. `agent`, `edge`, `init`, `install`, `doctor` and `upgrade`
# act on a host, its systemd, its cgroups and its own binary, and a container is
# not that host.
#
# THE BINARY IS NOT BUILT HERE. The build context is a directory holding the
# binaries extracted from the release's own signed archives:
#
#     <context>/amd64/kanea
#     <context>/arm64/kanea
#
# so what `checksums.txt` attests to is what ends up in the image, with no second
# compilation to reconcile. See the `image` job in .github/workflows/release.yml,
# which downloads and verifies them before it calls this file.
#
#     docker buildx build --platform linux/amd64,linux/arm64 \
#       -f Containerfile --push -t ghcr.io/m18h/kanea:vX.Y.Z dist/image

# alpine 3.24. Pinned by digest, never by tag: a tag is a mutable pointer to a
# root filesystem, which is exactly what §5.2.12 refuses for the BuildKit
# component. Dependabot bumps it (.github/dependabot.yml) - a digest nothing
# updates is a frozen CVE surface rather than a pin.
FROM alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# TARGETARCH is buildx's, and it is what selects the binary below.
ARG TARGETARCH
ARG VERSION="dev"
ARG REVISION=""

LABEL org.opencontainers.image.title="kanea" \
      org.opencontainers.image.description="The Kanea CLI: deploy to a Kanea node from CI or a terminal" \
      org.opencontainers.image.source="https://github.com/m18h/kanea" \
      org.opencontainers.image.url="https://github.com/m18h/kanea" \
      org.opencontainers.image.documentation="https://m18h.github.io/kanea/docs/" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# The trust store matters here and the reason is not the obvious one. Alpine's
# base already ships ca-certificates-bundle, so the public roots are present
# either way, and they are needed: the binary is static, `--ca-cert` REPLACES
# the system pool rather than adding to it, and without roots a node behind a
# public CA fails the handshake outright. What the full `ca-certificates`
# package adds on top is `update-ca-certificates` and
# /usr/local/share/ca-certificates, which is the drop-in point for a corporate
# root - a TLS-inspecting proxy is ordinary in the CI networks this image runs
# in, and without the tooling there is nowhere to put its certificate.
# tzdata for anything that renders a local time.
#
# A real /etc/passwd entry rather than a bare numeric USER: with CGO off,
# os/user resolves by parsing that file, and a uid with no line in it fails.
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 65532 -h /home/kanea kanea \
 && install -d -o kanea -g kanea /workspace

COPY ${TARGETARCH}/kanea /usr/local/bin/kanea

USER kanea
WORKDIR /workspace

# No CMD: `kanea` with no arguments prints its usage and exits 0, which is the
# right answer to a bare `docker run ghcr.io/m18h/kanea`.
ENTRYPOINT ["/usr/local/bin/kanea"]
