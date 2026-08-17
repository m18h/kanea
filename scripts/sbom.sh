#!/usr/bin/env bash
# Writes the SBOMs a release publishes (PRD §14 A06, §21).
#
# The release workflow runs this between building the archives and writing
# checksums.txt, so every SBOM is covered by the same sha256 manifest, and
# therefore by the one cosign signature over it, with no second signing step.
# That ordering is the whole design: an SBOM nobody can authenticate describes
# software nobody can authenticate.
#
# Two kinds of document come out, because they answer different questions:
#
#   <archive>.spdx.json         what is actually IN the artefact you downloaded.
#                               syft reads the Go binary's own build info, so
#                               this lists the modules the linker kept, not the
#                               ones the build merely walked past.
#
#   kanea_<ver>_source.spdx.json  what the build consumed. This is the only
#                               document that can carry the dashboard's npm
#                               graph: those packages are compiled into minified
#                               bundles that go:embed puts inside the binary, and
#                               no scan of the binary can recover their names.
#                               It reads dashboard/package-lock.json instead.
#
# The offline bundles are deliberately NOT scanned. A bundle is a carrier for
# upstream tarballs and an OCI archive; syft does not descend into nested
# archives, so it would emit a near-empty document that reads as "this bundle
# contains nothing": worse than no document at all. What a bundle carries is
# already published, more precisely than an SBOM would state it, by
# internal/provision/components.json: name, version and SHA-256 per component,
# compiled into the binary and verified at install time.
#
#     scripts/sbom.sh dist v0.17.0
#     scripts/sbom.sh --dry-run dist v0.17.0   # names only; no syft needed
set -euo pipefail

die() { printf 'sbom: %s\n' "$*" >&2; exit 1; }

DRY_RUN=""
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
  shift
fi

[ $# -eq 2 ] || die "usage: sbom.sh [--dry-run] <dist-dir> <vX.Y.Z>"
DIST="$1"
TAG="$2"

# The same grammar check the tap repo's update-formula.sh and kanea upgrade
# apply. The version
# composes into a published filename, so a tag that is not a version must not
# become a plausible-looking asset name.
case "$TAG" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) die "tag ${TAG} does not look like vX.Y.Z" ;;
esac
[ -d "$DIST" ] || die "no such directory: ${DIST}"

VERSION="${TAG#v}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# The naming contract. Three readers parse the checksums.txt these land in, and
# two properties keep all three working:
#
#   A name is one whitespace-free field. The tap repo's update-formula.sh
#   (m18h/homebrew-kanea) reads the file with
#   awk '$2 == name' and checksumFor (cmd/kanea/selfupdate.go) requires exactly
#   two fields per line, so a space in a name silently breaks both.
#
#   A name is never one an archive already has. install.sh selects its line with
#   `grep " <archive>$"` and pipes it to `sha256sum -c -`; a second line ending
#   in the same name hands it a file the installer never downloaded and fails
#   the installation. Note the leading space in that pattern does the real work:
#   a *prefixed* name like "sbom-<archive>" cannot match it, so the hazard is
#   duplication, not resemblance.
#
# cmd/kanea/sbom_contract_test.go drives this function and asserts both.
sbom_name() { printf '%s.spdx.json' "$1"; }

# Only the binary archives: see the header for why the bundles are not here.
ARCHIVES=()
for archive in "$DIST"/kanea_"${VERSION}"_*.tar.gz; do
  [ -e "$archive" ] || continue
  case "$(basename "$archive")" in
    *_bundle.tar.gz) continue ;;
  esac
  ARCHIVES+=("$archive")
done

# An empty dist means the build step changed shape and this one silently did
# nothing. A release that publishes no SBOM must fail loudly, not quietly.
[ ${#ARCHIVES[@]} -gt 0 ] ||
  die "no kanea_${VERSION}_*.tar.gz archives in ${DIST}"

SOURCE_SBOM="${DIST}/kanea_${VERSION}_source.spdx.json"

if [ -n "$DRY_RUN" ]; then
  for archive in "${ARCHIVES[@]}"; do
    printf '%s\n' "$(dirname "$archive")/$(sbom_name "$(basename "$archive")")"
  done
  printf '%s\n' "$SOURCE_SBOM"
  exit 0
fi

command -v syft >/dev/null 2>&1 || die "syft is not installed"

for archive in "${ARCHIVES[@]}"; do
  out="$(dirname "$archive")/$(sbom_name "$(basename "$archive")")"
  printf 'cataloguing %s\n' "$(basename "$archive")"
  # syft expands the tarball itself; there is no extract step to clean up.
  syft scan "file:${archive}" -o "spdx-json=${out}" -q
done

printf 'cataloguing the source tree\n'
# node_modules is excluded because package-lock.json is the authoritative graph
# and scanning both reports each package twice. spikes/ is excluded because each
# spike carries its own go.mod: throwaway validation code that ships in nothing,
# and listing it would describe a product that does not exist.
syft scan "dir:${ROOT}" -o "spdx-json=${SOURCE_SBOM}" -q \
  --exclude './dist/**' \
  --exclude './dashboard/node_modules/**' \
  --exclude './spikes/**' \
  --exclude './.git/**'

printf 'wrote %d SBOMs in %s\n' "$(( ${#ARCHIVES[@]} + 1 ))" "$DIST"
