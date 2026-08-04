#!/usr/bin/env bash
# fetch-release — download an asset from a GitHub release into a directory.
#
#   fetch-release <owner/repo> <asset-regex> <destdir> [member-regex]
#
# Pinning versions in a Dockerfile rots: the URL 404s the next time the image is
# built and the failure is silent until an engagement needs the binary. This
# resolves the latest release through the API instead, so the image tracks
# upstream. Archives are unpacked and the interesting member kept.
#
# Every failure is recorded in /opt/skipped-downloads.txt rather than failing the
# build — a missing post-ex binary is a degraded image, not a broken one.
set -uo pipefail

repo="${1:?repo}"; pattern="${2:?asset regex}"; dest="${3:?destdir}"; member="${4:-}"
mkdir -p "$dest"

note_fail() { echo "$repo ($pattern): $1" >> /opt/skipped-downloads.txt; exit 0; }

api="https://api.github.com/repos/$repo/releases/latest"
url=$(curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} "$api" 2>/dev/null \
      | jq -r --arg p "$pattern" '.assets[]? | select(.name | test($p)) | .browser_download_url' \
      | head -1)
[ -n "$url" ] || note_fail "no asset matched in the latest release"

tmp=$(mktemp -d); file="$tmp/$(basename "$url")"
curl -fsSL -o "$file" "$url" || note_fail "download failed: $url"

case "$file" in
  *.tar.gz|*.tgz) tar -xzf "$file" -C "$tmp" || note_fail "tar failed" ;;
  *.zip)          unzip -qo "$file" -d "$tmp" || note_fail "unzip failed" ;;
  *.gz)           gunzip -f "$file" && file="${file%.gz}" ;;
esac

# Plain binary: keep it. Archive: keep whatever matches the member pattern.
if [ -f "$file" ] && [ -z "${member:-}" ] && [[ "$file" != *.zip && "$file" != *.tar.gz && "$file" != *.tgz ]]; then
  install -m755 "$file" "$dest/" || note_fail "install failed"
else
  # The downloaded archive itself lives in $tmp and will match a loose member
  # pattern, so exclude archives and docs — only real members get installed.
  found=0
  while IFS= read -r m; do
    install -m755 "$m" "$dest/" && found=1
  done < <(find "$tmp" -type f | grep -E "${member:-.}" \
           | grep -vE '\.(txt|md|json|sig|tar\.gz|tgz|zip|gz)$')
  [ "$found" -eq 1 ] || note_fail "no archive member matched '${member:-.}'"
fi

rm -rf "$tmp"
