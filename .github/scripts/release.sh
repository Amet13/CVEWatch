#!/usr/bin/env bash
# Release helpers for autorelease.yml. Run from the repository root.
#
#   release.sh version          the version in [workspace.package] of Cargo.toml
#   release.sh next             the next version: a minor bump when `## [Unreleased]` in
#                               CHANGELOG.md has an `### Added` section, else a patch bump
#                               (never a major bump: 1.0.0 and 2.0.0 are for a person)
#   release.sh notes <tag>      the commit subjects since <tag>, one per line, with the
#                               dependency bumps folded into one line
#   release.sh bump <next> <tag>
#                               sets the version in Cargo.toml (the package and the
#                               workspace path dependencies), refreshes Cargo.lock, and
#                               moves `[Unreleased]` in CHANGELOG.md to a dated section
#
# Needs git history (fetch-depth: 0) for `notes` and `bump`; `bump` needs cargo.
set -euo pipefail

version() {
  awk '
    /^\[/ { in_pkg = ($0 == "[workspace.package]") }
    in_pkg && /^version[ ]*=/ { split($0, parts, "\""); print parts[2]; exit }
  ' Cargo.toml
}

next() {
  local current major minor patch
  current="$(version)"
  IFS=. read -r major minor patch <<< "$current"
  patch="${patch%%[-+]*}"
  if awk '/^## \[Unreleased\]/ { on = 1; next } /^## \[/ { on = 0 } on && /^### Added/ { found = 1 } END { exit !found }' CHANGELOG.md; then
    echo "$major.$((minor + 1)).0"
  else
    echo "$major.$minor.$((patch + 1))"
  fi
}

notes() {
  local tag="$1" subjects deps
  subjects="$(git log --no-merges --format='%s' "$tag..HEAD" || true)"
  deps="$(grep -ciE '^(chore|build)(\(.*\))?(\(deps\))?: bump |^bump |dependabot' <<< "$subjects" || true)"
  grep -viE '^(chore|build)(\(.*\))?(\(deps\))?: bump |^bump |^Release v|dependabot' <<< "$subjects" |
    sed '/^$/d; s/^/- /' || true
  if [ "${deps:-0}" -gt 0 ]; then
    echo "- Dependency updates ($deps)"
  fi
}

bump() {
  local next="$1" tag="$2" current today body
  current="$(version)"
  today="$(date -u +%Y-%m-%d)"
  # The package version, and the version of each workspace path dependency.
  sed -i -E \
    -e "/^\[workspace\.package\]/,/^\[/ s/^version = \"$current\"/version = \"$next\"/" \
    -e "/path = \"(crates|xtask)\// s/version = \"$current\"/version = \"$next\"/" \
    Cargo.toml
  cargo update --workspace --quiet
  body="$(mktemp)"
  notes "$tag" > "$body"
  awk -v v="$next" -v d="$today" -v notes_file="$body" '
    /^## \[Unreleased\]/ && !done {
      print; print ""; print "## [" v "] - " d
      seen = 1; done = 1; next
    }
    seen && /^## \[/ && !flushed {
      # The end of the released section: add the commit subjects, then go on.
      if ((getline line < notes_file) > 0) {
        print "### Other changes"; print ""; print line
        while ((getline line < notes_file) > 0) print line
        print ""
      }
      flushed = 1
    }
    { print }
    END {
      if (seen && !flushed && (getline line < notes_file) > 0) {
        print ""
        print "### Other changes"; print ""; print line
        while ((getline line < notes_file) > 0) print line
      }
    }
  ' CHANGELOG.md > CHANGELOG.md.new
  mv CHANGELOG.md.new CHANGELOG.md
  rm -f "$body"
}

cmd="${1:-}"
shift || true
case "$cmd" in
  version) version ;;
  next) next ;;
  notes) notes "$@" ;;
  bump) bump "$@" ;;
  *) echo "usage: release.sh version|next|notes <tag>|bump <next> <tag>" >&2; exit 2 ;;
esac
