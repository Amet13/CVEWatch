#!/usr/bin/env bash
# Publishes the workspace crates to crates.io one by one, dependencies first.
#
#   .github/scripts/publish-crates.sh
#
# - A version that is already on crates.io is skipped, so the script can run again.
# - crates.io limits new crates (a burst of 5, then one every 10 minutes). On HTTP 429
#   the script waits 11 minutes and tries again, until DEADLINE_SECONDS have passed.
# - Needs CARGO_REGISTRY_TOKEN, cargo, jq and tsort.
#
# For tests: PUBLISH_CMD replaces `cargo publish --locked -p` (the crate name is added),
# SLEEP_CMD replaces `sleep`, EXISTS_CMD <crate> <version> replaces the crates.io
# lookup (exit 0 means the version exists).
set -euo pipefail

wait_seconds="${WAIT_SECONDS:-660}"
deadline_seconds="${DEADLINE_SECONDS:-5100}"
publish_cmd="${PUBLISH_CMD:-cargo publish --locked -p}"
sleep_cmd="${SLEEP_CMD:-sleep}"
start="$(date +%s)"

exists() {
  local crate="$1" version="$2" code
  if [ -n "${EXISTS_CMD:-}" ]; then
    $EXISTS_CMD "$crate" "$version"
    return
  fi
  code="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --user-agent "unpatched-release (https://github.com/Amet13/unpatched)" \
    "https://crates.io/api/v1/crates/$crate/$version")"
  [ "$code" = "200" ]
}

# Publishable workspace crates, each after the crates it depends on.
order() {
  local meta
  meta="$(cargo metadata --no-deps --format-version 1)"
  {
    jq -r '.packages[] | select(.publish == null) | "\(.name) \(.name)"' <<< "$meta"
    jq -r '
      [.packages[] | select(.publish == null) | .name] as $own
      | .packages[] | select(.publish == null) | .name as $n
      | .dependencies[] | select(.kind != "dev" and (.name as $d | $own | index($d)))
      | "\(.name) \($n)"' <<< "$meta"
  } | tsort
}

publish_one() {
  local crate="$1" version="$2" out status
  while true; do
    out="$(mktemp)"
    set +e
    # shellcheck disable=SC2086
    $publish_cmd "$crate" 2>&1 | tee "$out"
    status="${PIPESTATUS[0]}"
    set -e
    if [ "$status" -eq 0 ]; then
      rm -f "$out"
      return 0
    fi
    if exists "$crate" "$version"; then
      echo "$crate $version is on crates.io now."
      rm -f "$out"
      return 0
    fi
    if grep -qE '429|Too Many Requests' "$out"; then
      rm -f "$out"
      if [ "$(($(date +%s) - start))" -ge "$deadline_seconds" ]; then
        echo "::error::crates.io still limits new crates after $deadline_seconds seconds. Run the workflow again later; published crates are skipped."
        return 1
      fi
      echo "::notice::crates.io rate limit for $crate. Waiting $wait_seconds seconds."
      $sleep_cmd "$wait_seconds"
      continue
    fi
    rm -f "$out"
    echo "::error::Publishing $crate failed. Fix the cause above and run the workflow again."
    return 1
  done
}

version="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "unpatched-core") | .version')"
for crate in $(order); do
  if exists "$crate" "$version"; then
    echo "$crate $version is already on crates.io: skipped."
    continue
  fi
  echo "Publishing $crate $version"
  publish_one "$crate" "$version"
done
