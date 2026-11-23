#!/usr/bin/env bash
# The watchdog's logic, shared by watchdog.yml (after each run GitHub reports, and on a
# schedule for the runs it does not report) and ci.yml (its `automation` job).
#
#   watchdog.sh missed <run id> [attempt]       how many failed or cancelled jobs of that
#                                               attempt never got a runner (prints a number)
#   watchdog.sh rerun <run id>                  re-runs the failed jobs once when one of
#                                               them never got a runner
#   watchdog.sh report <workflow id> <name> <branch>
#                                               opens, updates or closes the issue for that
#                                               workflow on that branch, from its newest run
#   watchdog.sh sweep [minutes]                 rerun and report for every run that finished
#                                               in the last <minutes> (default 90), and
#                                               restarts runs stuck in the queue
#
# GitHub starts no workflow_run for a run started with GITHUB_TOKEN (what the automation
# dispatches after its merges, and every release autorelease starts), so only the sweep
# sees those. Everything here is safe to repeat: the issue follows the newest run of a
# workflow on a branch, a run is re-run only while it is on its first attempt, and a stuck
# workflow is started again only once per open issue.
#
# Needs GH_TOKEN (actions: write, checks: read, issues: write) and GH_REPO. NOW (epoch
# seconds) can be set for tests.
# JSON lists and jq programs are meant literally.
# shellcheck disable=SC2016,SC2089,SC2090
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
NOW="${NOW:-$(date +%s)}"
export NOW

# The workflows watched (watchdog.yml lists the same under workflow_run).
WATCHED='["ci","codeql","build-db","pages","release","maintenance","autorelease","automerge","OpenSSF Scorecard"]'
# Workflows whose failed jobs are re-run once when a job never got a runner.
RERUN='["ci","build-db","release"]'
# Workflows started again after a run stuck in the queue: their dispatch needs no inputs.
REDISPATCH='["ci","codeql","build-db","pages"]'
export WATCHED RERUN REDISPATCH

missed() {
  local run="$1" attempt="${2:-1}"
  gh api "repos/$GH_REPO/actions/runs/$run/attempts/$attempt/jobs?per_page=100" --paginate \
    --jq '.jobs[] | select(.conclusion == "failure" or .conclusion == "cancelled") | .check_run_url' |
    while read -r url; do
      gh api "${url#https://api.github.com/}/annotations" --jq '.[].message'
    done | grep -cE 'not acquired by Runner|lost communication with the server' || true
}

rerun() {
  local run="$1"
  if [ "$(missed "$run" 1)" -eq 0 ]; then
    echo "Run $run: every failed job ran, nothing to re-run."
    return 0
  fi
  if gh run rerun "$run" --failed; then
    echo "Run $run: a job never got a runner; re-running the failed jobs once."
  else
    echo "::warning::Run $run: a job never got a runner, and the re-run could not start."
  fi
}

# The issue title for a workflow on a branch; empty for branches that are not watched.
title_for() {
  local name="$1" branch="$2"
  case "$branch" in
    main) echo "Automation failed: $name" ;;
    automation/*) echo "Automation failed: $name on $branch" ;;
    v[0-9]*) echo "Automation failed: $name on a release tag" ;;
  esac
}

# The newest run of a workflow on a branch (all release tags count as one branch), not
# counting pull requests: id, status, conclusion, URL and event, tab-separated.
newest() {
  local wf="$1" branch="$2" query="per_page=50"
  case "$branch" in v[0-9]*) ;; *) query="branch=$branch&per_page=50" ;; esac
  BRANCH="$branch" gh api "repos/$GH_REPO/actions/workflows/$wf/runs?$query" --jq '
    [.workflow_runs[]
      | select(.event != "pull_request" and .event != "pull_request_target")
      | select(.head_repository.full_name == env.GH_REPO)
      | select(if (env.BRANCH | test("^v[0-9]")) then (.head_branch | test("^v[0-9]"))
               else .head_branch == env.BRANCH end)]
    | sort_by(.created_at) | last // empty
    | [.id, .status, (.conclusion // "none"), .html_url, .event] | @tsv'
}

report() {
  local wf="$1" name="$2" branch="$3" title line id status conclusion url event body
  title="$(title_for "$name" "$branch")"
  if [ -z "$title" ]; then echo "$name on $branch: not watched."; return 0; fi
  line="$(newest "$wf" "$branch")"
  if [ -z "$line" ]; then echo "$name on $branch: no run."; return 0; fi
  IFS=$'\t' read -r id status conclusion url event <<< "$line"
  if [ "$status" != completed ]; then
    echo "$name on $branch: the newest run ($url) is $status; its result decides."
    return 0
  fi
  body="$(mktemp)"
  case "$conclusion" in
    failure | timed_out | startup_failure)
      {
        echo "The **$name** workflow failed ($event on \`$branch\`)."
        echo
        echo "Run: $url"
        echo
        echo "This issue closes itself when $name next succeeds there."
      } > "$body" ;;
    success) : > "$body" ;;
    *)
      echo "$name on $branch: the newest run (run $id) ended $conclusion; nothing to do."
      return 0 ;;
  esac
  bash "$here/issue.sh" "$title" "$body"
}

# A run that waited in the queue for 20 minutes without a single job never started (a
# lost GitHub event): cancel it, start the workflow again once, and say so in the issue.
unstick() {
  local id="$1" name="$2" branch="$3" path="$4" url="$5" title body jobs again=""
  jobs="$(gh api "repos/$GH_REPO/actions/runs/$id/jobs" --jq .total_count)"
  [ "$jobs" = 0 ] || return 0
  title="$(title_for "$name" "$branch")"
  [ -n "$title" ] || return 0
  if ! gh run cancel "$id" > /dev/null 2>&1; then
    gh api -X POST "repos/$GH_REPO/actions/runs/$id/force-cancel" > /dev/null 2>&1 ||
      echo "::warning::Run $id could not be cancelled."
  fi
  # Started again only once: not when the open issue already reports a stuck run.
  if NAME="$name" jq -e 'index(env.NAME)' <<< "$REDISPATCH" > /dev/null &&
    ! TITLE="$title" gh issue list --state open --label maintenance --limit 200 --json title,body \
      --jq '.[] | select(.title == env.TITLE) | .body' | grep -q 'stuck in the queue'; then
    gh workflow run "${path##*/}" --ref "$branch" && again=1
  fi
  body="$(mktemp)"
  {
    echo "A **$name** run on \`$branch\` was stuck in the queue for more than 20 minutes"
    echo "without a single job (GitHub never started it), so it was cancelled."
    echo
    echo "Run: $url"
    echo
    if [ -n "$again" ]; then
      echo "$name was started again on \`$branch\`."
    else
      echo "Start it again by hand: Actions → $name → Run workflow (on \`$branch\`)."
    fi
    echo
    echo "This issue closes itself when $name next succeeds there."
  } > "$body"
  bash "$here/issue.sh" "$title" "$body"
  echo "Run $id ($name on $branch) was stuck in the queue: cancelled${again:+ and started again}."
}

sweep() {
  local minutes="${1:-90}" runs keys stuck
  # One page holds the newest 100 runs, about a day of this repository's activity.
  runs="$(MINUTES="$minutes" gh api "repos/$GH_REPO/actions/runs?per_page=100" --jq '
    .workflow_runs[]
    | select(.status == "completed")
    | select(.name as $n | env.WATCHED | fromjson | index($n))
    | select(.event != "pull_request" and .event != "pull_request_target")
    | select(.head_repository.full_name == env.GH_REPO)
    | select(.head_branch == "main" or (.head_branch | startswith("automation/"))
             or (.head_branch | test("^v[0-9]")))
    | select((.updated_at | fromdateiso8601) >= ((env.NOW | tonumber) - (env.MINUTES | tonumber) * 60))
    | [.id, .workflow_id, .name, .head_branch, .conclusion, .run_attempt] | @tsv')"

  local id wf name branch conclusion attempt
  while IFS=$'\t' read -r id wf name branch conclusion attempt; do
    [ -n "$id" ] || continue
    [ "$conclusion" = failure ] && [ "$attempt" = 1 ] || continue
    NAME="$name" jq -e 'index(env.NAME)' <<< "$RERUN" > /dev/null || continue
    # ci on an automation branch starts itself again (ci.yml, `automation` job).
    if [ "$name" = ci ] && [[ "$branch" == automation/* ]]; then continue; fi
    rerun "$id" < /dev/null
  done <<< "$runs"

  # One report per workflow and branch (all release tags count as one), from its newest run.
  keys="$(awk -F '\t' 'NF {
    g = ($4 ~ /^v[0-9]/) ? "tags" : $4; k = $2 FS g
    if (!(k in seen)) { seen[k] = 1; print $2 "\t" $3 "\t" $4 }
  }' <<< "$runs")"
  while IFS=$'\t' read -r wf name branch; do
    [ -n "$wf" ] || continue
    report "$wf" "$name" "$branch" < /dev/null
  done <<< "$keys"

  stuck="$(gh api "repos/$GH_REPO/actions/runs?status=queued&per_page=100" --jq '
    .workflow_runs[]
    | select(.name as $n | env.WATCHED | fromjson | index($n))
    | select(.event != "pull_request" and .event != "pull_request_target")
    | select(.head_repository.full_name == env.GH_REPO)
    | select((.created_at | fromdateiso8601) < ((env.NOW | tonumber) - 20 * 60))
    | [.id, .name, .head_branch, .path, .html_url] | @tsv')"
  local path url
  while IFS=$'\t' read -r id name branch path url; do
    [ -n "$id" ] || continue
    unstick "$id" "$name" "$branch" "$path" "$url" < /dev/null
  done <<< "$stuck"
}

cmd="${1:-}"
shift || true
case "$cmd" in
  missed) missed "$@" ;;
  rerun) rerun "$@" ;;
  report) report "$@" ;;
  sweep) sweep "$@" ;;
  *) echo "usage: watchdog.sh missed|rerun|report|sweep ..." >&2; exit 2 ;;
esac
