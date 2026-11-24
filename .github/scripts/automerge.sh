#!/usr/bin/env bash
# Merges the open same-repository pull request for <branch> labelled `automerge` when its
# head is <sha>, every check run on <sha> passed and the branch is not behind main, then
# starts on main what the merge would have started (a merge made with GITHUB_TOKEN starts
# no workflows by itself): ci and codeql always, pages when a
# changed file matches their push path filters.
#
# A branch behind main was tested without main's newest commits, so it is not merged:
# main is merged into it and ci starts again on it (that run merges it when it passes).
#
# Only pull requests opened by the repository owner, the repository's own workflows
# (GitHub Actions) or Dependabot are merged; anyone else's is left for a person, even
# with the label (adding a label needs triage access, so this matters only for people
# given access to the repository).
#
#   .github/scripts/automerge.sh <branch> <sha> [check suite to ignore]
#
# The third argument is the calling run's own check suite: its jobs are still running
# while it asks, and the caller has already checked them. AUTOMERGE_WAIT (seconds,
# default 0) waits that long for checks still running (codeql started next to ci).
# Needs GH_TOKEN (contents: write, pull-requests: write, actions: write, checks: read,
# issues: write) and GH_REPO; reads the workflows' path filters from .github/workflows.
set -euo pipefail
branch="$1"
sha="$2"
ignore_suite="${3:-0}"
wait="${AUTOMERGE_WAIT:-0}"
here="$(cd "$(dirname "$0")" && pwd)"
workflows="${WORKFLOWS_DIR:-$here/../workflows}"

owner="${GH_REPO%%/*}"
# gh names apps "app/<slug>"; the REST form "<slug>[bot]" is accepted too.
pr="$(SHA="$sha" OWNER="$owner" gh pr list --head "$branch" --state open \
  --json number,headRefOid,labels,isCrossRepository,author \
  --jq '[.[] | select(.isCrossRepository == false and .headRefOid == env.SHA
      and any(.labels[]; .name == "automerge")
      and (.author.login | IN(env.OWNER, "app/github-actions", "github-actions[bot]",
        "app/dependabot", "dependabot[bot]")))][0].number // empty')"
if [ -z "$pr" ]; then
  echo "No open same-repository PR labelled automerge at $sha opened by $owner, GitHub Actions or Dependabot."
  exit 0
fi

waited=0
while :; do
  # "failed <name>" or "pending <name>" for every check run that has not passed.
  checks="$(gh api "repos/$GH_REPO/commits/$sha/check-runs?per_page=100" --paginate \
    --jq ".check_runs[] | select(.check_suite.id != $ignore_suite) |
      if .status != \"completed\" then \"pending \" + .name
      elif (.conclusion as \$c | [\"success\",\"skipped\",\"neutral\"] | index(\$c)) then empty
      else \"failed \" + .name end")"
  if grep -q '^failed ' <<< "$checks"; then
    echo "Not merging #$pr; failed:"
    sed -n 's/^failed //p' <<< "$checks"
    exit 0
  fi
  [ -n "$checks" ] || break
  if [ "$waited" -ge "$wait" ]; then
    echo "Not merging #$pr yet; waiting for:"
    sed -n 's/^pending //p' <<< "$checks"
    exit 0
  fi
  sleep 30
  waited=$((waited + 30))
done

behind_title="Automation pull request #$pr is behind main"
behind="$(gh api "repos/$GH_REPO/compare/main...$sha" --jq .behind_by)"
if [ "$behind" -gt 0 ]; then
  if gh api -X PUT "repos/$GH_REPO/pulls/$pr/update-branch" -f expected_head_sha="$sha" > /dev/null; then
    gh workflow run ci.yml --ref "$branch"
    echo "#$pr is $behind commit(s) behind main: merged main into $branch and started ci on it; that run merges it."
    exit 0
  fi
  # GITHUB_TOKEN cannot write a merge that changes workflow files, for one.
  body="$(mktemp)"
  {
    echo "Pull request #$pr passed CI but is $behind commit(s) behind main, and the automation"
    echo "could not merge main into \`$branch\`. Press \"Update branch\" on the pull request (CI"
    echo "then runs again and the pull request merges itself), or close it."
    echo
    echo "This issue closes itself when the pull request is merged."
  } > "$body"
  bash "$here/issue.sh" "$behind_title" "$body"
  exit 0
fi

# Does a push of these files start <workflow>? Yes when it has no push path filter (or one
# this cannot read), or when a file matches one of its paths. "**" is read as "*", which
# can only start a workflow more often than GitHub would, never less.
paths_of() {
  [ -f "$1" ] || return 0
  awk '
    /^"?on"?:/ { on = 1; next }
    on && /^[^ #]/ { on = 0 }
    on && /^  push:/ { push = 1; next }
    push && /^  [^ #]/ { push = 0 }
    push && /^    paths:/ { paths = 1; next }
    paths && /^      - / { sub(/^      - /, ""); sub(/[ ]+#.*$/, ""); print; next }
    paths && /^    [^ #]/ { paths = 0 }
  ' "$1" | tr -d "\"'"
}
starts() {
  local patterns pattern file
  patterns="$(paths_of "$workflows/$1")"
  [ -n "$patterns" ] && [ -n "$files" ] || return 0
  while IFS= read -r file; do
    while IFS= read -r pattern; do
      case "$pattern" in "!"*) return 0 ;; esac
      # shellcheck disable=SC2254 # the pattern is a glob on purpose
      case "$file" in ${pattern//\*\*/*}) return 0 ;; esac
    done <<< "$patterns"
  done <<< "$files"
  return 1
}

# The files the squash commit will change; when they cannot be read, everything starts.
files="$(gh api "repos/$GH_REPO/pulls/$pr/files?per_page=100" --paginate --jq '.[].filename')" || files=""

gh pr merge "$pr" --squash --delete-branch
empty="$(mktemp)"
: > "$empty"
bash "$here/issue.sh" "$behind_title" "$empty" > /dev/null || true
started=()
for w in ci.yml codeql.yml pages.yml; do
  if starts "$w"; then
    gh workflow run "$w" --ref main
    started+=("${w%.yml}")
  fi
done
# A merged release pull request (it changes the version): publish it now, not at the
# next daily run. The publish step waits for ci on main before it tags anything.
if [ "${branch:-}" = "automation/release" ]; then
  gh workflow run autorelease.yml --ref main -f release=publish
  started+=("autorelease")
fi
echo "Merged #$pr and started ${started[*]} on main."
