#!/usr/bin/env bash
# Keeps one open issue per title: creates or updates it with the body file, or closes it
# when the body file is empty (the problem is gone).
#
#   .github/scripts/issue.sh <title> <body file> [label]
#
# Needs GH_TOKEN with issues: write and GH_REPO.
set -euo pipefail
title="$1"
body_file="$2"
label="${3:-maintenance}"
# With Issues turned off in the repository settings there is nowhere to file it: say it
# in the run (a warning and the job summary) instead of failing the job.
if [ "$(gh api "repos/$GH_REPO" --jq .has_issues)" != "true" ]; then
  if [ -s "$body_file" ]; then
    echo "::warning title=Issues are off::$title (not filed: Issues are turned off for this repository)"
    { echo "### $title"; echo; cat "$body_file"; echo; } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
  fi
  echo "Issues are turned off for $GH_REPO; nothing filed."
  exit 0
fi
gh label create "$label" --color c5def5 --description "Opened by the repository's own automation" 2>/dev/null || true
# Titles come from the workflows themselves (no quotes in them).
number="$(TITLE="$title" gh issue list --state open --label "$label" --limit 200 --json number,title \
  --jq '[.[] | select(.title == env.TITLE)][0].number // empty')"
if [ -s "$body_file" ]; then
  if [ -n "$number" ]; then
    gh issue edit "$number" --body-file "$body_file"
    echo "Updated issue #$number."
  else
    gh issue create --title "$title" --body-file "$body_file" --label "$label"
  fi
elif [ -n "$number" ]; then
  gh issue close "$number" --comment "Resolved: the latest run found nothing to report."
  echo "Closed issue #$number."
else
  echo "Nothing to report."
fi
