#!/usr/bin/env bash
# Commits the working-tree changes to an automation branch and opens (or updates) a pull
# request labelled `automerge`. CI and CodeQL are started explicitly, because pull requests
# and pushes made with GITHUB_TOKEN start no workflows; the ci run merges the PR when every
# check passed (ci.yml, `automation` job).
#
#   .github/scripts/automation-pr.sh <branch> <title> <body file>
#
# Needs GH_TOKEN (contents: write, pull-requests: write, actions: write) and a checkout.
set -euo pipefail
branch="automation/$1"
title="$2"
body_file="$3"

if git diff --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
  echo "No changes; no pull request."
  exit 0
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git checkout -B "$branch"
git add -A
git commit -q -m "$title" -m "Opened by the $GITHUB_WORKFLOW workflow (run $GITHUB_RUN_ID)."
git push -q --force "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" "HEAD:refs/heads/$branch"

gh label create automerge --color 0e8a16 --description "Merged automatically when CI passes" 2>/dev/null || true
# `--head` matches any repository's branch of that name: a fork PR from `automation/...`
# would be retitled and labelled instead of ours. Only a PR from this repository counts.
number="$(gh pr list --head "$branch" --state open --json number,isCrossRepository |
  jq -r 'map(select(.isCrossRepository == false)) | .[0].number // empty')"
if [ -n "$number" ]; then
  gh pr edit "$number" --title "$title" --body-file "$body_file" --add-label automerge
else
  gh pr create --base main --head "$branch" --title "$title" --body-file "$body_file" --label automerge
fi
gh workflow run codeql.yml --ref "$branch"
gh workflow run ci.yml --ref "$branch"
echo "Pull request for $branch is open; CI and CodeQL started."
