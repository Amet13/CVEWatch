# 7. State in GitHub Issues, no commits from the Action

Date: 2026-11-23. Status: accepted.

## Context

The tool must not repeat itself: a finding is reported once, and closed when it
is fixed. The first plan kept a `state.json` that the Action committed, and
counted the commit as activity so that GitHub would not pause the schedule.
That needs `contents: write`, fails on protected branches, and fills the
history with bot commits.

GitHub disables scheduled workflows after 60 days without repository activity
only in public repositories. We tell users to keep the stack in a private
repository, where the rule does not apply.

## Decision

- The Action never commits and needs only `issues: write`.
- Each finding is one issue with a hidden marker
  (`<!-- unpatched:finding=<key> -->`). A pinned "unpatched status" issue is the
  dashboard and holds the delivery state for other channels in a hidden JSON
  block.
- The CLI keeps the same state in `.unpatched/state.json` on the local disk.
  Both stores sit behind one trait.
- If the repository is public, the Action warns in its log.

## Consequences

- Closing an issue means "done". The audit trail comes for free.
- State is as durable as the issues. If someone deletes the status issue, the
  next run rebuilds it and may repeat messages once.
- A public repository can see its schedule paused after 60 idle days. The
  docs say so, and tell users to keep the stack private.
