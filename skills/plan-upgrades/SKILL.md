---
name: plan-upgrades
description: Turn the open findings from unpatched into an ordered patch plan with target versions, using buckets, fixed_in, latest_in_cycle and end of life. Use when the user asks what to upgrade first, wants a maintenance plan, or has an unpatched report with several findings.
---

# Plan upgrades

## Get the report

Run `unpatched check --format json` (add `--offline` if the user has no
network or only uses catalog products). If the user pasted a report, use that.
Check `db.built_at`: if the data is older than 3 days, say so and suggest
`unpatched db update`.

Read `findings` (open) and `items`. Ignore `ignored` unless the user asks.
`findings` holds only what needs a look: each has a `verdict` of `affected` or
`unknown`, never `not-affected` (those are only counted in `summary`). Each
finding has: `item`, `product`, `version`, `exposure`, `vuln`, `title`,
`verdict`, `bucket`, `rules`, `fixed_in`, `latest_in_cycle`, `signals`,
`evidence`. Each entry of `items` is one stack item with `counts` per bucket,
`upgrade_to`, `fixes` (how many affected findings that upgrade clears), `of`
(how many are affected), `unfixed` and `eol`.

## Order

1. Bucket `now`: fix today. Known exploited, or exposed with a public exploit.
2. Bucket `week`: this week.
3. Bucket `eol`: the release cycle no longer gets fixes. It needs a move to a
   newer cycle, which is a bigger job: plan it, do not just patch.
4. Bucket `unknown`: the data cannot say yet. Do not call these safe. Say what
   is missing (`rules` has `UNP-UNKNOWN-NO-RANGES`, `UNP-UNKNOWN-VERSION` or
   `UNP-UNVERIFIED-PRODUCT`) and what the user can check.
5. Bucket `fyi`: affected, low urgency. Batch it into the next planned upgrade.

Inside a bucket, put internet-facing items (`exposure: internet`) first.

## One step per item, not per finding

Several findings often hit the same item. Use `items`, one entry per stack
item: the target version is `items[].upgrade_to`. Do not work it out again from
`fixed_in`: unpatched already chose the smallest version that fixes the most
findings in the item's release cycle. `fixes` of `of` says how much it clears;
`of - fixes` findings stay open (see `unfixed` for the ones with no known fix).
If a finding has `latest_in_cycle`, it is the newest release in the same cycle:
mention it as an option, since it also holds later fixes. If an item has `eol`
set (or an `eol` finding), the target is a supported release cycle. Take it from
the vendor's support page; do not invent one.

Never invent a version. If `upgrade_to` is empty and `fixed_in` is empty, say
that no fix is known. Name a
mitigation only if the finding's `evidence` or `references` name one.

## Write the plan

For each item, in order: item name, current version, target version, the
bucket and the reason in one line (for example "in CISA KEV, internet-facing"),
the CVEs it clears, and a note when the upgrade skips a release cycle (read the
vendor upgrade path first) or needs downtime. End with the items that stay open
and why. After the user upgrades, they update `version:` in `unpatched.yml` and
run `unpatched check` again to confirm.
