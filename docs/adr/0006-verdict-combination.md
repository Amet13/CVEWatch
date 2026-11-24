# 6. Combine verdicts across sources, no precedence

Date: 2026-11-23. Status: accepted.

## Context

The first plan ranked sources (vendor, then CVE record, then NVD, then CISA).
Ranking hides mistakes in the higher source: if the vendor record is wrong or
incomplete, a correct NVD range never shows. For a security tool the costly
error is a missed vulnerability.

## Decision

Every source is evaluated on its own, then the verdicts are combined:

- `affected` if any source with a parseable range says the version is inside it.
  An affected verdict is *weak* when it came only from an `all versions`
  constraint (no specific range or exact version matched), and *specific*
  otherwise. A specific affected verdict from any source wins.
- `not-affected` only if at least one source has data and every source with
  data says the version is outside its ranges. This is the evidence rule: no
  data is never "not affected".
- `fixed` if the version was inside a range and is at or above the fix.
- `unknown` with rule `UNP-CONFLICT` when every affected verdict is weak and a
  source with specific ranges or exact versions says the version is outside
  them. A record that says "affected, except these exact versions" must not
  outweigh real ranges that exclude the version.
- Otherwise `unknown`, with the reason (no ranges yet, unparseable version, conflict).

Conflicts between sources are listed by `unpatched explain`. When in doubt,
report.

## Consequences

- More findings when a source is too broad. Users can accept a risk with an
  `ignore` entry that has a reason and an `until` date.
- No source needs to be trusted more than another, and no precedence list has
  to be kept up to date.
- Every finding lists the evidence of each source that contributed.
