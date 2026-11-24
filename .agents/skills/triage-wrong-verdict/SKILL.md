---
name: triage-wrong-verdict
description: Turn a "wrong verdict" issue (unpatched says affected, not-affected or unknown and the reporter disagrees) into a failing corpus case, then fix the cause. Use when an issue has the wrong-verdict label or when someone reports a verdict that looks wrong.
---

# Triage a wrong verdict

The corpus is the spec. A verdict is never fixed without a failing case first,
and a case is never loosened to make a fix pass. Read `AGENTS.md`,
`docs/adr/0006-verdict-combination.md` and `CONTEXT.md` first.

## Steps

1. **Read the issue.** You need: product (or purl), version, CVE, the verdict
   the reporter expects, the verdict they got, and their evidence (vendor
   advisory link). If one is missing, ask on the issue and stop.
2. **Reproduce.** Put the item in a scratch `unpatched.yml` and run
   `unpatched check --offline --format json` against the current database
   (`unpatched db update` first), or use the smoke database
   (`--db fixtures/smoke/unpatched-db.sqlite`). Run `unpatched explain <CVE>`.
   Note the verdict, the rules and each source's evidence.
3. **Decide who is wrong.** Read the vendor advisory yourself.
   - The reporter is right: continue.
   - The data is right and the reporter is mistaken: reply with the evidence
     (the source ranges, the version scheme) and close. Do not change code.
   - The vendor and the sources disagree: the verdict stays as combined
     (`affected` if any source says so), and the explanation says why. Offer an
     `ignore` entry with a reason and an `until` date.
   - You cannot tell: the right verdict is `unknown`. Never move to
     `not-affected` without evidence from at least one source.
4. **Write the failing case.** Copy the shape of an existing case in
   `corpus/`. Use the real source records for this CVE (record them into the
   case's data from CVE.org, NVD or OSV; never type them from memory) and the
   reporter's stack item. Expected output is what the correct verdict is, with
   bucket and rules. Run `cargo xtask check` (or the corpus test) and confirm
   the new case fails for the reason in the issue.
5. **Find the cause.** Usual places:
   - the catalog entry has a wrong or missing key (`catalog/<id>.yml`): the
     source records are not matched to the product;
   - a source parser reads a range wrong (`crates/unpatched-sources`);
   - the version scheme compares wrongly (`crates/unpatched-core/src/version`);
   - the matcher or the rules (`crates/unpatched-core/src/matching.rs`, `rules.rs`).
6. **Fix the smallest thing.** Add a unit test at the level of the cause (a
   parser test, a version-compare test) as well as the corpus case.
7. **Run `cargo xtask check`.** All of it must pass, including old cases. If an
   old case now fails, the fix is wrong or that case encoded the bug: explain
   which, in the pull request, with evidence.
8. **Changelog and pull request.** One line under `## [Unreleased]`. In the
   pull request link the issue, show the verdict before and after, and the
   evidence.
