---
name: explain-a-finding
description: Explain why unpatched reports a finding or a verdict (affected, fixed, not-affected, unknown): the evidence per source, the rule ids, and what to do. Also answers "am I affected by CVE-X?" for one product and version. Use when the user asks why something is flagged, what a rule id means, or whether a specific CVE hits what they run.
---

# Explain a finding

## "Am I affected by CVE-X?"

1. You need the product and the exact version. Ask the user for the version.
   Do not guess it. Find the product id with `unpatched search "<name>"`.
2. If the `unpatched` MCP server is available, call `is_affected` with
   `product`, `version`, `cve` and `exposure`. Otherwise put the item in a
   scratch `unpatched.yml` and run `unpatched check --offline --format json`
   (`--offline` needs a database that is already downloaded: run
   `unpatched db update` first), then look for the CVE in `findings`.
   `findings` only holds `affected` and `unknown` results. A CVE that is not
   there is not affected, or is not in the data: run `unpatched explain <CVE>`
   to see which, and never report "not affected" from an empty list alone.
3. Answer with the verdict, then the evidence:
   - `affected`: say the fixed version (`fixed_in`) and the bucket.
   - `not-affected`: only because every source with data says the version is
     outside the affected range. Quote that evidence.
   - `unknown`: say why (no version data, version cannot be read, CVE not in
     the database). Do not turn `unknown` into "not affected".

## "Why is this flagged?"

1. Run `unpatched explain <CVE>` (or the MCP tool `explain`) for the
   vulnerability: summary, CVSS, the affected range each source gives, and
   the exploitation signals.
2. Read the finding's JSON:
   - `verdict`: `affected`, `fixed`, `not-affected` or `unknown`.
   - `bucket`: `now`, `week`, `eol`, `unknown` or `fyi`.
   - `rules`: why it is in that bucket, most important first.
   - `evidence[]`: one entry per source with its own verdict and detail.
     Sources are combined, not ranked: one source saying affected is enough.
   - `signals`: `kev` (CISA Known Exploited, with date and ransomware flag),
     `epss` (chance of exploitation in the next 30 days), `exploits`
     (public exploit code), `ssvc_exploitation`.
   - `fixed_in`, `fixed_after`, `fix_other_train` and `latest_in_cycle`: where to upgrade.
3. Explain each rule id with `unpatched explain UNP-KEV` (and so on). The ids:
   `UNP-KEV`, `UNP-SSVC-ACTIVE`, `UNP-EXPLOIT-EXPOSED`, `UNP-EPSS`, `UNP-CVSS`,
   `UNP-EXPOSED`, `UNP-AFFECTED`, `UNP-EOL`, `UNP-UNKNOWN-NO-RANGES`,
   `UNP-UNKNOWN-VERSION`, `UNP-UNKNOWN-DATA`, `UNP-CONFLICT`, `UNP-UNVERIFIED-PRODUCT`,
   `UNP-IGNORED`, `UNP-IGNORE-EXPIRED`, `UNP-STALE-DATA`.
4. If sources disagree (`UNP-CONFLICT`), say which source says what. The tool
   reports the item when in doubt.

## Rules

- Say what the data says, not what you think. No model decides a verdict.
- If the user disagrees with a verdict and has evidence (a vendor advisory),
  tell them to file a "wrong verdict" issue at
  `https://github.com/Amet13/unpatched/issues` with product, version, CVE and
  the expected verdict. To accept a risk for now, add an `ignore` entry with a
  `reason` and an `until` date to `unpatched.yml`.
- Check the database age first (`unpatched db info`): old data can miss new CVEs.
