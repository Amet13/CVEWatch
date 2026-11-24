# Findings and rules

<!-- description: What a finding is, the four verdicts, the five buckets, how to read a GitHub issue and the JSON report, and every rule id. -->

A **finding** is one thing you run and one vulnerability that matters for it. It
has a **verdict** (is your version affected?), a **bucket** (how soon to act)
and **rules** (why it is in that bucket). The end of life of a release and a few
problems with the data are findings too.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `affected` | Your version is inside an affected range that at least one source gives. |
| `fixed` | It was affected and your version is now at or past the fix. Used to close issues. |
| `not-affected` | At least one source has data and every source with data says your version is outside its ranges. Not reported. |
| `unknown` | The data cannot say: no source has version data yet (new CVEs often wait for NVD analysis), your version cannot be read in the product's scheme, or the product is not found in the data. |

Every source is judged on its own, then the verdicts are combined. One source
saying `affected` is enough. `not-affected` needs evidence: having no data is
never "not affected". When sources disagree the finding is reported and the rule
`UNP-CONFLICT` is added, so you can read the evidence and decide. The reasoning is
in the decision record ADR-0006.

An `unknown` is not shown for every vulnerability that lacks data: that would
bury the report. It is shown only when the signals would have made it "fix today"
or "this week" if it were confirmed (for example a CVE in KEV for your product
with no version range yet). The reason is given in the finding.

## Buckets

The bucket is decided by evidence of exploitation first, not by severity.

| Bucket | Label | When (for an `affected` finding) |
| --- | --- | --- |
| `now` | Fix today | In CISA KEV, or CISA SSVC says exploitation is active, or a public exploit exists (Exploit-DB or Metasploit) and the item is `exposure: internet`. |
| `week` | Fix this week | EPSS at or above `epss_week` (default 0.05), or CVSS at or above `cvss_week` (default 9.0), or the item is `exposure: internet`. |
| `fyi` | FYI | Any other affected finding. No issue is opened for it; it is listed in the status issue and the digest. |
| `eol` | End of life | The release cycle of the item is past its end of life (endoflife.date). One finding per item, not one per CVE. |
| `unknown` | Unknown | An `unknown` verdict that would have been `now` or `week` if confirmed, or a data problem (product not found, stale database). |

The first matching bucket wins, from the top. A `now` finding lists the `week`
rules too, so you see every reason. Thresholds can be changed in
[the config](config.md#thresholds); the other conditions cannot. The reasoning
(why not CVSS) is in ADR-0008.

For an affected finding, `fixed_in` is the lowest version that fixes it, taken
from the upper bound of the affected range. `latest_in_cycle` is the newest
release in your release cycle from endoflife.date, shown when it is newer.

## Read a GitHub issue

The title is the bucket, the product and version, the CVE, and `(exploited)` or
`(public exploit)` when that is the reason. Labels: `unpatched` and one of
`unpatched:now`, `unpatched:week`, `unpatched:eol`, `unpatched:unknown`. This is the body
the renderer writes for a "fix today" finding (the renderer's own test fixture,
so the CVE text and numbers differ from the sample database):

<!-- generated:start example-issue -->

```markdown
**Office firewall** runs `FortiOS 7.2.5`, which is affected by CVE-2024-21762.

**CVE-2024-21762**: Out-of-bounds write in sslvpnd allows remote code execution

**Why now:** In CISA KEV since 2024-02-09 · ransomware use: known · CISA due date 2024-02-16 · SSVC: exploitation is active · SSVC: automatable · EPSS 94.1% (percentile 100) · public exploit: fortios_sslvpnd · CVSS 9.8 · internet-facing

**Do:** Upgrade to 7.2.7 or later (7.2.11 is current in this branch).

**Evidence**

- CVE.org: affected 7.2.0 to 7.2.6 (CNA Fortinet) (affected)
- NVD: cpe:2.3:o:fortinet:fortios up to (excluding) 7.2.7 (affected)

**Rules**

- `UNP-KEV` Known to be exploited. CISA lists this vulnerability in its Known Exploited Vulnerabilities catalog, so attackers are using it now. Fix it today.
- `UNP-EXPOSED` Affected and reachable from the internet
- Verdict: affected · bucket: Fix today

**References**

- https://fortiguard.fortinet.com/psirt/FG-IR-24-015

---

Close this issue when it is fixed; unpatched closes it on its own once unpatched.yml shows a fixed version.

<!-- unpatched:finding=office-firewall/CVE-2024-21762 -->
```

<!-- generated:end -->

- The first line says which of your items is affected and by what.
- **Why now** is the list of signals: KEV (with the date and whether ransomware
  groups use it), the CISA due date, SSVC, EPSS, public exploits, CVSS,
  internet exposure.
- **Do** says what to do: upgrade to the fixed version, or to a supported release.
- **Evidence** is one line per source, with its own verdict.
- **Rules** are the ids that put the finding in its bucket.
- The hidden comment at the end (`<!-- unpatched:finding=... -->`) is how
  unpatched finds the issue again. Do not remove it.

When a finding disappears (you upgraded, the advisory was withdrawn, or an ignore
entry covers it), unpatched comments on the issue and closes it. If a finding
comes back, an issue that unpatched closed is reopened. An issue that *you* closed
is left closed, and is listed under "Closed but still affected" in the status
issue.

## The status issue

One issue called **unpatched status** (label `unpatched:status`, pinned when
GitHub allows it) is rewritten on every run. It has the count per bucket, the
open findings with links to their issues, FYI findings, issues you closed that
are still affected, notes, the date of the database and the time of the last run.
It also holds a hidden block with what was already sent to chat channels, so
messages are not repeated. Do not delete it: the next run would make a new one
and may repeat messages once. More in [Notifications](notifications.md#how-state-works).

## Read the JSON report

`unpatched check --format json` prints the report. It has a published schema:
`unpatched schema report` (also `schema/report.schema.json`). Scripts and agents
should read this, not the text output. One, with parts cut out for this page and
marked with `...` (the database sources, the long `title` and `evidence`, and the
second finding):

<!-- generated:start example-check-json -->

```json
{
  "format": 1,
  "generated_at": "2026-11-24T00:00:00Z",
  "db": { ... },
  "summary": {
    "now": 1,
    "week": 0,
    "eol": 1,
    "unknown": 0,
    "fyi": 0,
    "ignored": 0,
    "not_affected": 1
  },
  "findings": [
    {
      "key": "office-firewall/CVE-2024-21762",
      "item": "Office firewall",
      "product": "fortios",
      "product_name": "FortiOS",
      "version": "7.2.5",
      "exposure": "internet",
      "vuln": "CVE-2024-21762",
      "title": "...",
      "verdict": "affected",
      "bucket": "now",
      "rules": [
        "UNP-KEV",
        "UNP-SSVC-ACTIVE",
        "UNP-EPSS",
        "UNP-CVSS",
        "UNP-EXPOSED"
      ],
      "fixed_in": "7.2.7",
      "latest_in_cycle": null,
      "cvss": {
        "version": "3.1",
        "score": 9.6,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:W/RC:C"
      },
      "signals": {
        "kev": {
          "date_added": "2024-02-09",
          "due_date": "2024-02-16",
          "known_ransomware": true,
          "required_action": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
          "vendor_project": "Fortinet",
          "product": "FortiOS"
        },
        "epss": {
          "score": 0.84589,
          "percentile": 0.99711,
          "date": "2026-11-23"
        },
        "ssvc_exploitation": "active",
        "ssvc_automatable": true
      },
      "evidence": [ ... ],
      "references": [
        "https://fortiguard.com/psirt/FG-IR-24-015",
        "https://fortiguard.com/psirt/FG-IR-24-015",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-21762"
      ]
    },
    ...
  ],
  "ignored": [],
  "notes": [
    "stack[2]: unknown product \"postgresql\". Run `unpatched catalog list` to see the ids.",
    "stack[3]: unknown product \"home-assistant\". Run `unpatched catalog list` to see the ids."
  ]
}
```

<!-- generated:end -->

`summary` counts the findings per bucket, plus `ignored` and `not_affected`. Each
finding has its `key` (stable across runs), `verdict`, `bucket`, `rules`,
`fixed_in`, `latest_in_cycle`, `cvss`, `signals` (KEV, EPSS, SSVC, exploits),
`evidence` per source and `references`. `notes` lists problems with the run
itself: an unknown product id, a stale database, a version that cannot be
compared.

## Explain a finding

```sh
unpatched explain UNP-KEV                         # what a rule means
unpatched explain CVE-2024-21762                  # the record: ranges per source, signals
unpatched explain office-firewall/CVE-2024-21762  # one finding of your stack, with its evidence
```

The finding key is `<item>/<vulnerability>`, where the item is your `name`
(lowercased, spaces become `-`) or the product id. Examples are on
[Start with the command line](start-cli.md#look-closer).

## Every rule

Rule ids are part of the public interface: they do not change meaning, and
renaming one would be a breaking change.

<!-- generated:start rules -->

| Rule | Title | What it means | Effect |
| --- | --- | --- | --- |
| `UNP-KEV` | Known to be exploited | CISA lists this vulnerability in its Known Exploited Vulnerabilities catalog, so attackers are using it now. Fix it today. | This rule puts an affected finding in: Fix today (now). |
| `UNP-SSVC-ACTIVE` | Exploitation is active | CISA's SSVC assessment says exploitation of this vulnerability is active. Treat it like a known exploited vulnerability and fix it today. | This rule puts an affected finding in: Fix today (now). |
| `UNP-EXPLOIT-EXPOSED` | Public exploit and reachable from the internet | A public exploit exists (Exploit-DB or Metasploit) and this item is marked as internet-facing. Anyone can try it against you, so fix it today. | This rule puts an affected finding in: Fix today (now). |
| `UNP-EPSS` | Likely to be exploited soon | The EPSS score is at or above your threshold (default 0.05), which means exploitation in the next 30 days is more likely than for most vulnerabilities. Fix it this week. | This rule puts an affected finding in: This week (week), unless a Fix today rule applies. |
| `UNP-CVSS` | Critical severity | The CVSS base score is at or above your threshold (default 9.0). Severity alone does not mean it is being exploited, but it is serious enough to fix this week. | This rule puts an affected finding in: This week (week), unless a Fix today rule applies. |
| `UNP-EXPOSED` | Affected and reachable from the internet | This version is affected and the item is marked as internet-facing, so attackers can reach it. Fix it this week. | This rule puts an affected finding in: This week (week), unless a Fix today rule applies. |
| `UNP-AFFECTED` | Affected, no sign of exploitation | This version is affected, but nothing says it is exploited, it is not internet-facing and the scores are below your thresholds. Fix it with your normal updates. | This rule puts an affected finding in: FYI (fyi). |
| `UNP-EOL` | End of life | This release cycle no longer gets security fixes (endoflife.date). New vulnerabilities will not be patched, so plan an upgrade to a supported cycle. | This rule makes the finding: End of life (eol), one per stack item. |
| `UNP-UNKNOWN-NO-RANGES` | No usable version data yet | No source says which versions are affected (new CVEs often wait for NVD analysis). It could matter, so check the advisory yourself. The finding goes away when data arrives. | This rule makes the verdict unknown; shown when the signals would make it Fix today or This week. |
| `UNP-UNKNOWN-VERSION` | Version cannot be compared | Either your configured version or a version in the data does not parse under this product's version scheme. unpatched does not guess, so check the version in unpatched.yml. | This rule makes the verdict unknown; shown when the signals would make it Fix today or This week. |
| `UNP-CONFLICT` | Sources disagree | At least one source says this version is affected and another says it is not. When in doubt unpatched reports it. Read the evidence to see which source to trust. | This rule is added when sources disagree. |
| `UNP-UNVERIFIED-PRODUCT` | Product not found in the data | The catalog's names for this product match no record in the database, so an empty result would not mean you are safe. Check the catalog entry or report it. | This rule makes a finding in: Unknown, so an empty result is never read as safe. |
| `UNP-IGNORED` | Ignored on purpose | An ignore entry in unpatched.yml accepts this risk until its date. The finding is listed separately and comes back when the entry expires. | This rule moves the finding to the ignored list. |
| `UNP-IGNORE-EXPIRED` | Ignore entry has expired | An ignore entry matched this finding but its date has passed, so the finding is back. Fix the issue or write a new entry with a new date. | This rule is added when an ignore entry ran out. |
| `UNP-STALE-DATA` | Data is out of date | The vulnerability database is older than your warning threshold (default 3 days). Results may miss new vulnerabilities, so check that the daily database build is running. | This rule makes a finding in: Unknown about the database itself. |

<!-- generated:end -->
