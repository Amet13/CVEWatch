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
`UNP-CONFLICT` is added, so you can read the evidence and decide.

An `unknown` is not shown for every vulnerability that lacks data: that would
bury the report. It is shown only when the signals would have made it "fix today"
or "this week" if it were confirmed (for example a CVE in KEV for your product
with no version range yet). The reason is given in the finding.

## Buckets

The bucket is decided by evidence of exploitation first, not by severity.

The report says the bucket in words, and the JSON keeps short ids. They mean
the same:

| JSON (`bucket`) | In the text report, issues and chat | Meaning |
| --- | --- | --- |
| `now` | today | Fix today |
| `week` | this week | Fix this week |
| `eol` | end of life | The release is past its end of life |
| `unknown` | unknown | The data cannot say yet |
| `fyi` | FYI | Affected, low urgency |

The first line of a report counts what you can act on, then the FYI findings:
`87 to act on (14 today, 69 this week, 3 end of life, 1 unknown), 228 FYI`.
"To act on" is everything except FYI. The line "990 vulnerabilities checked
against your versions: not affected" counts the vulnerabilities that were
compared with your versions and found not to affect you; it does not count the
findings above.

| Bucket | Label | When (for an `affected` finding) |
| --- | --- | --- |
| `now` | Fix today | In CISA KEV, or CISA SSVC says exploitation is active, or a public exploit exists (Exploit-DB or Metasploit) and the item is `exposure: internet`. |
| `week` | Fix this week | EPSS at or above `epss_week` (default 0.05), or CVSS at or above `cvss_week` (default 9.0), or the item is `exposure: internet` and CVSS is at or above `cvss_week_exposed` (default 7.0). Exposure alone is not enough, and an unknown CVSS score does not count. |
| `fyi` | FYI | Any other affected finding. No issue is opened for it. The text and Markdown reports and the status issue show only a count per item; `-v` and `--format json` list them. |
| `eol` | End of life | The release cycle of the item is past its end of life (endoflife.date). One finding per item, not one per CVE. |
| `unknown` | Unknown | An `unknown` verdict that would have been `now` or `week` if confirmed, or a data problem (product not found, stale database). |

The first matching bucket wins, from the top. A `now` finding lists the `week`
rules too, so you see every reason. Thresholds can be changed in
[the config](config.md#thresholds); the other conditions cannot. The reasoning
(why not CVSS) is in the comments of `crates/unpatched-core/src/matching.rs`.

For an affected finding, `fixed_in` is the lowest version that fixes it, taken
from the upper bound of the affected range. `latest_in_cycle` is the newest
release in your release cycle from endoflife.date, shown when it is newer.
When a source only gives an inclusive upper bound ("up to 9.8"), `fixed_after`
holds that bound and the advice reads "upgrade to a release after 9.8". When
your release branch has no fix in the data but a newer one does,
`fix_other_train` names it and the advice says so.

## Read a GitHub issue

There is one issue per stack item, not one per CVE. The title is the most urgent
bucket's emoji, the product and version, how many findings are in that bucket and
the one upgrade that helps most, like `🔴 FortiOS 7.2.5 (Office firewall): 14 to fix
today — upgrade to 7.2.12`. Labels: `unpatched` and the label of the most urgent
bucket (`unpatched:now`, `unpatched:week`, `unpatched:eol` or `unpatched:unknown`).
This is the body the renderer writes for an item with a "fix today" finding (the
renderer's own test fixture, so the CVE text and numbers differ from the sample
database):

<!-- generated:start example-issue -->

````markdown
🔴 FortiOS 7.2.5 (Office firewall)  1 today  →  upgrade to 7.2.7 (fixes it)

This item is marked as internet-facing.

### 🔴 Fix today (1)

- **CVE-2024-21762** Out-of-bounds write in sslvpnd allows remote code execution — In CISA KEV since 2024-02-09 · ransomware use: known · CISA due date 2024-02-16 · SSVC: exploitation is active · SSVC: automatable · EPSS 94.1% (percentile 100) · public exploit: fortios_sslvpnd · CVSS 9.8 · internet-facing — Upgrade to 7.2.7 or later (7.2.11 is current in this branch).

---

unpatched keeps this issue up to date and closes it once the item has nothing left to fix (when the version in unpatched.yml is fixed).

To accept this risk, add to unpatched.yml:

```yaml
ignore:
  - cve: CVE-…
    reason: …
    until: YYYY-MM-DD
```

<!-- unpatched:item=office-firewall -->
````

<!-- generated:end -->

- The first line is the recommendation for the item: counts per bucket and the
  smallest version that fixes the most findings. It says whether that upgrade
  clears everything (`fixes all 11`) or not (`fixes 61 of 110; 49 have no fix
  on 7.2`). FYI findings are only counted, not listed.
- Then one section per bucket lists its findings: id, a one-sentence title, why
  it is in that bucket, and what to do. A long list stops after about 60 entries
  with "...and N more (run `unpatched check` for all)".
- The hidden comment at the end (`<!-- unpatched:item=... -->`) is how unpatched
  finds the issue again. Do not remove it.

When an item has no `now`, `week`, `eol` or `unknown` finding left (you upgraded,
the advisories were withdrawn, or ignore entries cover them), unpatched comments on
the issue and closes it. If findings come back, an issue that unpatched closed is
reopened. An issue that *you* closed
is left closed, and is listed under "Closed but still affected" in the status
issue.

## The status issue

One issue called **unpatched status** (label `unpatched:status`, pinned when
GitHub allows it) is rewritten on every run. It has the count per bucket
(FYI only as a count), the open findings with links to their issues, issues
you closed that are still affected, notes, the date of the database and the time of the last run.
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
          "score": 0.8458899855613708,
          "percentile": 0.9971100091934204,
          "date": "2026-11-23"
        },
        "ssvc_exploitation": "active",
        "ssvc_automatable": true
      },
      "evidence": [ ... ],
      "references": [
        "https://fortiguard.com/psirt/FG-IR-24-015",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2024-21762"
      ]
    },
    ...
  ],
  "ignored": [],
  "items": [
    ...
    ...
  ],
  "notes": [
    "stack[2]: the database has no data for product \"postgresql\" yet. Run `unpatched db update`; if the id may be wrong, `unpatched catalog list` shows the ids.",
    "stack[3]: the database has no data for product \"home-assistant\" yet. Run `unpatched db update`; if the id may be wrong, `unpatched catalog list` shows the ids."
  ]
}
```

<!-- generated:end -->

`summary` counts the findings per bucket, plus `ignored` and `not_affected`. Each
finding has its `key` (stable across runs), `verdict`, `bucket`, `rules`,
`fixed_in`, `fixed_after`, `fix_other_train`, `latest_in_cycle`, `cvss`, `signals` (KEV, EPSS, SSVC, exploits),
`evidence` per source and `references`. `notes` lists problems with the run
itself: an unknown product id, a stale database, a version that cannot be
compared.

## Accept a risk

Every issue, and `unpatched explain <finding key>`, ends with how to accept the
risk on purpose. Add this to `unpatched.yml`:

```yaml
ignore:
  - cve: CVE-2024-21762
    reason: "The SSL VPN is switched off"
    until: 2027-01-31
```

`until` is required. The report tells you when an entry does nothing:
`ignore[2]: CVE-2099-1 matches no finding. Check the id or remove it.` and
`ignore[1] expired on 2020-01-01; the finding is back.` More in
[the config](config.md#ignore-entries).

## Explain a finding

```sh
unpatched explain UNP-KEV                         # what a rule means
unpatched explain CVE-2024-21762                  # the record: ranges per source, signals
unpatched explain office-firewall/CVE-2024-21762  # one finding of your stack, with its evidence
```

The finding key is `<item>/<vulnerability>`, where the item is your `name`
(lowercased, spaces become `-`) or the product id. `unpatched explain --rules`
lists every rule id. Examples are on
[Start with the command line](start-cli.md#look-closer).

The examples on this page come from a small sample database
(`fixtures/smoke/unpatched-db.sqlite`) and the date 2026-11-24. The issue
example above comes from the renderer's own test fixture, so its CVE text and
numbers differ from the other examples.

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
| `UNP-EXPOSED` | Affected, reachable from the internet and severe | This version is affected, the item is marked as internet-facing and the CVSS base score is at or above your exposed threshold (default 7.0). Attackers can reach it, so fix it this week. | This rule puts an affected, internet-facing finding with CVSS at or above cvss_week_exposed in: This week (week), unless a Fix today rule applies. |
| `UNP-AFFECTED` | Affected, no sign of exploitation | This version is affected, but nothing says it is exploited, it is not both internet-facing and severe, and the scores are below your thresholds. Fix it with your normal updates. | This rule puts an affected finding in: FYI (fyi). |
| `UNP-EOL` | End of life | This release cycle no longer gets security fixes (endoflife.date). New vulnerabilities will not be patched, so plan an upgrade to a supported cycle. | This rule makes the finding: End of life (eol), one per stack item. |
| `UNP-UNKNOWN-NO-RANGES` | No usable version data yet | No source names the affected versions: new CVEs often wait for NVD analysis, and a record that only says "all versions" or gives no version is not a range anyone checked. It could matter, so check the advisory yourself. The finding goes away when data arrives. | This rule makes the verdict unknown; shown when the signals would make it Fix today or This week. |
| `UNP-UNKNOWN-VERSION` | Version cannot be compared | Your configured version does not parse under this product's version scheme. unpatched does not guess, so check the version in unpatched.yml (`unpatched catalog show` says how the product writes versions). | This rule makes the verdict unknown; shown when the signals would make it Fix today or This week. |
| `UNP-UNKNOWN-DATA` | A version in the data cannot be read | A source gave a version bound that does not parse under this product's version scheme, so it cannot be compared. Your own version is fine. Read the advisory and check it by hand. | This rule makes the verdict unknown; shown when the signals would make it Fix today or This week. |
| `UNP-CONFLICT` | Sources disagree | One source says this version is affected and another says it is not. A source that only says "all versions" does not outweigh one with exact ranges, so the verdict is unknown. Read the evidence to see which source to trust. | This rule is added when sources disagree; it makes the verdict unknown when the only "affected" comes from a source that says all versions. |
| `UNP-UNVERIFIED-PRODUCT` | Product not found in the data | The catalog's names for this product match no record in the database, so an empty result would not mean you are safe. Check the catalog entry or report it. | This rule makes a finding in: Unknown, so an empty result is never read as safe. |
| `UNP-IGNORED` | Ignored on purpose | An ignore entry in unpatched.yml accepts this risk until its date. The finding is listed separately and comes back when the entry expires. | This rule moves the finding to the ignored list. |
| `UNP-IGNORE-EXPIRED` | Ignore entry has expired | An ignore entry matched this finding but its date has passed, so the finding is back. Fix the issue or write a new entry with a new date. | This rule is added when an ignore entry ran out. |
| `UNP-STALE-DATA` | Data is out of date | The vulnerability database is older than your warning threshold (default 3 days). Results may miss new vulnerabilities, so check that the daily database build is running. | This rule makes a finding in: Unknown about the database itself. |

<!-- generated:end -->
