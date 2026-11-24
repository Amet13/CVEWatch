# Data

<!-- description: Every data source unpatched reads, how often the database is built, what happens when a source fails, how to verify the download, and the licenses. -->

unpatched uses only open data that needs no account or API key. A workflow in
this repository builds one SQLite database every day and publishes it. Your Action
or command downloads it and matches your stack locally.

## Sources

| Source | What it gives | How it is read | Terms |
| --- | --- | --- | --- |
| [CISA KEV](https://www.cisa.gov/kev) | Known exploited vulnerabilities: date added, due date, ransomware use | One JSON file, daily | Public domain (US government) |
| [NVD](https://nvd.nist.gov) | CPE version ranges and CVSS scores | The yearly JSON 2.0 feeds, which carry a SHA-256 in a `.meta` file; no API key | Public; NVD notice in [NOTICE](https://github.com/Amet13/unpatched/blob/main/NOTICE) |
| [CVE.org](https://www.cve.org) (`cvelistV5`) | Vendor-supplied affected versions from the CVE record, plus CISA's SSVC exploitation and automatable flags (CISA ADP, "Vulnrichment") | A shallow clone of the repository in the build workflow | CVE Terms of Use; the CISA data is CC0 |
| [EPSS](https://www.first.org/epss) | The estimated chance each CVE is exploited in the next 30 days | One daily file | Free, with attribution |
| [endoflife.date](https://endoflife.date) | End of life dates and the newest release of each cycle | The JSON API, once per product | MIT |
| [Exploit-DB](https://www.exploit-db.com) and [Metasploit](https://github.com/rapid7/metasploit-framework) | Whether a public exploit exists | Only the CVE ids from the index and the module metadata | Exploit-DB GPLv2 and Metasploit BSD-3: no exploit code or text is stored |
| [OSV](https://osv.dev) | Package vulnerabilities (Debian, Alpine, PyPI, npm, Go and more) | Queried live at run time, only for `purl` items; not in the database | CC-BY 4.0 |

Attributions and exact terms are in [NOTICE](https://github.com/Amet13/unpatched/blob/main/NOTICE).
The database holds facts and identifiers taken from these sources, not their
prose or code beyond what a finding shows.

Not used: vendor advisories (CSAF) and the EUVD and CIRCL mirrors. They may
come later. Today the fixed version is read from the upper bound of an affected
range, and the newest release in a cycle from endoflife.date.

## How often

| What | When |
| --- | --- |
| The database is built and published | Every day at 02:41 UTC, by `build-db.yml` |
| Your Action runs | As you schedule it; the template uses 06:17 UTC |
| The command line fetches a new database | When the one on disk is more than 20 hours old, or `unpatched db update` |
| The sources are probed for format changes | Every Wednesday (`unpatched db sources-health`), and a failure opens an issue |

The database is published as assets of the rolling pre-release `db` of this
repository: `unpatched-db.sqlite.zst`, `SHA256SUMS` and a GitHub build
attestation. The release is replaced every day, so do not pin to it.

## When a source fails

| What fails | What happens |
| --- | --- |
| CISA KEV or NVD, at build time | No database is built. The previous assets stay as they are, and a watchdog opens an issue. A broken database is never published. |
| EPSS, CVE.org, endoflife.date, Exploit-DB or Metasploit, at build time | The database is built without that source and records it as failed. `unpatched db info` shows its state. Findings still work; signals from that source are missing. |
| The daily build stops for several days | The database gets old. After `stale_warn_days` (3) the report has a "data is out of date" finding. After `stale_fail_days` (7) `check` exits with code 3, unless `--allow-stale`. |
| The download fails when you run | If an older database is on disk, `check` warns and uses it. If there is none, it exits with code 3. |
| OSV is down for a `purl` item | The item cannot be checked; the report says so. Catalog products are not affected. |
| A source changes its format | The weekly health check opens an issue, "Sources need a look". A person updates the parser. Until then the last good database is used. |

The freshness of every source is in the report (`db.sources` in the JSON, and
`unpatched db info`).

## Check what you downloaded

The checksum of the database is verified on download against `SHA256SUMS` from
the same release. You can also verify the build attestation:

```sh
gh attestation verify unpatched-db.sqlite.zst --repo Amet13/unpatched
```

Anyone can build the same kind of file from the sources, and compare:

```sh
git clone --depth 1 https://github.com/CVEProject/cvelistV5 cvelist
unpatched db build --cvelist cvelist --out unpatched-db.sqlite.zst
```

Then pass it with `--db`. `UNPATCHED_DB_URL` points the download somewhere else,
for example an internal mirror.

## What is in the database

Only catalog products go in: their vulnerabilities with the affected ranges each
source gives, all of KEV, EPSS scores, exploit flags, end of life cycles, and a
`meta` table with the schema version, the build time and the state of every
source. Packages are not stored; they go to OSV when you ask. A binary refuses a
database with a schema version it does not know, and asks to be upgraded.
