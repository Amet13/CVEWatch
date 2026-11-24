# Start with the command line

<!-- description: Install the unpatched command, write unpatched.yml, run a check, and use the exit codes in scripts and cron. -->

The command line is for a laptop, a cron job or a script. It does the same
matching as the Action. Without GitHub, it keeps its delivery state in
`.unpatched/state.json` next to your config file.

## Install

| How | Command |
| --- | --- |
| Shell (Linux, macOS) | `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Amet13/unpatched/releases/latest/download/unpatched-installer.sh \| sh` |
| PowerShell (Windows) | `powershell -ExecutionPolicy Bypass -c "irm https://github.com/Amet13/unpatched/releases/latest/download/unpatched-installer.ps1 \| iex"` |
| Homebrew | Download `unpatched.rb` from the [latest release](https://github.com/Amet13/unpatched/releases/latest), then `brew install --formula ./unpatched.rb` |
| Cargo | `cargo install unpatched --locked` |
| Archive | Download the `.tar.xz` (Linux, macOS) or `.zip` (Windows) from the releases page, check the `.sha256` file, and put `unpatched` on your `PATH` |

The installers put the binary in `$CARGO_HOME/bin` (usually `~/.cargo/bin`).
There is no Homebrew tap: the formula is a release asset that you install from
a file. Builds exist for Linux (x86_64 and aarch64, static musl), macOS (Intel
and Apple silicon) and Windows (x86_64). Every archive has a GitHub build
attestation: `gh attestation verify <file> --repo Amet13/unpatched`.

Check it works:

```sh
unpatched --version
```

## Write `unpatched.yml`

In a terminal, `unpatched init` asks what you run (it searches the catalog for
each name, asks the version and whether it faces the internet) and writes
`unpatched.yml`. With `--github` it also writes the workflow for the
[GitHub route](start-github.md). When input is not a terminal, it writes the
commented template instead.

<!-- generated:start example-init -->

```text
$ unpatched init --github
Wrote unpatched.yml
Wrote .github/workflows/unpatched.yml

Next steps:
  1. Edit unpatched.yml: list what you really run, with exact versions.
  2. Run `unpatched check` to see the result.
  3. Keep this repository PRIVATE: unpatched.yml lists your software and versions.
  4. Commit and push both files. The workflow runs every day at 06:17 UTC; start it once from the Actions tab (workflow_dispatch).
  5. For Telegram, Slack, Discord, ntfy or a webhook, add the secrets named in unpatched.yml under Settings > Secrets and variables > Actions, and uncomment the `env:` lines in the workflow.
```

<!-- generated:end -->

`init` refuses to overwrite files; add `--force` to do it anyway. Find product
ids without `init`:

<!-- generated:start example-search -->

```text
$ unpatched search forti
ID            NAME          VENDOR    KIND       VERSIONS
fortimanager  FortiManager  Fortinet  appliance  dotted
fortios       FortiOS       Fortinet  appliance  dotted
fortiproxy    FortiProxy    Fortinet  appliance  dotted
fortiweb      FortiWeb      Fortinet  appliance  dotted

Use the id in unpatched.yml: `product: <id>`.
```

<!-- generated:end -->

## Run a check

```sh
unpatched check
```

The first run downloads the database (a release asset of this repository, hash
checked) into your cache folder. Later runs reuse it and refresh it when it is
more than 20 hours old. If the refresh fails and an older copy exists, it warns
and uses the older one. See [Data](data.md).

The examples below use a small sample database that is in the repository
(`fixtures/smoke/unpatched-db.sqlite`) and the date 2026-11-24, so you can
compare. Your output uses live data. The stack is the template from above.

<!-- generated:start example-check -->

```text
$ unpatched check
2 to act on (1 today, 1 end of life)

🔴 FortiOS 7.2.5 (Office firewall)  1 today  →  upgrade to 7.2.7 (fixes it)
⚫ Nextcloud 29.0.3  1 end of life  →  upgrade to a supported release

🔴 Fix today (1)

  FortiOS 7.2.5 (Office firewall)
  CVE-2024-21762  A out-of-bounds write vulnerability in Fortinet FortiOS 7.4.0 through 7.4.2, FortiOS 7.2.0 through 7.2.6, FortiOS 7.0.0 through 7.0.13, For…
    Why   In CISA KEV since 2024-02-09 · ransomware use: known · CISA due date 2024-02-16 · SSVC: exploitation is active · SSVC: automatable · EPSS 84.6% (percentile 100) · CVSS 9.6 · internet-facing
    Do    Upgrade to 7.2.7 or later.
    Rule  UNP-KEV, UNP-SSVC-ACTIVE, UNP-EPSS, UNP-CVSS, UNP-EXPOSED · verdict affected

⚫ End of life (1)

  Nextcloud 29.0.3
  nextcloud 29.0.3 is past end of life: the 29 release cycle no longer gets security fixes
    Why   End of life · internet-facing
    Do    Upgrade to a supported release.
    Rule  UNP-EOL · verdict affected

🟢 1 vulnerability checked against your versions: not affected
Database: built 2026-11-23 12:00 UTC, 0 days old
Note: stack[2]: the database has no data for product "postgresql" yet. Run `unpatched db update`; if the id may be wrong, `unpatched catalog list` shows the ids.
Note: stack[3]: the database has no data for product "home-assistant" yet. Run `unpatched db update`; if the id may be wrong, `unpatched catalog list` shows the ids.
```

<!-- generated:end -->

Each finding shows the product and your label, the CVE, why it is in its bucket
(`Why`), what to do (`Do`), and the rule ids. The title of a CVE can be long:
it is the CVE's own description. Read [Findings and rules](findings.md) for the
buckets.

### Formats

`--format` is one of `text` (the default), `json`, `markdown` and `sarif`.
`--output FILE` writes to a file instead of the screen. `json` has a published
schema (`unpatched schema report`), so scripts and agents should read that, not
the text. `sarif` is for code-scanning tools; uploading it to GitHub's Security
tab needs GitHub Advanced Security on private repositories, so unpatched does not
do it for you.

The text and Markdown reports start with the counts
(`87 to act on (14 today, 69 this week, ...), 228 FYI`) and show FYI findings
only as a count per item, plus a line `228 FYI not shown: run with -v or --format
json`. With `--verbose` (or `-v`) they list the FYI findings too and include the
evidence of each source. The JSON always has everything.

`--quiet` prints nothing on stdout, so a script or cron job stays silent; errors
still go to stderr and the exit code is the same. If you give `--output FILE`, the
report is still written there:

```sh
unpatched check --quiet --format json --output report.json
```

The same report as `--format json`. Parts are cut out for this page and marked
with `...`: the database sources, the long `title` and `evidence`, and the second
finding.

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

### Packages and the network

A `purl` item in `unpatched.yml` is looked up live in OSV (see
[Privacy](privacy.md)). `--offline` skips that and the database download. Catalog
products still work with `--offline` when a database is on disk. Use
`--db FILE` (or `$UNPATCHED_DB`) to choose the database file.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | OK |
| 1 | `check --exit-code` found something to fix today |
| 2 | Usage or configuration error (bad YAML, unknown product, missing secret) |
| 3 | Data error (no database, database too old, a download failed) |
| 4 | Delivery error (a chat channel or GitHub issue failed) |

`--exit-code` makes `check` return 1 when there is a "fix today" finding, so a
script or pipeline can stop:

```sh
unpatched check --exit-code --quiet || echo "something to fix today"
```

A database older than `stale_fail_days` (7 by default) stops the run with
exit code 3. `--allow-stale` overrides that. At `stale_warn_days` (3) you get a
finding that says the data is old.

## Send messages from the command line

`--notify` sends the findings to the channels in `unpatched.yml`. Outside GitHub
Actions it uses the local state file to avoid repeats. `--dry-run` prints each
message that would be sent (the channel, then its text) and what would be
written, and sends and writes nothing. A missing secret is only a warning in a
dry run. Secrets come from environment variables. See
[Notifications](notifications.md).

```sh
export UNPATCHED_NTFY_TOKEN=...   # only if your ntfy topic needs one
unpatched check --notify
```

A cron entry that runs it every morning (`--quiet` keeps cron from mailing you
the report on stdout; errors still reach you):

```text
17 6 * * *  cd /home/me/stack && unpatched check --notify --quiet
```

To keep a copy of the report as well:

```text
17 6 * * *  cd /home/me/stack && unpatched check --notify --quiet --format json --output report.json
```

`--github` makes the command keep issues and state in a GitHub repository (it
needs `GITHUB_TOKEN` and `GITHUB_REPOSITORY`). It is on by itself inside GitHub
Actions.

## Look closer

Show the evidence for a CVE, and what a rule means:

<!-- generated:start example-explain-cve -->

```text
$ unpatched explain CVE-2024-21762
CVE-2024-21762
  A out-of-bounds write vulnerability in Fortinet FortiOS 7.4.0 through 7.4.2, FortiOS 7.2.0 through 7.2.6, FortiOS 7.0.0 through 7.0.13, FortiOS 6.4.0 through 6.4.14, FortiOS 6.2.0 through 6.2.15, FortiOS 6.0 all versions, FortiProxy 7.4.0 through 7.4.2, FortiProxy 7.2.0 through 7.2.8, FortiProxy 7.0.0 through 7.0.14, FortiProxy 2.0.0 through 2.0.13, FortiProxy 01.02 all versions, FortiProxy 1.2 all versions, FortiProxy 01.01 all versions, FortiProxy 1.1 all versions, FortiProxy 01.00 all versions allows attacker to execute unauthorized code or commands via specifically crafted requests
  status: published · published 2024-02-09 · modified 2026-10-22
  CVSS 3.1: 9.6 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:W/RC:C

Exploitation signals
  CISA KEV: added 2024-02-09, due 2024-02-16, ransomware use: known
  EPSS: 84.6% (percentile 100) on 2026-11-23
  SSVC exploitation: Active, automatable: yes
...
```

<!-- generated:end -->

<!-- generated:start example-explain-rule -->

```text
$ unpatched explain UNP-KEV
UNP-KEV: Known to be exploited

CISA lists this vulnerability in its Known Exploited Vulnerabilities catalog, so attackers are using it now. Fix it today.

This rule puts an affected finding in: Fix today (now).
```

<!-- generated:end -->

With a stack file, `explain CVE-...` also shows what the CVE means for your
items, and `explain <item>/<CVE>` explains one finding by its key (the key is in
the JSON report and in the hidden marker of each issue). It ends with the lines
to add to `unpatched.yml` to accept the risk. `unpatched explain --rules` lists
every rule id.

Show a catalog entry, the names it matches in each source:

<!-- generated:start example-catalog-show -->

```text
$ unpatched catalog show fortios
# catalog/fortios.yml
# Write the version like: 7.2.5 (three numbers; leave out 'build 1517')
id: fortios
name: FortiOS
vendor: Fortinet
kind: appliance
versioning: dotted
match:
  cpe:
  - fortinet:fortios
  cna:
  - vendor: Fortinet
    product: FortiOS
  - vendor: Fortinet
    product: Fortinet FortiOS, FortiProxy, FortiSwitchManager
  - vendor: Fortinet
    product: FortiOS-6K7K
  kev:
  - vendorProject: Fortinet
    product: FortiOS
  - vendorProject: Fortinet
    product: FortiOS and FortiProxy
  - vendorProject: Fortinet
    product: FortiOS and FortiProxy SSL-VPN
  - vendorProject: Fortinet
    product: FortiOS and FortiADC
eol: fortios
aliases:
- fortigate
- fortinet firewall
homepage: https://www.fortinet.com/products/fortigate/fortios
version_hint: 7.2.5 (three numbers; leave out 'build 1517')
checked: 2026-11-23
```

<!-- generated:end -->

Check how old the database is:

<!-- generated:start example-db-info -->

```text
$ unpatched db info
File:             fixtures/smoke/unpatched-db.sqlite
Schema version:   1
Built:            2026-11-23 12:00 UTC (0 days old)
Products:         7 (6 found in the data)
Vulnerabilities:  7
Sources:
  CISA KEV        ok  7 records   2026-11-23 12:00 UTC
  EPSS            ok  8 records   2026-11-23 12:00 UTC
  NVD             ok  2 records   2026-11-23 12:00 UTC  1 feeds, 7 records scanned
  CVE.org         ok  14 records  2026-11-23 12:00 UTC
  endoflife.date  ok  1 records   2026-11-23 12:00 UTC
  Exploit-DB      ok  9 records   2026-11-23 12:00 UTC
  Metasploit      ok  9 records   2026-11-23 12:00 UTC
```

<!-- generated:end -->

`unpatched db update` downloads the latest database now. `unpatched db build`
builds one from the sources yourself (slow; the repository does it daily), for
people who do not want to trust the published one. The
[command reference](cli.md) lists every command and option.
