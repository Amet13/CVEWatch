<p align="center"><img src="logo.png" alt="unpatched" width="140"></p>

# unpatched

**Hear about vulnerabilities only when something you run is affected.**

You run software you did not write: a firewall, a VPN, a NAS, Nextcloud,
PostgreSQL, Home Assistant. Dependabot and Trivy scan code and containers, not
those. A CVE feed lists every CVE for a vendor and leaves the sorting to you.

Write down what you run and its version, once. Every day a GitHub Action checks
it against open vulnerability data. It opens an issue only when something you
run is affected, says which version to upgrade to, and ranks the issues by
whether the bug is being exploited, not by CVSS. A quiet week says so.

No account, no API key, no server. The list of what you run stays in your own
private repository.

## What you get

The summary of a run, from the sample database in this repository (the
[guide](https://amet13.github.io/unpatched/findings.html) shows the issue it
opens and the same report as JSON):

<!-- generated:start example-check-markdown -->

```text
$ unpatched check --format markdown
## unpatched

2 to act on (1 today, 1 end of life). 🟢 1 vulnerability checked against your versions: not affected

- 🔴 FortiOS 7.2.5 (Office firewall)  1 today  →  upgrade to 7.2.7 (fixes it)
- ⚫ Nextcloud 29.0.3  1 end of life  →  upgrade to a supported release

| Bucket | Findings |
| --- | ---: |
| 🔴 Fix today | 1 |
| 🟡 This week | 0 |
| ⚫ End of life | 1 |
| ❔ Unknown | 0 |
| ⚪ FYI | 0 |

### 🔴 Fix today

- **FortiOS 7.2.5 (Office firewall)**: CVE-2024-21762
  - Why: In CISA KEV since 2024-02-09 · ransomware use: known · CISA due date 2024-02-16 · SSVC: exploitation is active · SSVC: automatable · EPSS 84.6% (percentile 100) · CVSS 9.6 · internet-facing
  - Do: Upgrade to 7.2.7 or later.
  - Rules: `UNP-KEV`, `UNP-SSVC-ACTIVE`, `UNP-EPSS`, `UNP-CVSS`, `UNP-EXPOSED`

### ⚫ End of life

- **Nextcloud 29.0.3**: past end of life
  - Why: End of life · internet-facing
  - Do: Upgrade to a supported release.
  - Rules: `UNP-EOL`

Database: built 2026-11-23 12:00 UTC, 0 days old

### Notes

- stack[2]: the database has no data for product "postgresql" yet. Run `unpatched db update`; if the id may be wrong, `unpatched catalog list` shows the ids.
- stack[3]: the database has no data for product "home-assistant" yet. Run `unpatched db update`; if the id may be wrong, `unpatched catalog list` shows the ids.
```

<!-- generated:end -->

The two notes at the end are because the sample database holds only a few
products. The real database has all of the [catalog](https://amet13.github.io/unpatched/catalog.html).

## Start in two files

In a new **private** repository, add `unpatched.yml` with what you run:

```yaml
version: 1
stack:
  - product: fortios
    version: 7.2.5
    exposure: internet
    name: Office firewall
  - product: nextcloud
    version: 29.0.3
    exposure: internet
  - product: postgresql
    version: "15.4"
```

and `.github/workflows/unpatched.yml`:

```yaml
name: unpatched
on:
  schedule:
    - cron: "17 6 * * *"
  workflow_dispatch:
permissions:
  contents: read
  issues: write
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: amet13/unpatched@v3
```

Push, then run the workflow once from the Actions tab. Find product ids with
`unpatched search <name>`. To accept a risk you know about, add an `ignore:`
entry (a `cve`, a `reason` and an `until` date) to `unpatched.yml`; every issue
shows the lines to copy. The full walk-through, including secrets for
Telegram, Slack and the others, is in
[Start with GitHub](https://amet13.github.io/unpatched/start-github.html).
`unpatched init --github` writes both files for you.

## Install

| How | Command |
| --- | --- |
| GitHub Action | `uses: amet13/unpatched@v3` (downloads the release binary and checks its SHA-256) |
| Shell (Linux, macOS) | `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Amet13/unpatched/releases/latest/download/unpatched-installer.sh \| sh` |
| PowerShell (Windows) | `powershell -ExecutionPolicy Bypass -c "irm https://github.com/Amet13/unpatched/releases/latest/download/unpatched-installer.ps1 \| iex"` |
| Homebrew | Download `unpatched.rb` from the [latest release](https://github.com/Amet13/unpatched/releases/latest), then `brew install --formula ./unpatched.rb` (there is no tap) |
| Cargo | `cargo install unpatched --locked` |
| Docker | `docker run --rm -v "$PWD:/work" ghcr.io/amet13/unpatched` |

Release archives for Linux, macOS and Windows have a `.sha256` file each and a
GitHub build attestation. Details: [Start with the command line](https://amet13.github.io/unpatched/start-cli.html)
and [Start with Docker](https://amet13.github.io/unpatched/start-docker.html).

## What it is not

- **Not a catalog of everything.** It knows named products (see the
  [catalog](https://amet13.github.io/unpatched/catalog.html)). WordPress plugins
  and themes are not covered, and neither are operating-system packages unless
  you name them with a `purl`, like
  `pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm`.
- **Not a dependency or container scanner.** It does not read your code, lock
  files or images. For those use [OSV-Scanner](https://google.github.io/osv-scanner/)
  or [Trivy](https://trivy.dev/). unpatched can check a single package you name
  by `purl`, but it does not find packages for you.
- **Not a network scanner.** It never looks at your hosts. You tell it what runs
  and in which version.
- **Not a guarantee.** A quiet report means no source it reads says you are
  affected. See [How accurate is it](https://amet13.github.io/unpatched/accuracy.html).

## Data

CVE.org records, NVD, CISA KEV, EPSS, OSV (packages only), endoflife.date and
the CVE ids from Exploit-DB and Metasploit. All are open and need no key. A
workflow in this repository builds one database a day and publishes it as a
release asset. Licenses and attributions are in [NOTICE](NOTICE); the
[data page](https://amet13.github.io/unpatched/data.html) says what happens when
a source fails.

## Guide

[Guide](https://amet13.github.io/unpatched/) ·
[Findings and rules](https://amet13.github.io/unpatched/findings.html) ·
[Config reference](https://amet13.github.io/unpatched/config.html) ·
[Catalog](https://amet13.github.io/unpatched/catalog.html) ·
[FAQ](https://amet13.github.io/unpatched/faq.html) ·
[Coming from CVEWatch](https://amet13.github.io/unpatched/migrate-from-cvewatch.html)

## With an AI agent

`unpatched mcp` is a read-only MCP server (`check_stack`, `is_affected`,
`explain`, `search_catalog`, `db_status`). The repository also ships skills
(`set-up-unpatched`, `inventory-from-notes`, `plan-upgrades`,
`explain-a-finding`), a Claude Code plugin and a Gemini CLI extension, and the
site has [`llms.txt`](https://amet13.github.io/unpatched/llms.txt). See
[With an agent](https://amet13.github.io/unpatched/with-an-agent.html).

## Contributing

Wrong verdicts and new products are the most useful reports. See
[CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md) and
[MAINTAINING.md](MAINTAINING.md). Security problems: [SECURITY.md](SECURITY.md).

This repository was CVEWatch, a Go tool. It is now `unpatched`, written in
Rust; see [Coming from CVEWatch](https://amet13.github.io/unpatched/migrate-from-cvewatch.html).

## License

Code: [MIT](LICENSE). Data keeps the terms of its publishers: [NOTICE](NOTICE).
