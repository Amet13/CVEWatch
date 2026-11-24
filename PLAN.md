# Rewrite plan: CVEWatch → `unpatched`

Status: **approved with the review in §16** (name `unpatched` chosen). §16 overrides earlier sections where they differ.
Date: 2026-11-23.

## 0. Summary

- **New name:** `unpatched`. Repo `Amet13/unpatched`, crate `unpatched`,
  command `unpatched`, config file `unpatched.yml`.
- **One sentence:** list the software you run; once a day, a GitHub Action
  checks it against open vulnerability data. It tells you only when something
  you run is affected, what to do, and how urgent it is.
- **Language:** Rust (edition 2024), one binary.
- **Hosting:** GitHub only. No servers, no accounts, no API keys.
- **Approach:** a full rewrite on the same repository. The history is kept, the
  Go v2 code is frozen under a tag, and the repo is renamed at launch.
- **AI in two directions:** the repository is built to be worked on by coding
  agents (AGENTS.md, skills, a test corpus, evals). The product is usable by
  agents too (MCP server, plugin manifests, stable JSON).

---

## 1. Name

**Recommendation: `unpatched`**

- It is the word for the problem. It answers the question people ask: "what is
  still unpatched on my side?"
- It's one short lowercase domain word, like `overfull`.
- Free on crates.io (checked 2026-11-23). The GitHub repos using the name are
  unrelated (Minecraft mods).
- It reads well in use: `unpatched check`, `unpatched.yml`,
  `uses: amet13/unpatched@v0`, "Unpatched: 1 to fix today".

Alternatives (all free on crates.io, no notable GitHub projects):

| Name | Note |
| --- | --- |
| `patchnudge` | Friendly, says what it does. Two words joined. |
| `needpatch` | Plain. Reads as a question. |
| `kevwatch` | An insider pun on CISA KEV, but too narrow and too much like the old name. |
| `stillvuln` | Memorable, slightly negative. |

Decision: `unpatched`.

---

## 2. The product

### Problem

People who run software they did not write have no tool that answers "do I
need to do something today?". That includes small IT teams, MSPs, homelabbers
and small businesses running firewalls and VPNs, NAS boxes, self-hosted apps,
databases and CMSs.

- Dependabot, Renovate, OSV-Scanner, Trivy and Grype cover code and container
  images, not a FortiGate or a Nextcloud install.
- CVE feeds (OpenCVE, Vulners, NVD) show every CVE for a vendor and leave the
  sorting to you. About 40% of CVEs score CVSS 7 or more, so filtering by CVSS
  is noise.
- What gets small organisations breached is edge devices with exploited bugs
  (Fortinet, Ivanti, Citrix, Palo Alto, MOVEit) and software past its end of
  life.

### Promise

> Describe your stack once. Hear from us only when something you run is
> affected, with the version to upgrade to, and whether it is being exploited.
> A quiet week says so.

### Who it is for (in order)

1. A homelabber or self-hoster with 5–30 things running.
2. A one-person or small IT team at a small business.
3. An MSP running one private repo per client (later: a summary across clients).

### Principles (the contract, like overfull's ARCHITECTURE.md)

- **Act, don't list.** Every finding says what to do: upgrade to X, apply
  workaround Y, or replace (end of life).
- **Never claim "not affected" without evidence.** Each finding has one of four
  verdicts: `affected`, `not-affected`, `fixed`, `unknown`. An `unknown` is
  shown with its reason, never dropped silently.
- **Rank by exploitation, not CVSS.** Being in CISA KEV, the vendor confirming
  exploitation, a public exploit, EPSS and internet exposure decide the bucket.
- **Quiet by default.** A weekly digest; an immediate message only for "fix
  today" items; a short "nothing to do" line so you know it's still running.
- **Private by default.** The stack stays in your private repo. Matching runs in
  your Action. No telemetry.
- **Keyless.** Every data source works without an account. Optional extras
  (an NVD key, notification tokens) live in GitHub Secrets.
- **Deterministic and explainable.** No model decides a verdict. Every finding
  has a rule id and lists the evidence it came from
  (`unpatched explain <finding>`).

### Not in scope

- Scanning code, dependencies or container layers. Point people to OSV-Scanner
  or Trivy, and read their SBOM output later.
- Network scanning or fingerprinting hosts.
- A hosted SaaS. A web dashboard may come later as a static GitHub Pages page.
- Writing exploits or proofs of concept.

---

## 3. How people use it

### A. GitHub Action in a private repo (the main way)

1. Create a private repo (or run `unpatched init --github` in an empty one).
2. Add two files:

   `unpatched.yml`
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
     - product: home-assistant
       version: 2024.10.1
   notify:
     issues: true          # default; needs no secret
     telegram: { chat: "123456789" }   # token in secret UNPATCHED_TELEGRAM_TOKEN
   digest: monday          # weekly digest; "fix today" items are sent at once
   ```

   `.github/workflows/unpatched.yml`
   ```yaml
   on:
     schedule: [{ cron: "17 6 * * *" }]
     workflow_dispatch:
   permissions: { contents: read, issues: write }
   jobs:
     check:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v5
         - uses: amet13/unpatched@v0
           env:
             UNPATCHED_TELEGRAM_TOKEN: ${{ secrets.UNPATCHED_TELEGRAM_TOKEN }}
   ```
3. The result is GitHub Issues, one per finding, with a label for the bucket.
   GitHub emails you, closing an issue means "done", and you get an audit trail
   for free. Optionally a message is also sent to Telegram, Slack, Discord,
   ntfy, email or a webhook.

### B. The command line (local, cron, scripts)

```text
unpatched init                 write unpatched.yml from questions or a pasted list
unpatched check                match the stack, print the report
  --format text|json|markdown|sarif
  --notify                     also send to the configured channels
unpatched explain <id|CVE>     the evidence behind a verdict
unpatched search <text>        find a product in the catalog
unpatched db update|info       fetch the latest prebuilt database, show its age
unpatched catalog list|show    the products the tool knows
unpatched mcp                  MCP server on stdio
unpatched scan                 (v1.1) read local dpkg/apk/rpm/brew/winget/docker inventories
```

### C. Docker (homelab cron or a NAS)

`ghcr.io/amet13/unpatched` runs `unpatched check --notify` on a schedule.

### D. AI agents (see §9)

For example, someone asks Claude "is anything I run affected by the new Ivanti
bug?" and the agent calls the `unpatched` MCP server.

### What the output looks like

GitHub issue title: `🔴 Fix today: FortiOS 7.2.5 — CVE-2024-21762 (exploited)`

```text
Office firewall runs FortiOS 7.2.5, which is affected.

Why now   In CISA KEV since 2024-02-09 · ransomware use: known · internet-facing
Do        Upgrade to 7.2.7 or later (7.2.11 is current in this branch)
Or        Disable SSL-VPN until upgraded (vendor workaround)
Evidence  Fortinet PSIRT FG-IR-24-015 · CVE record (Fortinet, affected 7.2.0–7.2.6)
Rule      UNP-AFFECTED · verdict affected · data 2026-11-23

Close this issue when it is fixed; unpatched closes it on its own once
unpatched.yml shows a fixed version.
```

Weekly digest (Telegram, or the body of a pinned issue):

```text
unpatched · week 48
🔴 Fix today   FortiOS 7.2.5 (Office firewall): exploited, upgrade to 7.2.7+
🟡 This week   Nextcloud 29.0.3: 2 advisories, upgrade to 29.0.8
⚪ End of life PostgreSQL 13 ended 2025-11-13: plan an upgrade
❔ Unknown     Home Assistant 2024.10.1: 1 CVE with no version data yet
🟢 1,412 new CVEs this week; none of the others affect you.
```

---

## 4. Data

All sources were checked live on 2026-11-23 with no keys.

| Source | Use | Access | License or terms |
| --- | --- | --- | --- |
| **CVE.org** (`cvelistV5`) | Official records; vendor-supplied affected versions; CISA ADP enrichment | git / raw JSON / `cveawg.mitre.org` API | CVE Terms of Use (attribution) |
| **CISA KEV** | "Exploited" signal, ransomware flag, due date | One JSON file | Public domain (US gov) |
| **CISA Vulnrichment** | SSVC exploitation and automatable flags for CVEs NVD has not processed | git | CC0 |
| **EPSS** (FIRST) | Exploit probability for every CVE | Daily CSV, 2.9 MB gz | Free; attribution requested |
| **NVD 2.0** | CPE version ranges, CVSS; filling gaps | Keyless API, about 5 requests per 30 s, incremental by `lastModStartDate` | Public; NVD notice required |
| **OSV.dev** | Package-level ranges (deb, apk, rpm, PyPI, npm, Go, …) | `querybatch` API at run time | CC-BY 4.0 (attribution) |
| **endoflife.date** | EOL dates and latest version per release cycle (489 products) | JSON API | MIT |
| **Vendor CSAF / RSS** | Fixed versions and workarounds (Fortinet, Microsoft, Red Hat, …) | CSAF provider metadata, RSS | Per vendor |
| **Exploit-DB, Metasploit metadata** | "Public exploit exists" flag | CSV / JSON from git | GPLv2 / BSD-3 (only the CVE ids are stored) |
| **EUVD, CIRCL vulnerability-lookup** | Fallback mirrors if CVE.org or NVD fail | API | Check terms in phase 2 |

The licenses need a legal read in phase 2. A `docs/guide/data.md` page and a
`NOTICE` file list the attributions.

### Two matching paths

1. **Catalog products** (FortiOS, Nextcloud, PostgreSQL, WordPress, Synology DSM,
   …). These are matched with versions from CVE.org (CNA `affected`),
   NVD CPE ranges and vendor advisories. They are prebuilt into the database
   every day.
2. **Packages** (`purl: pkg:deb/debian/openssl@3.0.11-1~deb12u1`). These are
   queried live from OSV with `querybatch`. That keeps the database small, and
   OSV is the best source for packages.

### The prebuilt database

- Built every day by `build-db.yml` in this repo. It is published as an asset
  on a rolling GitHub release, `db`: `unpatched-db.sqlite.zst`, plus
  `SHA256SUMS` and a GitHub build-provenance attestation. The binary checks the
  hash and refuses data older than 7 days unless given `--allow-stale`.
- Contents:
  - catalog products and their vulnerabilities, with normalised ranges
  - all of KEV
  - EPSS for every CVE
  - exploit flags
  - EOL cycles
  - CSAF fix data
  - a `meta` table (schema version, build time, the date and health of each
    source)
- Expected size: a few tens of MB compressed. That is checked in phase 2.
- Schema changes bump `schema_version`. A binary refuses a database with an
  unknown major version and asks to be upgraded.

### The catalog (`catalog/*.yml`): the main asset

The catalog is one file per product. It ties the names a product has across
sources together:

```yaml
id: fortios
name: FortiOS
vendor: Fortinet
kind: appliance            # appliance | app | os | database | library | desktop
versioning: dotted         # dotted | semver | calver | debian | rpm | apk | pep440 | custom:<name>
match:
  cpe: [fortinet:fortios]
  cna: [{ vendor: Fortinet, product: FortiOS }]
  kev: [{ vendorProject: Fortinet, product: FortiOS }]
eol: fortios               # endoflife.date slug
advisories: [fortinet-psirt]
aliases: [fortigate, "fortinet firewall"]
checked: 2026-11-23        # when a person last verified this entry
```

- v1 target: **50 products**, chosen from KEV vendor frequency plus the
  self-hosted lists (awesome-selfhosted).
- v1.x target: 200 products.
- `build-catalog` turns the YAML files into a generated module. It is never
  edited by hand (like overfull's venues).
- `catalog-watch` opens an issue when a KEV entry names a vendor or product
  that is not in the catalog. An agent skill drafts the entry, and a person
  checks it (§9).

---

## 5. Matching and priority

### Versions

`unpatched-core::version` has one parser and comparator per scheme: `dotted`,
`semver`, `calver`, `debian` (dpkg rules), `rpm` (rpmvercmp), `apk`, `pep440`,
plus named custom schemes for awkward vendors (for example FortiOS builds, or
Windows build numbers).

- Ranges are stored as the purl **`vers:`** spec (`vers:deb/>=1.0|<1.2.3`), one
  format for every source.
- A version that cannot be parsed gives `unknown` with a reason, never a guess.
- Each parser gets property tests (`proptest`: ordering is total and
  transitive) and a fuzz target (`cargo-fuzz`).

### Verdict (per stack item × vulnerability)

| Verdict | When |
| --- | --- |
| `affected` | The version is inside an affected range from at least one trusted source, and no source with higher precedence says otherwise. |
| `fixed` | It was affected, and the configured version is now at or above the fix. Used to close issues. |
| `not-affected` | Every range is known and the version is outside all of them. Not reported. |
| `unknown` | No version data yet (the NVD backlog), conflicting sources, or an unparseable version. Reported, with the reason. |

Source precedence, highest first: vendor CSAF → CNA record → NVD CPE → CISA ADP.
The precedence is written down in an ADR.

### Bucket

| Bucket | Rule (defaults; can be changed in `unpatched.yml`) |
| --- | --- |
| 🔴 `now` | `affected` and (in KEV, or the vendor says exploited, or SSVC exploitation=active, or (a public exploit exists and exposure is internet)) |
| 🟡 `week` | `affected` and (EPSS ≥ 0.05, or CVSS ≥ 9, or exposure is internet) |
| ⚪ `fyi` | other `affected` |
| ⚫ `eol` | the version's cycle is past its end of life (one finding per item, not per CVE) |
| ❔ `unknown` | an `unknown` verdict that would be `now` or `week` if confirmed; others only in `--verbose` |

Each rule has a stable id (`UNP-KEV`, `UNP-EOL`, `UNP-UNKNOWN-NO-RANGES`, …),
shown by `unpatched explain`.

### State

`.unpatched/state.json` lives in the user's repo and is committed by the
Action. It records which findings were already reported and in which issue,
and when the last digest went out. This prevents repeat messages, and the
commit counts as activity, so GitHub does not disable the schedule after 60
idle days.

---

## 6. Architecture

```text
crates/
  unpatched-core/     pure logic, no I/O: model, version schemes, vers ranges,
                      verdicts, buckets, rules, report types (the contract)
  unpatched-sources/  one module per source: fetch + parse into core types
                      (cve_org, kev, epss, nvd, osv, eol, csaf, exploits)
  unpatched-db/       SQLite schema, builder (from sources), reader (for check)
  unpatched-catalog/  catalog YAML → generated module; validation
  unpatched-notify/   issues, telegram, slack, discord, ntfy, email (SMTP), webhook
  unpatched-mcp/      MCP server on stdio (tools below)
  unpatched/          the binary: CLI (clap), config, state, output formats
xtask/                build-catalog, build-db, bench, corpus, release helpers
```

Data flow:

```text
build-db.yml (daily, this repo)          user repo Action / CLI / Docker
sources ─► normalise ─► vuln.sqlite ─►   download db (verify hash)
          (catalog)     release "db"     + OSV querybatch for purls
                                         ─► verdicts ─► buckets ─► diff vs state
                                         ─► issues / messages / report
```

### Rust choices

| Need | Crate | Why |
| --- | --- | --- |
| CLI | `clap` (derive) | Standard |
| HTTP | `reqwest` + `rustls` | No OpenSSL; static builds |
| Async | `tokio` (only in sources, notify, mcp) | Core stays sync and pure |
| JSON / YAML | `serde`, `serde_json`, `serde_yaml_ng` (or `serde_norway`) | `serde_yaml` is unmaintained |
| SQLite | `rusqlite` with `bundled` | One file, no system library |
| zstd | `zstd` | DB compression |
| Errors | `thiserror` (libraries), `miette` (CLI, readable diagnostics) | Errors with fixes, like overfull |
| Logs | `tracing` | |
| Tests | `cargo-nextest`, `insta` (snapshots), `proptest`, `wiremock` | |
| Quality | `clippy` (pedantic where sensible), `rustfmt`, `cargo-deny`, `cargo-machete` | |
| Release | `dist` (cargo-dist): binaries, shell/PowerShell installers, Homebrew formula | Less hand-written release code |

MSRV: latest stable minus two, checked in CI. Targets: Linux x86_64/aarch64
(musl), macOS arm64/x86_64, Windows x86_64.

---

## 7. Repository layout after the rewrite

```text
AGENTS.md              how to work on this repo (agents first, people too)
CLAUDE.md              one line: see AGENTS.md (plus GEMINI.md as a symlink)
CONTEXT.md             glossary: product, stack item, verdict, bucket, source, …
README.md              what it is, a 2-minute start, one screenshot
CHANGELOG.md           Keep a Changelog; one line per user-visible change
MAINTAINING.md         what runs on its own, what stays with a person
CONTRIBUTING.md        adding a product, adding a source, tests
SECURITY.md  SUPPORT.md  CODE_OF_CONDUCT.md  LICENSE (MIT)  NOTICE (data attributions)
action.yml             the GitHub Action (composite: download a verified binary, run check)
Cargo.toml  rust-toolchain.toml  deny.toml  clippy.toml  .editorconfig
crates/  xtask/        (§6)
catalog/               one YAML file per product
corpus/                truth set: <case>/case.yml (stack + data fixture + expected findings)
fixtures/              frozen source snapshots for offline tests
bench/                 accuracy benchmark against held-out KEV and advisory cases
evals/                 agent evals (tasks, runner, results)
skills/                agent skills shipped to users (§9)
.agents/skills/        maintainer skills for this repo (§8)
docs/adr/              decisions, numbered
docs/guide/            user documentation (the source of the site)
site/                  GitHub Pages (guide, catalog browser, accuracy page, llms.txt)
templates/github/      the files `init --github` writes (workflow + unpatched.yml)
docker/                Dockerfile
schema/                JSON Schema for unpatched.yml and the JSON report
.claude-plugin/  gemini-extension.json  server.json   (agent distribution)
.github/               workflows (§10), issue templates incl. "wrong verdict" and "add a product"
```

---

## 8. Built with AI, for AI: the development side

The goal is that a coding agent can take an issue, change the code or the
catalog, and prove the change is right, with no human explaining the repo.

- **`AGENTS.md`** (the cross-tool standard). It covers the layout, the single
  command to run before committing (`cargo xtask check`: fmt, clippy, tests,
  corpus, catalog, schema, deny), what is generated and must never be
  hand-edited, and the style (plain, short English).
- **`CLAUDE.md` / `GEMINI.md`**: pointers to `AGENTS.md`, so there is one
  source of truth.
- **`CONTEXT.md`**: the domain glossary, so agents and people use the same words.
- **ADRs** in `docs/adr/`: name, Rust, keyless data, `vers:` ranges, verdict
  precedence, database distribution, state in the user repo. Agents read them
  instead of reopening settled decisions.
- **Maintainer skills** in `.agents/skills/`:
  - `add-product`: draft `catalog/<id>.yml` from the KEV, CVE.org and
    endoflife data, add a corpus case, run the checks.
  - `add-source`: the steps and the contract for a new source module.
  - `triage-wrong-verdict`: turn a "wrong verdict" issue into a failing corpus
    case, then a fix.
  - `refresh-fixtures`: record new source snapshots, and explain the diffs.
- **The corpus is the spec.** Each case is a small stack, a frozen data slice
  and the expected findings. Every bug fix starts as a new failing case. Agents
  can't "fix" a test by loosening it: the rule is written in AGENTS.md and
  checked in review.
- **Fast, offline, deterministic tests.** No network in unit or corpus tests;
  all sources replay from `fixtures/`. A full check runs in under a minute.
- **Machine-checked contracts.** The JSON Schemas for config and report are
  generated from the Rust types (`schemars`), and CI fails if they drift.
- **Issue templates** that agents can act on: "wrong verdict" asks for the
  product, version, CVE, and expected versus actual result.

## 9. Built with AI, for AI: the product side

- **MCP server** (`unpatched mcp`, stdio, read-only):
  - `check_stack(path?)`: findings for `unpatched.yml`
  - `is_affected(product, version, cve?)`: an ad-hoc question ("am I hit by X?")
  - `explain(finding_or_cve)`: the evidence and the rule
  - `search_catalog(text)`
  - `db_status()`

  It is published to the MCP Registry (`server.json`), as overfull is.
- **Distribution manifests:** `.claude-plugin/` (plugin with the MCP server and
  skills), `gemini-extension.json`.
- **User skills** in `skills/`:
  - `set-up-unpatched`: create the private repo files from a conversation.
  - `inventory-from-notes`: turn a pasted list, a docker-compose file or
    screenshots of admin pages into `unpatched.yml` entries. The agent proposes
    and `unpatched check` validates against the catalog.
  - `plan-upgrades`: order the open findings into a patch plan.
- **Stable JSON report** with a published schema. Agents consume it, never the
  text output.
- **`llms.txt`** and `llms-full.txt` on the site, generated from `docs/guide`.
- **Optional AI summaries (off by default, phase 8).** In the Action, use
  GitHub Models through the workflow's own token (`permissions: models: read`),
  so no extra key is needed, to write a two-line plain-language summary of a
  vendor advisory. They are always labelled as generated and never affect a
  verdict. (GitHub Models limits and terms need checking first.)
- **Agent evals** (`evals/`), as in overfull: tasks such as "set up unpatched
  for this homelab description" or "is this server affected by CVE-X?", scored
  on whether the produced `unpatched.yml` is valid and the answers are correct.

---

## 10. Automation: the repo maintains itself (MAINTAINING.md)

| When | Workflow | What it does |
| --- | --- | --- |
| Every PR, push | `ci.yml` | fmt, clippy, nextest on Linux/macOS/Windows, corpus, catalog validation, schema drift, `cargo-deny`, MSRV, docs build |
| Daily 03:xx UTC | `build-db.yml` | Sync the sources, build and test the database (smoke corpus against live data), publish to the `db` release with an attestation. If any source fails or shrinks by more than 20%, keep the previous database and open an issue. |
| Weekly | `sources-health` (in `maintenance.yml`) | Ask each source for one known item, and report format changes in one issue |
| Weekly | `catalog-watch` | New KEV vendors or products not in the catalog, catalog entries not checked for a year, and EOL slugs that disappeared → one issue |
| Monthly | `bench` | Accuracy against held-out cases → PR updating `bench/results.json` (shown on the accuracy page) |
| Monthly | `refresh-fixtures` | Re-record the source snapshots → PR (green merges; red means a format changed) |
| Mondays | Dependabot + `automerge.yml` | cargo, actions, docker; patch and minor updates merge once CI passes |
| 1st of the month | `autorelease.yml` | Release PR from `[Unreleased]` when shipped files changed |
| On a tag | `release.yml` | `dist` builds, checksums, cosign / attestations, Homebrew/Scoop/Nix manifests, Docker image, crates.io, MCP Registry |
| Hourly | `watchdog.yml` | An issue per failing automation run; closed when it next succeeds |
| Weekly | `codeql.yml`, `scorecard.yml` | Security scanning |

The watchdog, automerge, autorelease and packaging scripts are adapted from
overfull's.

---

## 11. Documentation

`docs/guide/` is the single source, rendered by the site (same Astro setup as
overfull) and summarised into `llms.txt`:

| Page | Content |
| --- | --- |
| `index.md` | What it is, who it's for, what it is not |
| `start-github.md` | The private repo in 5 minutes (the main path) |
| `start-cli.md` / `start-docker.md` | Local and homelab |
| `config.md` | `unpatched.yml` reference (generated from the schema, with examples) |
| `findings.md` | Verdicts, buckets, every rule id, how to read an issue |
| `notifications.md` | Each channel, its secret, an example message |
| `catalog.md` | Supported products (generated), and how to ask for one |
| `data.md` | Every source, refresh times, licenses, what happens when one fails |
| `accuracy.md` | Method and the latest bench numbers; honest limits |
| `privacy.md` | What leaves your machine (OSV queries for purls; nothing else) |
| `with-an-agent.md` | MCP, plugin, skills |
| `faq.md` | "Why not Dependabot/Trivy/OpenCVE?", "Why is this unknown?" |
| `migrate-from-cvewatch.md` | For existing users: what changed, the v2 tag |

README: a 30-second pitch, a screenshot of an issue and a digest, the
two-file quick start, and links. No badge wall, no feature-emoji list.

---

## 12. Migrating the current repository

1. Tag the current `main` as `v2-final` and mark the last Go release as final.
   Its release notes point to the new tool.
2. On a branch: delete the Go code and its config (`cmd/`, `internal/`, `pkg/`,
   `go.*`, `Taskfile.yml`, `.golangci.yml`, `.goreleaser.yml`,
   `config.yaml.example`). Keep LICENSE and update the community files.
3. Add the Rust workspace, AGENTS.md and the CI skeleton. Merge once CI is green.
4. Build phases 2–6 in PR-sized steps (§13).
5. At launch: rename the repo `CVEWatch` → `unpatched` (GitHub redirects the old
   URLs and clones), new logo, release `v1.0.0` of `unpatched`. The version
   restarts with the new name, and the Go releases stay listed under `v2.x`.

---

## 13. Phases

Each phase is a series of small PRs. A phase ends when its acceptance check
passes.

| # | Phase | Main work | Done when |
| --- | --- | --- | --- |
| 0 | **Decide** | This plan, the name, ADR-0001…0007, CONTEXT.md | You approve this plan |
| 1 | **Reset** | `v2-final` tag, remove Go, Cargo workspace, AGENTS.md, `cargo xtask check`, CI on 3 OSes, deny, Dependabot, watchdog | An empty `unpatched --version` builds and releases in a dry run on all targets |
| 2 | **Data** | Source modules with fixtures, database schema and builder, `build-db.yml`, the `db` release, sources-health, license review, NOTICE | The daily database publishes on its own for 7 days in a row; size and freshness are recorded |
| 3 | **Core** | Version schemes (property tests, fuzzing), `vers` ranges, catalog format with 50 products, verdicts, buckets, rules, ≥ 60 corpus cases | Corpus green; FortiOS, Ivanti, Nextcloud, PostgreSQL, WordPress and Synology cases give the expected verdicts on live data |
| 4 | **Deliver** | `check`/`explain`/`init`/`db` commands, text/JSON/Markdown/SARIF output, state, issues notifier, Telegram/Slack/Discord/ntfy/email/webhook, `action.yml`, `templates/github` | A test private repo receives correct issues and a digest for 14 days with no repeats; issues close when the config shows the fixed version |
| 5 | **AI surfaces** | MCP server, skills, plugin and extension manifests, schemas, evals harness | An agent answers "am I affected by CVE-X" through MCP correctly in the evals |
| 6 | **Docs and site** | The guide pages, generated catalog and config pages, accuracy page, llms.txt, README, migration page | Someone new to the project sets it up from the README alone (tested with an agent and a person) |
| 7 | **Launch** | `v1.0.0`, repo rename, Homebrew/Scoop/Nix/Docker/crates.io/MCP Registry, a short announcement | Install by any listed method gives a working `unpatched check` |
| 8 | **After** | `unpatched scan` (dpkg/apk/rpm/brew/winget/docker), 200 products, SBOM input (CycloneDX/SPDX), MSP multi-client summary on Pages, optional AI summaries | Decided per item after launch, from real use |

Phases 2 and 3 can overlap: the core can be built against the fixtures while
the live pipeline is being hardened.

---

## 14. Risks

| Risk | Mitigation |
| --- | --- |
| Messy version data for appliances leads to wrong verdicts | Vendor CSAF has top precedence; `unknown` instead of guessing; the corpus grows from every report; a "wrong verdict" issue template |
| A source changes format or goes away (NVD backlog, CVE program funding) | Several sources per fact, sources-health, keeping the last good database, the EUVD/CIRCL fallbacks |
| The database gets too big for releases | Only catalog products go in the database; packages are queried live from OSV; zstd; measured in phase 2 |
| GitHub disables idle scheduled workflows | The state commit is activity; the digest includes a heartbeat |
| A user puts their stack in a public repo | `init --github` warns; the Action warns in its log when the repo is public |
| Catalog upkeep becomes the bottleneck | catalog-watch plus the `add-product` skill; entries show their `checked` date; community PRs through a template |
| Licensing of combined data | Legal read in phase 2; only ids and facts stored; NOTICE file |

---

## 15. Questions for you

1. **Name:** `unpatched`, or one of the alternatives?
2. **Version numbering:** restart at `v1.0.0` under the new name (proposed), or
   continue as `v3`?
3. **Site:** reuse overfull's Astro setup (proposed), or a lighter mdBook?
4. **Default notification:** GitHub Issues only (proposed; no secrets), or
   issues plus a weekly digest issue?
5. **License:** keep MIT (proposed), or MIT OR Apache-2.0 (the Rust convention)?
6. **Catalog v1:** fine to pick the 50 products from KEV frequency and
   awesome-selfhosted, or do you have a list of what you run?

---

## 16. Review round 2: problems found and decisions

This section was written after grilling the plan above. Where it differs
from an earlier section, this one wins.

### Bugs and wrong assumptions

1. **The 60-day schedule pause only hits public repos.** GitHub disables
   scheduled workflows after 60 idle days only in *public* repositories. We
   tell people to use private repos, so the "state commit as a heartbeat" idea
   is not needed, and it was harmful: it needs `contents: write` and fails on
   protected default branches. **Decision:** the Action never commits. It
   needs only `issues: write`.
2. **State lives in GitHub Issues, not in a committed file.** Each finding issue
   carries a hidden marker (`<!-- unpatched:finding=<key> -->`). One pinned
   "unpatched status" issue is the dashboard, kept current on every run, and
   holds the delivery state for other channels (which messages were sent) in a
   hidden JSON block. The CLI keeps `.unpatched/state.json` locally. Same state
   model, two stores behind one trait.
3. **NVD bulk feeds exist again and need no key.** Yearly JSON 2.0 feeds
   (`nvdcve-2.0-<year>.json.gz`, about 25 MB for 2024) plus a `modified` feed
   every 2 hours, each with a `.meta` file holding a SHA-256. Checked
   2026-11-23. **Decision:** `build-db` uses the feeds, not the
   rate-limited API.
4. **CVE.org data has the CISA ADP container inside.** `cvelistV5` records
   already carry CISA Vulnrichment (SSVC exploitation, automatable).
   **Decision:** no separate vulnrichment source. `build-db` takes a
   shallow clone of `cvelistV5` in Actions.
5. **Source "precedence" was wrong for a security tool.** CSAF is not in v1, and
   picking one source over another hides bugs in the higher-ranked one.
   **Decision:** each source is evaluated on its own and the verdict is
   combined:
   - `affected` if any source with a parseable range says affected
   - `not-affected` only if every source with data says not affected and at
     least one has data
   - otherwise `unknown`

   Conflicts are shown in `explain`. When in doubt, report.
6. **CSAF parsing is a project of its own.** Moved to phase 8. v1 takes the fix
   version from range upper bounds (`lessThan`, `versionEndExcluding`), and
   the "latest in your branch" from endoflife.date.
7. **Rejected and disputed CVEs.** Rejected records are dropped and their open
   issues closed with a note. Disputed ones are kept, with a label.
8. **The database release needs a bootstrap.** Until `build-db` has run
   once, there is no `db` release. **Decision:** the CLI can build the
   database itself (`unpatched db build`, slow, used by CI and by people who
   do not trust our build). `check` also accepts `--db <path>`.
9. **The Action cannot fetch a binary before the first release.** **Decision:**
   `action.yml` takes a `version` input (default: the Action's own tag) and a
   `binary` input (a path, for CI and forks). It verifies the SHA-256 against
   the release's `SHA256SUMS`.
10. **The timing between `build-db` and user runs.** Users' default cron is
    06:17 UTC; `build-db` runs at 02:41 UTC and takes well under an hour.
11. **Product catalog ids versus CPE truth.** A wrong `cpe` id in the catalog
    silently means "no vulnerabilities". **Decision:** `cargo xtask catalog
    verify` (network, weekly in `maintenance`) checks that every `cpe` and
    `cna` key matches at least one record. A product whose keys match nothing
    in the database is marked "unverified" in the output, so it is never read
    as safe.

### Feature requests accepted into v1

- **Ignore / accept-risk entries** (a VEX-style "not affected because…"):
  ```yaml
  ignore:
    - cve: CVE-2024-1234
      product: nextcloud        # optional, else all
      reason: "app disabled"
      until: 2027-01-31         # required: no silent forever
  ```
  An expired ignore becomes a finding again.
- **Upgrade target.** Every finding shows: the minimum fixed version, and the
  latest release in the same cycle (endoflife.date) when it is newer.
- **Several instances** of the same product with different versions: one
  stack item each, with `name` to tell them apart.
- **`unpatched check --exit-code`** returns non-zero when there are `now`
  findings, so the tool can gate CI or a cron alert.
- **A "nothing to do" heartbeat** in the digest and the status issue, with the
  database date, so silence never means "broken".
- **Data freshness is a finding:** if the database is older than 3 days, the
  status issue says so, and the run fails at 7 days.

### Rejected or deferred

- Uploading SARIF to the GitHub Security tab needs Advanced Security on
  private repos. SARIF output stays; uploading is the user's choice.
- Email over SMTP adds a dependency and most users get the issue emails from
  GitHub anyway. **Deferred** to phase 8; the webhook covers the rest.
- A web dashboard on GitHub Pages: deferred (the status issue is the dashboard).

### Answers to §15 (decided without asking, as requested)

1. Name: `unpatched`.
2. Versions: the crate starts at `0.1.0`; `1.0.0` comes at launch. Go releases stay as `v2.x`.
3. Site: **mdBook**, not Astro. It's Rust-native and needs no Node toolchain
   to build docs for a Rust project. `llms.txt` is generated by `xtask`.
4. Default notification: GitHub Issues plus the status issue. Other
   channels are opt-in.
5. License: MIT, unchanged.
6. Catalog v1: about 50 products from KEV vendor frequency and common
   self-hosted software, each checked against real data.

### What "implement everything" covers in PR #18

Phases 1–6 in full, and the tooling for phase 7 (release workflow, packaging,
manifests). What stays with the owner:
- renaming the repository
- running the first release
- the crates.io and MCP Registry tokens
- approving the `release` environment
- turning on GitHub Pages
