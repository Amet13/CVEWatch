# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and this project follows [Semantic Versioning](https://semver.org/).

History: versions 1.x and 2.x were CVEWatch, a Go command-line tool. It is not developed any more. Its releases stay listed on the releases page, and its last commit is tagged `v2-final`. This changelog starts with the Rust rewrite.

## [Unreleased]

## [3.0.0] - 2026-11-24

### Added

- `unpatched`, a full rewrite in Rust of the Go tool CVEWatch: list the software you run, and a daily GitHub Action tells you only when something you run is affected, what to do, and whether it is being exploited. Keyless and open data only, and no servers: the database is built daily in this repository and published on the rolling `db` release.
- The `unpatched` command line: `check` (text, JSON, Markdown and SARIF output, `--exit-code`, `--notify`, `--dry-run`), `init` (questions in a terminal, a commented template otherwise; `--github` adds the daily workflow), `explain` (a rule, a CVE or a finding key), `search`, `catalog list|show`, `db update|info|build|sources-health`, `mcp` and `schema config|report`. Exit codes: 1 fix today (with `--exit-code`), 2 usage or config error, 3 data error, 4 delivery error.
- The GitHub Action (`uses: amet13/unpatched@v3`): downloads the release binary, checks its SHA-256, caches it, and writes the run summary to the job. Inputs: `version`, `binary`, `config`, `db`, `dry-run`, `args`. `templates/github/` has a starting `unpatched.yml` and workflow.
- The end-to-end corpus (`corpus/`, 70+ cases) and `cargo xtask corpus new <name>`; `cargo xtask schema` writes `schema/unpatched.schema.json` and `schema/report.schema.json`.
- Findings and reports show the product's display name (`FortiOS 7.2.5`) instead of its id, and `Finding` has a new `product_name` field.
- The user guide (mdBook, `docs/guide/`, published at https://amet13.github.io/unpatched/), a new README, and `llms.txt` and `llms-full.txt`. `cargo xtask docs` regenerates the parts that come from the code (config reference, rules, catalog, command help, examples), and `cargo xtask check` fails when they are out of date.
- Every report has `items`: one recommendation per stack item (counts per bucket, the smallest upgrade that fixes the most findings, how many it fixes, end-of-life and unfixed counts). `check` prints it first, as one line per item; the digest uses these lines only.
- `Finding.fixed_after`: when a source only gives an inclusive upper bound (`<= 9.8`), the advice reads "Upgrade to a release after 9.8" (with the latest release of the cycle when known).
- New threshold `cvss_week_exposed` (default 7.0).
- `check --notify` in GitHub Actions warns (`::warning::`) when the repository is public, because the stack and the issues are then visible to everyone.
- `--now` is a hidden global option, used by `check`, `explain` and `db info`.
- `unpatched db build --strict` (fails, and writes nothing, when any source failed) and `unpatched db info --json` (counts and sources, for scripts). The daily database build uses both, and refuses to replace the published database when it has more than 20% fewer vulnerabilities or KEV entries.
- `unpatched db update` tries again (after 20 s, then 60 s) when the release is being replaced and the checksum does not match yet, or the file is not there.
- Repository automation: CI on three operating systems, the daily database build, releases with `dist`, a Docker image, and weekly and monthly upkeep (see MAINTAINING.md).

### Changed

- `week` needs more than exposure: an affected finding is `week` when EPSS is at or above `epss_week`, or CVSS is at or above `cvss_week`, or the item is internet-facing and CVSS is at or above `cvss_week_exposed`. An unknown CVSS score does not count. `UNP-EXPOSED` now means that. A first real run put 220 findings in `week` because of exposure alone.
- A source that only says "all versions" (with a few unaffected versions) no longer beats a source with specific ranges that exclude your version: the verdict is `unknown` with `UNP-CONFLICT` (ADR-0006).
- GitHub issues are per stack item, not per CVE: one issue lists the item's findings by bucket, is updated as they change, and is closed when none of `now`, `week`, `eol` or `unknown` are left. The hidden marker is now `<!-- unpatched:item=... -->` and the delivery state tracks items for issues and findings for chat alerts.
- Finding titles in text, Markdown and issue output are the first sentence, at most 140 characters, unless `--verbose`. JSON keeps the full text.
- `unpatched explain <CVE>` no longer says "not affected" for stack items the vulnerability is not about; it prints one line saying how many are not concerned.
- CVSS and EPSS scores are `f64`, so JSON shows `9.6` and not `9.600000381469727`.
- A product that is in the catalog but not in the database now says so ("the database has no data for product ... yet. Run `unpatched db update`").
- `unpatched init --github` prints `.github/workflows/unpatched.yml` without a stray `./`; every command and argument has a help line; the config schema has a description for every key.
- The project, the crate, the command and the config file are now called `unpatched` (was CVEWatch).
- Everything from the Go tool is removed. The last Go commit is tagged `v2-final`.
