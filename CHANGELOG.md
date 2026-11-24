# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/) and this project follows [Semantic Versioning](https://semver.org/).

History: versions 1.x and 2.x were CVEWatch, a Go command-line tool. It is not developed any more. Its releases stay listed on the releases page, and its last commit is tagged `v2-final`. This changelog starts with the Rust rewrite.

## [Unreleased]

### Added

- `unpatched`, a full rewrite in Rust of the Go tool CVEWatch: list the software you run, and a daily GitHub Action tells you only when something you run is affected, what to do, and whether it is being exploited. Keyless and open data only, and no servers: the database is built daily in this repository and published on the rolling `db` release.
- The `unpatched` command line: `check` (text, JSON, Markdown and SARIF output, `--exit-code`, `--notify`, `--dry-run`), `init` (questions in a terminal, a commented template otherwise; `--github` adds the daily workflow), `explain` (a rule, a CVE or a finding key), `search`, `catalog list|show`, `db update|info|build|sources-health`, `mcp` and `schema config|report`. Exit codes: 1 fix today (with `--exit-code`), 2 usage or config error, 3 data error, 4 delivery error.
- The GitHub Action (`uses: amet13/unpatched@v0`): downloads the release binary, checks its SHA-256, caches it, and writes the run summary to the job. Inputs: `version`, `binary`, `config`, `db`, `dry-run`, `args`. `templates/github/` has a starting `unpatched.yml` and workflow.
- The end-to-end corpus (`corpus/`, 70+ cases) and `cargo xtask corpus new <name>`; `cargo xtask schema` writes `schema/unpatched.schema.json` and `schema/report.schema.json`.
- Findings and reports show the product's display name (`FortiOS 7.2.5`) instead of its id, and `Finding` has a new `product_name` field.
- Repository automation: CI on three operating systems, the daily database build, releases with `dist`, a Docker image, and weekly and monthly upkeep (see MAINTAINING.md).

### Changed

- The project, the crate, the command and the config file are now called `unpatched` (was CVEWatch).
- Everything from the Go tool is removed. The last Go commit is tagged `v2-final`.
