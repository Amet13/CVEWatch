# Command reference

<!-- description: Every unpatched command and option, from the program's own help, with the exit codes. -->

`unpatched <command> [options]`. The help below is the program's own, written by
`cargo xtask docs`. Run `unpatched <command> --help` for the same on your machine.

## Global options

These work with every command, before or after its name:

| Option | Meaning |
| --- | --- |
| `--config FILE` | Your stack and settings. Default `unpatched.yml`. |
| `--db FILE` | The vulnerability database. Default `$UNPATCHED_DB`, else the cache folder. |
| `--offline` | No network: no database download and no OSV lookups for packages. |
| `-v`, `--verbose` | More detail: evidence in reports; `-v` info logs, `-vv` debug logs. |
| `--quiet` | Print only what was asked for, and errors. Cannot be used with `-v`. |
| `--color WHEN` | `auto` (default), `always` or `never`. |

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | OK |
| 1 | `check --exit-code` found something to fix today |
| 2 | Usage or configuration error: bad YAML, unknown product, a missing secret |
| 3 | Data error: no database, database too old, a download or source failed |
| 4 | Delivery error: a notification channel or GitHub issue failed |

## Environment variables

| Variable | Meaning |
| --- | --- |
| `UNPATCHED_DB` | The same as `--db`. |
| `UNPATCHED_DB_URL` | Where `check` and `db update` download the database from. Default: the `db` release of `Amet13/unpatched`. |
| `UNPATCHED_CACHE_DIR` | Where the downloaded database is kept. Default: your system's cache folder, plus `unpatched`. |
| `UNPATCHED_TELEGRAM_TOKEN`, `UNPATCHED_SLACK_WEBHOOK`, `UNPATCHED_DISCORD_WEBHOOK`, `UNPATCHED_NTFY_TOKEN`, `UNPATCHED_WEBHOOK_URL`, `UNPATCHED_WEBHOOK_SECRET` | Secrets for [notifications](notifications.md). |
| `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_API_URL` | Used for GitHub issues (set by GitHub Actions). |

## Commands

<!-- generated:start cli-help -->

### `unpatched`

```text
Tells you when software you run has a vulnerability you need to act on

Usage: unpatched [OPTIONS] <COMMAND>

Commands:
  check    Match your stack against the database and print the report
  init     Write a starting unpatched.yml (and, with --github, the workflow)
  explain  Show the evidence: a rule id, a CVE, or a finding key
  search   Find a product in the catalog
  catalog  The products unpatched knows
  db       The vulnerability database
  mcp      Run the MCP server on stdio, for AI agents
  schema   Print a JSON Schema
  help     Print this message or the help of the given subcommand(s)

Options:
      --config <FILE>  Your stack and settings [default: unpatched.yml]
      --db <FILE>      The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --offline        Use no network: no database download and no package (OSV) lookups
  -v, --verbose...     More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet          Print only what was asked for, and errors
      --color <WHEN>   When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help           Print help
  -V, --version        Print version

Exit codes:
  0  ok
  1  `check --exit-code` found something to fix today
  2  usage or configuration error
  3  data error (no database, database too old, a download or source failed)
  4  delivery error (a notification channel or GitHub issue failed)

Docs: https://amet13.github.io/unpatched/
```

### `unpatched check`

```text
Match your stack against the database and print the report

Usage: unpatched check [OPTIONS]

Options:
      --config <FILE>    Your stack and settings [default: unpatched.yml]
      --format <FORMAT>  How to print the report [default: text] [possible values: text, json, markdown, sarif]
      --db <FILE>        The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --output <FILE>    Write the report to FILE instead of stdout. A file named by $GITHUB_STEP_SUMMARY is appended to, so other steps keep their text
      --exit-code        Exit with 1 when something has to be fixed today
      --offline          Use no network: no database download and no package (OSV) lookups
      --notify           Also send the findings to the configured channels (issues, chat)
  -v, --verbose...       More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --dry-run          With --notify: send and write nothing; print what would happen
      --quiet            Print only what was asked for, and errors
      --color <WHEN>     When to use colour [default: auto] [possible values: auto, always, never]
      --github           Keep delivery state and issues in GitHub (automatic inside GitHub Actions)
      --allow-stale      Do not fail when the database is older than `stale_fail_days`
  -h, --help             Print help
  -V, --version          Print version
```

### `unpatched init`

```text
Write a starting unpatched.yml (and, with --github, the workflow)

Usage: unpatched init [OPTIONS]

Options:
      --config <FILE>  Your stack and settings [default: unpatched.yml]
      --github         Also write .github/workflows/unpatched.yml
      --db <FILE>      The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --force          Overwrite files that exist
      --offline        Use no network: no database download and no package (OSV) lookups
  -v, --verbose...     More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet          Print only what was asked for, and errors
      --color <WHEN>   When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help           Print help
  -V, --version        Print version
```

### `unpatched explain`

```text
Show the evidence: a rule id, a CVE, or a finding key

Usage: unpatched explain [OPTIONS] <TARGET>

Arguments:
  <TARGET>  `UNP-KEV`, `CVE-2024-21762` or a finding key such as `office-firewall/CVE-2024-21762`

Options:
      --config <FILE>  Your stack and settings [default: unpatched.yml]
      --db <FILE>      The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --offline        Use no network: no database download and no package (OSV) lookups
  -v, --verbose...     More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet          Print only what was asked for, and errors
      --color <WHEN>   When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help           Print help
  -V, --version        Print version
```

### `unpatched search`

```text
Find a product in the catalog

Usage: unpatched search [OPTIONS] <TEXT>...

Arguments:
  <TEXT>...  Words from the product's name, vendor or alias

Options:
      --config <FILE>  Your stack and settings [default: unpatched.yml]
      --db <FILE>      The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --offline        Use no network: no database download and no package (OSV) lookups
  -v, --verbose...     More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet          Print only what was asked for, and errors
      --color <WHEN>   When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help           Print help
  -V, --version        Print version
```

### `unpatched catalog list`

```text
List the products

Usage: unpatched catalog list [OPTIONS]

Options:
      --config <FILE>  Your stack and settings [default: unpatched.yml]
      --kind <KIND>    Only this kind of product [possible values: appliance, app, os, database, server, library, desktop, cms]
      --db <FILE>      The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --offline        Use no network: no database download and no package (OSV) lookups
  -v, --verbose...     More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet          Print only what was asked for, and errors
      --color <WHEN>   When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help           Print help
  -V, --version        Print version
```

### `unpatched catalog show`

```text
Show one product (id or alias)

Usage: unpatched catalog show [OPTIONS] <ID>

Arguments:
  <ID>

Options:
      --config <FILE>  Your stack and settings [default: unpatched.yml]
      --db <FILE>      The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --offline        Use no network: no database download and no package (OSV) lookups
  -v, --verbose...     More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet          Print only what was asked for, and errors
      --color <WHEN>   When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help           Print help
  -V, --version        Print version
```

### `unpatched db update`

```text
Download the latest prebuilt database now

Usage: unpatched db update [OPTIONS]

Options:
      --config <FILE>  Your stack and settings [default: unpatched.yml]
      --db <FILE>      The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --offline        Use no network: no database download and no package (OSV) lookups
  -v, --verbose...     More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet          Print only what was asked for, and errors
      --color <WHEN>   When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help           Print help
  -V, --version        Print version
```

### `unpatched db info`

```text
Show what is in the database and how old it is

Usage: unpatched db info [OPTIONS]

Options:
      --config <FILE>  Your stack and settings [default: unpatched.yml]
      --db <FILE>      The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --offline        Use no network: no database download and no package (OSV) lookups
  -v, --verbose...     More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet          Print only what was asked for, and errors
      --color <WHEN>   When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help           Print help
  -V, --version        Print version
```

### `unpatched db build`

```text
Build the database from the sources (slow; CI does this daily)

Usage: unpatched db build [OPTIONS] --out <FILE>

Options:
      --config <FILE>     Your stack and settings [default: unpatched.yml]
      --out <FILE>        Where to write. A name ending in `.zst` is compressed
      --cvelist <DIR>     A checkout of CVEProject/cvelistV5. Without it CVE.org is skipped
      --db <FILE>         The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --nvd-years <A..B>  NVD years to read, like `2018..2026` (default: all)
      --offline           Use no network: no database download and no package (OSV) lookups
      --nvd-cache <DIR>   Keep downloaded NVD feeds here between builds
  -v, --verbose...        More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet             Print only what was asked for, and errors
      --color <WHEN>      When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help              Print help
  -V, --version           Print version
```

### `unpatched db sources-health`

```text
Ask every source for one known item; fails when any source fails

Usage: unpatched db sources-health [OPTIONS]

Options:
      --config <FILE>  Your stack and settings [default: unpatched.yml]
      --db <FILE>      The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --offline        Use no network: no database download and no package (OSV) lookups
  -v, --verbose...     More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet          Print only what was asked for, and errors
      --color <WHEN>   When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help           Print help
  -V, --version        Print version
```

### `unpatched mcp`

```text
Run the MCP server on stdio, for AI agents

Usage: unpatched mcp [OPTIONS]

Options:
      --config <FILE>  Your stack and settings [default: unpatched.yml]
      --db <FILE>      The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --offline        Use no network: no database download and no package (OSV) lookups
  -v, --verbose...     More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet          Print only what was asked for, and errors
      --color <WHEN>   When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help           Print help
  -V, --version        Print version
```

### `unpatched schema`

```text
Print a JSON Schema

Usage: unpatched schema [OPTIONS] <WHICH>

Arguments:
  <WHICH>  `config` (unpatched.yml) or `report` (check --format json) [possible values: config, report]

Options:
      --config <FILE>  Your stack and settings [default: unpatched.yml]
      --db <FILE>      The vulnerability database (default: $UNPATCHED_DB, else the cache directory) [env: UNPATCHED_DB=]
      --offline        Use no network: no database download and no package (OSV) lookups
  -v, --verbose...     More detail (evidence in reports, `-v` info logs, `-vv` debug logs)
      --quiet          Print only what was asked for, and errors
      --color <WHEN>   When to use colour [default: auto] [possible values: auto, always, never]
  -h, --help           Print help
  -V, --version        Print version
```

<!-- generated:end -->
