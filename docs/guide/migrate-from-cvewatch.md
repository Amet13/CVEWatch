# Coming from CVEWatch

<!-- description: For people who used CVEWatch (the Go tool): what changed in unpatched, how old commands and config map to the new ones, and where the old versions are. -->

This project used to be CVEWatch, a command-line tool written in Go (versions 1.x
and 2.x). It has been rewritten from scratch in Rust and renamed `unpatched`. The
Go tool is not developed any more. Its releases stay listed on the releases page,
and its last release is `v2.6.1`.

The old tool and the new one answer different questions:

- **CVEWatch** searched NVD for CVEs by date, CVSS and product keywords, and could
  watch for new ones. You read a list of CVEs and decided what mattered.
- **unpatched** starts from a list of what you actually run, with versions, and
  tells you only when one of those is affected, with the fixed version, ranked by
  exploitation. You do not read CVE lists.

## What changed

| | CVEWatch (Go, 1.x and 2.x) | unpatched (Rust, 0.x) |
| --- | --- | --- |
| Command | `cvewatch` | `unpatched` |
| Config | `~/.cvewatch/config.yaml`: NVD settings, cache, filters, product keywords | `unpatched.yml`: what you run (product, version, exposure) and where to be told |
| Question | "Which new CVEs mention these keywords?" | "Is the version I run affected, and how urgent is it?" |
| Data | NVD API, live, with an optional API key | A daily prebuilt database from CVE.org, NVD, CISA KEV, EPSS, endoflife.date and exploit indexes. No key. |
| Ranking | CVSS score filter | Exploitation first: KEV, SSVC, public exploits, EPSS, internet exposure |
| Run it | On your machine, in watch mode | A daily GitHub Action in a private repository (or the command line, or Docker) |
| Output | Table, JSON, YAML, CSV, text | Text, JSON, Markdown, SARIF; GitHub issues; chat messages |
| Matching | Keyword and CPE patterns | Catalog products with version-aware comparison; packages through OSV |

## Command map

| CVEWatch | unpatched |
| --- | --- |
| `cvewatch init` | `unpatched init` (writes `unpatched.yml`; `--github` adds the workflow) |
| `cvewatch search --min-cvss 7` | `unpatched check` (your stack, ranked by exploitation). To look at one CVE: `unpatched explain CVE-...`. To ask about a product and version: `unpatched check` with a scratch file, or the MCP tool `is_affected`. |
| `cvewatch info CVE-...` | `unpatched explain CVE-...` |
| `cvewatch watch --interval 5m` | The daily Action, or cron with `unpatched check --notify`. There is no watch mode: the database is built daily. |
| `cvewatch health` | `unpatched db info` and `unpatched db sources-health` |
| `--format json\|yaml\|csv\|table` | `unpatched check --format text\|json\|markdown\|sarif` |

There is no equivalent of a free-text search over all CVEs. unpatched is not a CVE
browser; use [NVD](https://nvd.nist.gov) or [cve.org](https://www.cve.org) for
that.

## Move your watch list

Your old `products:` entries were keywords and CPE patterns for products you
wanted to hear about. Turn each into a stack entry with a catalog id and the
version you really run:

1. Run `unpatched search <name>` for each product. If it is not in the
   [catalog](catalog.md), [ask for it](catalog.md#ask-for-a-product).
2. Write the entry with the exact version:

   ```yaml
   version: 1
   stack:
     - product: nextcloud
       version: 29.0.3
       exposure: internet
   ```

3. Follow [Start with GitHub](start-github.md), or run `unpatched check`.

Settings with no equivalent are dropped on purpose: the NVD API key, the cache and
rate limits (the database is prebuilt), and date and CVSS filters.

## Versions and the old releases

unpatched continues the version line: CVEWatch was 2.x, unpatched starts at 3.0.0. Go releases remain
under the 1.x and 2.x numbers and are not updated. If you need the old tool, take
a release from the [releases page](https://github.com/Amet13/unpatched/releases)
or check out the `v2.6.1` tag. It is not maintained and will not get fixes.

The repository is renamed from `Amet13/CVEWatch` to `Amet13/unpatched` at launch.
GitHub redirects the old address, including clones.
