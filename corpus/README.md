# The corpus

The corpus is the spec. Each folder holds one `case.yml`: a stack, the data it is
checked against, and the findings that must come out. `cargo test -p unpatched
--test corpus` runs every case through `unpatched_core::evaluate` and prints a
diff for each wrong result.

**Every wrong verdict starts as a failing case here.** When `unpatched` says
`not-affected` for something that is affected (or the other way round, or puts a
finding in the wrong bucket), add a case that shows it, see it fail, then fix the
code. `cargo xtask corpus new <name>` writes a starting file. It fails on purpose
(its `description` starts with `TODO`) until you say what the case proves and
write what should come out.

## Format

```yaml
description: One sentence: what this case shows.
now: 2026-11-24T00:00:00Z        # the clock for the run
config: |                        # the text of an unpatched.yml
  version: 1
  stack:
    - product: fortios
      version: "7.2.5"
data:                            # a MemoryDataset
  products: []                   # catalog entries (id, name, vendor, kind, versioning, match, checked)
  vulns: []                      # vulnerabilities with their ranges per source
  signals: {}                    # exploitation signals by vulnerability id
  eol: {}                        # endoflife.date cycles by product id
  unverified: []                 # product ids that match nothing in the data
  info: {schema_version: 1, built_at: 2026-11-23T12:00:00Z, sources: []}
packages: {}                     # OSV-shaped results for `purl` items, by the purl as written in config
expect:                          # every finding that must be reported, and no others
  - key: fortios/CVE-2026-0001
    bucket: now                  # now | week | eol | unknown | fyi
    verdict: affected            # affected | fixed | not-affected | unknown
    rules: [UNP-KEV]             # optional: the exact rule ids, in order
    fixed_in: 7.2.7              # optional: a version, or `none`
    latest_in_cycle: 7.2.11      # optional: a version, or `none`
    fixed_after: 9.8             # optional: a version, or `none` (an inclusive upper bound with no fix named)
    title_contains: (disputed)   # optional
expect_ignored: []               # findings an `ignore` entry covers (same fields as expect)
expect_items:                    # the per-item recommendation (only the items and fields listed are checked)
  - key: fortios                 # the stack item's key
    upgrade_to: 7.2.9            # a version, or `none`
    fixes: 2                     # affected findings that version fixes
    of: 4                        # affected findings
    unfixed: 1                   # affected findings with no known fix
    eol: false
    now: 1                       # findings in the now bucket (also: week)
absent: []                       # keys that must not be reported at all (also not as ignored)
notes_contain: []                # pieces of text that must appear in the report's notes
```

Rules of the format:

- `expect` is exact: a finding that is reported but not listed fails the case, so
  nothing appears by surprise. A quiet result is an empty list.
- Data is written by hand, in the shape the sources produce. Keep it small: one
  product, one or two vulnerabilities. Say in `description` what the case proves.
- Always set `now`; a case never depends on today's date. A database `built_at` more than three days
  before `now` adds a stale-data finding.
- Folder names are lowercase kebab-case and say what the case is about.

The runner also checks that, across all cases, every rule id and every bucket is
expected at least once.
