---
name: add-source
description: Add a new data source to unpatched (a vendor feed, a mirror, another exploit list). Covers the module contract in crates/unpatched-sources, fixtures, the database builder, the source id and the tests. Use when asked to support a new source of vulnerability, exploit or end-of-life data.
---

# Add a source

Read `AGENTS.md`, `CONTEXT.md` and `docs/guide/data.md`
first. A source must work without an account or an API key. If it needs one,
stop and say so: it does not fit the product.

## The contract

`crates/unpatched-sources` has one module per source (`kev.rs`, `epss.rs`,
`osv.rs`, ...). Each module has:

- `parse_*` functions: pure, bytes in, `unpatched-core` types out. No network,
  no files, no clock. Bad or unexpected input returns an error with a message
  that says what was wrong; it never panics and never yields a guessed value.
- `fetch_*` functions: the network, through the shared `Http` client (fixed
  User-Agent, retries, timeouts). A new source never builds its own client.
- Output types from `unpatched-core` (`Vulnerability`, `AffectedRange`,
  `Signals`, `EolCycle`, ...). If the source needs a new field, change core
  deliberately and update every user.

## Steps

1. **Record a fixture.** Fetch real data, trim it to a few records that cover
   the odd cases (a rejected record, a missing field, a multi-value row), save
   it in `fixtures/<source>/`, and add a row to `fixtures/README.md` (URL, date,
   how it was trimmed). Never write fixture data by hand or from memory.
2. **Add the id.** A new variant in `SourceId` (`crates/unpatched-core/src/model.rs`)
   with a doc comment, kebab-case in JSON. Check the schemas: run
   `cargo xtask check`, and regenerate whatever it says is out of date.
3. **Write `parse_*` first, with tests** that read the fixture (see
   `testutil::fixture`). Cover: the normal record, each odd case, empty input,
   truncated input, an unknown field.
4. **Write `fetch_*`** on `Http`. Add a `wiremock` test for the success path and
   for a 404 or 5xx.
5. **Wire it into the builder** in `crates/unpatched-db/src/build.rs`, the
   schema in `schema.rs` if it needs a table (bump `SCHEMA_VERSION` for an
   incompatible change), the reader in `read.rs`, and `sources_health` in
   `health.rs` (one live probe for a known item).
6. **Use it in matching only through core.** `evaluate` treats every source
   on its own and combines verdicts (see the comments at the top of `crates/unpatched-core/src/matching.rs`).
   Do not add a precedence. A source with no data for an item says nothing
   about it; that is never "not affected".
7. **Corpus.** Add a case where the new source changes a verdict or a signal.
8. **Docs and attribution.** Add the license and terms to `NOTICE` and the data
   page in `docs/guide/` when it exists. Add a `CHANGELOG.md` line.
9. Run `cargo xtask check`.

## Rules

- No network in tests.
- Be polite to the source: use its documented rate limits, cache what you can.
- Say in the pull request what happens when the source is down or its format
  changes (the daily database build keeps the last good database and opens an
  issue).
