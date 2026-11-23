# AGENTS.md

Instructions for agents (and people) working on the `unpatched` repository.
Read `PLAN.md` §2, §5 and §16 for what the product does and why, and
`CONTEXT.md` for the words we use.

## Layout

- `crates/unpatched-core`: pure logic (no network, files or clock). The types in
  `model.rs`, `catalog.rs`, `config.rs`, `report.rs` and `rules.rs` are the
  contract between crates; change them deliberately and update every user.
- `crates/unpatched-sources`: one module per data source; `parse_*` functions are
  pure (bytes in, core types out), `fetch_*` functions do the network.
- `crates/unpatched-catalog`: loads the generated catalog
  (`src/catalog.generated.json`, built from `catalog/*.yml` by
  `cargo xtask catalog build`; never edit the generated file by hand).
- `crates/unpatched-db`: SQLite schema, builder and reader (implements `core::Dataset`).
- `crates/unpatched-notify`: rendering (text, Markdown) and channels.
- `crates/unpatched-mcp`: the MCP server.
- `crates/unpatched`: the `unpatched` binary (CLI, config loading, state).
- `xtask/`: repo tasks (`cargo xtask <task>`).
- `catalog/`: one YAML file per product. `fixtures/`: frozen source data for tests.
- `corpus/`: end-to-end cases (stack + data + expected findings). The corpus is the spec.

## Before you commit

```sh
cargo xtask check
```

That runs fmt, clippy (warnings are errors), all tests, and the generated-file
checks. Add or update tests for every behaviour change. Tests never use the
network: record what you need into `fixtures/`. Never skip, ignore or loosen a
test to get green. A wrong verdict is fixed by adding a failing corpus case first.

## Rules of the domain

- Never claim `not-affected` without evidence. If data is missing, conflicting
  or unparseable, the verdict is `unknown`, with the reason.
- No model or heuristic decides a verdict. Every finding lists its evidence and rule ids.
- Nothing needs an account or API key. Secrets only come from environment variables.

## Style

Plain, short English in docs, messages and comments. Errors say what to do
next. `cargo fmt` formats the code. Add a line to `CHANGELOG.md` under
`## [Unreleased]` for every user-visible change.
