# Contributing to unpatched

Thank you for helping. The most useful contributions are wrong-verdict reports
and new catalog products. Both are small, and both end as a test.

Read [AGENTS.md](AGENTS.md) for the layout and the rules, and
[CONTEXT.md](CONTEXT.md) for the words we use. Be kind: see the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Set up

You need Rust (the repository pins the toolchain in `rust-toolchain.toml`; the
minimum supported version is in `Cargo.toml`, `rust-version`).

```sh
git clone https://github.com/Amet13/unpatched
cd unpatched
cargo xtask check
```

`cargo xtask check` is the one command to run before every commit. It runs
`cargo fmt --check`, clippy (warnings are errors), all tests, and the checks
that generated files are up to date. CI runs the same command. Tests never use
the network: source data is recorded in `fixtures/`.

Optional tools: `cargo install cargo-deny` (licenses and advisories, as in CI),
`mdbook` (the guide), `shellcheck` and `actionlint` (the workflows).

## Adding a product

A product is one file in `catalog/`, named after its id.

1. Check that it is not there: `unpatched search <name>`.
2. Copy a similar file in `catalog/` and change the names: the CPE
   vendor and product, the CNA names used in CVE records, the KEV names, the
   endoflife.date slug, and the versioning scheme (`dotted`, `semver`, `calver`,
   `debian`, `rpm`, `apk`, `pep440`, or a named custom scheme).
3. Pick one CVE that affects it and check the names against the real CVE
   record and NVD entry. A wrong name silently means "no vulnerabilities".
4. Add a corpus case (see below) for that CVE with one affected and one fixed version.
5. Run `cargo xtask catalog build` (it regenerates the file that the code
   reads, never edit that file by hand), then `cargo xtask check`.
6. Set `checked:` to today's date. It means a person looked at the entry.

The `add-product` agent skill does steps 2 to 4 for you; a person still checks
the result.

## Adding a source

Each source is one module in `crates/unpatched-sources`.

- `parse_*` functions are pure: bytes in, core types out. They have unit tests
  against files in `fixtures/`.
- `fetch_*` functions do the network and nothing else.
- The source must work without an account or an API key.
- Check its license and add the attribution to [NOTICE](NOTICE) and to the data
  page of the guide.
- Add it to `unpatched db sources-health` (one known item) so a format change is
  noticed.

## Corpus cases

The corpus is the spec: `corpus/<case>/case.yml` holds a small stack, the data
slice it needs and the findings that must come out. A bug fix starts as a new
failing case. Do not loosen, skip or delete a case to get green. A report
labelled "wrong verdict" gives you the product, version and CVE for the case.

## Commits and pull requests

- Commit subjects are short and in the present tense. A prefix is welcome:
  `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`, `catalog:`.
- One change per pull request. Say what and why; the template has the rest.
- Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for every
  change a user can see.
- Dependency and CI updates are made by Dependabot; see
  [MAINTAINING.md](MAINTAINING.md) for what runs on its own.

## Security

Do not open an issue for a vulnerability in unpatched itself; see
[SECURITY.md](SECURITY.md).

## License

By contributing you agree that your work is released under the [MIT License](LICENSE).
