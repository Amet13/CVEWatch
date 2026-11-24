# Maintaining unpatched

The repository keeps itself up to date. Workflows open pull requests for every
update, merge them when CI passes, build the database every day, release on their
own, and open an issue when something needs a person. This page lists what runs,
when, and what is still yours.

## What runs on its own

| When | Workflow | What it does |
| --- | --- | --- |
| Every pull request and push | `ci.yml` | `cargo xtask check` on Linux (fmt, clippy, tests, generated files), clippy and tests on macOS and Windows, MSRV (`cargo check` on 1.90), `cargo deny`, markdown lint and the mdBook build, `actionlint` and `shellcheck`, the Docker build, and the action smoke test (skipped until `action.yml` exists). One job, "CI passed", sums them up. |
| Sundays | `ci.yml` | The full CI on `main`, so a change outside the repository (a new Rust release, a yanked crate) is noticed without a commit. |
| Daily 02:41 UTC | `build-db.yml` | Builds the database from the sources (`db build --strict`: any failed source fails the run), smoke-checks it, compares it with the published one (more than 20% fewer vulnerabilities or KEV entries: nothing is published and the issue "Database build refused" opens), and replaces the assets of the rolling `db` release: `unpatched-db.sqlite.zst` first, then `SHA256SUMS` (the CLI retries for a minute when it sees the two disagree). If the build fails, the previous assets stay and the watchdog opens an issue. |
| Thursdays | `maintenance.yml` (toolchain) | Opens "A newer Rust is out" when the stable Rust is newer than the pin in `rust-toolchain.toml`. It closes itself when the pin catches up. See "Bumping Rust". |
| Wednesdays | `maintenance.yml` (health) | `cargo xtask catalog verify` and `unpatched db sources-health`. Problems go in one issue, "Sources need a look", that closes itself when the next run is clean. |
| 3rd of the month | `maintenance.yml` (bench) | `cargo xtask bench`, as a pull request with the new accuracy numbers. Skipped until the task exists. |
| Mondays | Dependabot | Pull requests for Cargo crates, GitHub Actions and the Docker base image. Only versions at least 7 days old are proposed (30 days for a major crate version; security updates at once). Patch and minor updates are labelled `automerge`; majors come in their own pull request and wait for you. |
| When ci or codeql finishes | `automerge.yml` | Merges a same-repository pull request labelled `automerge` (opened by you, by the repository's own workflows or by Dependabot) once every check on its head commit has passed. A pull request behind `main` gets `main` merged in and CI runs again. |
| 1st of the month | `autorelease.yml` (propose) | When shipped files changed since the last release, opens "Release vX.Y.Z": a minor bump when `[Unreleased]` has `### Added` entries, else a patch bump (never a major one), the version in `Cargo.toml`, and a dated CHANGELOG section with the commit subjects. |
| Daily | `autorelease.yml` (publish) | When `Cargo.toml` has a version with no tag yet and CI passed on `main`, creates the tag and starts `release.yml` on it. Never makes the very first release. |
| On a release | `release.yml` | `dist` builds archives for Linux (x86_64, aarch64, musl), macOS (x86_64, arm64) and Windows (x86_64), the shell and PowerShell installers, the Homebrew formula (`unpatched.rb`, a release asset: there is no tap), checksums and attestations, and creates the GitHub release. Then `publish-crates.yml` (crates.io, one crate at a time in dependency order; versions already there are skipped, and when crates.io limits new crates it waits 11 minutes and tries again, up to about 85 minutes) and `publish-docker.yml` (`ghcr.io/amet13/unpatched`, amd64 and arm64) run in the `release` environment, then the MCP Registry entry (`server.json`) is updated; a failure of that last job does not fail the release. `action-e2e.yml` runs the Action with the released binary on Linux, macOS and Windows, and only then does the major tag (`v3`) move: it needs the GitHub release and that test, not crates.io or Docker, and it never moves backwards. |
| On changes to the docs | `pages.yml` | Builds the guide with mdBook and publishes it to GitHub Pages. Does nothing until `book.toml` exists. |
| After any of the above, and hourly | `watchdog.yml` | Opens "Automation failed: …" when a run on `main`, a scheduled run, an automation branch or a release tag fails, and closes it when the newest run succeeds. A job that never got a runner is re-run once. The hourly sweep also covers runs the automation started itself, and restarts a run stuck in the queue. |
| Weekly | `codeql.yml`, `scorecard.yml` | CodeQL for Rust and for the workflows, and the OpenSSF Scorecard. |

Every pull request goes through the same CI as a person's. Nothing is merged on
a red or missing check.

## What stays with a person

- **The first release.** Nothing makes the first release (`v3.0.0`) for you. See
  "First-time steps" below. After that, `autorelease.yml` makes the patch and
  minor releases. A major release (`4.0.0`, …) is always yours: change the
  version in `Cargo.toml` and in the path dependencies, move `[Unreleased]` in
  `CHANGELOG.md`, and merge.
- **Major updates.** Dependabot's major-version pull requests are not labelled
  `automerge`. Read the changelog of the dependency, then merge or close.
- **Wrong verdicts.** Each report becomes a failing corpus case, then a fix. A
  person (or an agent that a person checks) reviews the case.
- **New products.** A person checks every catalog entry: `checked:` is the date it
  was last verified.
- **"Sources need a look".** A source that changed its format needs a code change
  in `crates/unpatched-sources`. An outage needs nothing: the last good database stays.
- **Issues the automation opens.** Each links the failing run. Fix the cause in a
  pull request; the issue closes itself on the next successful run.
- **The release file `release.yml`.** It is generated by `dist` and edited once to
  add `workflow_dispatch` (so `autorelease.yml` can start it on a tag). After
  `dist generate`, put the edit back (it is marked `CUSTOM`), or run
  `dist init` again in a pull request and review the diff.

## First-time steps

Do these once. The workflows cannot do them for you.

1. **Rename the repository** `Amet13/CVEWatch` to `Amet13/unpatched` (Settings →
   General). GitHub redirects the old URLs. Tag the last Go commit `v2-final`
   before the rewrite is merged: `git tag v2-final dba17e2 && git push origin v2-final`.
   Delete the stray tags `rm` and `tm` (`git push origin :refs/tags/rm :refs/tags/tm`),
   so no tag looks like a version to `autorelease.yml` or the Action.
2. **Allow Actions to open pull requests:** Settings → Actions → General →
   Workflow permissions → tick "Allow GitHub Actions to create and approve pull
   requests". Without it the maintenance workflows cannot open their pull requests.
3. **Protect `main`:** a ruleset that requires the "CI passed" check (source:
   GitHub Actions). That one job passes only when every CI job passed or was
   skipped on purpose, so the list never needs updating when jobs change. Do not
   require reviews: the automation's merges would be refused.
4. **Turn on GitHub Pages:** Settings → Pages → Source: GitHub Actions. The guide
   appears at `https://amet13.github.io/unpatched/` after `pages.yml` runs.
5. **Create the `release` environment:** Settings → Environments → New
   environment → `release` (the first release run also creates it). Add yourself
   as a required reviewer: crates.io and Docker publishing then wait for your
   approval, so a compromised dependency cannot publish with no person involved.
6. **Add the crates.io token:** create an API token at crates.io (scope:
   publish-new and publish-update for the `unpatched*` crates) and store it as the
   repository secret `CARGO_REGISTRY_TOKEN` (not an environment secret: `release.yml`
   passes it on to `publish-crates.yml`, and the `release` environment still asks
   for your approval first). Without it, `publish-crates.yml` says so in the log
   and publishes nothing. crates.io limits new crates to 5 at once, then one every
   10 minutes, and `unpatched` has 7. Either ask crates.io for a higher limit first
   (email help@crates.io), or let the job wait: it retries on the limit for up to
   about 85 minutes, and if it still fails, re-run it (published crates are skipped).
7. **Run `build-db` once by hand:** Actions → build-db → Run workflow. It creates
   the rolling `db` release. The action and the CLI need it. Check that the
   release is marked as a pre-release and not as the latest release.
8. **Make the Docker image public:** after the first image is pushed, Packages →
   `unpatched` → Package settings → Change visibility.
9. **Protect release tags (recommended):** Settings → Rules → New tag ruleset,
   target `v*.*.*`, restrict updates and deletions only. Do not restrict creations:
   `autorelease.yml` creates tags with `GITHUB_TOKEN`, which cannot be a bypass
   actor. Do not cover the floating major tag (`v3`): `release.yml` moves it with a
   force push, and `v*.*.*` does not match it.
10. **Make the first release by hand:** `CHANGELOG.md` already has the
    `## [3.0.0]` section (dist puts it in the release notes: check
    `dist plan --tag=v3.0.0 --output-format=json`, field `announcement_changelog`).
    Merge, then `git tag v3.0.0 && git push origin v3.0.0`. `release.yml` starts
    on the tag. After that, `autorelease.yml` takes over.

The `automerge` and `maintenance` labels are created by the workflows on first
use.

## Bumping Rust

The Rust version is pinned, so a new Rust release cannot break a build by surprise.
Change it in one pull request, in these places (they all say `1.100.0` now):

- `rust-toolchain.toml` (`channel`): the one source. `release.yml` reads it for the
  release builds.
- `toolchain:` in `ci.yml`, `build-db.yml`, `maintenance.yml`, `autorelease.yml` and
  `publish-crates.yml`.
- The tag of the `rust:` image in `docker/Dockerfile` (with its digest: look it up with
  `docker buildx imagetools inspect rust:<version>-alpine`).

Search for the old version (`grep -rn 1.100.0 .github rust-toolchain.toml docker`) to be
sure nothing is left. The MSRV (`rust-version` in `Cargo.toml`, and the `msrv` job in
`ci.yml`) is separate: raise it only when the code needs it. `maintenance.yml` opens
"A newer Rust is out" on Thursdays when the pin is behind.

## Turning it off

Disable a workflow under Actions → the workflow → "Disable workflow". Any task of
`maintenance.yml` can also be run by hand (Actions → maintenance → Run workflow
→ task). To stop automatic merges, disable `automerge.yml`; pull requests then
stay open for you. To stop automatic releases, disable `autorelease.yml`;
releasing by hand (push a `vX.Y.Z` tag) still works. To pause the database,
disable `build-db.yml`: the last published database stays, and the CLI refuses
data older than 7 days, so users will see that.
