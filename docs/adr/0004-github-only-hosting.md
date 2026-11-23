# 4. GitHub only, no servers

Date: 2026-11-23. Status: accepted.

## Context

We do not want to run, pay for or secure a server. Users already have GitHub,
and a private repository is a good place for their stack list. Matching a
stack against the whole of NVD at run time is slow and needs many requests.

## Decision

Everything runs on GitHub:

- A workflow in this repository (`build-db.yml`) builds the database daily
  from the sources and publishes `unpatched-db.sqlite.zst`, `SHA256SUMS` and a
  build-provenance attestation as assets of a rolling release with the tag `db`.
  The release is a prerelease and not marked latest, so it does not shadow the
  binary releases. New assets replace the old ones only after a build passed.
- The user's Action downloads that file, verifies the hash, and matches the
  stack locally. The stack never leaves the user's repository.
- Binaries, the Docker image (ghcr.io) and the docs (GitHub Pages) are also
  published from this repository.

## Consequences

- No hosting cost and nothing to keep patched, but we depend on GitHub: a
  GitHub outage is our outage.
- The release assets are public. Anyone can build the same file with
  `unpatched db build` and compare.
- The database must stay small. Only catalog products go into it; packages
  are queried live from OSV.
- Until the first `build-db` run there is no `db` release. `check --db <path>`
  and `unpatched db build` cover that.
