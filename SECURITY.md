# Security policy

## Supported versions

Only the latest release of `unpatched` gets fixes. The database on the `db`
release is rebuilt every day.

## Reporting a vulnerability

Please do not open a public issue.

Report it privately with GitHub's "Report a vulnerability" button on the
Security tab of this repository
(<https://github.com/Amet13/unpatched/security/advisories/new>). Say:

- what is wrong and what it lets an attacker do
- the version, and the steps to reproduce it
- how you think it can be fixed, if you know

You can expect an answer within 72 hours, and a fix or a plan within 14 days.
The fix is released before the advisory is published, and you are credited
unless you ask not to be.

## What counts

Things that are in scope: running unpatched on untrusted input (config files,
source data, the MCP server's input), leaking a secret (a token in a log or an
issue), a release or database that does not match its checksum or attestation,
and weaknesses in the workflows of this repository.

A wrong verdict (a missed or false vulnerability) is not a security report. Use
the "Wrong verdict" issue template.

## Checking what you download

Every release has `sha256.sum` and a GitHub build-provenance attestation. The
database has `SHA256SUMS` and an attestation too:

```sh
gh attestation verify unpatched-db.sqlite.zst --repo Amet13/unpatched
```
