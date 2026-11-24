# Privacy

<!-- description: What leaves your machine when you run unpatched: the database download from GitHub and OSV queries for package items. There is no telemetry. -->

unpatched has no server, no account and no telemetry. It does not know who you
are and does not phone home. This page lists every network request it makes.

## What stays with you

- **Your stack.** `unpatched.yml` is read on your machine (or in your own
  GitHub Action) and is never uploaded. Matching runs locally against the
  database.
- **Your findings.** They go only where you send them: your repository's
  issues, and the chat channels you set up.

## What leaves your machine

| Request | When | What is sent | To whom |
| --- | --- | --- | --- |
| Database download | A run with no database, or one older than 20 hours, and `db update` | A plain `GET` for `unpatched-db.sqlite.zst` and `SHA256SUMS` | GitHub (the release of `Amet13/unpatched`). GitHub sees the request like any download: your IP address and a user agent `unpatched/<version>` |
| Binary download | The Action, once per release and runner; the installers | A `GET` for the release archive and its `.sha256` | GitHub |
| Package lookups | Only for `purl` items in your stack, and not with `--offline` | The package name, ecosystem and version, for example `openssl`, `Debian`, `3.0.11-1~deb12u1`. For a package type OSV has no named ecosystem for, the purl without qualifiers. Then a request for each vulnerability id found | OSV (`api.osv.dev`) |
| Issues | In GitHub Actions or with `--github` | The findings, as issues | The GitHub API of your repository |
| Chat messages | Only for channels you turn on | The findings: product, version, CVE, advice | Telegram, Slack, Discord, ntfy (or the server you set) or your webhook |

That is all. Catalog products are matched without any request about them: the
database holds the vulnerabilities of every catalog product, so nobody learns
which ones you run. `--offline` stops the database download and the package
lookups.

The requests carry a user agent `unpatched/<version> (+https://github.com/Amet13/unpatched)`,
nothing that identifies you.

## What you should know

- **Package lookups tell OSV what you run.** If that matters, use catalog products
  instead of `purl` items, or run with `--offline` and no packages.
- **Messages go through third parties.** A chat message about your firewall is
  sent through Telegram, Slack or Discord. Use a channel you trust, or use only
  GitHub issues in a private repository.
- **The status issue and the issues name your items and versions.** In a public
  repository, anyone can read them. Keep the repository private. See
  [the FAQ](faq.md#can-i-use-a-public-repository).
- **Secrets** come from environment variables, are not written to logs or error
  messages, and are never read from `unpatched.yml`.

## The database is public

The database on the `db` release is built from public data and is the same for
everyone. It holds no information about any user. You can build the same file
yourself (`unpatched db build`) and use it with `--db`, so that even the download
is not needed.
