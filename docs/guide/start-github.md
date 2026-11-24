# Start with GitHub

<!-- description: Set up unpatched in a private GitHub repository in five minutes: two files, a first manual run, optional chat channels. -->

This is the main way to run unpatched. You need a GitHub account and about five
minutes. The Action runs once a day, opens an issue for each finding, and keeps
one status issue up to date. It needs no token of your own and no secret, unless
you also want chat messages.

## 1. Make a private repository

Create a new repository and set it to **Private**. The stack file lists your
software and its versions, which is a map for an attacker. Do not put it in a
public repository. See [the public repository warning](faq.md#can-i-use-a-public-repository).

## 2. Write `unpatched.yml`

Add `unpatched.yml` at the top of the repository. Start from this file (it is
what `unpatched init` writes) and keep only what you run:

<!-- generated:start template-config -->

```yaml
# unpatched.yml: what you run, and where to tell you.
# Keep this file in a PRIVATE repository: it lists your software and versions.
# Check it with `unpatched check`; `unpatched schema config` prints the format.

# File format version. Only 1 exists.
version: 1

# The software you run. Each entry is either a catalog `product` (find ids with
# `unpatched search <name>`) or a package `purl`.
stack:
  # A firewall that faces the internet. Edge devices are what attackers hit first.
  - product: fortios
    version: 7.2.5
    exposure: internet # internet | internal (default: internal)
    name: Office firewall # your label; tells several instances apart

  - product: nextcloud
    version: 29.0.3
    exposure: internet

  # Quote versions YAML would read as numbers ("15.4" is a number to YAML).
  - product: postgresql
    version: "15.4"

  - product: home-assistant
    version: 2024.10.1

  # A package: unpatched asks OSV about it (needs the network).
  # - purl: pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm

# Accept a risk on purpose. `until` is required: nothing is ignored forever, and
# the finding comes back when the date has passed.
# ignore:
#   - cve: CVE-2024-1234
#     product: nextcloud # optional: a product id or a stack `name`; default is all
#     reason: "The app is disabled"
#     until: 2027-01-31

# Where findings go. GitHub issues need no secret and are on by default.
# Secrets are never written here: they come from environment variables
# (repository secrets in GitHub Actions).
notify:
  issues: true
  # telegram:
  #   chat: "123456789" # the bot token is in UNPATCHED_TELEGRAM_TOKEN
  # slack: true # webhook URL in UNPATCHED_SLACK_WEBHOOK
  # discord: true # webhook URL in UNPATCHED_DISCORD_WEBHOOK
  # ntfy:
  #   topic: my-unpatched-topic # optional token in UNPATCHED_NTFY_TOKEN
  # webhook: true # URL in UNPATCHED_WEBHOOK_URL

# The day of the weekly digest (monday ... sunday), or `daily`. "Fix today"
# findings are sent at once, whatever the day.
digest: monday

# When a finding gets more urgent. The defaults are shown.
# thresholds:
#   epss_week: 0.05 # EPSS at or above this: fix this week
#   cvss_week: 9.0 # CVSS at or above this: fix this week
#   cvss_week_exposed: 7.0 # CVSS at or above this on an internet-facing item: fix this week
#   stale_warn_days: 3 # warn when the database is older than this
#   stale_fail_days: 7 # fail when the database is older than this
```

<!-- generated:end -->

How to fill it in:

- **`product`**: a catalog id. Run `unpatched search fortigate` (or look in the
  [catalog](catalog.md)) to find it. Aliases work in `search`, but write the id
  in the file.
- **`version`**: the exact version that runs now, from the admin page or
  `--version`. Quote it if YAML would read it as a number: `"15.4"`.
- **`exposure`**: `internet` if it is reachable from the internet (VPN portal,
  web app, mail server), else leave it out. It moves findings up a bucket.
- **`name`**: your own label. Needed to tell two instances of one product apart.
- A package that is not in the catalog (an OS package or a library) can be given
  as a `purl` instead. See the [config reference](config.md).

If a product is not in the catalog, it cannot be matched yet.
[Ask for it](catalog.md#ask-for-a-product).

## 3. Add the workflow

Add `.github/workflows/unpatched.yml`. This is the file `unpatched init --github`
writes:

<!-- generated:start template-workflow -->

```yaml
# Checks your stack (unpatched.yml) every day and opens a GitHub issue for each
# finding. Use it in a PRIVATE repository. It needs no token of your own.
name: unpatched

on:
  schedule:
    # Every day at 06:17 UTC. The database is rebuilt at 02:41 UTC.
    - cron: "17 6 * * *"
  # Lets you run it by hand from the Actions tab.
  workflow_dispatch:

permissions:
  contents: read
  issues: write

jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: amet13/unpatched@v3
        # Only for the chat channels you turned on in unpatched.yml.
        # Add each value as a repository secret first (Settings > Secrets and variables > Actions).
        # env:
        #   UNPATCHED_TELEGRAM_TOKEN: ${{ secrets.UNPATCHED_TELEGRAM_TOKEN }}
        #   UNPATCHED_SLACK_WEBHOOK: ${{ secrets.UNPATCHED_SLACK_WEBHOOK }}
        #   UNPATCHED_DISCORD_WEBHOOK: ${{ secrets.UNPATCHED_DISCORD_WEBHOOK }}
        #   UNPATCHED_NTFY_TOKEN: ${{ secrets.UNPATCHED_NTFY_TOKEN }}
        #   UNPATCHED_WEBHOOK_URL: ${{ secrets.UNPATCHED_WEBHOOK_URL }}
        with:
          config: unpatched.yml
```

<!-- generated:end -->

The job needs only `issues: write` (to open and close issues) and
`contents: read` (to read your stack file). It never commits. The database is
built at 02:41 UTC; the default run time is 06:17 UTC, a few hours later. Pick
another time if you like, but a run before 02:41 UTC uses the day-old database,
which is fine.

`amet13/unpatched@v3` runs the newest `v3.x.y` release. To pin one exact
release, use its full tag, such as `@v3.0.0`. See [GitHub Action](action.md).

## 4. Commit, push and run it once

Commit both files and push. A scheduled workflow does not run until its first
schedule, so start it by hand:

1. Open the repository on GitHub, then the **Actions** tab.
2. Choose **unpatched** in the list on the left.
3. Click **Run workflow**, then the green **Run workflow** button.

When the run finishes, open it and read the **summary**: it has
the same table you would get from `unpatched check --format markdown`.

## 5. Read the first result

The first run creates:

- the labels `unpatched`, `unpatched:now`, `unpatched:week`, `unpatched:eol`,
  `unpatched:unknown`, `unpatched:fyi` and `unpatched:status`
- one issue for each stack item that has a finding that is not FYI, labelled with its most urgent bucket
- one **unpatched status** issue (pinned when GitHub allows it) that lists
  everything open, the database date and the time of the last run

GitHub emails you about new issues like any other. How to read an issue and the
rules behind its label: [Findings and rules](findings.md). What closes an issue:
fix it (change the version in `unpatched.yml`), and the next run closes it with a
note. Closing an issue yourself means "I know"; unpatched does not reopen it,
and lists it under "Closed but still affected" in the status issue.

If the first run reports `unknown product`, the id in `unpatched.yml` is not in
the catalog. Read the message: it suggests close matches, and says what to do for
an operating-system package (use a purl).

**Accept a risk you know about.** Every issue ends with the lines to add to
`unpatched.yml`; the next run moves the finding out of the issue and lists it as
ignored until the date you set:

```yaml
ignore:
  - cve: CVE-2024-21762
    reason: "The SSL VPN is switched off"
    until: 2027-01-31
```

The report notes an entry that matches nothing or has expired. More in
[the config](config.md#ignore-entries).

## Private repository, secrets and settings

- **Actions must be on.** In an organization, check that Actions may run
  `amet13/unpatched`, `actions/checkout` and `actions/cache`.
- **No token is needed** for issues. The workflow's own `GITHUB_TOKEN` is used.
- **Secrets** are only for chat channels. Add each one under **Settings,
  Secrets and variables, Actions, New repository secret**, then uncomment the
  matching line in the workflow's `env:` block. Names and details are on
  [Notifications](notifications.md). A secret never goes in `unpatched.yml`.
- **Minutes.** A run is short: it downloads one binary (cached) and one
  database. Private repositories on the free plan have 2,000 Actions minutes a
  month, far more than a daily run uses.
- **Schedules pause in public repositories only.** GitHub turns off scheduled
  workflows after 60 days with no repository activity in a *public* repository.
  In a private one they keep running. See the [FAQ](faq.md#will-the-schedule-stop).

## Change what you run

Edit `unpatched.yml` and push. The next run uses it. To see the result at once,
run the workflow by hand again, or run `unpatched check` on your machine
([Start with the command line](start-cli.md)).

## Test without side effects

Run the Action with `dry-run: true` to print what would happen (each message
once, with its channel) and send nothing:

```yaml
      - uses: amet13/unpatched@v3
        with:
          dry-run: "true"
```

## If something goes wrong

| What you see | What to do |
| --- | --- |
| `unknown product "..."` | Use an id from `unpatched catalog list`. The message suggests names. |
| `stack[n]: ...` YAML error | Fix the line it shows. `unpatched schema config` prints the format. |
| Exit code 3, "database too old" | The daily database build stopped. See [Data](data.md). |
| `Resource not accessible by integration` | The job lacks `issues: write`. Copy the `permissions:` block above. |
| `check` fails and names an environment variable | A chat channel is on but its secret is not passed in the workflow's `env:` block (exit code 2). |
| A chat message is missing, the rest is fine | The token or URL is wrong, or the service is down. The run exits with code 4 and names the channel. |
