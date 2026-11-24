# Config reference

<!-- description: Every key of unpatched.yml with type, default and meaning, and examples for the stack, ignore entries, thresholds and notifications. -->

`unpatched.yml` says what you run and where to tell you. It is read by every
command (`--config FILE` chooses another path). Keep it in a private repository.

The file is YAML. Unknown keys are an error, so a typo such as `exposur:` is
reported with its line instead of being ignored. Only `version` and `stack` are
required. `unpatched schema config` prints the JSON Schema, which most editors
can use for completion; it is also in `schema/unpatched.schema.json`.

## A complete example

```yaml
version: 1

stack:
  - product: fortios
    version: 7.2.5
    exposure: internet
    name: Office firewall
  - product: fortios
    version: 7.0.13
    name: Lab firewall
  - product: nextcloud
    version: 29.0.3
    exposure: internet
  - product: postgresql
    version: "15.4"
  - purl: pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm

ignore:
  - cve: CVE-2024-1234
    product: nextcloud
    reason: The app is disabled
    until: 2027-01-31

notify:
  issues: true
  telegram:
    chat: "123456789"
  ntfy:
    topic: my-unpatched-topic

digest: monday

thresholds:
  epss_week: 0.1
  cvss_week: 8.0
```

## Keys

<!-- generated:start config-reference -->

### Top level

| Key | Type | Required | Default | What it does |
| --- | --- | --- | --- | --- |
| `version` | integer | yes | none | File format version. Only `1` exists. |
| `stack` | list of `stack[]` | yes | none | The software you run, one entry per instance. |
| `ignore` | list of `ignore[]` | no | none | Risks you accept on purpose, each with a reason and an end date. |
| `notify` | object (see `notify`) | no | none | Channels. Secrets (tokens, webhook URLs) never go here: they come from environment variables named in the docs (`UNPATCHED_TELEGRAM_TOKEN`, …). |
| `digest` | string | no | `monday` | Day of the weekly digest (`monday` … `sunday`), or `daily`. |
| `thresholds` | object (see `thresholds`) | no | none | When a finding gets more urgent. |

### `stack[]`

One thing you run. Give either `product` (a catalog id) or `purl` (a package).

| Key | Type | Required | Default | What it does |
| --- | --- | --- | --- | --- |
| `product` | string | no | none | Catalog product id (`unpatched catalog list`). |
| `purl` | string | no | none | Package URL with version, e.g. `pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm`. |
| `version` | string | no | none | Required with `product`; taken from the purl otherwise. |
| `exposure` | `internet` or `internal` | no | `internal` | Whether the item is reachable from the internet. It can move a finding up a bucket. |
| `name` | string | no | none | Your label, e.g. "Office firewall". Tells instances apart. |

### `ignore[]`

Accept a risk on purpose. `until` is required: nothing is ignored forever.

| Key | Type | Required | Default | What it does |
| --- | --- | --- | --- | --- |
| `cve` | string | yes | none | The CVE (or advisory) id to ignore. |
| `product` | string | no | none | Only for this product id (or stack item `name`); all items when empty. |
| `reason` | string | yes | none | Why you accept the risk. Shown in the report. |
| `until` | date (`YYYY-MM-DD`) | yes | none | The last day the entry applies. After it the finding comes back. |

### `notify`

Channels. Secrets (tokens, webhook URLs) never go here: they come from environment variables named in the docs (`UNPATCHED_TELEGRAM_TOKEN`, …).

| Key | Type | Required | Default | What it does |
| --- | --- | --- | --- | --- |
| `issues` | true or false | no | `true` | GitHub Issues in the repository the Action runs in. |
| `telegram` | object (see `notify.telegram`) | no | none | Send messages to a Telegram chat. |
| `slack` | true or false | no | `false` | Slack incoming webhook (URL in `UNPATCHED_SLACK_WEBHOOK`). |
| `discord` | true or false | no | `false` | Discord webhook (URL in `UNPATCHED_DISCORD_WEBHOOK`). |
| `ntfy` | object (see `notify.ntfy`) | no | none | Send messages to an ntfy topic. |
| `webhook` | true or false | no | `false` | Generic JSON webhook (URL in `UNPATCHED_WEBHOOK_URL`). |

### `notify.telegram`

| Key | Type | Required | Default | What it does |
| --- | --- | --- | --- | --- |
| `chat` | string | yes | none | Chat id. The bot token comes from `UNPATCHED_TELEGRAM_TOKEN`. |

### `notify.ntfy`

| Key | Type | Required | Default | What it does |
| --- | --- | --- | --- | --- |
| `topic` | string | yes | none | The ntfy topic to publish to. |
| `server` | string | no | `https://ntfy.sh` | The ntfy server. |

### `thresholds`

| Key | Type | Required | Default | What it does |
| --- | --- | --- | --- | --- |
| `epss_week` | number | no | `0.05` | EPSS score at or above which an affected finding is at least `week`. |
| `cvss_week` | number | no | `9.0` | CVSS base score at or above which an affected finding is at least `week`. |
| `stale_warn_days` | integer | no | `3` | Days after which the database counts as stale (warning). |
| `stale_fail_days` | integer | no | `7` | Days after which a run fails because the data is too old. |
| `cvss_week_exposed` | number | no | `7.0` | CVSS base score at or above which an affected, internet-facing finding is at least `week`. |

Unknown keys are an error: `additionalProperties` is `false` everywhere, so a typo is caught instead of ignored. The same schema is in `schema/unpatched.schema.json` and is printed by `unpatched schema config`.

<!-- generated:end -->

## The stack

Each entry is one thing you run. Give either `product` or `purl`, never both.

**A catalog product** has `product` (an id from `unpatched catalog list`) and
`version`. This is the better choice when the product is in the
[catalog](catalog.md): matching is aware of the product's version scheme, end of
life dates come from endoflife.date, and findings can name the fixed version.

**A package** has `purl`, a [package URL](https://github.com/package-url/purl-spec)
with the version after `@`: `pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm`,
`pkg:apk/alpine/curl@8.5.0-r0?distro=alpine-3.19`, `pkg:pypi/django@3.2.0`,
`pkg:npm/lodash@4.17.15`. Packages are looked up live in OSV, so they need the
network and are skipped with `--offline`. See [Privacy](privacy.md) for what is
sent.

**Several instances** of one product are several entries. Give each a `name`,
so findings say which one. The name also becomes the start of the finding's key
(`office-firewall/CVE-2024-21762`).

**Versions** are compared by the product's own scheme (dotted numbers, semver,
calendar versions, Debian, RPM, APK, PEP 440). If a version cannot be read in
that scheme, the verdict is `unknown` with the reason, never a guess. Quote
versions that YAML could read as numbers (`"15.4"`).

**`exposure`** is `internet` (reachable from the internet: VPN portals, web
apps, mail servers) or `internal`, the default. It changes the bucket: an
affected internet-facing finding with CVSS ≥ 7.0 (`cvss_week_exposed`) is at
least this week; with a public exploit it is fix today, whatever the score.
Mark only what really is reachable.

## Ignore entries

An ignore entry accepts a risk on purpose, like a VEX statement "not affected
because...":

```yaml
ignore:
  - cve: CVE-2024-1234
    product: nextcloud          # optional: a product id or a stack `name`
    reason: The app is disabled
    until: 2027-01-31
```

- `cve`, `reason` and `until` are required. There is no "ignore forever":
  `until` is the last day the entry applies.
- Without `product`, the entry covers every stack item that the CVE affects.
  With it, only the item whose product id or `name` matches.
- An ignored finding leaves the main report and is listed under "ignored", with
  the reason and date (rule `UNP-IGNORED`). Its GitHub issue is closed with a
  note.
- When the date has passed, the finding is back in its bucket with the rule
  `UNP-IGNORE-EXPIRED`, and the issue is reopened.
- The report has a note for an entry that does nothing: `ignore[2]: CVE-2099-1
  matches no finding. Check the id or remove it.` (the number counts from 0), or
  `ignore[1] expired on 2020-01-01; the finding is back.`

## Thresholds

Every number has a default; set only what you want to change.

```yaml
thresholds:
  epss_week: 0.05
  cvss_week: 9.0
  cvss_week_exposed: 7.0
  stale_warn_days: 3
  stale_fail_days: 7
```

- `epss_week`: an affected finding with an EPSS score at or above this is at
  least "this week" (rule `UNP-EPSS`). EPSS is the estimated probability of
  exploitation in the next 30 days, from 0 to 1.
- `cvss_week`: the same for the CVSS base score (rule `UNP-CVSS`).
- `cvss_week_exposed`: the CVSS base score at or above which an affected internet-facing finding is at least `week` (rule `UNP-EXPOSED`, default 7.0). With a public exploit it is `now`, whatever the score.
- `stale_warn_days`: when the database is older than this, the report has a
  finding that says so (rule `UNP-STALE-DATA`).
- `stale_fail_days`: when it is older than this, the run stops with exit code 3.
  `check --allow-stale` overrides it.

The "fix today" conditions (KEV, SSVC active, public exploit on an internet-facing
item) have no threshold. See [Findings and rules](findings.md).

## Notifications

```yaml
notify:
  issues: true          # GitHub issues; the default
  telegram:
    chat: "123456789"   # token in UNPATCHED_TELEGRAM_TOKEN
  slack: true           # webhook URL in UNPATCHED_SLACK_WEBHOOK
  discord: true         # webhook URL in UNPATCHED_DISCORD_WEBHOOK
  ntfy:
    topic: my-topic     # optional: server (default https://ntfy.sh); token in UNPATCHED_NTFY_TOKEN
  webhook: true         # URL in UNPATCHED_WEBHOOK_URL, optional signing secret in UNPATCHED_WEBHOOK_SECRET

digest: monday          # monday ... sunday, or daily
```

Secrets are never read from this file. If a channel is turned on and its
variable is missing, the run stops with exit code 2 and names the variable. Each
channel, with an example message, is on [Notifications](notifications.md).

`digest` is the day of the weekly digest sent to chat channels. It does not delay
"fix today" findings, which are sent once as soon as they appear.
