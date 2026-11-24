# Notifications

<!-- description: Each way unpatched tells you (GitHub issues, Telegram, Slack, Discord, ntfy, webhook), its environment variable, an example message, and how state avoids repeats. -->

unpatched tells you in three kinds of message:

| Message | When |
| --- | --- |
| Alert | A finding that is "fix today" is new, or has just become "fix today". Sent once. |
| Digest | On your digest day (`digest:` in `unpatched.yml`, default `monday`), even when nothing needs action: the footer says how many items were checked and how old the database is, so silence never means broken. Also sent if the last one is 7 or more days old. |
| Resolved | A finding that you were told about is gone. |

GitHub issues work differently: one issue per stack item, opened and closed as the
item's findings change. See [Findings and rules](findings.md#read-a-github-issue).

Chat channels are opt-in. Add them in `unpatched.yml` and give each its secret in
an environment variable. In GitHub Actions, add a repository secret and pass it
in the workflow's `env:` block (the workflow template has the lines, commented
out). Elsewhere, export the variable. A secret is never read from
`unpatched.yml`, and never printed in logs or error messages.

If a channel is on and its variable is missing, `check --notify` stops with exit
code 2 and names every missing variable at once. If a channel fails to deliver
(wrong token, service down), the others are still delivered and the run exits
with code 4.

## Channels

| Channel | In `unpatched.yml` | Environment variable |
| --- | --- | --- |
| GitHub issues | `issues: true` (default) | none; the workflow's `GITHUB_TOKEN` and `issues: write` |
| Telegram | `telegram: { chat: "123456789" }` | `UNPATCHED_TELEGRAM_TOKEN` (the bot token) |
| Slack | `slack: true` | `UNPATCHED_SLACK_WEBHOOK` (an incoming webhook URL) |
| Discord | `discord: true` | `UNPATCHED_DISCORD_WEBHOOK` (a webhook URL) |
| ntfy | `ntfy: { topic: "my-topic" }` | `UNPATCHED_NTFY_TOKEN`, optional (for a protected topic) |
| Webhook | `webhook: true` | `UNPATCHED_WEBHOOK_URL`; `UNPATCHED_WEBHOOK_SECRET`, optional |

### GitHub issues

On by default inside GitHub Actions (and with `check --github`). Needs the job
permission `issues: write` and nothing else. Outside GitHub it is skipped.
FYI findings do not get an issue; the others do, with a label for the bucket. Set
`issues: false` to turn it off, for example if you only want chat messages.

### Telegram

Create a bot with [@BotFather](https://t.me/BotFather) and copy its token into
`UNPATCHED_TELEGRAM_TOKEN`. Send the bot a message, then find your chat id (for
example with `https://api.telegram.org/bot<token>/getUpdates`) and put it in
`chat`. Keep the id quoted. Messages are sent with MarkdownV2 and are cut to fit
Telegram's length limit ("...and 3 more").

### Slack

Create an [incoming webhook](https://api.slack.com/messaging/webhooks) for a
channel and store its URL in `UNPATCHED_SLACK_WEBHOOK`.

### Discord

In the channel settings, Integrations, Webhooks, make a webhook and store its URL
in `UNPATCHED_DISCORD_WEBHOOK`. Messages do not mention anyone.

### ntfy

Set `topic`. The default server is `https://ntfy.sh`; use `server` for your own.
If the topic needs authentication, put the access token in `UNPATCHED_NTFY_TOKEN`.
Anyone who knows a public topic name can read it, so choose a long random name.

```yaml
notify:
  ntfy:
    topic: unpatched-8f3k29dkq1
    server: https://ntfy.example.org
```

### Webhook

A JSON `POST` to the URL in `UNPATCHED_WEBHOOK_URL`, for your own tooling:

```json
{
  "event": "alert",
  "generated_at": "2026-11-24T06:17:00Z",
  "summary": { "now": 1, "week": 0, "eol": 1, "unknown": 0, "fyi": 0, "ignored": 0, "not_affected": 1 },
  "findings": [ { "key": "office-firewall/CVE-2024-21762", "bucket": "now" } ],
  "report_url": "https://github.com/me/stack/actions/runs/123"
}
```

`event` is `alert`, `digest` or `resolved`; each finding is shaped like a finding
of [the JSON report](findings.md#read-the-json-report) (the example above is cut
down). A `resolved` message has a `resolved` list of keys. `report_url` is set
inside GitHub Actions. If you set `UNPATCHED_WEBHOOK_SECRET`, the request carries
`X-Unpatched-Signature: sha256=<hex>`, the HMAC-SHA256 of the exact body bytes
with that secret. Check it before you trust the request.

## Example messages

An alert (plain text; Slack, Discord and Telegram get the same lines with their
own bold and escaping). This is the renderer's own test fixture:

<!-- generated:start example-alert -->

```text
unpatched · 1 to fix today

🔴 Fix today  FortiOS 7.2.5 (Office firewall): CVE-2024-21762, exploited, upgrade to 7.2.7+

🟢 1,412 checked, nothing else affects you
Database: built 2026-11-22 02:41 UTC, 1 day old
https://example.com/r
```

<!-- generated:end -->

A digest, with one line per item and bucket, `(new)` for findings since the last
digest, and a footer that says it is still running:

<!-- generated:start example-digest -->

```text
unpatched · week 48

🔴  FortiOS 7.2.5 (Office firewall): 1 now → upgrade to 7.2.7 (fixes 1 of 1)
🟡  Nextcloud 29.0.3: 2 week → upgrade to 29.0.8 (fixes 2 of 2)
⚫  PostgreSQL 13.12: 1 eol → upgrade to a supported release
❔  Home Assistant 2024.10.1: 1 unknown
⚪  Redis 7.2.1: 1 fyi → upgrade to 7.2.4 (fixes 1 of 1)

🟢 1,412 checked, nothing else affects you
Database: built 2026-11-22 02:41 UTC, 1 day old
```

<!-- generated:end -->

## How state works

unpatched must not repeat itself, and must close what is fixed. It needs to
remember what it already told you, and it does this without committing anything
to your repository.

**In GitHub Actions** the state lives in GitHub itself:

- Each finding issue has a hidden marker, `<!-- unpatched:finding=<key> -->`. A
  run finds its issues by that marker, and creates, updates, closes or reopens
  them to match the report.
- The pinned **unpatched status** issue holds, in a hidden JSON block, which
  findings were seen, in which bucket, and which channels were told. That is how
  an alert is sent once, and how a chat channel you add later still gets the
  open "fix today" findings once.
- The Action never commits and needs only `issues: write`.

If you delete the status issue, the next run makes a new one and may repeat
messages once. A finding that becomes "fix today" is announced even if it was
reported in a lower bucket before.

**On the command line or in Docker** the same state is kept in
`.unpatched/state.json`, next to your config file. Keep that file between runs.
A run with `--dry-run` writes nothing.

The state is as durable as the issues or the file. Both stores hold the same
information. Treat both as private, like `unpatched.yml`: they name your items
and versions.
