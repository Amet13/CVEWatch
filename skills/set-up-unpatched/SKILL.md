---
name: set-up-unpatched
description: Set up unpatched for someone who runs their own software (firewall, NAS, self-hosted apps, databases). Creates unpatched.yml and the GitHub workflow in a private repository, picks the notification channel, and runs the first check. Use when the user wants to be told when something they run is affected by a vulnerability, or says "set up unpatched", "watch my homelab" or "monitor my stack for CVEs".
---

# Set up unpatched

`unpatched` tells you when software you run is affected by a vulnerability,
which version to upgrade to, and whether it is being exploited. The stack
lives in `unpatched.yml` in a private repository.

## Steps

1. Check that `unpatched` is on the PATH (`unpatched --version`). If not, tell
   the user to install it (`https://github.com/Amet13/unpatched`) and stop.
2. Work in a private repository. If the current folder is a public repository,
   stop and say so: the stack list would be public. Never push to a public repo.
3. Collect the stack. Ask the user for each item:
   - what it is, and the exact version it runs;
   - whether it is reachable from the internet (`exposure: internet`) or only
     from inside the network (`exposure: internal`, the default);
   - an optional label (`name`), if there are two of the same product.

   Never invent or guess a version. If the user does not know it, say where to
   find it (the admin page footer, `--version`, the package list) or leave the
   item out and say that it is not watched.
4. Find the product ids. For each item run `unpatched search "<name>"` and
   use the `id` it prints. If nothing matches, the product is not in the
   catalog yet: tell the user. For an operating system package or a library,
   use a `purl` instead (see the `inventory-from-notes` skill).
5. Write `unpatched.yml`:

   ```yaml
   version: 1
   stack:
     - product: fortios
       version: 7.2.5
       exposure: internet
       name: Office firewall
     - product: nextcloud
       version: 29.0.3
       exposure: internet
   notify:
     issues: true
   digest: monday
   ```

   Quote versions that look like numbers ("15.4") so YAML keeps them as text.
6. Pick where alerts go. GitHub Issues need no secret and are on by default.
   Offer Telegram (`notify.telegram.chat`), Slack, Discord, ntfy or a webhook.
   Secrets never go in `unpatched.yml`. Tell the user to add them as
   repository secrets (`UNPATCHED_TELEGRAM_TOKEN`, `UNPATCHED_SLACK_WEBHOOK`,
   `UNPATCHED_DISCORD_WEBHOOK`, `UNPATCHED_WEBHOOK_URL`) in the GitHub
   settings. Do not ask them to paste a secret into the chat.
7. Write `.github/workflows/unpatched.yml`:

   ```yaml
   on:
     schedule: [{ cron: "17 6 * * *" }]
     workflow_dispatch:
   permissions: { contents: write, issues: write }
   jobs:
     check:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v5
         - uses: amet13/unpatched@v1
           with:
             telegram-token: ${{ secrets.UNPATCHED_TELEGRAM_TOKEN }}
   ```

   Drop the `with:` block when no channel needs a secret.
8. Validate offline: `unpatched check --offline --format json`. If it fails
   with an unknown product or a bad version, fix `unpatched.yml` and run it
   again. If the database is missing, run `unpatched db update` first.
9. Read the result (see the `explain-a-finding` skill for the fields). Tell the
   user the count per bucket, and the most urgent findings first.
10. Tell the user to commit both files, push, and start the workflow once from
    the Actions tab (`workflow_dispatch`).

## Rules

- Keep the repository private.
- Do not run `unpatched check --notify` from here: sending messages is the
  workflow's job.
- A quiet result is not proof of safety. Say so if the report has `unknown`
  findings or notes.
