# What is unpatched

<!-- description: What unpatched does, who it is for, and what it is not. -->

unpatched tells you when software you run is affected by a vulnerability, which
version to upgrade to, and whether the bug is being exploited. You write down
what you run, with versions, in one file (`unpatched.yml`). Every day it checks
that list against open vulnerability data and tells you only about what needs
action.

It is for people who run software they did not write and have nobody whose job
it is to watch advisories:

- homelabbers and self-hosters with 5 to 30 things running
- one-person IT teams and small businesses with a firewall, a VPN, a NAS, a
  mail server, a CMS and a few databases
- MSPs that keep one private repository per client

Edge devices with exploited bugs (Fortinet, Ivanti, Citrix, Palo Alto, MOVEit)
and software past its end of life are what get small organisations breached.
Dependabot, Renovate, OSV-Scanner and Trivy cover code and container images, not
a FortiGate or a Nextcloud install. CVE feeds list every CVE for a vendor and
leave the sorting to you. About 40% of CVEs have a CVSS score of 7 or more, so
sorting by CVSS gives mostly noise.

## What you get

- **Told only when it matters.** A finding is one product you run and one
  vulnerability that affects its version. Nothing else is sent.
- **What to do.** Every finding says the version to upgrade to, and for end of
  life software, that you have to move to a supported release.
- **Ranked by exploitation.** The bucket is decided by CISA KEV, the CISA SSVC
  exploitation flag, public exploits, EPSS and whether the item faces the
  internet. See [Findings and rules](findings.md).
- **Evidence for every verdict.** Each finding lists the sources that said so
  and the rule ids behind its bucket. `unpatched explain` shows them. No model
  decides anything.
- **Honest about gaps.** If the data is missing, conflicting or cannot be read,
  the verdict is `unknown`, with the reason. It is never "not affected" without
  evidence.
- **Quiet by default.** A GitHub issue per finding, a weekly digest in the chat
  channels you choose, and a status issue that says when it last ran, so silence
  never means broken.

## How it works

```text
daily, in the unpatched repository           daily, in your repository
CVE.org, NVD, KEV, EPSS, endoflife.date,     download the database (hash checked)
Exploit-DB, Metasploit ids                   match your stack locally
        |                                    rank findings, compare with last run
        v                                            |
one SQLite database, a release asset  ------->       v
                                             issues, chat messages, report
```

The list of what you run never leaves your repository. See [Privacy](privacy.md).

## Ways to run it

| Way | For |
| --- | --- |
| [GitHub Action](start-github.md) | The main way. A private repository, two files, issues in your inbox. |
| [Command line](start-cli.md) | A laptop, a cron job, a script. `--exit-code` can gate a pipeline. |
| [Docker](start-docker.md) | A homelab server or a NAS that runs a scheduled container. |
| [An AI agent](with-an-agent.md) | "Am I affected by this new Ivanti bug?" answered through an MCP server. |

## What it is not

- **Not a dependency or container scanner.** It does not read your code, lock
  files or images. Use [OSV-Scanner](https://google.github.io/osv-scanner/) or
  [Trivy](https://trivy.dev/) for that. It can check a package you name with a
  `purl`, through OSV, but it does not discover packages.
- **Not a network scanner.** It does not probe hosts or fingerprint versions.
  You say what runs and in which version, and it is only as good as that list.
- **Not a SaaS.** There is no server, no account and no API key. GitHub runs it.
- **Not a guarantee.** It can be wrong, and a quiet report is not proof of
  safety. Read [How accurate is it](accuracy.md).

## Where to go next

- New here: [Start with GitHub](start-github.md).
- Something looks wrong: [Findings and rules](findings.md) and the [FAQ](faq.md).
- Was a CVEWatch user: [Coming from CVEWatch](migrate-from-cvewatch.md).
