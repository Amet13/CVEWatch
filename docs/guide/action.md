# GitHub Action

<!-- description: The amet13/unpatched Action: what it does, its inputs and outputs, permissions, and examples for pinning a version, dry runs and chat secrets. -->

`amet13/unpatched` is a composite Action. It downloads the release binary for the
runner, checks its SHA-256 against the release, caches it, runs
`unpatched check --notify`, and writes the report to the run summary. The
step-by-step setup is on [Start with GitHub](start-github.md).

```yaml
- uses: actions/checkout@v7
- uses: amet13/unpatched@v3
```

It needs `actions/checkout` before it (to read `unpatched.yml`) and the job
permissions `contents: read` and `issues: write`. It sets `GITHUB_TOKEN` for
itself. Linux, macOS and Windows runners are supported, on x86_64 and, except for
Windows, arm64.

## Inputs

<!-- generated:start action-inputs -->

| Input | Default | What it does |
| --- | --- | --- |
| `args` | empty | Extra arguments for `unpatched check`, for example `--exit-code --verbose`. |
| `binary` | empty | Path to an unpatched binary you built. Skips the download. Used by this repository's CI. |
| `config` | `unpatched.yml` | Path to your stack file. |
| `db` | empty | Path to a database file. Empty: download the daily database. |
| `dry-run` | `false` | Send nothing and write no issues; only print what would happen. |
| `version` | empty | The unpatched release to run, like v3.0.0 or v3 (the newest v3.x.y). Empty: the version in the tag you used (`uses: amet13/unpatched@v3.0.0`), else the latest release. |

<!-- generated:end -->

`version` takes a full tag (`v3.0.0`), or a major or minor prefix (`v3`, `v3.0`),
which means the newest published release that starts with it. It defaults to the
version in the tag you wrote after `@`, and to the latest release when that is a
branch or a commit. The checksum comes from the `.sha256` file of the same
release; on a mismatch the Action stops and does not run the file.

The action always passes `--notify --format markdown` and writes the report to the
run summary (`$GITHUB_STEP_SUMMARY`). `args` adds options to `unpatched check`, split on
spaces.

## Outputs

The Action has no outputs. The report is in the run summary, findings are in
issues, and the exit code of the step is the exit code of `unpatched`: see
[Exit codes](start-cli.md#exit-codes). With `args: --exit-code` the step fails
(exit code 1) when something is to be fixed today, which turns the run red in the
Actions tab and sends GitHub's own failure email.

## Secrets for chat channels

The Action reads secrets from the environment of the step. Set the ones you use:

```yaml
- uses: amet13/unpatched@v3
  env:
    UNPATCHED_TELEGRAM_TOKEN: ${{ secrets.UNPATCHED_TELEGRAM_TOKEN }}
    UNPATCHED_SLACK_WEBHOOK: ${{ secrets.UNPATCHED_SLACK_WEBHOOK }}
```

Names for each channel are on [Notifications](notifications.md).

## Examples

**Pin an exact release**, so an upgrade is your decision:

```yaml
- uses: amet13/unpatched@v3.0.0
```

**Try it without side effects.** Prints what would happen; opens no issues and
sends nothing:

```yaml
- uses: amet13/unpatched@v3
  with:
    dry-run: "true"
```

**Fail the run on a "fix today" finding**, and see more in the summary:

```yaml
- uses: amet13/unpatched@v3
  with:
    args: --exit-code --verbose
```

**Another config path**, if the file is not called `unpatched.yml` or is in a folder:

```yaml
- uses: amet13/unpatched@v3
  with:
    config: infra/stack.yml
```

Use one config per repository. Issues, the status issue and the delivery state
belong to the repository, and a run closes every issue whose finding is not in
*its* report. Two configs in one repository would close each other's issues. An
MSP uses one private repository per client.

**A database you built or downloaded yourself:**

```yaml
- uses: amet13/unpatched@v3
  with:
    db: ./unpatched-db.sqlite
```

**A binary you built** (used by this repository's own tests): `binary: target/release/unpatched`
skips the download.

## Behaviour to know

- A run does not commit and does not need `contents: write`.
- A scheduled workflow is paused by GitHub after 60 days without repository
  activity **in public repositories**. Private repositories are not paused.
- The cache key is the release tag and the runner, so the binary is downloaded
  once per release and runner.
