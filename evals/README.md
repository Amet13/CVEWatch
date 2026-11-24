# Evals

Small, honest measurements of whether the unpatched skills help an AI agent do
the job. Each task prepares a folder, runs an agent with a prompt, then scores
the result: either by running `unpatched check` on the `unpatched.yml` the agent
wrote, or by comparing the agent's answer to facts taken from the smoke database.

No numbers are published from this folder until the owner has run the agents.
Runs cost money, so they are not part of CI; only `--dry-run` is.

## Run it

```sh
# Check that every task and variant can be prepared. No agent, no network.
python3 evals/run.py --dry-run

# A real run: all tasks, both variants, three runs each.
python3 evals/run.py --agent "claude -p {prompt} --permission-mode acceptEdits" \
  --label claude-code --model "<model name as the vendor states it>" --runs 3

# One task, one variant, keep the folders to look at
python3 evals/run.py --agent "codex exec --full-auto {prompt}" --label codex \
  --task is-affected-fortios --variant skills --keep
```

The script needs Python 3 and nothing else. Scoring `config` tasks needs the
`unpatched` binary: it is found on `PATH`, in `UNPATCHED_BIN`, or with
`--unpatched <path>`. It is called as
`unpatched check --offline --format json --db fixtures/smoke/unpatched-db.sqlite --config <file>`.

| Option | Meaning |
| --- | --- |
| `--agent "<cmd>"` | Runs the agent inside the task folder. `{prompt}` is replaced by the shell-quoted prompt. The agent's standard output is its answer. Do not put secrets in the command: it is recorded. |
| `--label <name>` | Required. Names the results file. |
| `--model <text>` | Free text, recorded as given. |
| `--runs <n>` | Runs per task and variant (default 1). Use 3 or more. |
| `--variant` | `bare`, `skills`, a comma list or `all` (default). |
| `--task <id>` | Only this task; repeatable. |
| `--keep` | Keep the working folders and print where they are. |
| `--out <dir>` | Where results go (default `evals/results`). |
| `--dry-run` | Validate every task, prepare every folder, call no agent. |

## Variants

| Variant | What the agent finds in the folder |
| --- | --- |
| `bare` | Only the task files. |
| `skills` | The files plus the user skills from `skills/`, copied to `.claude/skills/` and `.agents/skills/`, and a short `AGENTS.md` that points to them. |

Every prompt ends with the path of the smoke database and the instruction to
pass it with `--db`. Both variants get the same text.

## Tasks

| Task | Kind | What it asks |
| --- | --- | --- |
| `set-up-homelab` | config | Set up unpatched for a described firewall and server: `unpatched.yml` and the workflow, no secrets in files. |
| `inventory-from-compose` | config | Read a docker-compose file. Add only what has a version in the file; leave out `latest` and `stable`. |
| `is-affected-fortios` | answer | "Am I affected by CVE-2024-21762 with FortiOS 7.2.5?" Verdict, fixed version, evidence. |
| `plan-upgrades` | answer | Order two open findings into a plan, with versions only from the data. |
| `explain-a-finding` | answer | Explain a `now` finding with its rule ids and the evidence of each source. |

The expected facts come from `fixtures/smoke/unpatched-db.sqlite` (FortiOS 7.2.5
is affected by CVE-2024-21762, fixed in 7.2.7, in KEV with ransomware use).
End-of-life findings change with the date, so no task scores them.

### Task format

`evals/tasks/<id>.json`:

```jsonc
{
  "id": "set-up-homelab",              // = file name
  "title": "...",
  "kind": "config",                    // or "answer"
  "prompt": "...",                     // given to the agent as is
  "files": { "path": "text" },         // files the folder starts with
  "config": "unpatched.yml",           // config tasks: the file to check
  "expect": { ... },
  "reference": { "path": "text" }      // a known-good result, used by --dry-run
}
```

`config` expectations: `stack` (product, version, optional exposure that must be
in the file), `stackExcludes` (regexes the file must not match), `findings`
(vuln, verdict, optional bucket and fixed_in that the report must contain),
`files`, `fileContains`, `fileNotContains`. The report must have no notes
(no unknown product, no version problem).

`answer` expectations: `matches` (regexes the answer must match), `notMatches`,
`order` (patterns that must first appear in this order).

`--dry-run` checks the format and every regex, prepares both variants, and
scores each task's `reference` against its own expectations (config tasks only
when `unpatched` is available). A task whose reference fails is reported.

## Results file

`evals/results/<date>-<label>.json`: date, label, model, agent command, runs per
cell, tasks, a per-cell summary (`n` and `pass`), and every run with its
problems, exit code and seconds. A run passes when every expectation holds.
With a few runs per cell the numbers say little; read the individual problems.
