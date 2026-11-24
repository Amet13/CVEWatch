# With an agent

<!-- description: Use unpatched from an AI agent: the read-only MCP server and its tools, the four skills, the Claude Code plugin and Gemini CLI extension, the MCP Registry entry, and llms.txt. -->

unpatched is built to be used by agents as well as people. The verdicts are
deterministic and carry their evidence, so an agent can pass them on without
guessing. The agent never decides a verdict: it asks.

What is available:

| Piece | What it does |
| --- | --- |
| MCP server (`unpatched mcp`) | Read-only tools: check your stack, ask if a product and version is affected, explain, search the catalog, show database status. |
| Skills | Instructions for four jobs: set up, inventory, plan upgrades, explain. |
| Plugin and extension | Claude Code plugin and Gemini CLI extension that install the skills and the server together. |
| JSON report and schemas | `check --format json`, with `schema/report.schema.json`. Read this, not the text output. |
| `llms.txt`, `llms-full.txt` | The guide, for a model: <https://amet13.github.io/unpatched/guide/llms.txt> and <https://amet13.github.io/unpatched/guide/llms-full.txt>. |

All of them need the `unpatched` command on the `PATH` (see
[Start with the command line](start-cli.md)), except the Docker form of the
server.

## The MCP server

`unpatched mcp` speaks the Model Context Protocol on stdio (newline-delimited
JSON-RPC). Every tool is read-only: nothing is written, no message is sent, no
issue is opened.

| Tool | Arguments | What it returns |
| --- | --- | --- |
| `check_stack` | `config_path`, `bucket`, `limit`, `include_evidence` (all optional) | The report for `unpatched.yml`. It always has `summary` (counts) and `items` (the upgrade that helps most, per stack item). `findings` lists, by default, only the `now`, `week`, `eol` and `unknown` buckets, at most 50, without evidence; ask for `fyi` with `bucket`, for more with `limit`, and for the evidence and references with `include_evidence`. Packages are looked up in OSV unless the server runs with `--offline`. |
| `is_affected` | `product`, `version`, `cve` (optional), `exposure` (optional), `include_raw` (optional) | An answer for one product at one version, without a config file. With `cve` it always gives a verdict (`affected`, `not-affected` or `unknown`) with evidence. A source's own text is cut to about 200 characters unless `include_raw` is true. |
| `explain` | `id`, `include_raw` (optional) | A CVE or advisory id (summary, CVSS, affected ranges per source, exploitation signals), a rule id such as `UNP-KEV`, or a finding key such as `office-firewall/CVE-2024-21762` (judged with the server's `unpatched.yml`). |
| `search_catalog` | `text` | Catalog product ids by name, vendor or alias, with the version scheme and endoflife slug. |
| `db_status` | none | When the database was built, its age, whether it is stale, and the state of each source. Run this before trusting an answer. |

A tool that fails because of its input (an unknown product, an argument it does
not have, a missing database) answers with an error that the model can read and
fix; it is not a protocol error.

`check_stack` reads only the server's own config file, or a file named
`unpatched*.yml` or `unpatched*.yaml` under the folder the server runs in (links
are followed first, so a link cannot point elsewhere). Any other `config_path` is
refused, and an error about a config file never repeats what the file says, only
the line and column. `is_affected` needs an exact version: the instructions tell the agent to
ask you, not to guess.

Options before `mcp` apply to the server: `unpatched --config path/to/unpatched.yml --db path/to/db.sqlite --offline mcp`.

### Claude Code

Install the plugin (skills and server together):

```text
/plugin marketplace add Amet13/unpatched
/plugin install unpatched@unpatched
```

or add only the server:

```sh
claude mcp add unpatched -- unpatched mcp
```

### Gemini CLI

```sh
gemini extensions install https://github.com/Amet13/unpatched
```

The extension (`gemini-extension.json`) starts `unpatched mcp`.

### Any other MCP client

Run the command `unpatched` with the argument `mcp`. For clients that use a JSON
config:

```json
{
  "mcpServers": {
    "unpatched": {
      "command": "unpatched",
      "args": ["mcp"]
    }
  }
}
```

### Docker

For clients that start servers with Docker, mount the folder with `unpatched.yml`:

```sh
docker run -i --rm \
  -e UNPATCHED_CACHE_DIR=/work/.cache \
  --mount type=bind,src=/path/to/stack,dst=/work \
  ghcr.io/amet13/unpatched mcp
```

`-i` keeps stdin open, which the protocol needs. See
[Start with Docker](start-docker.md) for the user and cache options.

### The MCP Registry

The server is listed in the MCP Registry as `io.github.Amet13/unpatched`
(`server.json` in the repository), as an OCI package on `ghcr.io/amet13/unpatched`
that runs `mcp` over stdio.

## Skills

The skills are folders with a `SKILL.md` in `skills/`. The plugin and extension
install them. For other agents that read skills, copy the folders into
`.claude/skills/` or `.agents/skills/` in your project.

| Skill | Use it when |
| --- | --- |
| `set-up-unpatched` | You want to be told about vulnerabilities in what you run. The agent asks what you run and its versions, finds the catalog ids, writes `unpatched.yml` and the workflow in a private repository, and runs the first check. It does not guess versions and does not put secrets in files. |
| `inventory-from-notes` | You have a pasted list, a `docker-compose.yml`, Kubernetes manifests, package lists or screenshots of admin pages. The agent proposes stack entries (`product` or `purl`), leaves out anything without a real version, and checks them with `unpatched check`. |
| `plan-upgrades` | You have several findings. The agent orders them into a patch plan by bucket and exposure, with target versions from the data. |
| `explain-a-finding` | You ask why something is flagged, what a rule id means, or "am I affected by CVE-X?". The agent answers from the verdict, rules and evidence, and does not turn `unknown` into "not affected". |

Agents should write `unpatched.yml` from facts you give them, never from a guess.
The rule in every skill: never invent a version.

## Evals

`evals/` has small tasks that check whether the skills help an agent: set up a
homelab, read a compose file, answer "am I affected by CVE-2024-21762 with FortiOS
7.2.5?", plan upgrades, explain a finding. Each is scored by running
`unpatched check` on what the agent wrote or by comparing the answer to the sample
database. No results are published yet; running agents costs money, so the owner
runs them by hand. See `evals/README.md` to run them yourself.

## For agents that work on this repository

`AGENTS.md` has the layout and the one command to run before a commit
(`cargo xtask check`). `CONTEXT.md` is the glossary. The end-to-end corpus
(`corpus/`) is the specification: a wrong verdict is fixed by adding a failing
case first. See [Accuracy](accuracy.md).
