# Support

## Getting help

1. Read the [README](README.md) and the guide at <https://amet13.github.io/unpatched/>.
2. Search the [issues](https://github.com/Amet13/unpatched/issues) and
   [discussions](https://github.com/Amet13/unpatched/discussions).
3. Ask in Discussions, or open an issue with the right template:
   - **Wrong verdict**: unpatched says affected, not affected or unknown, and you think it is wrong.
   - **Add a product**: a product is not in the catalog.
   - **Bug report**: something does not work.

## What to include

- The output of `unpatched --version` and `unpatched db info`
- How you run it (CLI, Docker, GitHub Action) and on which OS
- The command, and the smallest `unpatched.yml` that shows the problem (remove secrets)
- The full error message. For a verdict, the output of `unpatched explain <CVE>`

## Security problems

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## What this is not

unpatched is a free tool that reads public data and tells you what it finds.
It can be wrong, and a quiet report is not a guarantee that nothing is
affected. There is no support contract.
