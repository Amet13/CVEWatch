# 1. The name is `unpatched`

Date: 2026-11-23. Status: accepted.

## Context

The tool is a full rewrite of CVEWatch, so the old name would suggest the old
product (a Go search tool for CVEs). The new name should say which problem the
tool answers, be one short lowercase word, and be free on crates.io.

## Decision

The project, the crate, the command and the config file are called
`unpatched` (`unpatched check`, `unpatched.yml`, `uses: amet13/unpatched@v1`).
The repository `Amet13/CVEWatch` is renamed to `Amet13/unpatched` at launch.
GitHub redirects the old URLs.

The version starts again at `0.1.0` and `1.0.0` comes at launch. The Go
releases stay listed as `v2.x`, and the last Go commit has the tag `v2-final`.

## Consequences

- Docs, workflows and packages use the new name from the start. Until the
  rename, links to `Amet13/unpatched` do not work.
- Existing CVEWatch users need a migration page.
- Searching for "unpatched" finds unrelated projects. The crate name and the
  command are what people type, so this is acceptable.
