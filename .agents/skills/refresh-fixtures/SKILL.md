---
name: refresh-fixtures
description: Record new snapshots of source data into fixtures/ (KEV, EPSS, NVD, CVE.org, OSV, endoflife.date, exploits) and explain what changed. Use when a source changed its format, when a parser test needs a new real record, or when the fixtures are old.
---

# Refresh fixtures

Fixtures are frozen data for tests. Tests never use the network. Read
`fixtures/README.md`: it lists, for every file, where it came from and how it
was trimmed. Keep that table true.

## Steps

1. **Pick what to refresh.** One source at a time. Say why (a format change, a
   new case to cover).
2. **Fetch from the URL in the README table.** Use `curl` with the User-Agent
   `unpatched-fixtures`. Write to a scratch folder first, not into `fixtures/`.
   Do not hand-edit records or write them from memory.
3. **Trim like before.** Keep the same records the tests use, plus any new ones
   you need. Trim by removing whole records, never by editing fields, except for
   the documented rewrites (for example the KEV `count` and `note`). Keep
   the file format (gzip for the EPSS file, one JSON per CVE in `cve-org/`).
4. **Diff.** Compare the old and new files (`git diff --stat`, then read the
   diff of the small ones). Write down what changed in plain words:
   - new or removed fields (a format change: the parser may need a fix);
   - changed values (a CVE got rescored, a range was corrected, a cycle ended);
   - new records.
5. **Run the tests** (`cargo test -p unpatched-sources -p unpatched-db`), then
   `cargo xtask check`. When a test fails because the data changed, decide:
   - the data changed for real (a new fixed version): update the expected value
     in the test, and say so, with the evidence;
   - the parser broke on a new format: fix the parser, keep the old test.
   Never loosen or skip a test to get green.
6. **Smoke database.** If the change affects `fixtures/smoke/unpatched-db.sqlite`,
   rebuild it the way its builder test does and check that the FortiOS 7.2.5 /
   CVE-2024-21762 case still gives `affected`. Do not edit the SQLite file by
   hand.
7. **Update `fixtures/README.md`**: the recording date, the counts, the trimming.
8. **Changelog** only if user-visible behaviour changed.
9. In the pull request, paste the "what changed" list from step 4.

## Rules

- Respect each source's terms and rate limits (`NOTICE`, `docs/guide/data.md`).
- No secrets or tokens in fixture files (some APIs echo your key; check).
- Fixtures are binary-safe: `fixtures/**` is `-text` in `.gitattributes`. Do not
  let an editor change line endings.
