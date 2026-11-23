# 3. Keyless, open data only

Date: 2026-11-23. Status: accepted.

## Context

A tool for small teams and homelabs must work the minute it is set up. Paid
feeds and sources that need an account add cost, secrets and lock-in. Open
sources cover what we need: CVE.org records, NVD, CISA KEV, EPSS, OSV,
endoflife.date, and CVE ids from Exploit-DB and Metasploit.

## Decision

Every source works without an account or an API key. Optional extras (an NVD
key, notification tokens) live in GitHub Secrets and are never required.
Only identifiers and facts are stored from sources whose license would not
allow redistribution of the content (Exploit-DB, Metasploit: CVE ids only).
Attributions are listed in `NOTICE` and in the data page of the guide.

## Consequences

- We depend on the availability and terms of public data. A failing source is
  reported by the weekly sources-health check, and the previous database stays.
- Vendor feeds that need a login are out of scope.
- Every new source needs a license check before it is added.
