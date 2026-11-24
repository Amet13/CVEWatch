# How accurate is it

<!-- description: How unpatched's verdicts are tested (the corpus, the catalog checks), and its honest limits. No measured accuracy numbers have been published yet. -->

**No accuracy has been measured yet, and this page does not claim one.** There is
no published figure for how many affected findings are found or how many
findings are wrong. What exists is a method, described here, and a list of
things that can go wrong. A report with no findings is not a guarantee that
nothing is affected.

## How verdicts are tested

**The corpus is the specification.** `corpus/` holds more than 70 end-to-end cases.
Each one is a small stack, a frozen slice of source data and the exact findings
that must come out (`expect` is exact: a finding that is reported but not listed
fails the case). The cases cover every rule id and every bucket, version
schemes (dotted, semver, calver, Debian, RPM, APK, PEP 440), range boundaries,
sources that agree, conflict or are empty, ignore entries and their expiry,
unknown products and versions, end of life, stale data, and packages. Some use
the shape of real records (FortiOS and CVE-2024-21762, Citrix Bleed, Ivanti
Connect Secure, Nextcloud, PAN-OS).

**A wrong verdict starts as a failing case.** When a report says something is
wrong, the fix is to add a case that shows it, watch it fail, then change the
code. Cases are never loosened, skipped or deleted to get green. This is the rule
in `AGENTS.md`, and a person reviews each case.

**Offline and deterministic.** No test uses the network. Source data is replayed
from `fixtures/`, recorded from the real sources. A case fixes its own clock, so a
run never depends on today's date.

**The catalog is checked against real data.** A wrong name in a catalog entry
would silently mean "no vulnerabilities". A person verifies each entry against a
real CVE record and NVD entry; `cargo xtask catalog verify` re-checks the keys
against the live sources every week; and a product whose names match nothing in
the daily database is reported as unverified, not as clean. See
[Catalog](catalog.md#how-an-entry-is-checked).

**Version comparison is per product scheme, and unparseable means unknown.**
A version that cannot be read in the product's scheme gives `unknown` with the
reason, never a guess or a fall back to another scheme. The dotted, semver,
Debian, RPM, APK and PEP 440 parsers have property tests (the order is total and
transitive, and garbage input never panics).

**No model decides.** Verdicts, buckets and rules are plain code. Every finding
lists the rule ids and the evidence of each source.

## Limits

These are real, and you should know them.

- **Your list is the input.** If a version in `unpatched.yml` is wrong, old, or
  missing, the result is wrong. unpatched does not look at your systems.
- **Only products in the catalog are matched.** Anything else is not checked at
  all (packages with a `purl` go through OSV instead). See [Catalog](catalog.md).
- **New CVEs lag.** NVD often has no version data for a new CVE for days or weeks.
  Such a CVE is `unknown`, and shown only when exploitation signals say it would
  matter. Many of the rest are not shown, by design.
- **Source data can be wrong.** A vendor can write a range too narrow or too wide.
  Sources are combined (one source saying affected is enough), which favours a
  false alarm over a miss. Conflicts are shown.
- **Vendor advisories are not read directly.** The fix version comes from the
  upper bound of a range in CVE.org or NVD. If a vendor ships a fix in a different
  branch, or a workaround without a fix, unpatched may not say so. Read the
  advisory linked in the finding.
- **Appliance version strings are messy.** Builds, patch levels and hotfixes that
  are not part of the version number cannot be compared. Such cases end as
  `unknown`, and can be added to the corpus.
- **A product can be affected through a component** that has its own CVE (a
  library inside an app). That is not found unless you list the component.
- **Configuration matters.** A CVE may apply only if a feature is on. unpatched
  does not know your configuration. It reports "affected" by version and leaves
  the feature to you. Use an `ignore` entry with a reason when the feature is off.
- **End of life comes from endoflife.date.** If the page is wrong or missing, so is
  that finding.
- **The signals are inputs, not truth.** KEV lists what CISA knows is exploited.
  A bug can be exploited and not yet listed. EPSS is a probability.
- **Data can be old.** The database is built daily. If the build stops, you get a
  finding at 3 days and a failure at 7. See [Data](data.md).

## Plans

The repository is set up to measure accuracy: a monthly benchmark against held-out
cases is planned, and so are agent evals (`evals/`). When measured numbers exist
they will be published here, with the method and the date. Until then, if you
find a wrong verdict, please report it:
<https://github.com/Amet13/unpatched/issues/new/choose> (the **Wrong verdict**
template asks for the product, version, CVE, and expected and actual result).
