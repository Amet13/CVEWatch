# Glossary

- **Stack**: the list of things you run, in `unpatched.yml`.
- **Stack item**: one entry: a catalog `product` with a `version`, or a package `purl`.
- **Product**: a catalog entry (`catalog/<id>.yml`) that ties a product's names
  in CPE, CVE records (CNA vendor/product) and KEV together.
- **Source**: where data comes from (CVE.org, NVD, OSV, KEV, EPSS, endoflife.date, Exploit-DB, Metasploit).
- **Range**: what one source says are the affected versions (`AffectedRange`).
- **Scheme**: how versions of a product compare (`dotted`, `semver`, `debian`, …).
- **Verdict**: `affected`, `fixed`, `not-affected` or `unknown`, per stack item and vulnerability.
- **Signals**: exploitation facts: KEV, EPSS, SSVC exploitation, public exploits.
- **Bucket**: how soon to act: `now`, `week`, `eol`, `unknown`, `fyi`.
- **Finding**: one stack item × one vulnerability (or an EOL or data problem), with verdict, bucket, rules and evidence.
- **Rule**: a stable id (`UNP-KEV`, …) that explains why a finding is in its bucket.
- **Ignore**: an accepted risk with a reason and an `until` date.
- **Database**: the prebuilt SQLite file published daily on the `db` release.
- **Status issue**: the pinned GitHub issue that shows the current state and holds delivery state.
