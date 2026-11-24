---
name: add-product
description: Add a product to the unpatched catalog. Drafts catalog/<id>.yml from CISA KEV, CVE.org records and endoflife.date, verifies the keys against live data, adds a corpus case, and runs the checks. Use when an issue asks for a new product ("add product" template), when catalog-watch reports a KEV vendor or product that is not in the catalog, or when a user asks to support a product.
---

# Add a product

A person reviews every catalog entry. Your job is a correct draft with the
evidence, not a guess. Read `AGENTS.md` and `CONTEXT.md` first. Look at
`catalog/fortios.yml` and `catalog/nextcloud.yml` as examples, and at
`schema/catalog.schema.json` for the format.

## Steps

1. **Check it is not there already.** `unpatched search <name>` or
   `grep -ril <name> catalog/`. Aliases count: add an alias to the existing
   entry instead of a new file.
2. **Pick the id.** Lowercase, hyphens, the name people type (`home-assistant`).
   The file is `catalog/<id>.yml`.
3. **Find the keys in real data. Do not write them from memory.**
   - `kev`: in the CISA KEV JSON
     (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)
     find entries for the product. Copy `vendorProject` and `product` exactly.
     Use one entry per distinct spelling.
   - `cna`: open two or three real CVE records for the product
     (`https://cveawg.mitre.org/api/cve/<CVE-ID>`). Copy `vendor` and `product`
     from `containers.cna.affected` exactly. CNAs spell the same product
     several ways: list each spelling you saw.
   - `cpe`: the `vendor:product` part of NVD's CPE names (`cpe:2.3:a:<vendor>:<product>`).
     Find it in the CPE dictionary or in the `configurations` of a real NVD record.
   - `eol`: the slug at `https://endoflife.date/api/all.json`. Leave it out when
     the product is not listed.
4. **Choose `versioning`** from how the vendor numbers releases: `dotted`,
   `semver`, `calver`, `debian`, `rpm`, `apk`, `pep440` or `custom:<name>`.
   Check against a real record that the version strings parse. If none fit,
   do not force one: say so in the pull request.
5. **Set `kind`** (`appliance`, `app`, `os`, `database`, `library`, `desktop`),
   `aliases` (names people type), `homepage`, and `checked:` with today's date.
6. **Build and verify.**

   ```sh
   cargo xtask catalog build
   cargo xtask catalog verify     # network: checks cpe, KEV and eol keys
   ```

   Fix every failure. Add a line for the new entry to `catalog/VERIFIED.md`:
   the CVE ids you took `cna` keys from, and the verify numbers. Never edit
   `crates/unpatched-catalog/src/catalog.generated.json` by hand.
7. **Add a corpus case** in `corpus/<id>-<cve>/`, copying the shape of an
   existing case there. Pick one real CVE for this product that has version
   data. Record the CVE.org record (and the NVD or KEV slice if used) into the
   case's data. Expected findings: one version inside the affected range
   (`affected`) and one outside it (`not-affected` or `fixed`). Take the
   versions from the record, never from memory. The case must fail without
   the new entry and pass with it.
8. **Run everything.** `cargo xtask check`. It must pass with no test skipped
   or loosened.
9. **Changelog.** Add a line under `## [Unreleased]` in `CHANGELOG.md`.
10. In the pull request list the evidence: the CVE ids, the KEV spellings, the
    verify output. Say what you could not confirm.

## Rules

- Never claim a key you did not see in real data.
- If the data for a product has no version ranges anywhere, add the entry only
  if the user still wants it, and say that its verdicts will be `unknown`.
- One product per pull request.
