---
name: inventory-from-notes
description: Turn what the user has (a pasted list, a docker-compose.yml, Kubernetes manifests, dpkg -l or apk/rpm output, notes, or screenshots of admin pages) into unpatched.yml stack entries with catalog product ids or package URLs, and validate them. Use when the user wants to add or update the software list for unpatched, or says "here is what I run".
---

# Inventory from notes

Goal: stack entries in `unpatched.yml` that `unpatched` can check. Read the
input, propose entries, let the user confirm, then validate.

## Rules

- Never invent a version. Take versions only from the input (a tag, a pinned
  package, a visible version number). If a version is missing, `latest`,
  a branch, or a range, ask the user, or list the item as "not watched".
- Propose first. Show the user the entries and what you left out, and write the
  file only after they agree.
- Mark `exposure: internet` only when the user says the item is reachable from
  the internet. The default is `internal`.

## Two kinds of entry

- `product` + `version`: a product in the catalog (firewalls, NAS, apps,
  databases). Find the id with `unpatched search "<name>"`. Write the `id`
  exactly as printed.
- `purl`: a package, for operating system packages and libraries. The version
  is in the purl. Examples:
  - `pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm`
  - `pkg:apk/alpine/curl@8.5.0-r0?distro=alpine-3.19`
  - `pkg:pypi/django@3.2.0`
  - `pkg:npm/lodash@4.17.15`

Use `product` when the catalog has it, because it gets version-aware matching,
end-of-life dates and fixed versions. Use `purl` for everything else.

## By input type

- **A pasted list or notes:** one entry per item. Ask about anything unclear.
- **docker-compose.yml:** read each `image:`. The tag after the colon is the
  version (`nextcloud:29.0.3` is product nextcloud, version 29.0.3). Skip
  entries with no tag, `latest`, `stable` or a digest only, and ask the user
  what runs. Only the application image is the item; the base image is not.
- **Kubernetes manifests (Deployments, StatefulSets, Helm values):** read
  `image:` the same way. Ignore sidecars the user did not choose.
- **`dpkg -l` / `apk info -v` / `rpm -qa` output:** do not convert hundreds of
  lines. Ask which packages matter (usually the ones exposed to the network:
  openssl, openssh, nginx, apache, sudo, the kernel). Build purls from the
  exact version column and the distro the user names.
- **Screenshots of admin pages:** read the product name and the version shown.
  Say what you read and ask the user to confirm each version before you use it.
  If a number is hard to read, ask.

## Validate

1. Write the entries into `unpatched.yml` (keep `version: 1` at the top).
2. Run `unpatched check --offline --format json`.
3. Read the JSON:
   - `notes` lists problems: an unknown product id, a missing version, a
     version that cannot be compared, packages skipped because of offline mode.
     Fix each one, or tell the user why it stays.
   - `findings[].bucket` is `now`, `week`, `eol`, `unknown` or `fyi`.
4. Package (`purl`) entries are not checked offline. Run
   `unpatched check --format json` (it asks OSV.dev) once the user agrees to
   that network call. Only the package names and versions are sent.
5. Show the user: entries added, items left out and why, and the findings.
