# Catalog

<!-- description: The products unpatched knows (generated list with id, vendor, kind, version scheme and end of life tracking), how entries are checked, and how to ask for a new one. -->

Sources name the same product in different ways: NVD writes CPE names
(`fortinet:fortios`), CVE records use the vendor's own words (`Fortinet` /
`FortiOS`), CISA KEV has its own pair, and endoflife.date has a slug. The catalog
is one small YAML file per product (`catalog/<id>.yml`) that ties these names
together, and says how the product's versions are compared.

You use the catalog id in `unpatched.yml`:

```yaml
stack:
  - product: fortios
    version: 7.2.5
```

Find an id with `unpatched search <words>` (it matches the id, name, vendor and
aliases such as `fortigate`) or `unpatched catalog list`. `unpatched catalog show <id>`
prints the whole entry.

## What is not covered

The catalog covers named products: appliances, servers, apps and the like.
It does **not** cover:

- **WordPress plugins and themes.** `wordpress` is the core only.
- **Operating-system packages**, other than ones you name with a `purl`. There
  is no `debian`, `ubuntu` or `windows` product. Write the package as a purl,
  for example `pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm`; it is
  looked up in OSV. unpatched does not discover packages for you.
- Libraries and anything else that is not listed below, unless you give it as a
  `purl`.

## Supported products

<!-- generated:start catalog-table -->

| Id | Name | Vendor | Kind | Versions | End of life | Checked |
| --- | --- | --- | --- | --- | --- | --- |
| `apache-http-server` | Apache HTTP Server | Apache Software Foundation | server | dotted | tracked (`apache-http-server`) | 2026-11-23 |
| `bitbucket` | Atlassian Bitbucket (Data Center and Server) | Atlassian | server | dotted | tracked (`bitbucket`) | 2026-11-23 |
| `caddy` | Caddy | Caddy | server | semver | tracked (`caddy`) | 2026-11-23 |
| `check-point-quantum` | Check Point Quantum Security Gateway | Check Point | appliance | dotted | not tracked | 2026-11-23 |
| `cisco-asa` | Cisco Adaptive Security Appliance (ASA) Software | Cisco | appliance | dotted | not tracked | 2026-11-23 |
| `cisco-ftd` | Cisco Firepower Threat Defense (FTD) Software | Cisco | appliance | dotted | not tracked | 2026-11-23 |
| `confluence` | Atlassian Confluence (Data Center and Server) | Atlassian | server | dotted | tracked (`confluence`) | 2026-11-23 |
| `docker-engine` | Docker Engine (Moby) | Docker | server | dotted | tracked (`docker-engine`) | 2026-11-23 |
| `dovecot` | Dovecot | Dovecot | server | dotted | tracked (`dovecot`) | 2026-11-23 |
| `drupal` | Drupal | Drupal | cms | dotted | tracked (`drupal`) | 2026-11-23 |
| `elasticsearch` | Elasticsearch | Elastic | database | dotted | tracked (`elasticsearch`) | 2026-11-23 |
| `esxi` | VMware ESXi | Broadcom | os | dotted | tracked (`esxi`) | 2026-11-23 |
| `exchange-server` | Microsoft Exchange Server | Microsoft | server | dotted | tracked (`msexchange`) | 2026-11-23 |
| `exim` | Exim | Exim | server | dotted | tracked (`exim`) | 2026-11-23 |
| `fortimanager` | FortiManager | Fortinet | appliance | dotted | not tracked | 2026-11-23 |
| `fortios` | FortiOS | Fortinet | appliance | dotted | tracked (`fortios`) | 2026-11-23 |
| `fortiproxy` | FortiProxy | Fortinet | appliance | dotted | not tracked | 2026-11-23 |
| `fortiweb` | FortiWeb | Fortinet | appliance | dotted | not tracked | 2026-11-23 |
| `gitea` | Gitea | Gitea | server | semver | not tracked | 2026-11-23 |
| `gitlab` | GitLab | GitLab | server | dotted | tracked (`gitlab`) | 2026-11-23 |
| `grafana` | Grafana | Grafana Labs | app | semver | tracked (`grafana`) | 2026-11-23 |
| `haproxy` | HAProxy | HAProxy | server | dotted | tracked (`haproxy`) | 2026-11-23 |
| `home-assistant` | Home Assistant | Home Assistant | app | calver | not tracked | 2026-11-23 |
| `ivanti-connect-secure` | Ivanti Connect Secure | Ivanti | appliance | dotted | not tracked | 2026-11-23 |
| `ivanti-epmm` | Ivanti Endpoint Manager Mobile (EPMM) | Ivanti | server | dotted | not tracked | 2026-11-23 |
| `jellyfin` | Jellyfin | Jellyfin | server | semver | not tracked | 2026-11-23 |
| `jenkins` | Jenkins | Jenkins Project | server | dotted | tracked (`jenkins`) | 2026-11-23 |
| `jira` | Atlassian Jira (Data Center and Server) | Atlassian | server | dotted | tracked (`jira-software`) | 2026-11-23 |
| `joomla` | Joomla! | Joomla! Project | cms | dotted | tracked (`joomla`) | 2026-11-23 |
| `keycloak` | Keycloak | Red Hat | server | semver | tracked (`keycloak`) | 2026-11-23 |
| `kubernetes` | Kubernetes | Kubernetes | server | semver | tracked (`kubernetes`) | 2026-11-23 |
| `linux-kernel` | Linux kernel | Linux | os | dotted | tracked (`linux`) | 2026-11-23 |
| `mariadb` | MariaDB | MariaDB Foundation | database | dotted | tracked (`mariadb`) | 2026-11-23 |
| `mattermost` | Mattermost | Mattermost | server | semver | tracked (`mattermost`) | 2026-11-23 |
| `moveit-transfer` | MOVEit Transfer | Progress | server | dotted | not tracked | 2026-11-23 |
| `mysql` | MySQL | Oracle | database | dotted | tracked (`mysql`) | 2026-11-23 |
| `netscaler` | NetScaler ADC and Gateway | Cloud Software Group | appliance | dotted | not tracked | 2026-11-23 |
| `nextcloud` | Nextcloud Server | Nextcloud | server | dotted | tracked (`nextcloud`) | 2026-11-23 |
| `nginx` | nginx | F5 | server | dotted | tracked (`nginx`) | 2026-11-23 |
| `nodejs` | Node.js | OpenJS Foundation | server | semver | tracked (`nodejs`) | 2026-11-23 |
| `openssh` | OpenSSH | OpenBSD | server | dotted | not tracked | 2026-11-23 |
| `openssl` | OpenSSL | OpenSSL | library | dotted | tracked (`openssl`) | 2026-11-23 |
| `opnsense` | OPNsense | Deciso | os | dotted | tracked (`opnsense`) | 2026-11-23 |
| `pan-os` | PAN-OS | Palo Alto Networks | appliance | dotted | tracked (`panos`) | 2026-11-23 |
| `pfsense` | pfSense | Netgate | os | dotted | not tracked | 2026-11-23 |
| `php` | PHP | PHP Group | server | dotted | tracked (`php`) | 2026-11-23 |
| `phpmyadmin` | phpMyAdmin | phpMyAdmin | app | dotted | tracked (`phpmyadmin`) | 2026-11-23 |
| `plex-media-server` | Plex Media Server | Plex | server | dotted | not tracked | 2026-11-23 |
| `postfix` | Postfix | Postfix | server | dotted | tracked (`postfix`) | 2026-11-23 |
| `postgresql` | PostgreSQL | PostgreSQL | database | dotted | tracked (`postgresql`) | 2026-11-23 |
| `proxmox-ve` | Proxmox Virtual Environment | Proxmox | os | dotted | tracked (`proxmox-ve`) | 2026-11-23 |
| `python` | Python (CPython) | Python Software Foundation | server | pep440 | tracked (`python`) | 2026-11-23 |
| `qnap-qts` | QNAP QTS | QNAP | os | dotted | not tracked | 2026-11-23 |
| `redis` | Redis | Redis | database | dotted | tracked (`redis`) | 2026-11-23 |
| `rocket-chat` | Rocket.Chat | Rocket.Chat | server | semver | tracked (`rocket-chat`) | 2026-11-23 |
| `roundcube` | Roundcube Webmail | Roundcube | app | dotted | tracked (`roundcube`) | 2026-11-23 |
| `routeros` | MikroTik RouterOS | MikroTik | os | dotted | tracked (`routeros`) | 2026-11-23 |
| `samba` | Samba | Samba | server | dotted | tracked (`samba`) | 2026-11-23 |
| `screenconnect` | ConnectWise ScreenConnect | ConnectWise | server | dotted | not tracked | 2026-11-23 |
| `sonicos` | SonicOS | SonicWall | appliance | dotted | not tracked | 2026-11-23 |
| `synology-dsm` | Synology DiskStation Manager (DSM) | Synology | os | dotted | not tracked | 2026-11-23 |
| `tomcat` | Apache Tomcat | Apache Software Foundation | server | dotted | tracked (`tomcat`) | 2026-11-23 |
| `traefik` | Traefik | Traefik Labs | server | semver | tracked (`traefik`) | 2026-11-23 |
| `truenas` | TrueNAS | iXsystems | os | dotted | tracked (`truenas`) | 2026-11-23 |
| `vaultwarden` | Vaultwarden | Vaultwarden | server | semver | not tracked | 2026-11-23 |
| `vcenter` | VMware vCenter Server | Broadcom | server | dotted | tracked (`vcenter`) | 2026-11-23 |
| `veeam-backup-replication` | Veeam Backup & Replication | Veeam | server | dotted | tracked (`veeam-backup-and-replication`) | 2026-11-23 |
| `wordpress` | WordPress | WordPress | cms | dotted | tracked (`wordpress`) | 2026-11-23 |
| `zabbix` | Zabbix | Zabbix | server | dotted | tracked (`zabbix`) | 2026-11-23 |
| `zimbra` | Zimbra Collaboration | Synacor | server | dotted | not tracked | 2026-11-23 |
| `zyxel-zld` | Zyxel firewalls (ZLD: USG FLEX, ATP, VPN series) | Zyxel | appliance | dotted | not tracked | 2026-11-23 |

71 products.

<!-- generated:end -->

Columns:

- **Versions** is the scheme used to compare versions of this product: `dotted`
  (numbers separated by dots), `semver`, `calver`, `debian`, `rpm`, `apk`,
  `pep440` or a named custom scheme.
- **End of life** says whether the product has an endoflife.date slug. If it does,
  `unpatched` reports a release cycle that is past its end of life. If it does not
  (endoflife.date has no page for it), end of life is not checked for that product.
- **Checked** is the date a person last verified the entry against real CVE and
  NVD data.

## How an entry is checked

A wrong name in the catalog would silently mean "no vulnerabilities". Three
things guard against that:

1. A person checks every entry against a real CVE record and NVD entry before it
   is added, and sets `checked:` to that date. The evidence (the NVD hit counts,
   the CNA names from real records, the KEV names and the endoflife slug) is kept in
   `catalog/VERIFIED.md`.
2. `cargo xtask catalog verify` re-checks the CPE, KEV and endoflife keys against
   the live sources. It runs weekly in the repository. It cannot check CNA keys,
   because CVE.org cannot be searched by vendor.
3. When the daily database is built, a product whose names match nothing in the
   data is marked unverified. A stack item with such a product shows up as an
   `unknown` finding with the rule `UNP-UNVERIFIED-PRODUCT`, so an empty result
   is never read as "safe".

Known gaps are listed at the top of `catalog/VERIFIED.md`. For example, a few
products have no CNA keys because every record names them `n/a`; matching uses
the CPE (and KEV) keys for them.

## Ask for a product

If something you run is not here, it cannot be matched yet. Open an issue with
the **Add a product** template at
<https://github.com/Amet13/unpatched/issues/new/choose> and give:

- the product name and vendor, and where its releases are published
- how its versions look (`7.2.5`, `2024.10.1`, `15.4`) and whether they follow
  semver, calendar versioning or something unusual
- one CVE that affects it, so the names can be checked against a real record
- its endoflife.date page, if there is one

Or add it yourself: copy a similar file in `catalog/`, fix the names, add a corpus
case for one affected and one fixed version, and run `cargo xtask check`. The steps
are in [CONTRIBUTING.md](https://github.com/Amet13/unpatched/blob/main/CONTRIBUTING.md#adding-a-product).
A person checks every new entry before it is merged.

For a library or an operating system package that is not a catalog product, use a
`purl` in your stack instead: those are looked up in OSV and need no catalog entry
(for example `pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm`). WordPress
plugins and themes are not covered either way.
See the [config reference](config.md#the-stack).
