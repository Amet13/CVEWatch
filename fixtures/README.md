# Fixtures

Frozen source data for tests. Tests read these files and never use the network.
Everything here was recorded on 2026-11-23. Big files are trimmed to the few
records the tests need (the trimming is noted below). Each source has its own
license; see `docs/guide/data.md` once it exists.

| Folder | Files | Where from | Trimmed how |
| --- | --- | --- | --- |
| `kev/` | `known_exploited_vulnerabilities.json` | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 7 of 1792 entries (5 well-known, 1 with ransomware use, 1 newest); `count` rewritten to 7 and a `note` added |
| `epss/` | `epss_scores-current.csv.gz` | https://epss.empiricalsecurity.com/epss_scores-current.csv.gz | the 2 header lines and 8 CVEs, gzip again |
| `nvd/` | `nvdcve-2.0-slice.json` | https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz | 7 records of 39382, full record bodies (FortiOS ranges, a rejected record, exact versions with platform context, a v4.0 score) |
| `nvd/` | `nvdcve-2.0-modified.meta` | https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta | whole file |
| `cve-org/` | `CVE-*.json` (14 records) | https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/... | whole records. Fortinet (CVE-2024-21762), Ivanti (CVE-2024-21887), Citrix (CVE-2023-3519, CVE-2023-4966), Nextcloud (CVE-2024-22212), Microsoft (CVE-2024-38063), Linux kernel (CVE-2024-26925, default affected plus an unaffected list), Apache (CVE-2024-38475, CVE-2021-44228), PHP (CVE-2024-4577), Synology (CVE-2024-10443), OpenSSH and Red Hat (CVE-2024-6387), Palo Alto (CVE-2024-3400), rejected (CVE-2024-0069) |
| `osv/` | `querybatch.json`, `querybatch_purl.json` | POST https://api.osv.dev/v1/querybatch | whole answers. The first holds four queries: Debian:12 openssl 3.0.11-1~deb12u1, PyPI django 3.2.0, npm lodash 4.17.15 and an unknown npm package |
| `osv/` | `vuln_<id>.json` | https://api.osv.dev/v1/vulns/<id> | whole records: Debian, Alpine, Ubuntu, PyPI, Go, crates.io, npm (GHSA), OSS-Fuzz (withdrawn), and CVE-2021-44228 (commit ranges only) |
| `endoflife/` | `nextcloud.json`, `ubuntu.json`, `nodejs.json`, `postgresql.json`, `windows.json`, `all.json` | https://endoflife.date/api/<slug>.json, https://endoflife.date/api/all.json | the 8 newest cycles of each product; the first 25 slugs of `all.json` (489 in all) |
| `exploits/` | `files_exploits.csv` | https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv | the header and 10 rows (PHP, Log4Shell, Citrix Bleed, multi-code rows, rows with no CVE) |
| `exploits/` | `modules_metadata_base.json` | https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json | 9 of the modules (Log4Shell, PHP-CGI, Citrix Bleed, one with CVE-2007-4387, one with no CVE) |

The NVD checksum test builds its gzip and `.meta` file in memory from
`nvdcve-2.0-slice.json`, so no big files are stored.
