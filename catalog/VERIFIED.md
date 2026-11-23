# Catalog verification evidence

Checked 2026-11-23 against live data. Re-run `cargo xtask catalog verify` to re-check the cpe, KEV and eol keys.

- **cpe**: `vendor:product` and the number of CVEs NVD 2.0 returned for `virtualMatchString=cpe:2.3:*:<vendor>:<product>` (`totalResults`).
- **cna**: vendor / product copied from `containers.cna.affected` of a real record fetched from `https://cveawg.mitre.org/api/cve/<id>`; the CVE id is in brackets. `n/a` is what the CNA wrote.
- **kev**: `vendorProject | product` as in the CISA KEV JSON, with the number of KEV entries that use that exact pair.
- **eol**: slug listed in `https://endoflife.date/api/all.json`.

`cargo xtask catalog verify` passed on 2026-11-23 for every cpe (hits above), KEV and eol key. It does not check `cna` keys (CVE.org has no search by vendor); those were copied from the records named below.

Known gaps:
- No `cna` keys: `mariadb`, `proxmox-ve`, `phpmyadmin`. Every record found for them names the product as `n/a`. Matching uses cpe (and KEV for phpMyAdmin) only.
- Joomla and Veeam have CPE products with a backslash escape (`joomla:joomla\!`, `veeam:veeam_backup_\&_replication`), exactly as NVD writes them. Matching code must compare them as plain strings.
- `openssh`, `home-assistant`, `vaultwarden`, `jellyfin`, `plex-media-server`, `synology-dsm`, `qnap-qts`, `pfsense`, `zimbra`, `zyxel-zld`, `cisco-asa`, `sonicos`, `check-point-quantum` have no endoflife.date slug (the site has none for them).
- `truenas` has CPE data only for TrueNAS CORE; TrueNAS SCALE has no CPE in NVD.
- `docker-engine`: KEV only lists Docker Desktop, so there is no KEV key.

## fortios
- cpe: `fortinet:fortios` = 280
- cna: Fortinet / FortiOS (CVE-2021-42757); Fortinet / Fortinet FortiOS, FortiProxy, FortiSwitchManager (CVE-2022-40684); Fortinet / FortiOS-6K7K (CVE-2023-27997)
- kev: Fortinet | FortiOS (9); Fortinet | FortiOS and FortiProxy (4); Fortinet | FortiOS and FortiProxy SSL-VPN (1); Fortinet | FortiOS and FortiADC (1)
- eol: `fortios` (listed)

## fortiproxy
- cpe: `fortinet:fortiproxy` = 125
- cna: Fortinet / FortiProxy (CVE-2021-42757); Fortinet / Fortinet FortiOS, FortiProxy, FortiSwitchManager (CVE-2022-40684)
- kev: Fortinet | FortiOS and FortiProxy (4); Fortinet | FortiOS and FortiProxy SSL-VPN (1)
- eol: no endoflife.date slug

## fortimanager
- cpe: `fortinet:fortimanager` = 115
- cna: Fortinet / FortiManager (CVE-2020-12811); Fortinet / Fortinet FortiManager (CVE-2021-24006)
- kev: Fortinet | FortiManager (1)
- eol: no endoflife.date slug

## fortiweb
- cpe: `fortinet:fortiweb` = 126
- cna: Fortinet / FortiWeb (CVE-2019-5590); Fortinet / Fortinet FortiWeb (CVE-2019-16156)
- kev: Fortinet | FortiWeb (3)
- eol: no endoflife.date slug

## ivanti-connect-secure
- cpe: `ivanti:connect_secure` = 133, `pulsesecure:pulse_connect_secure` = 57
- cna: Ivanti / Connect Secure (CVE-2025-0282); Ivanti / ICS (CVE-2023-46805); n/a / Pulse Connect Secure (CVE-2020-8204)
- kev: Ivanti | Connect Secure (3); Ivanti | Connect Secure and Policy Secure (2); Ivanti | Connect Secure, Policy Secure, and Neurons (1); Ivanti | Connect Secure, Policy Secure, and ZTA Gateways (2); Ivanti | Pulse Connect Secure (7); Ivanti | Pulse Connect Secure and Pulse Policy Secure (1)
- eol: no endoflife.date slug

## ivanti-epmm
- cpe: `ivanti:endpoint_manager_mobile` = 29, `mobileiron:core` = 3
- cna: Ivanti / Endpoint Manager Mobile (CVE-2023-35078); Ivanti / EPMM (CVE-2023-39337)
- kev: Ivanti | Endpoint Manager Mobile (EPMM) (7); Ivanti | Endpoint Manager Mobile (EPMM) and MobileIron Core (1); Ivanti | MobileIron Multiple Products (1)
- eol: no endoflife.date slug

## netscaler
- cpe: `citrix:netscaler_application_delivery_controller` = 48, `citrix:netscaler_gateway` = 58, `citrix:application_delivery_controller` = 27, `citrix:gateway` = 27
- cna: Citrix / NetScaler ADC (CVE-2023-3519); Citrix / NetScaler Gateway (CVE-2023-3466); NetScaler / ADC (CVE-2025-5349); NetScaler / Gateway (CVE-2025-5777); Cloud Software Group / NetScaler ADC (CVE-2023-4967); n/a / Citrix ADC, Citrix Gateway (CVE-2020-8197)
- kev: Citrix | NetScaler (6); Citrix | NetScaler ADC and Gateway (2); Citrix | NetScaler ADC and NetScaler Gateway (5); Citrix | Application Delivery Controller (ADC) and Gateway (1); Citrix | Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP Appliance (4)
- eol: no endoflife.date slug

## pan-os
- cpe: `paloaltonetworks:pan-os` = 238
- cna: Palo Alto Networks / PAN-OS (CVE-2024-0012)
- kev: Palo Alto Networks | PAN-OS (13)
- eol: `panos` (listed)

## cisco-asa
- cpe: `cisco:adaptive_security_appliance_software` = 355
- cna: Cisco / Cisco Adaptive Security Appliance (ASA) Software (CVE-2023-20269); Cisco / Cisco Secure Firewall Adaptive Security Appliance (ASA) Software (CVE-2025-20333)
- kev: Cisco | Adaptive Security Appliance (ASA) (4); Cisco | Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) (6); Cisco | Adaptive Security Appliance and Firepower Threat Defense (1); Cisco | Secure Firewall ASA Software and Cisco Secure FTD Software (1); Cisco | Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD) (1); Cisco | Secure Firewall Adaptive Security Appliance and Secure Firewall Threat Defense (2)
- eol: no endoflife.date slug

## cisco-ftd
- cpe: `cisco:firepower_threat_defense` = 9
- cna: Cisco / Cisco Firepower Threat Defense Software (CVE-2023-20269); Cisco / Cisco Secure Firewall Threat Defense (FTD) Software (CVE-2025-20333)
- kev: Cisco | Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) (6); Cisco | Secure Firewall ASA Software and Cisco Secure FTD Software (1); Cisco | Secure Firewall Adaptive Security Appliance (ASA) and Secure Firewall Threat Defense (FTD) (1)
- eol: no endoflife.date slug

## sonicos
- cpe: `sonicwall:sonicos` = 69
- cna: SonicWall / SonicOS (CVE-2019-7479)
- kev: SonicWall | SonicOS (3); SonicWall | SonicOS SSLVPN (1)
- eol: no endoflife.date slug

## check-point-quantum
- cpe: `checkpoint:quantum_security_gateway` = 4, `checkpoint:security_gateway` = 8
- cna: checkpoint / Check Point Quantum Gateway, Spark Gateway and CloudGuard Network (CVE-2024-24919)
- kev: Check Point | Quantum Security Gateways (1); Check Point | Security Gateway (1)
- eol: no endoflife.date slug

## zyxel-zld
- cpe: `zyxel:zld` = 21, `zyxel:usg_flex_100_firmware` = 30
- cna: Zyxel / USG FLEX series firmware (CVE-2022-26531); Zyxel / ATP series firmware (CVE-2022-26531); Zyxel / VPN series firmware (CVE-2022-26531); Zyxel / USG20(W)-VPN series firmware (CVE-2023-28767); Zyxel / USG FLEX 50(W) series firmware (CVE-2023-28767); Zyxel / ZyWALL/USG series firmware (CVE-2022-38547)
- kev: Zyxel | Multiple Firewalls (5)
- eol: no endoflife.date slug

## synology-dsm
- cpe: `synology:diskstation_manager` = 136
- cna: Synology / DiskStation Manager (DSM) (CVE-2017-12075)
- kev: Synology | DiskStation Manager (DSM) (1)
- eol: no endoflife.date slug

## qnap-qts
- cpe: `qnap:qts` = 320, `qnap:quts_hero` = 247
- cna: QNAP Systems Inc. / QTS (CVE-2018-0719); QNAP Systems Inc. / QuTS hero (CVE-2018-19957); QNAP / QNAP QTS (CVE-2018-14746)
- kev: QNAP | QTS (1); QNAP | QNAP Network-Attached Storage (NAS) (1); QNAP | Network Attached Storage (NAS) (4)
- eol: no endoflife.date slug

## routeros
- cpe: `mikrotik:routeros` = 88
- cna: MikroTik / RouterOS (CVE-2019-3943); n/a / MikroTik RouterOS (CVE-2019-3976)
- kev: MikroTik | RouterOS (5)
- eol: `routeros` (listed)

## pfsense
- cpe: `netgate:pfsense` = 49, `pfsense:pfsense` = 38
- cna: Netgate / pfSense CE (CVE-2025-34172); Netgate / pfSense Plus (CVE-2026-111214); Netgate / Netgate pfSense (CVE-2018-4019); pfSense / pfSense CE and pfSense Plus (CVE-2022-24299)
- kev: not in KEV
- eol: no endoflife.date slug

## opnsense
- cpe: `opnsense:opnsense` = 36
- cna: Opnsense / OPNsense (CVE-2019-25368); opnsense / core (CVE-2026-30868)
- kev: not in KEV
- eol: `opnsense` (listed)

## exchange-server
- cpe: `microsoft:exchange_server` = 271
- cna: Microsoft / Microsoft Exchange Server 2013 Cumulative Update 21 (CVE-2021-26855); Microsoft / Microsoft Exchange Server 2013 Cumulative Update 22 (CVE-2021-26855); Microsoft / Microsoft Exchange Server 2013 Cumulative Update 23 (CVE-2021-26855); Microsoft / Microsoft Exchange Server 2016 Cumulative Update 22 (CVE-2022-41040); Microsoft / Microsoft Exchange Server 2016 Cumulative Update 23 (CVE-2022-41040); Microsoft / Microsoft Exchange Server 2019 Cumulative Update 11 (CVE-2022-41040); Microsoft / Microsoft Exchange Server 2019 Cumulative Update 12 (CVE-2022-41040); Microsoft / Microsoft Exchange Server 2019 Cumulative Update 13 (CVE-2024-21410); Microsoft / Microsoft Exchange Server 2019 Cumulative Update 14 (CVE-2024-21410); Microsoft / Microsoft Exchange Server 2019 Cumulative Update 15 (CVE-2025-53786); Microsoft / Microsoft Exchange Server Subscription Edition RTM (CVE-2025-53786)
- kev: Microsoft | Exchange Server (17); Microsoft | Exchange (1)
- eol: `msexchange` (listed)

## confluence
- cpe: `atlassian:confluence_data_center` = 40, `atlassian:confluence_server` = 50, `atlassian:confluence` = 19
- cna: Atlassian / Confluence Data Center (CVE-2020-29448); Atlassian / Confluence Server (CVE-2019-15005)
- kev: Atlassian | Confluence (1); Atlassian | Confluence Data Center and Server (3); Atlassian | Confluence Server (1); Atlassian | Confluence Server and Data Center (2); Atlassian | Confluence Server and Data Server (1); Atlassian | Confluence Server/Data Center (1)
- eol: `confluence` (listed)

## jira
- cpe: `atlassian:jira_data_center` = 81, `atlassian:jira_server` = 136
- cna: Atlassian / Jira Server (CVE-2019-15005); Atlassian / Jira Data Center (CVE-2020-29453); Atlassian / Jira Server and Data Center (CVE-2019-11581); Atlassian / Jira (CVE-2018-13404); Atlassian / Jira Software Server (CVE-2022-0540); Atlassian / Jira Software Data Center (CVE-2022-0540)
- kev: Atlassian | Jira Server and Data Center (2)
- eol: `jira-software` (listed)

## bitbucket
- cpe: `atlassian:bitbucket_data_center` = 4, `atlassian:bitbucket_server` = 2, `atlassian:bitbucket` = 20
- cna: Atlassian / Bitbucket Server (CVE-2017-18036); Atlassian / Bitbucket Data Center (CVE-2019-15000)
- kev: Atlassian | Bitbucket Server and Data Center (1)
- eol: `bitbucket` (listed)

## gitlab
- cpe: `gitlab:gitlab` = 1507
- cna: GitLab / GitLab (CVE-2021-22205); GitLab / GitLab Community and Enterprise Editions (CVE-2017-0914)
- kev: GitLab | GitLab (1); GitLab | Community Edition and Enterprise Edition (2); GitLab | Community and Enterprise Editions (2); GitLab | GitLab CE/EE (1)
- eol: `gitlab` (listed)

## gitea
- cpe: `gitea:gitea` = 81
- cna: Gitea / Gitea (CVE-2019-1010261); go-gitea / go-gitea/gitea (CVE-2022-0905)
- kev: Gitea | Gitea (1)
- eol: no endoflife.date slug

## jenkins
- cpe: `jenkins:jenkins` = 303
- cna: Jenkins Project / Jenkins (CVE-2024-23897)
- kev: Jenkins | Jenkins (1); Jenkins | Jenkins Command Line Interface (CLI) (1); Jenkins | Jenkins Stapler Web Framework (1); Jenkins | Jenkins User Interface (UI) (1)
- eol: `jenkins` (listed)

## nextcloud
- cpe: `nextcloud:nextcloud_server` = 189, `nextcloud:nextcloud` = 28
- cna: Nextcloud / Nextcloud Server (CVE-2017-0883); n/a / Nextcloud Server (CVE-2018-16463); nextcloud / security-advisories (CVE-2021-32658)
- kev: not in KEV
- eol: `nextcloud` (listed)

## wordpress
- cpe: `wordpress:wordpress` = 585
- cna: WordPress / wordpress-develop (CVE-2022-21661)
- kev: WordPress | Core (3); WordPress | WordPress Core (1)
- eol: `wordpress` (listed)

## drupal
- cpe: `drupal:drupal` = 734
- cna: Drupal / Drupal core (CVE-2019-6341); Drupal / Drupal Core (CVE-2019-6342); Drupal / Core (CVE-2022-25271); Drupal / core (CVE-2018-7602)
- kev: Drupal | Core (3); Drupal | Drupal Core (1); Drupal | Drupal core (1)
- eol: `drupal` (listed)

## joomla
- cpe: `joomla:joomla\!` = 669
- cna: Joomla! Project / Joomla! CMS (CVE-2023-23752)
- kev: Joomla! | Joomla! (1)
- eol: `joomla` (listed)

## home-assistant
- cpe: `home-assistant:home-assistant` = 16
- cna: home-assistant / core (CVE-2023-27482)
- kev: not in KEV
- eol: no endoflife.date slug

## vaultwarden
- cpe: `dani-garcia:vaultwarden` = 20
- cna: dani-garcia / vaultwarden (CVE-2024-56335)
- kev: not in KEV
- eol: no endoflife.date slug

## jellyfin
- cpe: `jellyfin:jellyfin` = 19
- cna: jellyfin / jellyfin (CVE-2021-21402)
- kev: not in KEV
- eol: no endoflife.date slug

## plex-media-server
- cpe: `plex:media_server` = 19
- cna: Plex / Media Server (CVE-2025-69414); n/a / Plex Media Server (CVE-2020-5742)
- kev: Plex | Media Server (5)
- eol: no endoflife.date slug

## grafana
- cpe: `grafana:grafana` = 104
- cna: grafana / grafana (CVE-2021-39226)
- kev: Grafana Labs | Grafana (2)
- eol: `grafana` (listed)

## apache-http-server
- cpe: `apache:http_server` = 372
- cna: Apache Software Foundation / Apache HTTP Server (CVE-2021-41773)
- kev: Apache | HTTP Server (4)
- eol: `apache-http-server` (listed)

## tomcat
- cpe: `apache:tomcat` = 276
- cna: Apache Software Foundation / Apache Tomcat (CVE-2024-34750); Apache / Apache Tomcat (CVE-2020-1938)
- kev: Apache | Tomcat (6)
- eol: `tomcat` (listed)

## nginx
- cpe: `f5:nginx` = 41, `nginx:nginx` = 2
- cna: F5 / NGINX (CVE-2022-41741); nginx / nginx (CVE-2011-4968)
- kev: not in KEV
- eol: `nginx` (listed)

## openssh
- cpe: `openbsd:openssh` = 147
- cna: OpenBSD / OpenSSH (CVE-2025-32728)
- kev: OpenBSD | OpenSSH (1)
- eol: no endoflife.date slug

## openssl
- cpe: `openssl:openssl` = 330
- cna: OpenSSL / OpenSSL (CVE-2017-3731)
- kev: OpenSSL | OpenSSL (1)
- eol: `openssl` (listed)

## postgresql
- cpe: `postgresql:postgresql` = 209
- cna: n/a / PostgreSQL (CVE-2024-0985)
- kev: not in KEV
- eol: `postgresql` (listed)

## mysql
- cpe: `oracle:mysql` = 1328
- cna: Oracle Corporation / MySQL Server (CVE-2023-22084)
- kev: not in KEV
- eol: `mysql` (listed)

## mariadb
- cpe: `mariadb:mariadb` = 431
- cna: none (no CVE record names this product other than `n/a`)
- kev: not in KEV
- eol: `mariadb` (listed)

## redis
- cpe: `redis:redis` = 46
- cna: redis / redis (CVE-2022-24834); Debian / redis (CVE-2022-0543)
- kev: Redis | Debian-specific Redis Servers (1)
- eol: `redis` (listed)

## elasticsearch
- cpe: `elastic:elasticsearch` = 91
- cna: Elastic / Elasticsearch (CVE-2020-7021); Elastic / elasticsearch (CVE-2022-23708)
- kev: Elastic | Elasticsearch (2)
- eol: `elasticsearch` (listed)

## roundcube
- cpe: `roundcube:webmail` = 113
- cna: Roundcube / Webmail (CVE-2025-49113); Roundcube / Roundcubemail (CVE-2023-5631)
- kev: Roundcube | Webmail (7); Roundcube | Roundcube Webmail (4)
- eol: `roundcube` (listed)

## zimbra
- cpe: `zimbra:collaboration` = 41, `synacor:zimbra_collaboration_suite` = 105
- cna: Synacor / Zimbra Server (CVE-2022-37393)
- kev: Synacor | Zimbra Collaboration Suite (ZCS) (17); Synacor | Zimbra Collaboration Suite (1); Synacor | Zimbra Collaborate Suite (ZCS) (1)
- eol: no endoflife.date slug

## esxi
- cpe: `vmware:esxi` = 140
- cna: n/a / VMware ESXi (CVE-2021-21974)
- kev: VMware | ESXi (3); VMware | ESXi and Workstation (1); VMware | ESXi, Workstation, and Fusion (1)
- eol: `esxi` (listed)

## vcenter
- cpe: `vmware:vcenter_server` = 82
- cna: VMware / vCenter Server (CVE-2017-4926); n/a / VMware vCenter Server (CVE-2020-3952); n/a / VMware vCenter Server and VMware Cloud Foundation (CVE-2021-21985)
- kev: VMware | vCenter Server (9); VMware | vCenter Server and Cloud Foundation (1); Broadcom | VMware vCenter (2); Broadcom | VMware vCenter Server (1)
- eol: `vcenter` (listed)

## veeam-backup-replication
- cpe: `veeam:veeam_backup_\&_replication` = 42
- cna: Veeam / Backup & Replication (CVE-2024-29849); Veeam / Backup and Replication (CVE-2025-48983); n/a / Veeam Backup & Replication (CVE-2023-27532)
- kev: Veeam | Backup & Replication (4)
- eol: `veeam-backup-and-replication` (listed)

## proxmox-ve
- cpe: `proxmox:virtual_environment` = 8
- cna: none (no CVE record names this product other than `n/a`)
- kev: not in KEV
- eol: `proxmox-ve` (listed)

## truenas
- cpe: `ixsystems:truenas` = 3
- cna: iXsystems / TrueNAS CORE (CVE-2024-11944)
- kev: not in KEV
- eol: `truenas` (listed)

## docker-engine
- cpe: `mobyproject:moby` = 21, `docker:docker` = 55
- cna: moby / moby (CVE-2021-21284); Docker / Docker Engine (CVE-2014-8178)
- kev: not in KEV
- eol: `docker-engine` (listed)

## kubernetes
- cpe: `kubernetes:kubernetes` = 61
- cna: Kubernetes / Kubernetes (CVE-2017-1002100)
- kev: not in KEV
- eol: `kubernetes` (listed)

## linux-kernel
- cpe: `linux:linux_kernel` = 19856
- cna: Linux / Kernel (CVE-2024-1086); Linux / Linux (CVE-2024-26925)
- kev: Linux | Kernel (32)
- eol: `linux` (listed)

## php
- cpe: `php:php` = 760
- cna: PHP Group / PHP (CVE-2024-4577)
- kev: PHP Group | PHP (3); PHP | PHP (1); PHP | FastCGI Process Manager (FPM) (1)
- eol: `php` (listed)

## nodejs
- cpe: `nodejs:node.js` = 189
- cna: NodeJS / Node (CVE-2023-30581)
- kev: not in KEV
- eol: `nodejs` (listed)

## python
- cpe: `python:python` = 145
- cna: Python Software Foundation / CPython (CVE-2024-0450)
- kev: not in KEV
- eol: `python` (listed)

## moveit-transfer
- cpe: `progress:moveit_transfer` = 49
- cna: Progress / MOVEit Transfer (CVE-2024-5806); Progress Software Corporation / MOVEit Transfer (CVE-2023-40043); Progress Software / MOVEit Transfer (CVE-2024-2291)
- kev: Progress | MOVEit Transfer (1)
- eol: no endoflife.date slug

## screenconnect
- cpe: `connectwise:screenconnect` = 10
- cna: ConnectWise / ScreenConnect (CVE-2022-36781)
- kev: ConnectWise | ScreenConnect (4)
- eol: no endoflife.date slug

## zabbix
- cpe: `zabbix:zabbix` = 115
- cna: Zabbix / Frontend (CVE-2022-23131); Zabbix / Zabbix Server (CVE-2017-2824); Zabbix / Zabbix (CVE-2013-3628)
- kev: Zabbix | Frontend (2)
- eol: `zabbix` (listed)

## mattermost
- cpe: `mattermost:mattermost_server` = 506, `mattermost:mattermost` = 77
- cna: Mattermost / Mattermost (CVE-2021-37859)
- kev: not in KEV
- eol: `mattermost` (listed)

## rocket-chat
- cpe: `rocket.chat:rocket.chat` = 62
- cna: n/a / Rocket.Chat (CVE-2021-22886); RocketChat / Rocket.Chat (CVE-2021-32832)
- kev: not in KEV
- eol: `rocket-chat` (listed)

## keycloak
- cpe: `redhat:keycloak` = 99, `keycloak:keycloak` = 5
- cna: Red Hat / keycloak (CVE-2016-8609); n/a / Keycloak (CVE-2019-14909)
- kev: not in KEV
- eol: `keycloak` (listed)

## traefik
- cpe: `traefik:traefik` = 84
- cna: traefik / traefik (CVE-2021-32813)
- kev: not in KEV
- eol: `traefik` (listed)

## caddy
- cpe: `caddyserver:caddy` = 20
- cna: caddyserver / caddy (CVE-2026-27585)
- kev: not in KEV
- eol: `caddy` (listed)

## haproxy
- cpe: `haproxy:haproxy` = 36
- cna: HAProxy / HAProxy (CVE-2026-26080); haproxy / haproxy (CVE-2026-55203)
- kev: not in KEV
- eol: `haproxy` (listed)

## samba
- cpe: `samba:samba` = 216
- cna: Samba / Samba (CVE-2021-44142)
- kev: Samba | Samba (1)
- eol: `samba` (listed)

## exim
- cpe: `exim:exim` = 71
- cna: exim / exim (CVE-2019-10149)
- kev: Exim | Exim (3); Exim | Exim Internet Mailer (1); Exim | Mail Transfer Agent (MTA) (1)
- eol: `exim` (listed)

## postfix
- cpe: `postfix:postfix` = 12
- cna: Postfix / Postfix (CVE-2026-43964)
- kev: not in KEV
- eol: `postfix` (listed)

## dovecot
- cpe: `dovecot:dovecot` = 69
- cna: The Dovecot Project / Dovecot (CVE-2017-14461); The Dovecot Project / dovecot (CVE-2017-15130)
- kev: not in KEV
- eol: `dovecot` (listed)

## phpmyadmin
- cpe: `phpmyadmin:phpmyadmin` = 277
- cna: none (no CVE record names this product other than `n/a`)
- kev: phpMyAdmin | phpMyAdmin (1)
- eol: `phpmyadmin` (listed)
