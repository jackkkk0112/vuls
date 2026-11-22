The Tenda G1 (G1v3) Enterprise Router was discovered to contain an anonymous TFTP arbitrary file read and arbitrary file overwrite vulnerability

## Overview

Product: Tenda G1 (G1v3) Enterprise Router

Version: V16.01.7.15(4841)

Manufacturer's website information: https://www.tenda.com.cn/

## Affected version

V16.01.7.15(4841)

## Vulnerability description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain an anonymous TFTP vulnerability with arbitrary file read and arbitrary file overwrite. The tftpd daemon is started by netctrl ac_start (sub_4B1C0C) as "udpsvd -E 0 69 tftpd -c /" whenever ac.enable=1, which is the default in the shipped default_router.cfg: root-owned, serving the whole filesystem from "/", with no authentication. On the latest firmware the write path also accepts overwriting existing files (a regression: firmware V16.01.7.11 rejected overwrite with "can't open file"; V16.01.7.15 accepts it). Because the HTTP daemon serves /var/webroot as its document root and serves .js files verbatim, overwriting an existing administrator-UI JS bundle yields stored XSS against administrator sessions; writes under /cfg persist across reboots.

## Additional Information

### Product_version

Tenda G1 (G1v3) Enterprise Router

V16.01.7.15(4841)

### Affected_component

- tftpd via udpsvd, UDP port 69, root, root directory "/", started by netctrl ac_start (sub_4B1C0C)
- TFTP RRQ (arbitrary read) and WRQ (arbitrary create AND overwrite) opcodes

### Attack_vector

A LAN attacker with no credentials reads any file (e.g. /etc_ro/shadow with the root password hash) via TFTP RRQ, and writes or overwrites files via WRQ — including the HTTP document root /var/webroot (stored XSS) and /cfg (reboot persistence).

### CVSS

CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L (9.3)

### Proof_of_concept

Verified on a physical device running V16.01.7.15(4841): RRQ /etc_ro/shadow returned the root password hash; WRQ created files under /var/etc; WRQ /var/webroot/zz.js overwrote the existing file (content zz=1 replaced with zz=2, confirming overwrite); WRQ under /cfg succeeded (reboot persistence). The overwritten JS path is served verbatim by the HTTP daemon.

### Description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain an anonymous TFTP arbitrary file read and arbitrary file overwrite vulnerability leading to credential disclosure, stored XSS and reboot-persistent file writes

### Reference

- https://www.tenda.com.cn/
- https://github.com/jackkkk0112/vuls/blob/main/Tenda/G1V3.1si_V16.01.7.15/3_tftp_anon_rw/report-3.md
- Vendor notified via productsecure@tenda.cn
