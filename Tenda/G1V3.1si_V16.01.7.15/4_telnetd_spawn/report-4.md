The Tenda G1 (G1v3) Enterprise Router was discovered to contain a one-click root telnetd spawn vulnerability

## Overview

Product: Tenda G1 (G1v3) Enterprise Router

Version: V16.01.7.15(4841)

Manufacturer's website information: https://www.tenda.com.cn/

## Affected version

V16.01.7.15(4841)

## Vulnerability description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain a vulnerability in the httpd formTelnet handler (0x45dcfc): a single POST /goform/telnet request executes system("telnetd &"), immediately spawning a root telnet listener on TCP port 23. The endpoint requires no confirmation dialog, no re-authentication and produces no audit log entry beyond the session cookie. In practice the request can be triggered from an administrator's browser via CSRF (no anti-CSRF token is required beyond the session), or chained from stored XSS (see report-3's JS overwrite) — the administrator does not need to intend it.

## Additional Information

### Product_version

Tenda G1 (G1v3) Enterprise Router

V16.01.7.15(4841)

### Affected_component

- httpd formTelnet (0x45dcfc), endpoint POST /goform/telnet
- system("telnetd &") — root telnet on TCP 23

### Attack_vector

One authenticated admin request (or a CSRF/XSS-triggered request from the admin's browser) starts a root telnet service; an attacker on the LAN then obtains a root shell via telnet without knowing any password.

### CVSS

CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H (7.6; unauthenticated when chained via CSRF/XSS)

### Proof_of_concept

Verified on a physical device running V16.01.7.15(4841): POST /goform/telnet with a valid admin session returned "load telnet success." and TCP 23 was observed listening immediately after; a telnet login provided a root shell.

### Description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain a one-click root telnetd spawn vulnerability via the formTelnet endpoint

### Reference

- https://www.tenda.com.cn/
- https://github.com/jackkkk0112/vuls/blob/main/Tenda/G1V3.1si_V16.01.7.15/4_telnetd_spawn/report-4.md
- Vendor notified via productsecure@tenda.cn
