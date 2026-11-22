The Tenda G1 (G1v3) Enterprise Router was discovered to contain a factory-state pre-authentication remote code execution chain

## Overview

Product: Tenda G1 (G1v3) Enterprise Router

Version: V16.01.7.15(4841)

Manufacturer's website information: https://www.tenda.com.cn/

## Affected version

V16.01.7.15(4841)

## Vulnerability description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain a factory-state pre-authentication RCE chain. When sys.current.password is empty (factory-default or post-reset state, i.e. the first-boot window), the httpd authentication exception table (sub_44EF08) allows unauthenticated access not only to setup flows but also to /goform/ate and /goform/telnet. An unauthenticated POST /goform/ate starts the ate production-test daemon (see report-2), which provides unauthenticated root command execution over UDP 7329 — yielding complete pre-authentication root RCE during the first-boot window. Static analysis confirms this logic is unchanged in V16.01.7.15(4841). While a first-boot exception for setup flows is industry-common, this exception covers spawning debug services (telnetd, ate) rather than setup writes.

## Additional Information

### Product_version

Tenda G1 (G1v3) Enterprise Router

V16.01.7.15(4841)

### Affected_component

- httpd authentication exception table sub_44EF08 (sys.current.password empty check)
- exception entries covering POST /goform/ate and POST /goform/telnet
- chains into report-2 (ate UDP 7329 root RCE) and report-4 (root telnetd)

### Attack_vector

An attacker on the LAN reaches a device in factory/reset state (first-boot window) and, without any credentials, starts the ate daemon via /goform/ate, then obtains root command execution per report-2.

### CVSS

CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (9.4, conditional on factory state)

### Proof_of_concept

Static analysis of the V16.01.7.15(4841) httpd binary confirms the empty-password exception table entries for /goform/ate and /goform/telnet are present and unchanged. The chain into root RCE via the ate daemon is dynamically verified separately (report-2); this report documents the authentication-exception mechanism that makes it pre-authentication during first boot.

### Description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain a factory-state pre-authentication remote code execution chain via unauthenticated access to the ate daemon start endpoint

### Reference

- https://www.tenda.com.cn/
- https://github.com/jackkkk0112/vuls/blob/main/Tenda/G1V3.1si_V16.01.7.15/5_factory_preauth_chain/report-5.md
- Vendor notified via productsecure@tenda.cn
