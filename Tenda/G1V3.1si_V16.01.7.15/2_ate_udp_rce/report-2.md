The Tenda G1 (G1v3) Enterprise Router was discovered to contain an unauthenticated root command execution vulnerability in the ate production-test daemon

## Overview

Product: Tenda G1 (G1v3) Enterprise Router

Version: V16.01.7.15(4841)

Manufacturer's website information: https://www.tenda.com.cn/

## Affected version

V16.01.7.15(4841)

## Vulnerability description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain an unauthenticated root command execution vulnerability in the /bin/ate production-test daemon. The daemon binds UDP 7329 on 0.0.0.0 and decrypts all datagrams with AES-128-CBC using a hardcoded key compiled into the binary with a zero IV (AesCbcDecrypt128 at file offset 0x4099a8); the key is identical across all units and extractable from the public firmware image. Decrypted payloads are matched against a 19-entry command table; the ifconfig handler constructs a shell command by plain string concatenation — doSystemCmd("ifconfig " + arg) — so shell metacharacters in the argument execute as root. The daemon runs as root with full capabilities.

## Additional Information

### Product_version

Tenda G1 (G1v3) Enterprise Router

V16.01.7.15(4841)

### Affected_component

- /bin/ate daemon, UDP port 7329, AesCbcDecrypt128 (offset 0x4099a8), g_ate_cmds ifconfig handler
- started via monitor_mstart from the httpd formAte handler (POST /goform/ate)

### Attack_vector

An attacker with LAN access encrypts a shell payload with the firmware-extracted hardcoded AES key and sends one UDP datagram to port 7329; the daemon executes it as root. The daemon must be running: it is started by one authenticated admin request (/goform/ate), or without authentication when the device is in factory state (see report-5).

### CVSS

CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (8.4)

### Proof_of_concept

Verified end-to-end on a physical device running V16.01.7.15(4841): after starting the daemon via an authenticated /goform/ate request, a single AES-encrypted datagram carrying an ifconfig injection wrote a file that was retrieved over HTTP. On-device /proc/self/status for the spawned process showed Uid: 0 0 0 0 and CapEff: 0000003fffffffff (full root capabilities).

### Description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain an unauthenticated root command execution vulnerability in the ate UDP 7329 daemon via a hardcoded AES key and string-concatenation command dispatch

### Reference

- https://www.tenda.com.cn/
- https://github.com/jackkkk0112/vuls/blob/main/Tenda/G1V3.1si_V16.01.7.15/2_ate_udp_rce/report-2.md
- Vendor notified via productsecure@tenda.cn
