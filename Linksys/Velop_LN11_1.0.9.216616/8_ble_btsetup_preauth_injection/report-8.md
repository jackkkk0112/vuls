The Linksys Velop LN11/LN12 was discovered to contain a pre-authentication root command injection vulnerability in the BLE btsetup provisioning peripheral

## Overview

Product: Linksys Velop LN11 (Micro Router 6); also confirmed on LN12

Version: LN11 1.0.9.216616; LN12 1.0.1.213146; LN12 1.0.8.216033 (latest, still unpatched)

Manufacturer's website information: https://www.linksys.com/

## Affected version

LN11 1.0.9.216616

LN12 1.0.1.213146

LN12 1.0.8.216033

## Vulnerability description

Linksys Velop LN11/LN12 was discovered to contain a pre-authentication root command injection vulnerability in the BLE btsetup provisioning peripheral. The GATT service 00002080-8eab-46c2-b788-0e9440016fd1 accepts writes without any pairing (legacy pairing is not enforced). The Data characteristic (0x2082) carries three header lines (X-JNAP-Action, X-JNAP-Authorization, JSON body); after a trigger write of 0x01 to the CP characteristic (0x2081), the btsetup binary (sub_13778) copies the three fields unfiltered and builds the command "/usr/bin/btjnap -a '%s' -u '%s' -j '%s'" via sprintf at 0x1388c, then executes it with popen() at 0x13898 as root. A single quote in the X-JNAP-Authorization field closes the -u quoting, and a semicolon injects arbitrary commands; the injected output is read back in-band via fgets (0x138bc) and written to the same GATT characteristic. The identical code path is preserved byte-for-byte in the latest LN12 1.0.8.216033 firmware (unpatched). Reachability: the peripheral advertises persistently in unconfigured/slave mode; on configured Master devices, unplugging the WAN cable for ~10 seconds triggers a WAN-state event that restarts btsetup into a 30-60 second advertising window, extending the attack surface to deployed devices.

## Additional Information

### Product_version

Linksys Velop LN11 (Micro Router 6) 1.0.9.216616

Linksys Velop LN12 1.0.1.213146, 1.0.8.216033

### Affected_component

- BLE GATT service 00002080-8eab-46c2-b788-0e9440016fd1 (btsetup), characteristics Data 0x2082 / CP 0x2081
- /usr/bin/btsetup sub_13778: sprintf 0x1388c ("/usr/bin/btjnap -a '%s' -u '%s' -j '%s'"), popen 0x13898, fgets 0x138bc
- injection field: X-JNAP-Authorization line (single-quote closure)

### Attack_vector

A BLE attacker within radio range connects without pairing, writes a crafted X-JNAP-Authorization header (single-quote closure + arbitrary command) to the Data characteristic and 0x01 to the CP characteristic; the command executes as root and its output is returned over the same GATT characteristic (in-band readback, no external channel needed).

### CVSS

CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (8.8; BLE radio range, zero credentials, zero interaction)

### Proof_of_concept

Verified on physical devices on 2026-09-17 (LN11 1.0.9.216616 in Master mode via the WAN-unplug advertising window, and LN12 1.0.1.213146 in unconfigured mode): a benign round trip returned the btjnap authentication error (channel works, authentication is enforced inside btjnap only); the injection round returned uid=0(root) gid=0(root) via the GATT readback; on-device /tmp/poc_b1_out contained the command output. Static re-check of LN12 1.0.8.216033 (latest): the sprintf/popen/fgets chain is preserved byte-for-byte.

### Description

Linksys Velop LN11/LN12 was discovered to contain a pre-authentication root command injection vulnerability via single-quote closure in the BLE btsetup provisioning peripheral, with in-band output readback

### Reference

- https://www.linksys.com/
- https://github.com/jackkkk0112/vuls/blob/main/Linksys/Velop_LN11_1.0.9.216616/8_ble_btsetup_preauth_injection/report-8.md
- Vendor notified September 2026 (LN11/LN12 findings); vendor replied "no issue found" after approximately one month
