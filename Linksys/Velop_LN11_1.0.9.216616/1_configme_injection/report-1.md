The Linksys Velop LN11 (Micro Router 6) was discovered to contain an unauthenticated MQTT poisoning to root command injection vulnerability

## Overview

Product: Linksys Velop LN11 (Micro Router 6)

Version: 1.0.9.216616

Manufacturer's website information: https://www.linksys.com/

## Affected version

1.0.9.216616

## Vulnerability description

Linksys Velop LN11 1.0.9.216616 was discovered to contain a two-stage command injection vulnerability. Stage 1 requires no credentials: the on-device mosquitto broker (TCP 1883, allow_anonymous=true) grants anonymous write access to topic network/+/CONFIG-ME/subdev/+/status, and the JSON uuid field is stored verbatim into the sysevent key CONFIG-ME_&lt;pin&gt; without validation. Stage 2: when an administrator invokes the JNAP action StartSmartConnectServer (wiredEnabled=true, matching pin), libolympus_api.so's Ol_SetSmartConnectServer concatenates the stored value unquoted into system("/usr/sbin/pub_configure_self %s"). Shell metacharacters in the poisoned value execute as root. The issue was verified end-to-end on a physical device (uid=0 output captured).

## Additional Information

### Product_version

Linksys Velop LN11 (Micro Router 6)

1.0.9.216616

### Affected_component

- mosquitto broker (TCP 1883), topic network/+/CONFIG-ME/subdev/+/status, JSON field uuid
- sysevent key CONFIG-ME_&lt;pin&gt;
- JNAP action StartSmartConnectServer → libolympus_api.so Ol_SetSmartConnectServer → system("/usr/sbin/pub_configure_self %s")

### Attack_vector

A LAN attacker publishes one anonymous MQTT message to poison the sysevent value; the injected shell payload executes as root when any administrator later triggers SmartConnect.

### CVSS

CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (6.8; the poisoning stage itself requires no privileges)

### Proof_of_concept

Stage 1 (no credentials), MQTT publish to topic network/master/CONFIG-ME/subdev/owned/status with payload {"type":"status","uuid":"$(id; uptime >/tmp/pwned_LN11)","data":{"pin":"1234"}}; the broker accepts the anonymous write. Stage 2, an authenticated JNAP StartSmartConnectServer request (wiredEnabled=true, pin=1234) triggers execution. Result read back on the device: /tmp/pwned_LN11 contains uid=0(root) gid=0(root); the sysevent key is cleared after consumption. Verified on 2026-10-13.

PoC script: [poc.py](poc.py) - Screenshot: [screenshot.md](screenshot.md) (replace with screenshot.png)

### Description

Linksys Velop LN11 1.0.9.216616 was discovered to contain an unauthenticated MQTT poisoning to root command injection vulnerability via CONFIG-ME

### Reference

- https://www.linksys.com/
- https://github.com/jackkkk0112/vuls/blob/main/Linksys/Velop_LN11_1.0.9.216616/1_configme_injection/report-1.md
- Vendor notified 2026-09; vendor replied "no issue found" after approximately one month
