The Linksys Velop LN11 (Micro Router 6) was discovered to contain an authenticated command injection vulnerability in the BTRequestStartSmartConnectClient JNAP action (btsmartconnect namespace)

## Overview

Product: Linksys Velop LN11 (Micro Router 6)

Version: 1.0.9.216616

Manufacturer's website information: https://www.linksys.com/

## Affected version

1.0.9.216616

## Vulnerability description

Linksys Velop LN11 1.0.9.216616 was discovered to contain a command injection vulnerability in the JNAP action http://linksys.com/jnap/nodes/btsmartconnect/BTRequestStartSmartConnectClient. The "setupAP" string field is concatenated unescaped into a root-executed double-quoted shell invocation (sh -c "/etc/init.d/run_central.sh ... -S &lt;setupAP&gt;"). A field value of the form x$(command)y is evaluated by the outer shell as root before the script runs. The issue was verified on a physical device: the injected parameter was captured in the root process command line with the output of the root "id" command concatenated into it.

## Additional Information

### Product_version

Linksys Velop LN11 (Micro Router 6)

1.0.9.216616

### Affected_component

- JNAP action: http://linksys.com/jnap/nodes/btsmartconnect/BTRequestStartSmartConnectClient
- Parameter: setupAP (passed as -S)
- Sink: /etc/init.d/run_central.sh executed via sh -c as root

### Attack_vector

An authenticated LAN attacker sends one JNAP request whose setupAP field contains shell command substitution (x$(command)y); the command executes as root in the same request.

### CVSS

CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (6.8)

### Proof_of_concept

Request body {"setupAP":"x$(id)y"}; device process list captured the substitution result concatenated into the root run_central.sh command line. Constraints: no literal ")" or single quote in the injected command; the BT central is single-instance.

PoC script: [poc.py](poc.py) - Screenshot: [screenshot.md](screenshot.md) (replace with screenshot.png)

### Description

Linksys Velop LN11 1.0.9.216616 was discovered to contain an authenticated root command injection vulnerability via shell command substitution in the setupAP parameter of the btsmartconnect/BTRequestStartSmartConnectClient JNAP action

### Reference

- https://www.linksys.com/
- https://github.com/jackkkk0112/vuls/blob/main/Linksys/Velop_LN11_1.0.9.216616/3_btsmartconnect_client/report-3.md
- Vendor notified 2026-09; vendor replied "no issue found" after approximately one month
