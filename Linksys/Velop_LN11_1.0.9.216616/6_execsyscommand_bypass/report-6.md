The Linksys Velop LN11 (Micro Router 6) was discovered to contain a command execution vulnerability via whitelist bypass in the ExecSysCommand JNAP action

## Overview

Product: Linksys Velop LN11 (Micro Router 6)

Version: 1.0.9.216616

Manufacturer's website information: https://www.linksys.com/

## Affected version

1.0.9.216616

## Vulnerability description

Linksys Velop LN11 1.0.9.216616 was discovered to contain a command execution vulnerability in the JNAP diagnostics action ExecSysCommand. The "cmd" parameter is validated against a whitelist by prefix/substring matching on the raw string, then the normalized (realpath) path is executed. Submitting cmd=/lib/libnl/cli/cls/../../../../usr/bin/lua passes validation because the raw string contains a whitelisted substring, while normalization resolves the path to /usr/bin/lua; the "param" field becomes the Lua -e argument. This yields arbitrary root Lua code execution with the output returned in the same HTTP response. The issue was verified on a physical device (uid=0 output in output.cmdresult).

## Additional Information

### Product_version

Linksys Velop LN11 (Micro Router 6)

1.0.9.216616

### Affected_component

- JNAP action: http://linksys.com/jnap/diagnostics/ExecSysCommand
- Parameters: cmd (validated on raw string, executed on realpath), param (becomes Lua -e argument)
- Whitelist entry abused: /lib/libnl/cli/cls/

### Attack_vector

An authenticated LAN attacker submits cmd=/lib/libnl/cli/cls/../../../../usr/bin/lua with a Lua payload in param; the request executes the payload as root and returns the output in-band (output.cmdresult).

### CVSS

CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (6.8)

### Proof_of_concept

{"cmd":"/lib/libnl/cli/cls/../../../../usr/bin/lua","param":"-e local f=io.popen(\"id\") print(f:read(\"*a\"))"} → output.cmdresult: uid=0(root) gid=0(root). Verified verbatim on 2026-10-13.

PoC script: [poc.py](poc.py) - Screenshot: [screenshot.png](screenshot.png)

### Description

Linksys Velop LN11 1.0.9.216616 was discovered to contain a root command execution vulnerability via whitelist bypass (raw string vs realpath normalization confusion) in the ExecSysCommand JNAP action

### Reference

- https://www.linksys.com/
- https://github.com/jackkkk0112/vuls/blob/main/Linksys/Velop_LN11_1.0.9.216616/6_execsyscommand_bypass/report-6.md
- Vendor notified 2026-09; vendor replied "no issue found" after approximately one month
