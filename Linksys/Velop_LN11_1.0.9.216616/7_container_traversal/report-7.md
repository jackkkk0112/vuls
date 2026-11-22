The Linksys Velop LN11 (Micro Router 6) was discovered to contain a path traversal vulnerability in container.cgi

## Overview

Product: Linksys Velop LN11 (Micro Router 6)

Version: 1.0.9.216616

Manufacturer's website information: https://www.linksys.com/

## Affected version

1.0.9.216616

## Vulnerability description

Linksys Velop LN11 1.0.9.216616 was discovered to contain a path traversal vulnerability in /cgi-bin/container.cgi (lighttpd port 443, Basic authentication). The c_name parameter is URL-decoded at line 17 (%2F becomes /) and traversal sequences flow unvalidated into the root-executed service_container.sh via sysevent. With CMD=install the traversal value reaches a root wget (the download URL embeds the traversed name; plaintext HTTP without signature validation) and root lxc-start. With CMD=remove, deep traversal reaches rm -rf ${CONTAINER_DIR}/${NAME} for arbitrary directory deletion. Dynamically verified on a physical device: the request returned "Installing container ../etc" and the root service_container.sh and wget processes were captured on the device.

## Additional Information

### Product_version

Linksys Velop LN11 (Micro Router 6)

1.0.9.216616

### Affected_component

- /cgi-bin/container.cgi, parameter c_name (URL-decoded, traversal unvalidated)
- sink: root-executed service_container.sh (wget / lxc-start on install, rm -rf on remove)

### Attack_vector

An authenticated LAN attacker sends GET /cgi-bin/container.cgi?CMD=install&c_name=..%2Fetc; the traversal value flows into root script execution. With CMD=remove and deep traversal, arbitrary directory deletion.

### CVSS

CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H (6.8)

### Proof_of_concept

GET /cgi-bin/container.cgi?CMD=install&c_name=..%2Fetc → "Installing container ../etc"; device process list captured root "service_container.sh container::get ../etc" and root "wget .../utopia_containers/elm//../etc.container.tgz". Verified on 2026-10-11; environment restored after observation.

PoC script: [poc.py](poc.py) - Screenshot: [screenshot.md](screenshot.md) (replace with screenshot.png)

### Description

Linksys Velop LN11 1.0.9.216616 was discovered to contain a path traversal vulnerability in the c_name parameter of /cgi-bin/container.cgi leading to root script execution and arbitrary directory deletion

### Reference

- https://www.linksys.com/
- https://github.com/jackkkk0112/vuls/blob/main/Linksys/Velop_LN11_1.0.9.216616/7_container_traversal/report-7.md
- Vendor notified 2026-09; vendor replied "no issue found" after approximately one month
