The Tenda G1 (G1v3) Enterprise Router was discovered to contain a command injection vulnerability in the diagnostics ping function

## Overview

Product: Tenda G1 (G1v3) Enterprise Router

Version: V16.01.7.15(4841)

Manufacturer's website information: https://www.tenda.com.cn/

## Affected version

V16.01.7.15(4841)

## Vulnerability description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain a command injection vulnerability in the diagnostics ping function. The httpd formSetNetCheckTools handler (0x4e18fc) passes the ip parameter through a character blacklist (blocking ; & ` $ | >) and then concatenates it into snprintf("ping %s -%d -c %d -s %d -W %d") executed via popen(). Line feeds (\n), # and spaces are not blocked: a line feed starts a second shell line and # comments out the trailing ping arguments, enabling additional root commands. The 7.15-introduced ">" filter is bypassed by using cp instead of output redirection. The same diagnostics slot also deadlocks after a small number of requests (httpd worker threads blocking in futex_wait_queue_me, no pthread_cond timeout), wedging the diagnostics subsystem until power cycle — a denial of service independent of the injection.

## Additional Information

### Product_version

Tenda G1 (G1v3) Enterprise Router

V16.01.7.15(4841)

### Affected_component

- httpd formSetNetCheckTools (0x4e18fc), endpoint POST /goform/setModules with module diagnose
- sink: cmd_get_ping_output (0x4dbe50) via popen()
- blacklist: ; & ` $ | > (verified unchanged in 7.15); \n, #, spaces pass

### Attack_vector

An authenticated admin submits a diagnose ping request whose ip field contains \n#-delimited additional shell commands; they execute as root in the popen() shell. The readback requires the diagnostics async slot to be alive.

### CVSS

CVSS:3.1/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H (6.7)

### Proof_of_concept

Verified end-to-end on firmware V16.01.7.11(4267): ip = "127.0.0.1 -c1 #\ncp /etc_ro/shadow /var/webroot/x.t #\n#" produced the root-owned copy retrievable over HTTP. On V16.01.7.15(4841) the code path and blacklist are confirmed unchanged in the binary (payload accepted, set returned 0); the result readback is blocked by the async-slot deadlock (4-5 requests, futex_wait_queue_me), which is itself a DoS. A single-shot readback capture on 7.15 follows the device reboot.

### Description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain a command injection vulnerability in the diagnostics ping function via a blacklist bypass using line feeds and hash characters

### Reference

- https://www.tenda.com.cn/
- https://github.com/jackkkk0112/vuls/blob/main/Tenda/G1V3.1si_V16.01.7.15/6_ping_command_injection/report-6.md
- Vendor notified via productsecure@tenda.cn
