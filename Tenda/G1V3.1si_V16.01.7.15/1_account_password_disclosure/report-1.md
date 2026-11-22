The Tenda G1 (G1v3) Enterprise Router was discovered to contain a reversible password disclosure vulnerability in the account list

## Overview

Product: Tenda G1 (G1v3) Enterprise Router

Version: V16.01.7.15(4841)

Manufacturer's website information: https://www.tenda.com.cn/

## Affected version

V16.01.7.15(4841)

## Vulnerability description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain a reversible password disclosure vulnerability in the account list. The httpd formGetAccountList handler (0x4daf10) returns account passwords "encrypted" with prod_encode64 + Base64ToSimpleEncrypt (libcommonprod.so sub_2E500 at 0x2e500): a fixed single-byte substitution table applied to the base64 representation of the password. The substitution uses no key, no salt and no per-device secret; the table is extractable from the public firmware image. Any authenticated web session — including a guest-level account — can call POST /goform/getModules {"account":""} and decode every account's cleartext password, including the administrator's.

## Additional Information

### Product_version

Tenda G1 (G1v3) Enterprise Router

V16.01.7.15(4841)

### Affected_component

- httpd formGetAccountList (0x4daf10), endpoint POST /goform/getModules with body {"account":""}
- libcommonprod.so Base64ToSimpleEncrypt (sub_2E500) — hardcoded 33-byte substitution table

### Attack_vector

Any authenticated session (guest included) requests the account list and decodes the returned "encrypted" passwords using the substitution table extracted from the public firmware; the administrator cleartext password is recovered.

### CVSS

CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (7.3)

### Proof_of_concept

Verified on a physical device running V16.01.7.15(4841): a guest-level session called getModules {"account":""}; both admin accounts were returned with encoded passwords. Decoding with the firmware-extracted table recovered the exact password of the current session (algorithm validation) and the second account's password (123456) in cleartext.

### Description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain a reversible password disclosure vulnerability via the account list returned to any authenticated session

### Reference

- https://www.tenda.com.cn/
- https://github.com/jackkkk0112/vuls/blob/main/Tenda/G1V3.1si_V16.01.7.15/1_account_password_disclosure/report-1.md
- Vendor notified via productsecure@tenda.cn
