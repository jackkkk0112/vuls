# vuln

Security advisories for vulnerabilities discovered in embedded/IoT devices during independent research. All findings were verified on physically owned devices in an isolated lab.

Directory layout: `Vendor/Product_FirmwareVersion/vuln_folder/` — one folder per vulnerability, each containing `report-N.md`, `poc.py`, and a verification screenshot.

## Linksys Velop LN11 (Micro Router 6), firmware 1.0.9.216616

| Report | Vulnerability | CVSS 3.1 |
|---|---|---|
| [report-1](Linksys/Velop_LN11_1.0.9.216616/1_configme_injection/report-1.md) | Unauthenticated MQTT poisoning (CONFIG-ME) to root command injection | 6.8 (stage 1 unauthenticated) |
| [report-2](Linksys/Velop_LN11_1.0.9.216616/2_btsmartconnect_status/report-2.md) | Root command injection via pin parameter of btsmartconnect/BTRequestGetSmartConnectStatus | 6.8 |
| [report-3](Linksys/Velop_LN11_1.0.9.216616/3_btsmartconnect_client/report-3.md) | Root command injection via setupAP parameter of btsmartconnect/BTRequestStartSmartConnectClient | 6.8 |
| [report-4](Linksys/Velop_LN11_1.0.9.216616/4_smartconnect_status/report-4.md) | Root command injection via pin parameter of smartconnect/BTRequestGetSmartConnectStatus | 6.8 |
| [report-5](Linksys/Velop_LN11_1.0.9.216616/5_smartconnect_client/report-5.md) | Root command injection via setupAP parameter of smartconnect/BTRequestStartSmartConnectClient | 6.8 |
| [report-6](Linksys/Velop_LN11_1.0.9.216616/6_execsyscommand_bypass/report-6.md) | Root command execution via ExecSysCommand whitelist bypass (realpath confusion) | 6.8 |
| [report-7](Linksys/Velop_LN11_1.0.9.216616/7_container_traversal/report-7.md) | Path traversal in container.cgi c_name → root script execution / arbitrary directory deletion | 6.8 |

All seven issues were reported to Linksys in September 2026 with full technical details; the vendor replied "no issue found" after approximately one month, without substantive analysis. Each report documents on-device root-execution evidence disputing that position.

Reproducible PoC scripts (parameterized, credentials via environment variables) and verification screenshots live next to each report in its vulnerability folder — [Linksys/Velop_LN11_1.0.9.216616/](Linksys/Velop_LN11_1.0.9.216616/). For owned devices only.

A fifth, more severe finding (pre-authentication Bluetooth Low Energy root RCE) is withheld pending an active coordinated-disclosure process.

Product page: https://www.linksys.com/
