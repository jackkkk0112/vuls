# vuln

Security advisories for vulnerabilities discovered during independent research on owned devices.

Directory layout: `Vendor/Product_FirmwareVersion/vuln_folder/` — one folder per vulnerability, each containing `report-N.md`, `poc.py`, and a verification screenshot.

## Linksys Velop LN11 (Micro Router 6), firmware 1.0.9.216616

| Report | Entry point | Parameter | Type |
|---|---|---|---|
| [report-1](Linksys/Velop_LN11_1.0.9.216616/1_configme_injection/report-1.md) | MQTT topic `network/+/CONFIG-ME/subdev/+/status` (TCP 1883, anonymous) + JNAP `StartSmartConnectServer` | JSON `uuid` field → `system()` | Command injection (stage 1 unauthenticated) |
| [report-2](Linksys/Velop_LN11_1.0.9.216616/2_btsmartconnect_status/report-2.md) | JNAP `nodes/btsmartconnect/BTRequestGetSmartConnectStatus` | `pin` | Command injection |
| [report-3](Linksys/Velop_LN11_1.0.9.216616/3_btsmartconnect_client/report-3.md) | JNAP `nodes/btsmartconnect/BTRequestStartSmartConnectClient` | `setupAP` | Command injection |
| [report-4](Linksys/Velop_LN11_1.0.9.216616/4_smartconnect_status/report-4.md) | JNAP `nodes/smartconnect/BTRequestGetSmartConnectStatus` | `pin` | Command injection |
| [report-5](Linksys/Velop_LN11_1.0.9.216616/5_smartconnect_client/report-5.md) | JNAP `nodes/smartconnect/BTRequestStartSmartConnectClient` | `setupAP` | Command injection |
| [report-6](Linksys/Velop_LN11_1.0.9.216616/6_execsyscommand_bypass/report-6.md) | JNAP `diagnostics/ExecSysCommand` | `cmd` / `param` | Command execution (whitelist bypass via path normalization) |
| [report-7](Linksys/Velop_LN11_1.0.9.216616/7_container_traversal/report-7.md) | `GET /cgi-bin/container.cgi` | `c_name` | Path traversal |
