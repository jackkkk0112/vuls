The Tenda G1 (G1v3) Enterprise Router was discovered to contain a plaintext cloud MQTT channel with predictable credentials and dangerous command callbacks

## Overview

Product: Tenda G1 (G1v3) Enterprise Router

Version: V16.01.7.15(4841)

Manufacturer's website information: https://www.tenda.com.cn/

## Affected version

V16.01.7.15(4841)

## Vulnerability description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain an insecure cloud MQTT channel. The /bin/iot_mqtt daemon (config /etc/iot_mqtt.conf, broker iotdev-cloud.tenda.com.cn:4432) connects using libmosquitto_nossl — plaintext MQTT over TCP without TLS. The MQTT credentials are fully derived from public information: the username is the project id and the password is base64(json{dev_type, product_key, product, version, MAC}), with all fields obtainable from the device casing or LAN traffic. The same subsystem exposes an unauthenticated UDP fingerprint service bound to multicast 224.0.0.1:9999 (iot_create_udp_server) whose cmd=1/2 messages make the device disclose SN, MAC, model and firmware version to any attacker-supplied port — completing the credential-construction path from a bare network position. All 27 cloud command callbacks were decompiled and classified: file_upgrade executes system("curl -k ... %s") with a payload-supplied URL (arbitrary download into the firmware-flash pipeline); set_passwd replaces the web administrator password without verifying the old one (oldPwd defaults to 123456 when absent); reboot/reset/poe_reboot destroy or reset the device; set_dhcp/set_static_route/set_port_map/set_wan/set_vlan enable persistent network takeover (MITM); set_remote enables WAN-side web management remotely.

## Additional Information

### Product_version

Tenda G1 (G1v3) Enterprise Router

V16.01.7.15(4841)

### Affected_component

- /bin/iot_mqtt + libiot_ctrl.so + libmosquitto_nossl, config /etc/iot_mqtt.conf
- UDP 224.0.0.1:9999 fingerprint service (iot_create_udp_server / iot_parse_recv_data)
- callbacks: file_upgrade_cb, set_passwd_cb (iot_manage_cipher_set 0x4b3e8), set_dhcp_cb, set_static_route_cb, set_port_map_cb, set_wan_cb, set_vlan_cb, set_remote_cb, reboot_cb, reset_cb, poe_reboot_cb

### Attack_vector

An attacker able to intercept the device's WAN traffic (MITM) or redirect the broker via DNS hijack obtains full device control without any credentials: silent administrator password replacement, arbitrary firmware-image download, persistent DHCP/route manipulation for network-wide MITM, WAN management exposure, or destructive reset.

### CVSS

CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H (8.2, requires network position)

### Proof_of_concept

Static analysis of V16.01.7.15(4841): all 27 iot_mqtt_sub_*_cb callbacks decompiled and classified at function level; the iot_mqtt daemon and the UDP 9999 fingerprint service were confirmed listening on the physical device. The plaintext transport and public-field credential derivation were verified against the firmware binaries and observed configuration.

### Description

Tenda G1 (G1v3) V16.01.7.15(4841) was discovered to contain a plaintext cloud MQTT channel with publicly derivable credentials and unauthenticated device fingerprinting, enabling password replacement and network takeover from a network position

### Reference

- https://www.tenda.com.cn/
- https://github.com/jackkkk0112/vuls/blob/main/Tenda/G1V3.1si_V16.01.7.15/7_cloud_mqtt_channel/report-7.md
- Vendor notified via productsecure@tenda.cn
