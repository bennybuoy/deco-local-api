#!/usr/bin/env python3
"""CLI around DecoClient: login + arbitrary calls (read-only by default)."""

from __future__ import annotations

import json
import sys

from deco_client import DecoClient

PWD = "W@lbk051"
USER = "admin"


def session(host="192.168.68.1", scheme="http"):
    c = DecoClient(host=host, scheme=scheme)
    c.fetch_keys()
    st, raw, _, _ = c.login(USER, PWD)
    j = c._open(raw)
    c.stok = j["result"]["stok"]
    return c


def show(tag, st, obj, raw):
    print(f"--- {tag}  http={st}")
    print(json.dumps(obj, indent=2)[:4000])
    if isinstance(obj, dict) and "_decrypt_error" in obj:
        print(f"    raw={raw[:400]}")


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "get-cwmp"
    c = session()
    print(f"stok={c.stok} seq={c.seq}")
    if cmd == "get-cwmp":
        st, obj, raw = c.call("/admin/cwmp", "cwmp", {"operation": "get"})
        show("GET /admin/cwmp?form=cwmp", st, obj, raw)
    elif cmd == "set-cwmp":
        url = argv[2] if len(argv) > 2 else "http://192.168.68.53:7547/"
        st, obj, raw = c.call("/admin/cwmp", "cwmp",
                              {"operation": "set", "params": {"enable": True, "server_url": url}})
        show(f"SET /admin/cwmp?form=cwmp server_url={url}", st, obj, raw)
        st, obj, raw = c.call("/admin/cwmp", "cwmp", {"operation": "get"})
        show("VERIFY get", st, obj, raw)
    elif cmd == "raw":
        path, form, payload = argv[2], argv[3], json.loads(argv[4])
        st, obj, raw = c.call(path, form, payload)
        show(f"{path}?form={form}", st, obj, raw)
    else:
        print(f"unknown cmd {cmd}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
