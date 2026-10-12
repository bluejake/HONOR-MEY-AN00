#!/usr/bin/env python3
"""从设备拉 log.db 并打印最新 Oops 的 F1/F2/F3 + fault 虚拟地址。

用法: panic_fault.py [db路径]     # 省略则从设备拉取到 analysis/panic/_pull.db
"""
import json
import os
import re
import sqlite3
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB = os.path.join(ROOT, "analysis", "panic", "_pull.db")

ADDR_RE = re.compile(r"virtual address ([0-9a-fA-F]+)")


def pull():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    with open(DB, "wb") as f:
        subprocess.run(["adb", "exec-out", "cat /data/log/log.db"],
                       stdout=f, env=env, check=False)
    return DB


def main():
    db = sys.argv[1] if len(sys.argv) > 1 else pull()
    print("db =", db, os.path.getsize(db), "bytes")
    con = sqlite3.connect("file:%s?mode=ro" % db.replace("\\", "/"), uri=True)
    con.text_factory = lambda b: b.decode("utf-8", "replace")
    cur = con.cursor()
    cur.execute("SELECT extra, last_occurrence_time FROM event_info "
                "WHERE event_id='901000002' ORDER BY last_occurrence_time DESC LIMIT 6")
    for ex, t in cur.fetchall():
        try:
            d = json.loads(ex)
        except Exception:
            print("t=%s  <unparsable>" % t)
            continue
        f1 = d.get("F1NAME", "?")
        f2 = d.get("F2NAME", "?")
        f3 = d.get("F3NAME", "?")
        blob = " ".join(str(d.get(k, "")) for k in ("F3NAME", "F4NAME", "F5NAME", "F6NAME"))
        m = ADDR_RE.search(blob)
        print("t=%-12s F1=%-34s F2=%-38s fault=%s" % (t, str(f1)[:34], str(f2)[:38], m.group(1) if m else "?"))


main()
