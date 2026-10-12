#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""forensic_reason.py — 查 _ID=1108..1143 的 key_log reason（内核 fault 具体原因）+ 全部 t=0 事件"""
import sqlite3, os, sys, datetime

BASE = r"D:\MEY-AN00-root-repro\device_archive"
OUT  = r"D:\MEY-AN00-root-repro\analysis\output\forensic_reason_20261003.txt"
_orig = sys.stdout
sys.stdout = _f = open(OUT, "w", encoding="utf-8")
def P(*a): print(*a); print(*a, file=_orig)

con = sqlite3.connect(f"file:{os.path.join(BASE,'sync_boot40_pre','reliability','faultdetect','event.db')}?mode=ro", uri=True)
cur = con.cursor()

P("== key_log: _ID 1100..1143（含 dumplog 事件 reason）==")
for r in cur.execute("SELECT _ID,event_id,process_name,happentime,reason,substr(extra_info,1,300) FROM key_log WHERE _ID>=1100 ORDER BY _ID"):
    P(f"\n_ID={r[0]} eid={r[1]} proc={r[2]!r} t={r[3]}")
    P(f"  reason={r[4]!r}")
    P(f"  extra={r[5]!r}")

P("\n\n== key_log: 全部 reason 含 kernel/dump/panic/ree/tees/mm 的行（全历史）==")
for r in cur.execute("SELECT _ID,event_id,process_name,happentime,reason FROM key_log WHERE reason LIKE '%panic%' OR reason LIKE '%ree%' OR reason LIKE '%tee%' OR reason LIKE '%dump%' OR reason LIKE '%modem%' OR reason LIKE '%adsp%' OR reason LIKE '%slb%' OR reason LIKE '%kernel%' ORDER BY _ID DESC LIMIT 80"):
    P(f"  _ID={r[0]} eid={r[1]} proc={r[2]!r} t={r[3]} reason={str(r[4])[:220]!r}")

P("\n\n== event_info: _ID>=1100 的 event_fingerprint/space_type ==")
for r in cur.execute("SELECT _ID,event_id,event_fingerprint,space_type FROM event_info WHERE _ID>=1100 ORDER BY _ID"):
    P(f"  _ID={r[0]} eid={r[1]} fp={str(r[2])[:64]} space={r[3]}")

con.close()
_f.close()
