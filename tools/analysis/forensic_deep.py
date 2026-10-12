#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""forensic_deep.py — 针对 event.db key_log / event_id 分布 / log.db 内核事件 / boot 基准 diff"""
import sqlite3, os, sys, io, glob, datetime, re

BASE = r"D:\MEY-AN00-root-repro\device_archive"
OUT  = r"D:\MEY-AN00-root-repro\analysis\output\forensic_deep_20261003.txt"

_orig = sys.stdout
sys.stdout = _f = open(OUT, "w", encoding="utf-8")
def P(*a):
    print(*a); print(*a, file=_orig)

def fmt_ts(v):
    if v is None: return "None"
    try: v = int(v)
    except (TypeError, ValueError): return str(v)
    for div in (1, 1000):
        t = v / div
        if 1_700_000_000 < t < 1_900_000_000:
            return datetime.datetime.fromtimestamp(t).strftime("%m-%d %H:%M:%S")
    return str(v)

def open_ro(p): return sqlite3.connect(f"file:{p}?mode=ro", uri=True)

W0 = int(datetime.datetime(2026, 10, 2, 10, 0).timestamp())
W1 = int(datetime.datetime(2026, 10, 3, 1, 30).timestamp())
P(f"window {fmt_ts(W0)} .. {fmt_ts(W1)}")

NEW = os.path.join(BASE, "sync_boot40_pre", "reliability", "faultdetect", "event.db")

# 基准：最早带 event.db 的归档
cands = sorted(glob.glob(os.path.join(BASE, "sync_boot*_pre")), key=lambda d: int(re.search(r"boot(\d+)_pre", d).group(1)))
base_db = None
for d in cands:
    p = os.path.join(d, "reliability", "faultdetect", "event.db")
    if os.path.exists(p) and os.path.getsize(p) > 0:
        base_db = p; base_tag = os.path.basename(d); break
P(f"base={base_tag} new=boot40_pre")

con = open_ro(NEW); cur = con.cursor()

# 1) event_id 分布
P("\n== [1] event.db event_info: event_id 分布 ==")
for eid, n, mx in cur.execute("SELECT event_id, COUNT(*), MAX(happentime) FROM event_info GROUP BY event_id ORDER BY event_id"):
    P(f"  {eid}  n={n}  newest={fmt_ts(mx)}")

# 2) key_log 窗口内 + reason 非空
P("\n== [2] event.db key_log: 窗口内全部行（含 reason）==")
n = 0
for r in cur.execute("SELECT _ID,event_id,process_name,happentime,reason,extra_info FROM key_log WHERE happentime>=? AND happentime<=? ORDER BY happentime", (W0, W1)):
    n += 1
    P(f"  _ID={r[0]} eid={r[1]} proc={r[2]} t={fmt_ts(r[3])} reason={r[4]!r} extra={str(r[5])[:200]!r}")
P(f"  (窗口内 key_log 共 {n} 行)")

# 3) key_log reason 非空全部历史（找内核 fault reason 模式）
P("\n== [3] event.db key_log: reason 非空的全部行 ==")
n = 0
for r in cur.execute("SELECT _ID,event_id,process_name,happentime,reason FROM key_log WHERE reason IS NOT NULL AND reason!='' ORDER BY happentime DESC LIMIT 200"):
    n += 1
    P(f"  _ID={r[0]} eid={r[1]} proc={r[2]} t={fmt_ts(r[3])} reason={r[4]!r}")
P(f"  (reason 非空 {n} 行)")

# 4) event_info 窗口内全部行
P("\n== [4] event.db event_info: 窗口内全部行 ==")
for r in cur.execute("SELECT _ID,event_id,happentime,extra,space_type FROM event_info WHERE happentime>=? AND happentime<=? ORDER BY happentime", (W0, W1)):
    P(f"  _ID={r[0]} eid={r[1]} t={fmt_ts(r[2])} space={r[4]} extra={str(r[3])[:160]}")
con.close()

# 5) diff base -> boot40
P(f"\n== [5] DIFF event_info {base_tag} -> boot40_pre ==")
try:
    def load(p):
        c = open_ro(p).cursor()
        return {r[0]: r for r in c.execute("SELECT _ID,event_id,happentime,extra,space_type FROM event_info")}
    a, b = load(base_db), load(NEW)
    added = [b[k] for k in b if k not in a]
    P(f"  old={len(a)} new={len(b)} added={len(added)}")
    for r in sorted(added, key=lambda x: x[2]):
        P(f"  +_ID={r[0]} eid={r[1]} t={fmt_ts(r[2])} space={r[4]} extra={str(r[3])[:160]}")
except Exception as e:
    P(f"  ERROR {e}")

# 6) log.db 内核相关 event_id + 窗口
LOG = os.path.join(BASE, "sync_boot40_pre", "log.db")
P(f"\n== [6] log.db event_info: event_id 分布（含 last_occurrence_time）==")
con2 = open_ro(LOG); c2 = con2.cursor()
for eid, n, mx in c2.execute("SELECT event_id, COUNT(*), MAX(last_occurrence_time) FROM event_info GROUP BY event_id ORDER BY event_id"):
    P(f"  {eid}  n={n}  newest={fmt_ts(mx)}")

P("\n== [7] log.db event_info: last_occurrence_time 在窗口内的行 ==")
for r in c2.execute("SELECT _ID,event_id,occured_times,last_occurrence_time,substr(extra,1,150) FROM event_info WHERE last_occurrence_time>=? AND last_occurrence_time<=? ORDER BY last_occurrence_time", (W0, W1)):
    P(f"  _ID={r[0]} eid={r[1]} times={r[2]} t={fmt_ts(r[3])} extra={r[4]}")

P("\n== [8] log.db event_info: extra 中含 kasan/panic/WARN/Unable/UAF/slab 的行（全历史）==")
n = 0
for r in c2.execute("SELECT _ID,event_id,occured_times,last_occurrence_time,substr(extra,1,220) FROM event_info WHERE extra LIKE '%asan%' OR extra LIKE '%panic%' OR extra LIKE '%Unable to hand%' OR extra LIKE '%WARN%' OR extra LIKE '%page request%' OR extra LIKE '%BUG:%' ORDER BY last_occurrence_time DESC LIMIT 100"):
    n += 1
    P(f"  _ID={r[0]} eid={r[1]} times={r[2]} t={fmt_ts(r[3])} extra={r[4]}")
P(f"  ({n} 行)")
con2.close()
_f.close()
