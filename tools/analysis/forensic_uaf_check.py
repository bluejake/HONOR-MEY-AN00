#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""forensic_uaf_check.py — 2026-10-03
判定核心问题：~60 boots / ~2000 attempts 的 CVE-2026-64560 stage0 尝试期间，
设备上是否发生过任何内核级 fault（WARN_ON_ONCE / KASAN / panic / SSR）。

数据源（全部为本地归档副本，只读打开）：
  1. reliability/faultdetect/event.db   — faultdetect 事件索引（_ID,event_id,extra,happentime,...）
  2. reliability/faultdetect/history.log — fault 原因流水（reason[page_request|null_pointer|...]）
  3. reliability/faultdetect/subsystem_qcom.log —高通 SSR 日志
  4. log.db (127MB) — 全量日志库（含 901000002 内核 panic 类）
  5. ue_log.db — 用户环境日志
对每个 sync_bootN_pre 归档只取最新一个（boot40 = 数据最全），另外 diff boot2_pre
（campaign62 起点）与 boot40_pre 之间 event.db 的新增行 —— 精确定位测试窗口内新增 fault。
"""
import sqlite3, os, sys, io, glob, datetime, re

BASE = r"D:\MEY-AN00-root-repro\device_archive"
OUT  = r"D:\MEY-AN00-root-repro\analysis\output\forensic_uaf_check_20261003.txt"

_orig_stdout = sys.stdout
sys.stdout = _fout = open(OUT, "w", encoding="utf-8")

def P(*a):
    print(*a)
    print(*a, file=_orig_stdout)

_boot_re = re.compile(r"sync_boot(\d+)_pre$")

def boots():
    out = []
    for d in glob.glob(os.path.join(BASE, "sync_boot*_pre")):
        m = _boot_re.search(d)
        if m:
            out.append((int(m.group(1)), d))
    out.sort()
    return out

def fmt_ts(v):
    if v is None: return "None"
    try:
        v = int(v)
    except (TypeError, ValueError):
        return str(v)
    for div in (1, 1000):           # 秒 or 毫秒
        t = v / div
        if 1_700_000_000 < t < 1_900_000_000:
            return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S") + ("" if div == 1 else " (ms)")
    return str(v)

def open_ro(path):
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)

def dump_table(con, table, ts_cols):
    cur = con.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    cur.execute(f"SELECT COUNT(*) FROM {table}")
    n = cur.fetchone()[0]
    print(f"  table {table}: {n} rows, cols={cols}")
    return cols, n

def query_eventdb(path, tag, window=None):
    print(f"\n### event.db [{tag}] {path}")
    if not os.path.exists(path):
        print("  MISSING"); return None
    con = open_ro(path)
    rows = []
    try:
        cur = con.cursor()
        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        print(f"  tables={tables}")
        for t in tables:
            cols, n = dump_table(con, t, ["happentime", "last_occurrence_time"])
            # 找时间列
            tcol = next((c for c in ("happentime", "last_occurrence_time", "time", "timestamp") if c in cols), None)
            if tcol is None or n == 0:
                continue
            sel = ", ".join(cols)
            order = tcol if tcol in cols else "_ID"
            cur.execute(f"SELECT {sel} FROM {t} ORDER BY {order} DESC LIMIT 400")
            data = cur.fetchall()
            rows = [dict(zip(cols, r)) for r in data]
            print(f"  -- newest 400 of {n} (by {order}) --")
            # 全部打印（最多400行），重点标红窗口内的
            for r in reversed(rows):  # 旧→新
                ts = r.get(tcol)
                mark = ""
                if window and isinstance(ts, int):
                    if window[0] <= ts <= window[1]:
                        mark = "  <<< IN-TEST-WINDOW"
                print("   " + " | ".join(f"{k}={fmt_ts(v) if k.endswith('time') else v}" for k, v in r.items()) + mark)
    except Exception as e:
        print(f"  ERROR: {e}")
    finally:
        con.close()
    return rows

def diff_eventdb(old, new):
    """按 (_ID) 或 (event_id,happentime) 对比两份 event.db 的新增行"""
    print(f"\n### DIFF event.db {os.path.basename(os.path.dirname(old))} -> {os.path.basename(os.path.dirname(new))}")
    try:
        def load(p):
            con = open_ro(p); cur = con.cursor()
            tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            allrows = {}
            for t in tables:
                cur.execute(f"PRAGMA table_info({t})")
                cols = [r[1] for r in cur.fetchall()]
                if not cols: continue
                cur.execute(f"SELECT {','.join(cols)} FROM {t}")
                allrows[t] = [dict(zip(cols, r)) for r in cur.fetchall()]
            con.close()
            return allrows
        a, b = load(old), load(new)
        for t in b:
            ra, rb = a.get(t, []), b[t]
            key = "_ID" if rb and "_ID" in rb[0] else (list(rb[0].keys())[:3] if rb else None)
            def keyf(r):
                if key == "_ID": return r["_ID"]
                return tuple(str(r.get(k)) for k in key)
            sa = {keyf(r) for r in ra}
            added = [r for r in rb if keyf(r) not in sa]
            print(f"  table {t}: old={len(ra)} new={len(rb)} ADDED={len(added)}")
            for r in added:
                print("   +" + " | ".join(f"{k}={fmt_ts(v) if k.endswith('time') else v}" for k, v in r.items()))
    except Exception as e:
        print(f"  ERROR: {e}")

def tail_text(path, n=120, grep=None):
    print(f"\n### TEXT tail [{os.path.basename(path)}] {path}")
    if not os.path.exists(path):
        print("  MISSING"); return
    try:
        data = open(path, "rb").read()
        lines = data.decode("utf-8", "replace").splitlines()
        print(f"  total {len(lines)} lines; last {min(n,len(lines))}:")
        show = lines[-n:]
        for ln in show:
            if grep is None or re.search(grep, ln, re.I):
                print("   " + ln)
    except Exception as e:
        print(f"  ERROR: {e}")

def query_logdb(path, window=None):
    print(f"\n### log.db {path}  ({os.path.getsize(path)//1024} KB)")
    con = open_ro(path)
    try:
        cur = con.cursor()
        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        print(f"  tables={tables}")
        for t in tables:
            cur.execute(f"PRAGMA table_info({t})")
            cols = [r[1] for r in cur.fetchall()]
            cur.execute(f"SELECT COUNT(*) FROM {t}")
            n = cur.fetchone()[0]
            print(f"  table {t}: {n} rows cols={cols}")
            # 找时间列
            tcol = None
            for c in cols:
                if re.search(r"time|ts$|^ts", c, re.I):
                    tcol = c; break
            if tcol and n:
                cur.execute(f"SELECT MIN({tcol}),MAX({tcol}) FROM {t}")
                mn, mx = cur.fetchone()
                print(f"    {tcol} range: {fmt_ts(mn)} .. {fmt_ts(mx)}")
    except Exception as e:
        print(f"  ERROR: {e}")
    finally:
        con.close()

def main():
    allboots = boots()
    if not allboots:
        P("no archives found"); return
    newest_no, newest = allboots[-1]
    # boot2_pre 是 campaign62 的起点（boot1_pre 失败）
    first_ok = next((d for n, d in allboots if n == 2), allboots[0][1])
    P("=" * 100)
    P(f"forensic_uaf_check @ {datetime.datetime.now()}  newest=boot{newest_no}  archives={len(allboots)}")
    P("=" * 100)

    # 测试窗口：2026-10-02 12:00 → 2026-10-03 01:30 (CST, unix 秒)
    w0 = int(datetime.datetime(2026, 10, 2, 12, 0).timestamp())
    w1 = int(datetime.datetime(2026, 10, 3, 1, 30).timestamp())
    P(f"test window: {datetime.datetime.fromtimestamp(w0)} .. {datetime.datetime.fromtimestamp(w1)}  (unix {w0}..{w1})")

    fd = os.path.join(newest, "reliability", "faultdetect")
    query_eventdb(os.path.join(fd, "event.db"), f"boot{newest_no}_pre", window=(w0, w1))
    tail_text(os.path.join(fd, "history.log"), n=100)
    tail_text(os.path.join(fd, "subsystem_qcom.log"), n=60)
    diff_eventdb(os.path.join(first_ok, "reliability", "faultdetect", "event.db"),
                 os.path.join(newest, "reliability", "faultdetect", "event.db"))
    query_logdb(os.path.join(newest, "log.db"), window=(w0, w1))
    P("\nDONE ->", OUT)
    _fout.close()

if __name__ == "__main__":
    main()
