#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
精确版本：只枚举「真正到达 remove_waiter()」的调用链。

上一版 BFS 的问题：从 remove_waiter 向上的"任意到达"会把
exit/reboot 等无关函数也纳进来（因为它们能调用到中间层）。

正确做法：对 remove_waiter 的【三个直接调用者】逐个做
「谁调用了它」的精确回溯，并在每一层用白名单过滤
（只保留 rt_mutex / futex / sched 相关符号），得到真正的可达链。

输出: analysis/output/reachability2.txt
"""
import struct, sys, re
from collections import defaultdict

IMAGE = r"D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
TEXT_BASE = 0xffffffc080000000
KS = r"D:/MEY-AN00-root-repro/analysis/output/kallsyms_mey_an00.txt"
OUT = r"D:/MEY-AN00-root-repro/analysis/output/reachability2.txt"

ROOT = 0xffffffc081080e60  # remove_waiter

def load():
    funcs = []
    for line in open(KS, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) >= 3:
            try:
                funcs.append((int(p[0], 16), p[1], p[2]))
            except ValueError:
                pass
    funcs.sort()
    return funcs

def main():
    data = open(IMAGE, "rb").read()
    funcs = load()
    text = [(a, n) for a, t, n in funcs if t in ("T", "t")]
    ta = [a for a, n in text]

    def owner(va):
        lo, hi = 0, len(ta) - 1; best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if ta[mid] <= va: best = mid; lo = mid + 1
            else: hi = mid - 1
        return text[best] if best is not None else None

    # 建全量调用图
    n = len(data) // 4
    words = struct.unpack_from("<%dI" % n, data, 0)
    callers = defaultdict(set)   # callee_addr -> set(caller_addr, site)
    for i, w in enumerate(words):
        if (w & 0xFC000000) == 0x94000000:
            imm26 = w & 0x03FFFFFF
            if imm26 & 0x02000000: imm26 -= 0x04000000
            va = TEXT_BASE + i * 4
            tgt = va + imm26 * 4
            f = owner(tgt); fo = owner(va)
            if f and fo:
                callers[f[0]].add((fo[0], va))

    out = []
    out.append("=" * 74)
    out.append("remove_waiter() 精确可达性分析")
    out.append("root = remove_waiter @0x%x" % ROOT)
    out.append("=" * 74)
    out.append("")

    # 只看 rt_mutex / futex / sched 相关的上游（其余为噪声）
    RELEVANT = re.compile(r"rt_mutex|futex|sched|pi_state|rtmutex|"
                          r"proxy|slowlock|__mutex|ww_mutex|futex_requeue", re.I)

    # 三个直接调用者
    direct = {}
    for ca, site in callers[ROOT]:
        direct.setdefault(ca, []).append(site)

    out.append("【第 1 层】直接调用 remove_waiter()（全部）")
    out.append("-" * 74)
    for ca in sorted(direct):
        f = owner(ca)
        out.append("  %-38s @0x%x   调用点: %s" %
                   (f[1], ca, ", ".join("0x%x" % s for s in sorted(direct[ca]))))
    out.append("")

    # 对每个直接调用者，逐层向上（相关符号白名单）
    out.append("【上游链】每个直接调用者的上层（过滤：仅 rt_mutex/futex/sched 相关）")
    out.append("-" * 74)
    all_chains = []
    for d in sorted(direct):
        dname = owner(d)[1]
        out.append("")
        out.append("● %s @0x%x 的上游:" % (dname, d))
        # BFS 向上，深度 6
        q = [(d, [d])]
        found_leaf = []
        guard = 0
        while q and guard < 4000:
            guard += 1
            cur, path = q.pop(0)
            ups = [ca for ca, s in callers[cur]]
            if not ups:
                found_leaf.append(path); continue
            any_rel = False
            for ca in ups:
                f = owner(ca)
                if not f: continue
                if RELEVANT.search(f[1]):
                    any_rel = True
                    if ca in path:
                        continue
                    q.append((ca, path + [ca]))
                else:
                    # 无关符号：只记录一层，不再上溯
                    found_leaf.append(path + [ca])
            if not any_rel and len(path) >= 1:
                pass
        # 去重打印
        seen = set()
        cnt = 0
        for p in found_leaf:
            key = tuple(p)
            if key in seen: continue
            seen.add(key)
            names = [owner(x)[1] if owner(x) else "?" for x in p]
            # 只打印含 syscall 命名或长度>1 的
            if len(p) > 1 or "sys" in names[-1]:
                cnt += 1
                if cnt <= 12:
                    out.append("    %s" % "  <-  ".join(names))
                    all_chains.append(names)
        if cnt > 12:
            out.append("    ... 另有 %d 条" % (cnt - 12))

    out.append("")
    out.append("=" * 74)
    out.append("【入口层汇总】顶层为 syscall 的链")
    out.append("-" * 74)
    sysentry = [c for c in all_chains if c and re.search(r"__arm64_(compat_)?sys_|__se_sys_", c[-1])]
    if sysentry:
        for c in sysentry:
            out.append("  " + "  <-  ".join(c))
    else:
        out.append("  (无)")

    open(OUT, "w", encoding="utf-8").write("\n".join(out))
    print("wrote", OUT)
    print("直接调用者数:", len(direct))
    return 0

if __name__ == "__main__":
    sys.exit(main())
