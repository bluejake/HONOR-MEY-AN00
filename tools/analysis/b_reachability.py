#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
防御验证 05：追 B 类路径的用户态可达性

问题
  DEFENSE-VERIFY-04 发现 remove_waiter() 有第二个上游：
    rt_mutex_slowlock <- rt_mutex_lock（21 个直接调用者）
  本脚本回答：这 21 个调用点里，有没有能追到用户态 syscall 入口的？

方法
  1. 取 rt_mutex_lock / rt_mutex_lock_interruptible / rt_mutex_lock_killable
     的全部直接调用者作为第 1 层
  2. 对每个第 1 层函数做向上 BFS（不限符号白名单，但做深度限制）
  3. 判定每条链的顶端是不是 __arm64_sys_* / __se_sys_* / 已知 syscall 入口
  4. 输出：能到达 syscall 的链 + 不能的（及其中断点）

输出: analysis/output/b_reachability.txt
"""
import struct, sys, re
from collections import defaultdict

IMAGE = r"D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
TEXT_BASE = 0xffffffc080000000
KS = r"D:/MEY-AN00-root-repro/analysis/output/kallsyms_mey_an00.txt"
OUT = r"D:/MEY-AN00-root-repro/analysis/output/b_reachability.txt"

RT_MUTEX_LOCK_FAMILY = {
    0xffffffc08107fbe4: "rt_mutex_lock",
    0xffffffc08107fccc: "rt_mutex_lock_interruptible",
    0xffffffc08107fdb8: "rt_mutex_lock_killable",
}

SYS_RE = re.compile(r"^__arm64_(compat_)?sys_|^__se_sys_|^__do_sys_|^ksys_|^sys_")
# 已知的用户态可达顶层（syscall 分发）
DISPATCH = {
    "invoke_syscall", "do_el0_svc", "el0_svc_common", "el0t_64_sync_handler",
    "el0_svc", "__arm64_sys_", "__arm64_compat_sys_",
}

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

    # 全量调用图（双向）
    n = len(data) // 4
    words = struct.unpack_from("<%dI" % n, data, 0)
    callers = defaultdict(set)
    callees = defaultdict(set)
    for i, w in enumerate(words):
        if (w & 0xFC000000) == 0x94000000:
            imm26 = w & 0x03FFFFFF
            if imm26 & 0x02000000: imm26 -= 0x04000000
            va = TEXT_BASE + i * 4
            tgt = va + imm26 * 4
            f = owner(tgt); fo = owner(va)
            if f and fo:
                callers[f[0]].add(fo[0])
                callees[fo[0]].add(f[0])

    out = []
    out.append("=" * 76)
    out.append("B 类路径用户态可达性分析")
    out.append("入口: rt_mutex_lock / _interruptible / _killable")
    out.append("=" * 76)
    out.append("")

    # 第 1 层
    layer1 = {}
    for a, nm in RT_MUTEX_LOCK_FAMILY.items():
        for ca in callers[a]:
            layer1.setdefault(ca, set()).add(nm)
    out.append("【第 1 层】rt_mutex_lock 家族的直接调用者（去重后 %d 个）" % len(layer1))
    out.append("-" * 76)
    for ca in sorted(layer1):
        f = owner(ca)
        out.append("  %-42s @0x%x   [经由 %s]" %
                   (f[1], ca, ",".join(sorted(layer1[ca]))))
    out.append("")

    # 向上 BFS，找 syscall 入口
    out.append("【向上追溯】寻找 syscall 入口（深度上限 10）")
    out.append("-" * 76)
    MAXD = 10
    results = {"syscall": [], "leaf": []}

    for ca in sorted(layer1):
        start_name = owner(ca)[1]
        # BFS
        q = [(ca, [ca])]
        visited = set()
        found = []
        guard = 0
        while q and guard < 20000:
            guard += 1
            cur, path = q.pop(0)
            if len(path) > MAXD:
                found.append(("deep", path)); continue
            ups = callers[cur]
            if not ups:
                found.append(("leaf", path)); continue
            for u in ups:
                f = owner(u)
                if not f: continue
                if u in path:
                    continue
                # 命中 syscall？
                if SYS_RE.search(f[1]):
                    found.append(("syscall", path + [u]))
                    continue
                if f[1] in ("invoke_syscall", "do_el0_svc", "el0_svc_common",
                            "el0t_64_sync_handler", "el0_svc"):
                    found.append(("syscall", path + [u]))
                    continue
                key = (u, len(path))
                if key in visited: continue
                visited.add(key)
                q.append((u, path + [u]))
        # 归类
        sys_hits = [p for k, p in found if k == "syscall"]
        leaf_hits = [p for k, p in found if k != "syscall"]
        if sys_hits:
            for p in sys_hits[:5]:
                names = [owner(x)[1] if owner(x) else "?" for x in p]
                out.append("  ★ %s" % "  <-  ".join(names))
            results["syscall"].append((start_name, sys_hits))
        else:
            # 记录最长的几条未达链
            def depth(p): return len(p)
            leaf_hits.sort(key=depth, reverse=True)
            for p in leaf_hits[:2]:
                names = [owner(x)[1] if owner(x) else "?" for x in p]
                out.append("    · %s   [顶端: %s]" %
                           ("  <-  ".join(names), names[-1]))
            results["leaf"].append((start_name, leaf_hits))

    out.append("")
    out.append("=" * 76)
    out.append("【汇总】")
    out.append("-" * 76)
    out.append("  到达 syscall 入口的第 1 层函数数: %d / %d" %
               (len(results["syscall"]), len(layer1)))
    out.append("  未到达 syscall 的第 1 层函数数: %d" % len(results["leaf"]))
    out.append("")
    if results["syscall"]:
        out.append("  ★ 用户态可达的顶层函数:")
        tops = set()
        for nm, hits in results["syscall"]:
            for p in hits:
                tops.add(owner(p[-1])[1] if owner(p[-1]) else "?")
        for t in sorted(tops):
            out.append("     %s" % t)

    open(OUT, "w", encoding="utf-8").write("\n".join(out))
    print("wrote", OUT)
    print("第 1 层函数数:", len(layer1))
    print("到达 syscall 的:", len(results["syscall"]))
    print("未到达的:", len(results["leaf"]))
    return 0

if __name__ == "__main__":
    sys.exit(main())
