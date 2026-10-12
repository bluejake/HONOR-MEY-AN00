#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
防御侧可达性分析：穷尽所有到达 remove_waiter() 的调用路径。

为何重要（防御视角）
  remove_waiter() 是 CVE-2026-43499 的根因函数。
  攻击面大小 = 有多少条路径能到达它。
  枚举路径数（不是推演怎么利用）是纯粹的静态图上搜索，
  直接服务于「这个根因代码被多少入口暴露」这个防御问题。

方法
  1. 全镜像 bl 指令编码扫描，建「调用者 -> 被调用者」有向边
  2. 从 remove_waiter 反向 BFS / 从 syscall 入口正向 BFS
  3. 输出全部调用链（限制深度，避免爆炸）

输出: analysis/output/reachability.asm
"""
import struct, sys, re
from collections import defaultdict, deque

IMAGE = r"D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
TEXT_BASE = 0xffffffc080000000
KS = r"D:/MEY-AN00-root-repro/analysis/output/kallsyms_mey_an00.txt"
OUT = r"D:/MEY-AN00-root-repro/analysis/output/reachability.txt"

ROOT = 0xffffffc081080e60   # remove_waiter

def load_syms():
    funcs = []   # (addr, type, name)
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
    funcs = load_syms()

    # 函数边界：所有 text 符号 (T/t)
    text = [(a, n) for a, t, n in funcs if t in ("T", "t")]
    text_addr = [a for a, n in text]

    def owner(va):
        """返回包含 va 的函数 (start, name)"""
        lo, hi = 0, len(text_addr) - 1
        best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if text_addr[mid] <= va:
                best = mid; lo = mid + 1
            else:
                hi = mid - 1
        if best is None:
            return None
        return text[best]

    # ---- 建调用图（全量 bl 扫描） ----
    n = len(data) // 4
    words = struct.unpack_from("<%dI" % n, data, 0)
    callers = defaultdict(set)   # callee -> set(caller)
    edges = 0
    for i, w in enumerate(words):
        if (w & 0xFC000000) == 0x94000000:
            imm26 = w & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 -= 0x04000000
            va = TEXT_BASE + i * 4
            tgt = va + imm26 * 4
            f = owner(tgt)
            if f:
                callee_addr, callee_name = f
                fo = owner(va)
                if fo:
                    callers[callee_addr].add((fo[0], fo[1], tgt))
                    edges += 1

    out = []
    out.append("=" * 72)
    out.append("remove_waiter() 可达性分析")
    out.append("root = 0x%x" % ROOT)
    out.append("全镜像 bl 边数 = %d" % edges)
    out.append("=" * 72)

    # ---- 直接调用者 ----
    out.append("")
    out.append("【第 1 层】直接调用 remove_waiter 的函数")
    out.append("-" * 72)
    direct = sorted({(a, n) for a, n, t in callers[ROOT]})
    for a, n in direct:
        sites = sorted(t for ca, cn, t in callers[ROOT] if ca == a)
        out.append("  %-40s @0x%x" % (n, a))
        for s in sites:
            out.append("      调用点 0x%x" % s)
    out.append("  共 %d 个直接调用者" % len(direct))

    # ---- 反向 BFS：向上追溯所有调用链 ----
    out.append("")
    out.append("【上游链】从 remove_waiter 向上追溯调用链（深度上限 12）")
    out.append("-" * 72)
    MAXDEPTH = 12
    chains = []
    stack = [(ROOT, [ROOT])]
    seen_states = set()
    while stack:
        cur, path = stack.pop()
        if len(path) > MAXDEPTH:
            chains.append(path)
            continue
        ups = list(callers[cur])
        if not ups:
            chains.append(path)
            continue
        for ca, cn, site in ups:
            if ca in path:      # 防环
                chains.append(path + [ca])
                continue
            key = (ca, tuple(path))
            if key in seen_states:
                continue
            seen_states.add(key)
            stack.append((ca, path + [ca]))

    out.append("  上游链总数: %d" % len(chains))
    out.append("")
    for i, ch in enumerate(chains, 1):
        names = []
        for va in ch:
            f = owner(va)
            names.append("%s(0x%x)" % (f[1] if f else "?", va))
        out.append("  [%d] %s" % (i, "  <-  ".join(names)))
        out.append("")

    # ---- syscall 层判定 ----
    out.append("=" * 72)
    out.append("【入口层判定】哪些链的顶端是 syscall 入口 / 用户态可达")
    out.append("-" * 72)
    SYS_HINT = re.compile(
        r"(__arm64_sys_|__se_sys_|__do_sys_|^sys_|futex|io_uring|pthread|"
        r"do_syscall|invoke_syscall|el0_svc|__arm64_compat_sys_)", re.I)
    entry_hits = []
    for ch in chains:
        top = owner(ch[-1])
        if top and SYS_HINT.search(top[1]):
            entry_hits.append((top, ch))
    if entry_hits:
        for top, ch in entry_hits:
            out.append("  ★ 顶层入口: %s @0x%x" % (top[1], top[0]))
            names = []
            for va in ch:
                f = owner(va)
                names.append(f[1] if f else "?")
            out.append("     链: %s" % "  <-  ".join(names))
            out.append("")
    else:
        out.append("  (未识别到 syscall 命名入口 — 注意符号表可能无 __arm64_sys_* 前缀)")
        out.append("  顶层函数清单：")
        for ch in chains:
            top = owner(ch[-1])
            if top:
                out.append("    %s @0x%x" % (top[1], top[0]))

    open(OUT, "w", encoding="utf-8").write("\n".join(out))
    print("wrote", OUT)
    print("直接调用者:", [n for a, n in direct])
    print("上游链数:", len(chains))
    return 0

if __name__ == "__main__":
    sys.exit(main())
