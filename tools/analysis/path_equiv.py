#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
判定：本项目的 sched_setattr 触发路径，是否等价于官方公告的
      futex_requeue() → rt_mutex_start_proxy_lock() proxy-lock 回滚路径？

关键问题：
  1. remove_waiter() 的所有调用点在哪？各自的上游是谁？
  2. 是否有 remove_waiter() 的调用点能通过 sched_setattr / __sched_setscheduler 到达？
  3. 官方路径 (futex_requeue) 长什么样？

输出: analysis/output/path_equiv.asm
"""
import re, sys
from capstone import *

IMAGE = r"D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
TEXT_BASE = 0xffffffc080000000
KS = r"D:/MEY-AN00-root-repro/analysis/output/kallsyms_mey_an00.txt"
OUT = r"D:/MEY-AN00-root-repro/analysis/output/path_equiv.asm"

TARGETS = {
    0xffffffc081080e60: "remove_waiter",
    0xffffffc081080df4: "rt_mutex_start_proxy_lock",
    0xffffffc0810813a4: "rt_mutex_cleanup_proxy_lock",
    0xffffffc0810810cc: "rt_mutex_wait_proxy_lock",
    0xffffffc081080570: "__rt_mutex_start_proxy_lock",
    0xffffffc0810815d4: "rt_mutex_adjust_prio_chain",
    0xffffffc081081438: "rt_mutex_adjust_pi",
    0xffffffc080169894: "__sched_setscheduler",
    0xffffffc08016c618: "do_sched_setscheduler",
    0xffffffc0810809c0: "task_blocks_on_rt_mutex",
}

def load_syms():
    syms = []
    for line in open(KS, encoding="utf-8", errors="replace"):
        p = line.split()
        if len(p) >= 3:
            try:
                syms.append((int(p[0], 16), p[1], p[2]))
            except ValueError:
                pass
    syms.sort()
    return syms

def sym_at(syms, addr):
    """返回 >= addr 的最近符号"""
    lo, hi = 0, len(syms) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if syms[mid][0] <= addr:
            best = syms[mid]; lo = mid + 1
        else:
            hi = mid - 1
    return best

def disasm(data, va, length):
    off = va - TEXT_BASE
    buf = data[off:off+length]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    return list(md.disasm(buf, va))

def main():
    data = open(IMAGE, "rb").read()
    syms = load_syms()
    out = []

    # ---- 全局扫描：谁调用 remove_waiter ----
    out.append("=" * 70)
    out.append("全局扫描：bl 0xffffffc081080e60 (remove_waiter) 的调用点")
    out.append("=" * 70)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    hit_calls = []
    TARGET = 0xffffffc081080e60
    # 分段反汇编整个 .text 太慢；改为扫描所有函数入口附近不现实。
    # 改用：B 指令编码扫描（bl 是 0x94000000 掩码 0xFC000000）
    import struct
    n = len(data) // 4
    words = struct.unpack_from("<%dI" % n, data, 0)
    for i, w in enumerate(words):
        if (w & 0xFC000000) == 0x94000000:
            imm26 = w & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 -= 0x04000000
            va = TEXT_BASE + i*4
            tgt = va + imm26*4
            if tgt == TARGET:
                hit_calls.append(va)
    if hit_calls:
        for va in hit_calls:
            s = sym_at(syms, va)
            out.append("  调用点 0x%x   所在函数: %s (+0x%x)" %
                       (va, s[2] if s else "?", va - s[0] if s else 0))
    else:
        out.append("  (未找到)")
    out.append("")

    # ---- 反汇编关键函数 ----
    for va, name in TARGETS.items():
        out.append("=" * 70)
        out.append("%s @ 0x%x" % (name, va))
        out.append("=" * 70)
        try:
            insns = disasm(data, va, 0x300)
        except Exception as e:
            out.append("  disasm error: %s" % e); out.append(""); continue
        for ins in insns:
            mark = ""
            # 标记所有 bl 到已知符号的调用
            if ins.mnemonic in ("bl", "b") and ins.op_str.startswith("#0x"):
                tgt = int(ins.op_str[1:], 16)
                if tgt in TARGETS:
                    mark = "   <== %s" % TARGETS[tgt]
                elif tgt == TARGET:
                    mark = "   <== remove_waiter"
            out.append("  0x%x:\t%s\t%s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
        out.append("")

    open(OUT, "w", encoding="utf-8").write("\n".join(out))
    print("wrote", OUT)
    print("remove_waiter 调用点数:", len(hit_calls))
    for va in hit_calls:
        s = sym_at(syms, va)
        print("  0x%x  in %s" % (va, s[2] if s else "?"))
    return 0

if __name__ == "__main__":
    sys.exit(main())
