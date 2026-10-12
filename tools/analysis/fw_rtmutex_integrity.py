#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
固件完整性核查：rtmutex.c 整文件 vs 上游 v6.6.118

核心问题：
  1. 设备上的 rtmutex.c 是否含厂商/GKI 的 android_vh_* vendor hook？
  2. 若含，hook 挂在哪几个函数？
  3. remove_waiter() 函数体内是否引用了任何 vendor hook（即是否被厂商改动）？

方法：全静态。反汇编镜像中的 rtmutex 函数族，扫描：
  - bl / b 到 __traceiter_* / __tracepoint_* 的调用
  - adrp+add 形式的地址常量引用
"""
import re
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_INS_BL, ARM64_INS_B, \
    ARM64_INS_ADRP, ARM64_INS_ADD, ARM64_INS_LDR

OUT = Path(r"D:\MEY-AN00-root-repro\analysis\output")
IMG = OUT / "kernel_mey_an00.raw"
KS  = OUT / "kallsyms_mey_an00.txt"
REP = OUT / "fw_rtmutex_integrity.txt"

TEXT_BASE = 0xffffffc080000000
TEXT_OFF  = 0x0             # ★ 已用 remove_waiter.asm 实测校准：
                            #   file_off = va - TEXT_BASE（不再额外加 0x1000）
                            #   错误值 0x1000 会读到错位 0x1000 的指令。

# 我们关心的函数族（按地址排序后给定大小由下一个符号决定）
TARGET_RE = re.compile(r"^(remove_waiter|task_blocks_on_rt_mutex|rt_mutex_.*|__rt_mutex_.*|"
                       r"mark_rt_mutex_waiters|__mutex_remove_waiter)$")


def load_syms():
    syms = []
    for line in KS.read_text(errors="replace").splitlines():
        p = line.split()
        if len(p) < 3:
            continue
        try:
            a = int(p[0], 16)
        except ValueError:
            continue
        syms.append((a, p[1], p[2]))
    syms.sort()
    return syms


def main():
    lines = []
    def w(s=""):
        lines.append(s)
        print(s)

    syms = load_syms()
    addr2name = {a: n for a, t, n in syms}

    # 建立 地址 -> (名, 下一个地址) 用于界定函数体
    idx = {a: i for i, (a, t, n) in enumerate(syms)}

    # 收集所有 tracepoint / traceiter 符号地址
    tp_syms = {}
    for a, t, n in syms:
        if n.startswith("__traceiter_") or n.startswith("__tracepoint_") or n.startswith("__probestub_"):
            tp_syms[a] = n

    w("=" * 78)
    w(" 固件完整性核查：rtmutex.c 函数族 vs 上游 v6.6.118")
    w("=" * 78)
    w()

    # ---- 1. 列出 rtmutex 函数族及其地址范围 ----
    fam = [(a, t, n) for a, t, n in syms if TARGET_RE.match(n) and t in ("T", "t")]
    fam.sort()
    w(f"[1] rtmutex 函数族共 {len(fam)} 个符号")
    w()
    w(f"{'地址':<20} {'类型':<4} {'名称':<44} {'大小':>7}")
    w("-" * 78)
    ranges = []
    for i, (a, t, n) in enumerate(fam):
        # 下一个符号（任意类型）作为上界，更准确
        j = idx[a] + 1
        end = syms[j][0] if j < len(syms) else a + 0x400
        size = end - a
        ranges.append((a, end, n, size))
        w(f"0x{a:016x} {t:<4} {n:<44} 0x{size:5x}")
    w()

    # ---- 2. 反汇编并扫描 vendor hook 引用 ----
    blob = IMG.read_bytes()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    def off_of(va):
        return va - TEXT_BASE + TEXT_OFF

    hook_hits = []   # (func, insn_addr, kind, target_or_note)
    all_insns = {}   # func -> list[(addr, mnem, op_str)]

    for start, end, name, size in ranges:
        o = off_of(start)
        if o < 0 or o + size > len(blob):
            continue
        code = blob[o:o + size]
        lst = []
        last_adrp = {}   # reg -> imm
        for ins in md.disasm(code, start):
            lst.append((ins.address, ins.mnemonic, ins.op_str))
            # a) 直接跳转/调用到 tracepoint
            if ins.mnemonic in ("bl", "b") and ins.operands and \
               ins.operands[0].type == ARM64_OP_IMM:
                tgt = ins.operands[0].imm
                if tgt in tp_syms:
                    hook_hits.append((name, ins.address, ins.mnemonic, tp_syms[tgt]))
            # b) adrp+add / adrp+ldr 形式引用 tracepoint 结构体
            if ins.mnemonic == "adrp" and len(ins.operands) >= 2:
                rd = ins.operands[0].reg
                last_adrp[rd] = ins.operands[1].imm
            elif ins.mnemonic in ("add", "ldr") and len(ins.operands) >= 3:
                rd, rn = ins.operands[0].reg, ins.operands[1].reg
                if rn in last_adrp:
                    base = last_adrp[rn]
                    # 取立即数偏移
                    imm = None
                    for op in ins.operands[2:]:
                        if op.type == ARM64_OP_IMM:
                            imm = op.imm
                    if imm is not None:
                        va = base + imm
                        if va in tp_syms:
                            hook_hits.append((name, ins.address,
                                              f"adrp+{ins.mnemonic}", tp_syms[va]))
        all_insns[name] = lst

    w("[2] rtmutex 函数族中引用 vendor hook (tracepoint) 的位置")
    w()
    if not hook_hits:
        w("  ── 无任何引用 ──")
    else:
        w(f"{'函数':<40} {'指令地址':<20} {'形式':<12} {'hook 名称'}")
        w("-" * 78)
        for fn, ia, kind, tname in hook_hits:
            w(f"{fn:<40} 0x{ia:016x} {kind:<12} {tname}")
    w()

    # ---- 3. 重点：remove_waiter() 函数体独立复核 ----
    w("[3] ★ remove_waiter() 函数体逐条复核")
    w()
    rw = [r for r in ranges if r[2] == "remove_waiter"]
    if not rw:
        w("  !! 未找到 remove_waiter 符号")
    else:
        start, end, _, size = rw[0]
        w(f"  地址 0x{start:016x} .. 0x{end:016x}  (0x{size:x} 字节)")
        insns = all_insns.get("remove_waiter", [])
        w(f"  反汇编指令数: {len(insns)}")
        w()
        # 判据
        n_spel0 = sum(1 for _, m, o in insns if m == "mrs" and "sp_el0" in o)
        n_off50 = sum(1 for _, m, o in insns if m == "ldr" and "#0x50]" in o)
        n_bl    = sum(1 for _, m, _ in insns if m == "bl")
        n_tp    = sum(1 for fn, _, _, _ in hook_hits if fn == "remove_waiter")
        w(f"  判据 A  mrs sp_el0 次数            = {n_spel0}  (期望 1，取 current)")
        w(f"  判据 B  ldr [Xn,#0x50] 次数        = {n_off50}  (期望 0，即不读 waiter->task)")
        w(f"  判据 C  bl 调用次数                = {n_bl}")
        w(f"  判据 D  引用 vendor hook 次数      = {n_tp}  (期望 0)")
        w()
        w("  完整反汇编:")
        w("  " + "-" * 74)
        for a, m, o in insns:
            w(f"  0x{a:016x}  {m:<8} {o}")
    w()

    # ---- 4. 对比：rt_mutex_adjust_prio_chain 是否有 hook ----
    w("[4] 参照组：其他 rtmutex 函数是否被 hook 侵入")
    w()
    hitfuncs = sorted({h[0] for h in hook_hits})
    w(f"  被 hook 侵入的函数: {hitfuncs if hitfuncs else '（无）'}")
    w()
    w("  说明：若只有个别函数被侵入而 remove_waiter 干净，")
    w("        说明厂商改动是「定点插入 hook」，未触碰 remove_waiter。")

    REP.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[+] 报告已写入 {REP}")


if __name__ == "__main__":
    main()
