#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
反汇编 remove_waiter()，用于 CVE-2026-43499 静态暴露核查（防御侧）。

核心判据（来自官方公告）：
  官方修复 = remove_waiter() 内所有相关操作由 `current` 改为 `waiter::task`。
  - 已修函数应出现: ldr Xn, [waiter, #0x50]   (rt_mutex_waiter.task, BTF 实测 off=0x50)
                    然后基于该值做 pi_lock / pi_waiters / pi_blocked_on 操作
  - 未修函数应出现: mrs Xn, sp_el0  /  ldr Xn, [Xn, #offset]   (取 current)
                    并以 current 做出队与状态清理

输出: analysis/output/remove_waiter.asm
"""
import struct, sys, re
from capstone import *

IMAGE = r"D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
TEXT_BASE = 0xffffffc080000000   # _text
VA_REMOVE_WAITER = 0xffffffc081080e60
LEN = 0x300          # 函数体长度上限
OUT = r"D:/MEY-AN00-root-repro/analysis/output/remove_waiter.asm"

# BTF 实测偏移
OFF_waiter_task = 0x50
OFF_waiter_lock = 0x58
OFF_task_pi_lock = 0x90c
OFF_task_pi_waiters = 0x920
OFF_task_pi_blocked_on = 0x938

def main():
    data = open(IMAGE, "rb").read()
    off = VA_REMOVE_WAITER - TEXT_BASE
    if off < 0 or off >= len(data):
        print("ERROR: offset out of image (image size=0x%x)" % len(data)); return 1
    buf = data[off:off+LEN]

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    lines = []
    lines.append("=== remove_waiter @ 0x%x (file off 0x%x) ===" % (VA_REMOVE_WAITER, off))
    lines.append("")

    hit_current = []   # 疑似取 current
    hit_waiter_task = []  # 疑似取 waiter->task

    for ins in md.disasm(buf, VA_REMOVE_WAITER):
        lines.append("  0x%x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))

        # 取 current: mrs Xn, sp_el0
        if ins.mnemonic == "mrs" and "sp_el0" in ins.op_str:
            hit_current.append((ins.address, ins.mnemonic + " " + ins.op_str))

        # 取 waiter->task: ldr Xn, [Xm, #0x50]
        m = re.match(r"ldr\s+(\w+),\s*\[(\w+),\s*#(0x[0-9a-f]+)\]", ins.op_str)
        if m:
            imm = int(m.group(3), 16)
            if imm == OFF_waiter_task:
                hit_waiter_task.append((ins.address, ins.op_str))
            elif imm == OFF_task_pi_lock:
                hit_current.append((ins.address, "pi_lock via +0x90c " + ins.op_str))

    lines.append("")
    lines.append("=== 自动判据扫描 ===")
    lines.append("")
    lines.append("[取 current 的候选]  (mrs Xn, sp_el0)")
    if hit_current:
        for a, s in hit_current:
            lines.append("   0x%x  %s" % (a, s))
    else:
        lines.append("   (无)")
    lines.append("")
    lines.append("[取 waiter->task 的候选]  (ldr Xn, [Xm, #0x50])")
    if hit_waiter_task:
        for a, s in hit_waiter_task:
            lines.append("   0x%x  %s" % (a, s))
    else:
        lines.append("   (无)")
    lines.append("")
    lines.append("注意: 自动扫描仅供参考，最终判定需人工核对上面的完整反汇编。")
    lines.append("      关键看: 做 rbtree 出队 / pi_blocked_on 清零 时，用的是哪个 task 指针。")

    open(OUT, "w", encoding="utf-8").write("\n".join(lines))
    print("wrote", OUT)
    print("mrs sp_el0 次数:", len(hit_current))
    print("ldr [Xn,#0x50] 次数:", len(hit_waiter_task))
    return 0

if __name__ == "__main__":
    sys.exit(main())
