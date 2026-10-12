#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""H12: 找 cleanup_timerqueue / posix_cpu_timer_del 如何取 node，确认传入 rb_erase 的 x0。"""
import struct
from capstone import *
IMG = r"D:\MEY-AN00-root-repro\analysis\scratch\Image-mey"
TEXT = 0xffffffc080000000
data = open(IMG, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
def dis(vaddr, n):
    off = vaddr - TEXT
    code = data[off:off+n*4]
    for ins in md.disasm(code, vaddr):
        print("  %#x:\t%-8s\t%s" % (ins.address, ins.mnemonic, ins.op_str))

# 找所有 bl 到 0x3f7d8 (timerqueue_del) 的调用点
import re
TARGET = 0xffffffc08003f7d8
print("=== 搜索所有调用 timerqueue_del(0x3f7d8) 的位置 ===")
found=[]
# bl 指令: 0x94000000 | imm26 ; target = pc + imm26*4
for off in range(0, len(data)-4, 4):
    w = struct.unpack_from("<I", data, off)[0]
    if (w & 0xFC000000) == 0x94000000:
        imm = w & 0x03FFFFFF
        if imm & 0x02000000: imm -= 0x04000000
        pc = TEXT + off
        tgt = pc + imm*4
        if tgt == TARGET:
            found.append(pc)
print("共 %d 处调用" % len(found))
for i,p in enumerate(found[:12]):
    print("\n--- caller #%d @ %#x (前 14 条) ---" % (i, p))
    dis(p-14*4, 18)
