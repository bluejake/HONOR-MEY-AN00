#!/usr/bin/env python3
"""扫描 Image 中所有对 misc_register 的 BL 调用点，回溯 adrp+add 还原
被传进去的 struct miscdevice 静态 VA。这是 static 变量唯一可靠的查法。"""
import struct, sys, re

RAW = "analysis/output/kernel_mey_an00.raw"
TEXT = 0xffffffc080000000

data = open(RAW, "rb").read()
print("image bytes=%d" % len(data))

TARGETS = {}
for sym in sys.argv[1:] or ["misc_register"]:
    pass

def bl_targets():
    hits = []
    for off in range(0, len(data) - 4, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if (w >> 26) == 0b100101:  # BL
            imm = w & 0x03ffffff
            if imm & 0x02000000:
                imm -= 0x04000000
            va = TEXT + off
            hits.append((va, va + (imm << 2)))
    return hits

alls = bl_targets()
def find_calls(name, addr):
    return [(va, tgt) for va, tgt in alls if tgt == addr]

def disasm_one(off):
    w = struct.unpack_from("<I", data, off)[0]
    return w

def adrp_target(w, pc):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    return (pc & ~0xfff) + (imm << 12)

def add_imm(w):
    if (w >> 23) & 0x1ff == 0b100100001 or True:
        pass
    # ADD (immediate) 64-bit: sf=1 op=0 S=0 10001 shift(2) imm12 Rn Rd
    if (w & 0x7f000000) == 0x11000000:
        imm = (w >> 10) & 0xfff
        sh = (w >> 22) & 1
        return imm << (12 if sh else 0)
    return None

def reg_of(w):
    if (w & 0x7f000000) == 0x11000000:
        return w & 0x1f
    return None

def adrp_reg(w):
    if (w & 0x9f000000) == 0x90000000:
        return w & 0x1f
    return None

for name in sys.argv[1:]:
    addr = int(name, 16)
    calls = find_calls(name, addr)
    print("=== %s @ %#x : %d call site(s) ===" % (name, addr, len(calls)))
    for va, _ in calls:
        off = va - TEXT
        # 往回扫 48 条指令，追踪 adrp+add(reg) 对
        pairs = {}
        start = max(0, off - 48 * 4)
        for k in range(start, off, 4):
            w = disasm_one(k)
            r = adrp_reg(w)
            if r is not None:
                pairs[r] = adrp_target(w, TEXT + k)
        # 再扫调用点前 48 条，找 add
        cands = []
        for k in range(start, off, 4):
            w = disasm_one(k)
            r = reg_of(w)
            if r is None:
                continue
            im = add_imm(w)
            if im is None:
                continue
            if r in pairs:
                full = pairs[r] + im
                cands.append((TEXT + k, r, full))
        print("  call @ %#x  (file off %#x)" % (va, off))
        for k, r, full in cands:
            print("     %#012x: x%d = adrp+add = %#012x" % (k, r, full))
