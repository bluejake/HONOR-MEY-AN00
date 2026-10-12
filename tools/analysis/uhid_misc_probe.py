#!/usr/bin/env python3
"""在每个 misc_register 调用点前做寄存器跟踪，识别
  [x0+0x00]=minor(int)  [x0+0x08]=name  [x0+0x10]=fops  [x0+0x20]=parent
找到 name 指向 "uhid\\0" 的那个调用点 => 真实 uhid_misc VA。
"""
import struct, re

RAW = "analysis/output/kernel_mey_an00.raw"
TEXT = 0xffffffc080000000
data = open(RAW, "rb").read()

MISC_REGISTER = 0xffffffc0804ea124
MISC_DEREGISTER = 0xffffffc0804ea2e0

def w(off): return struct.unpack_from("<I", data, off)[0]

def adrp_t(wv, pc):
    immlo = (wv >> 29) & 3; immhi = (wv >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & 0x100000: imm -= 0x200000
    return (pc & ~0xfff) + (imm << 12)

def cstr(va, maxn=32):
    off = va - TEXT
    if not (0 <= off < len(data)): return None
    end = data.find(b"\0", off, off+maxn)
    if end < 0: return None
    s = data[off:end]
    try:
        t = s.decode('ascii')
    except Exception:
        return None
    if all(32 <= ord(c) < 127 for c in t): return t
    return None

def trace_callsite(callsite):
    """回溯 64 条指令，做极简的 adrp/add/ldr(str) 跟踪，找出对 x0 基址的 str。"""
    off = callsite - TEXT
    start = max(0, off - 96*4)
    reg = {}          # reg -> (kind, value)  kind: 'adrp' page / 'cst' const / 'str_val'
    stores = []       # (callsite_index, target_desc, reg, value)
    strsrc = {}       # 记录 str reg,[base,#imm] => value
    seq = []
    for k in range(start, off, 4):
        wv = w(k)
        pc = TEXT + k
        # BL
        if (wv >> 26) == 0b100101:
            imm = wv & 0x3ffffff
            if imm & 0x2000000: imm -= 0x4000000
            tgt = pc + (imm << 2)
            seq.append(('bl', pc, tgt))
            continue
        # ADRP
        if (wv & 0x9f000000) == 0x90000000:
            reg[wv & 0x1f] = ('adrp', adrp_t(wv, pc)); seq.append(('adrp', pc, wv&0x1f, reg[wv&0x1f][1])); continue
        # ADD (imm)
        if (wv & 0x7f000000) == 0x11000000:
            rd = wv & 0x1f; rn = (wv>>5)&0x1f
            imm = (wv>>10)&0xfff; sh = (wv>>22)&1
            if rn in reg and reg[rn][0]=='adrp':
                reg[rd] = ('adrp', reg[rn][1] + (imm << (12 if sh else 0)))
                seq.append(('add', pc, rd, reg[rd][1]))
            continue
        # MOV (reg) ORR reg, xzr
        if (wv & 0x7f200000) == 0x2a000000 and ((wv>>5)&0x1f)==31:
            rd = wv & 0x1f; reg[rd]=('cst',0); seq.append(('mov0',pc,rd)); continue
        # MOVZ
        if (wv & 0x7f800000) == 0x52800000:
            rd = wv & 0x1f
            hw = (wv>>21)&3; imm16=(wv>>5)&0xffff
            reg[rd]=('cst', imm16 << (16*hw)); seq.append(('movz',pc,rd,reg[rd][1])); continue
        # STR (unsigned imm) 64-bit: 11111001 imm12 rn rt
        if (wv & 0xffc00000) == 0xf9000000:
            imm = (wv>>10)&0xfff; rn=(wv>>5)&0x1f; rt=wv&0x1f
            val = reg.get(rt)
            if val and val[0]=='adrp' and rn in reg and reg[rn][0]=='adrp':
                stores.append((pc, rn, imm, val[1], cstr(val[1])))
            seq.append(('str', pc, rt, rn, imm))
            continue
    return seq, stores

calls = []
for off in range(0, len(data)-4, 4):
    wv = w(off)
    if (wv >> 26) == 0b100101:
        imm = wv & 0x3ffffff
        if imm & 0x2000000: imm -= 0x4000000
        if TEXT+off+(imm<<2) == MISC_REGISTER:
            calls.append(TEXT+off)

print("misc_register call sites: %d" % len(calls))
for c in calls:
    seq, stores = trace_callsite(c)
    base = None
    interesting = []
    for (pc, rn, imm, val, s) in stores:
        # base register page  = val - imm  => struct base
        b = val - imm
        if s:  interesting.append((pc, b, imm, val, s))
    if interesting:
        print("\ncall @ %#x" % c)
        for (pc, b, imm, val, s) in interesting:
            print("   %#012x: str -> base %#012x +%#x  (name=%r)" % (pc, b, imm, s))
