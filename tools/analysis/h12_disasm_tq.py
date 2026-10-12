#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H12: 反汇编 timerqueue_del 与 rb_erase 入口，确认 x0 指向哪个成员。
Image-mey 的加载基址（vaddr-_text）需先校准。
"""
import struct, sys
from capstone import *

IMG = r"D:\MEY-AN00-root-repro\analysis\scratch\Image-mey"
TEXT = 0xffffffc080000000   # _text

data = open(IMG, "rb").read()
print("Image size = %d (0x%x)" % (len(data), len(data)))

# 前 64 字节通常是 arm64 Image header
hdr = data[:64]
magic = struct.unpack_from("<I", hdr, 56)[0]
print("Image magic (off 0x38) = %#x  (期望 0x644d5241 'ARM\\x64')" % magic)
pe_off = struct.unpack_from("<Q", hdr, 8)[0]
print("text_offset = %#x" % pe_off)

# 内核 Image 的 file offset 与 vaddr 关系：需要找到 _text 在文件中的位置。
# 一般做法：从 kallsyms 拿一个已知符号，扫描匹配。
# 这里先用简化假设：file_off = vaddr - TEXT + base_file_off，base_file_off 用 magic 后的代码起点。
# 我们改为【验证法】：反汇编若干候选偏移，看是否出现预期的 timerqueue_del 模式。

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = False

def disasm(vaddr, n=48, base_off=None):
    off = vaddr - TEXT if base_off is None else base_off
    if off < 0 or off + n*4 > len(data):
        return None
    code = data[off:off+n*4]
    out = []
    for ins in md.disasm(code, vaddr):
        out.append("  %#x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
    return out

def try_off(base_off):
    """在给定 file base_off 假设下反汇编两个函数入口各 6 条"""
    print("\n=== 假设 file base_off = %#x ===" % base_off)
    for name, va in [("timerqueue_del", 0xffffffc08003f7d8),
                     ("rb_erase",      0xffffffc08003a9d4)]:
        off = base_off + (va - TEXT)
        if off + 32 > len(data):
            print("  %s: out of range" % name); continue
        code = data[off:off+24]
        print("  [%s @ %#x, file %#x]" % (name, va, off))
        for ins in md.disasm(code, va):
            print("    %#x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))

for bo in [0, 0x0, 0x100, 0x800, 0x1000]:
    try_off(bo)
