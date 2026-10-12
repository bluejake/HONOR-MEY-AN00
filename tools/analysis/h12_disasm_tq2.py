#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""H12: 完整反汇编 timerqueue_del，确认 x0 指向 timerqueue_node 哪个成员。"""
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

print("=== timerqueue_del @ 0xffffffc08003f7d8 (前 40 条) ===")
dis(0xffffffc08003f7d8, 40)

print("\n=== timerqueue_add @ 0xffffffc08003f724 (前 30 条) ===")
dis(0xffffffc08003f724, 30)

print("\n=== __rb_erase_augmented @ 0xffffffc08003a860 (前 30 条) ===")
dis(0xffffffc08003a860, 30)
