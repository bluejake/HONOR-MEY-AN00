#!/usr/bin/env python3
# diag12: dump u32 在 relative_base(0xffffffc080000000 @ 0x153d020) 前后，定位 num_syms。
import struct
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def s32(b,o): return struct.unpack_from("<i",b,o)[0]
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]

def main():
    kernel=open(KERNEL,"rb").read()
    rb=0x153d020
    print("relative_base @",hex(rb),"=",hex(u64(kernel,rb)))
    # 之前 8 个 u32
    print("u32 before rb:")
    for x in range(rb-32, rb, 4):
        print("  ",hex(x),u32(kernel,x))
    print("u32 after rb:")
    for x in range(rb+8, rb+32, 4):
        print("  ",hex(x),u32(kernel,x))
    # offsets 末段
    offs_start=0x14d09e0
    print("last 6 offsets (s32) before rb-32:")
    for x in range(rb-32-24, rb-32, 4):
        print("  ",hex(x),s32(kernel,x))

if __name__=="__main__":
    main()
