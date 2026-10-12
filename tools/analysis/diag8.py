#!/usr/bin/env python3
# diag8: 直接 hex dump names 之前的 256 字节，肉眼研判 num_syms/relative_base 布局。
import struct
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]

def main():
    kernel=open(KERNEL,"rb").read()
    ns=0x1352a7a
    for x in range(ns-256, ns+8, 16):
        row=kernel[x:x+16]
        h=" ".join(f"{b:02x}" for b in row)
        a="".join(chr(b) if 32<=b<127 else "." for b in row)
        vals=[hex(u64(kernel,x+i*8)) for i in range(2)]
        # 也解读为 u32
        u32s=[struct.unpack_from("<I",kernel,x+i*4)[0] for i in range(4)]
        print(f"{x:08x}  {h}  | {a}  u64={vals} u32={u32s}")

if __name__=="__main__":
    main()
