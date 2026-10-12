#!/usr/bin/env python3
# diag11: dump 区域在 offsets 数组之后，找 num_syms 与 relative_base。
import struct
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]

def main():
    kernel=open(KERNEL,"rb").read()
    offs_start=0x14d09e0
    # 先精确定位 offsets 数组结束：从 offs_start 开始找非递增或越界处
    N=0; prev=-1
    x=offs_start
    while x+4<=len(kernel):
        v=u32(kernel,x)
        if v<prev or v>0x8000000:  # 不再单调递增或过大 -> 结束
            break
        prev=v; x+=4; N+=1
    offs_end=x
    print("offsets: start=",hex(offs_start),"end=",hex(offs_end),"N=",N)
    # dump 之后 256 字节
    print("== after offsets [offs_end, offs_end+256) u64 ==")
    for y in range(offs_end, offs_end+256, 16):
        print(hex(y), [hex(u64(kernel,y+i*8)) for i in range(2)])

if __name__=="__main__":
    main()
