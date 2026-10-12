#!/usr/bin/env python3
# diag14: 用已知好 ns=0x1352aac 解码 N=111120 符号, 检查末位置是否落在 names/markers 边界附近。
import struct
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def main():
    kernel=open(KERNEL,"rb").read()
    p=0x14d07e0; ts=0x14d0450
    tidx=[u16(kernel,p+j*2) for j in range(256)]
    token_table=kernel[ts:p]
    N=111120
    for ns in [0x1352aac, 0x135297a]:
        pos=ns
        for i in range(N):
            ln=kernel[pos]; c=1
            if ln==255: ln=u16(kernel,pos+1); c=3
            pos+=c
        for mcnt in [434,435]:
            ms=ts-mcnt*4
            print(f"ns={hex(ns)} final pos={hex(pos)}  mcnt={mcnt} ms={hex(ms)}  diff={pos-ms}")

if __name__=="__main__":
    main()
