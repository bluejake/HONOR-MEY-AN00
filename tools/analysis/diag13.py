#!/usr/bin/env python3
# diag13: 在若干 ns 候选处解码前 5 个符号, 找出正确的 names 起点。
import struct
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def main():
    kernel=open(KERNEL,"rb").read()
    p=0x14d07e0; ts=0x14d0450
    tidx=[u16(kernel,p+j*2) for j in range(256)]
    token_table=kernel[ts:p]
    ms=0x14cfd88
    base_ns=ms-1561358
    def dec(pos):
        ln=kernel[pos]; c=1
        if ln==255: ln=u16(kernel,pos+1); c=3
        nm=bytearray()
        for _ in range(ln):
            b=kernel[pos+c]; c+=1; o=tidx[b]
            e=token_table.find(b'\x00',o)
            if e<0: e=len(token_table)
            nm+=token_table[o:e]
        return nm.decode('utf-8','replace'),c
    for D in [0, 50, 100, 150, 200, 300, 500, 1000]:
        ns=base_ns+D
        pos=ns
        syms=[]
        for i in range(5):
            nm,cc=dec(pos); syms.append(nm); pos+=cc
        print(f"D={D:5d} ns={hex(ns)} -> {syms}")

if __name__=="__main__":
    main()
