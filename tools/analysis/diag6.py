#!/usr/bin/env python3
# diag6b: 用对齐的 ts=0x14d0450，验证 names 解码，并在 names 之前搜索 num_syms / relative_base。
import struct
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]

def main():
    kernel=open(KERNEL,"rb").read()
    p=0x14d07e0
    ts=0x14d0450
    # markers 从 ts-4 向前
    markers=[]; off=ts-4; prev=None
    while off>=0:
        v=u32(kernel,off)
        if prev is not None and v>=prev: break
        if v>0x800000: break
        markers.append(v); prev=v; off-=4
    markers.reverse()
    mcnt=len(markers); ms=ts-mcnt*4
    names_len=markers[-1]; ns=ms-names_len
    print("mcnt=",mcnt,"ms=",hex(ms),"ns=",hex(ns),"names_len=",names_len)
    # 验证 names 解码前 12 个
    tidx=[u16(kernel,p+j*2) for j in range(256)]
    token_table=kernel[ts:p]
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
    print("first 12 names:")
    pos=ns; ndec=0
    for i in range(12):
        nm,cc=dec(pos); print("  ",i,nm); pos+=cc; ndec+=1
    # 在 [ns-8192, ns) 搜索 u64==合理 N (100000~130000) 与 内核地址(0xffffff...)
    print("searching num_syms/relbase in [ns-8192, ns):")
    found_n=[]; found_k=[]; 
    for x in range(ns-8192, ns-8, 8):
        v=u64(kernel,x)
        if 100000 <= v <= 130000: found_n.append((hex(x),v))
        if (v & 0xffffff0000000000) == 0xffffff0000000000: found_k.append((hex(x),hex(v)))
    print("  plausible N (num_syms):", found_n[:5])
    print("  kernel-addr (relbase?):", found_k[:5])
    # 也看 ns-16/ns-8 的值
    print("  ns-16 u64=",hex(u64(kernel,ns-16)),"ns-8 u64=",hex(u64(kernel,ns-8)))

if __name__=="__main__":
    main()
