#!/usr/bin/env python3
# diag7: 在 names 之前的较大区间用 numpy 搜索 num_syms(u64≈N) 与 relative_base(内核地址)，定位布局。
import struct
import numpy as np
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]

def main():
    kernel=open(KERNEL,"rb").read()
    ns=0x1352a7a
    # 搜索区间 [ns-3MB, ns)
    start=ns-3*1024*1024
    if start<0: start=0
    seg=kernel[start:ns]
    arr=np.frombuffer(seg,dtype="<u8")
    # num_syms 候选: 100000..130000
    mask_n=(arr>=100000)&(arr<=130000)
    pos_n=np.where(mask_n)[0]
    print("num_syms(u64) hits in [ns-3MB,ns):",len(pos_n))
    for off in pos_n[:10]:
        aa=start+int(off)*8
        print("  @",hex(aa),"val=",int(arr[off]),"  ns-this =",hex(ns-aa))
    # relative_base 候选: 0xffffff0000000000..0xffffffffffffffff
    mask_k=(arr>=0xffffff0000000000)&(arr<=0xffffffffffffffff)
    pos_k=np.where(mask_k)[0]
    print("kernel-addr(u64) hits:",len(pos_k))
    for off in pos_k[:10]:
        aa=start+int(off)*8
        print("  @",hex(aa),"val=",hex(int(arr[off])))
    # 也搜 u32 候选 num_syms
    arr32=np.frombuffer(seg,dtype="<u4")
    mask_n32=(arr32>=100000)&(arr32<=130000)
    pos_n32=np.where(mask_n32)[0]
    print("num_syms(u32) hits:",len(pos_n32))
    for off in pos_n32[:10]:
        aa=start+int(off)*4
        print("  @",hex(aa),"val=",int(arr32[off]))

if __name__=="__main__":
    main()
