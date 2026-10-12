#!/usr/bin/env python3
# diag5: 修正 index/byte 混淆。diag3 的 p 是 u16 索引，真实字节偏移 = 2*p。
import struct
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def is_print(c): return c==ord('_') or 32<=c<127

def score(kernel, tidx, ts, pe):
    n=len(tidx); ok=0; bad=0
    for i in range(n):
        pos=ts+tidx[i]
        if pos<ts or pos>=pe: bad+=1; continue
        if not is_print(kernel[pos]): bad+=1; continue
        e=kernel.find(b'\x00',pos,pe)
        if e<0: bad+=1; continue
        if all(is_print(x) for x in kernel[pos:e]): ok+=1
        else: bad+=1
    return ok,bad

def main():
    kernel=open(KERNEL,"rb").read()
    n=len(kernel)
    # diag3 的 u16 索引候选
    for p_index in [0xa683f0, 0x92fd88, 0x8cb7b0, 0x90c430]:
        p=2*p_index
        tidx=[u16(kernel,p+j*2) for j in range(256)]
        maxv=max(tidx)
        print(f"\n=== u16idx={hex(p_index)} byte={hex(p)} maxv={maxv} ===")
        # BEFORE 假设：token_table = [p-maxv-x, p)
        best=None
        for shift in range(0,256):
            ts=p-maxv-shift; pe=p
            if ts<0: break
            ok,bad=score(kernel,tidx,ts,pe)
            if best is None or ok>best[0]:
                best=(ok,bad,ts,pe,shift)
        print(f"  BEFORE best ok={best[0]} bad={best[1]} ts={hex(best[2])} shift={best[4]}")
        print("    tbl head:", repr(kernel[best[2]:best[2]+80]))
        # 也打印 p 之前的 128 字节 hex 确认 token_table 边界
        print("    raw 128B before p:", kernel[p-128:p].hex())

if __name__=="__main__":
    main()
