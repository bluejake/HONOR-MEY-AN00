#!/usr/bin/env python3
# diag4: 对最像 token_index 的候选，分别检验 "token_table 在前" 与 "token_table 在后" 两种假设。
import struct
import numpy as np
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def is_print(c): return c==ord('_') or 32<=c<127

def score(kernel, tidx, ts, pe):
    # token_table = [ts, pe)，检验每个 tidx[i] 是否指向可打印起始，且能 NUL 终止在 [ts,pe) 内
    n=len(tidx); ok=0; bad=0
    for i in range(n):
        pos=ts+tidx[i]
        if pos<ts or pos>=pe:
            bad+=1; continue
        if not is_print(kernel[pos]):
            bad+=1; continue
        e=kernel.find(b'\x00',pos,pe)
        if e<0:
            bad+=1; continue
        seg=kernel[pos:e]
        if all(is_print(x) for x in seg):
            ok+=1
        else:
            bad+=1
    return ok,bad

def main():
    kernel=open(KERNEL,"rb").read()
    n=len(kernel)
    # 候选 4 @ 0xa683f0
    cand=[0xa683f0, 0x92fd88]
    for p in cand:
        tidx=[u16(kernel,p+j*2) for j in range(256)]
        maxv=max(tidx)
        print(f"\n=== candidate @{hex(p)} maxv={maxv} ===")
        for direction,ts,pe in [("BEFORE",p-maxv-8,p), ("AFTER",p,p+maxv+8)]:
            # 对齐：token_table 实际可能略微偏移，尝试 ts=pe-maxv-x
            best=None
            for shift in range(0,64):
                tts=ts-shift if direction=="BEFORE" else ts
                tpe=pe-shift if direction=="BEFORE" else pe
                if tts<0 or tpe>n or tpe-tts<maxv: continue
                ok,bad=score(kernel,tidx,tts,tpe)
                if best is None or ok>best[0]:
                    best=(ok,bad,tts,tpe,shift)
            print(f"  {direction}: best ok={best[0]} bad={best[1]} ts={hex(best[2])} pe={hex(best[3])} shift={best[4]}")
            # dump 该区域 ascii 一角
            tts,best[3]
            print("    ascii head:", repr(kernel[best[2]:best[2]+60]))

if __name__=="__main__":
    main()
