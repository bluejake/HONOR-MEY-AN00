#!/usr/bin/env python3
# diag3: 用 numpy 高效找 256 个单调递增 u16 (t[0]==0, diff<=4096) 的候选，然后 dump 上下文供人工研判。
import struct
import numpy as np
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"

def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def is_print(c): return c==ord('_') or 32<=c<127

def main():
    kernel=open(KERNEL,"rb").read()
    n=len(kernel)
    arr=np.frombuffer(kernel,dtype="<u2")
    d=np.zeros(len(arr)-1,dtype=np.int64)
    d[:]=arr[1:].astype(np.int64)-arr[:-1].astype(np.int64)
    good=(d>0)&(d<=4096)   # 相邻增量合法
    # 找 good 的连续段，长度>=255 且段首 arr==0
    # 用累积法：把 good 当成 1，遇到 0 重置 run
    runs=[]
    run_start=-1; run_len=0
    for i in range(len(good)):
        if good[i]:
            if run_len==0: run_start=i
            run_len+=1
        else:
            if run_len>=255 and arr[run_start]==0:
                runs.append((run_start,run_len))
            run_len=0; run_start=-1
    if run_len>=255 and arr[run_start]==0:
        runs.append((run_start,run_len))
    print("monotonic-u16-from-0 runs(len>=255):", len(runs))
    for p,rl in runs[:8]:
        # 该 run 起点 p 是 t[0] 位置 = token_index 起点
        maxv=int(arr[p+255])
        # 检查 p 之前的可打印/NUL 区域长度
        q=p-1; L=0
        while q>=0 and (is_print(kernel[q]) or kernel[q]==0):
            q-=1; L+=1
        print(f"\ntoken_index candidate @{hex(int(p))} runlen={rl} maxv={maxv}  printable-NUL-before={L}")
        # dump 64 bytes before p
        pre=kernel[max(0,p-64):p]
        print("  64B before:", pre.hex())
        # dump first 32 token_index values
        print("  t[0..31]:", [int(arr[p+j]) for j in range(32)])
        # dump 32 bytes at the start of the printable region (ts)
        ts=p-L
        print("  ts region 32B:", kernel[ts:ts+32].hex(), "ascii:", repr(kernel[ts:ts+32]))

if __name__=="__main__":
    main()
