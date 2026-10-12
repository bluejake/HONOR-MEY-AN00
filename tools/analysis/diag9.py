#!/usr/bin/env python3
# diag9: 用 numpy 在全镜像中找最长的 "u32 值均 < 0x5000000" 连续段 —— 即 kallsyms_offsets 数组。
import numpy as np
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"

def main():
    kernel=open(KERNEL,"rb").read()
    n=len(kernel)
    arr=np.frombuffer(kernel,dtype="<u4")   # 全镜像 u32
    # offsets 候选: 值 < 0x5000000 (镜像 ~37MB)，且不是 0(0 也允许但单独出现多)
    mask=(arr < 0x5000000)
    # 找最长连续 True 段，长度>=80000
    best_len=0; best_start=0
    cur_start=-1; cur_len=0
    # 为了速度，只对 mask 中 True 的附近做游程统计；全扫 9.3M 也可
    for i in range(len(mask)):
        if mask[i]:
            if cur_len==0: cur_start=i
            cur_len+=1
        else:
            if cur_len>=80000 and cur_len>best_len:
                best_len=cur_len; best_start=cur_start
            cur_len=0
    if cur_len>=80000 and cur_len>best_len:
        best_len=cur_len; best_start=cur_start
    print("best offsets-run: start u32-idx=",best_start,"byte=",hex(best_start*4),"len=",best_len)
    # 报告首尾若干值
    if best_len:
        print("  first 8:", [int(x) for x in arr[best_start:best_start+8]])
        print("  last 8:", [int(x) for x in arr[best_start+best_len-8:best_start+best_len]])
        # 是否单调递增(相对偏移通常近似递增但非严格)
        seg=arr[best_start:best_start+best_len].astype(np.int64)
        diffs=seg[1:]-seg[:-1]
        print("  diff>0 比例:", float((diffs>0).sum())/len(diffs))
        print("  min/max:", int(seg.min()), int(seg.max()))

if __name__=="__main__":
    main()
