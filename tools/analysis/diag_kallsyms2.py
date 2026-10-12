#!/usr/bin/env python3
# diag2: 先找 token_table(可打印+NUL 的连续区域)，再检查其尾部是否紧跟 256 个单调递增 u16 (token_index)。
import struct
ROOT = "D:/MEY-AN00-root-repro"
KERNEL = ROOT + "/analysis/output/kernel_mey_an00.raw"

def is_print(c): return c == ord('_') or 32 <= c < 127

def u16(b,o): return struct.unpack_from("<H", b, o)[0]

def check_token_index(kernel, p):
    # p 处起应是 256 个 u16，t[0]=0，严格递增，diff<=4096
    if p + 512 > len(kernel): return None
    prev=0; maxv=0
    for j in range(256):
        v=u16(kernel,p+j*2)
        if j==0:
            if v!=0: return None
        else:
            if v<=prev or v-prev>4096: return None
        prev=v; maxv=max(maxv,int(v))
    return maxv

def main():
    kernel=open(KERNEL,"rb").read()
    n=len(kernel)
    # 找 token_table: 以 NUL 结尾的可打印串区域。从后往前找"可打印串起点"。
    # 策略：扫描每个位置，若为可打印起始，向前统计到 NUL 为止的长度。仅记录长度在 [64, 8192] 的可打印串，
    # 且其后(串尾NUL之后)紧跟的 512 字节是 token_index。
    results=[]
    # 用滑动方式：遍历每个位置 s，若 kernel[s] 可打印且 (s==0 或 kernel[s-1]==0 或 not is_print(kernel[s-1]))，
    # 则 s 是一个 token 起点；但我们想要整个 token_table 的起点 ts，其后全是 可打印/NUL 直到某个 p，p 处起是 token_index。
    # 简化：找连续"可打印或NUL"区域 [ts, pe)，且 pe 之后 512 字节是 token_index。
    pos=0
    while pos < n:
        c=kernel[pos]
        if is_print(c):
            # 开始一段
            ts=pos
            # 向前找真正起点：若前一个是可打印或NUL，则继续(处理粘连)，但我们要找最大连续段起点
            # 简化：直接延伸直到遇到非(可打印/NUL)
            pe=pos
            while pe<n and (is_print(kernel[pe]) or kernel[pe]==0):
                pe+=1
            L=pe-ts
            if 64 <= L <= 8192:
                # 检查 pe 处是否紧跟 token_index
                mv=check_token_index(kernel, pe)
                if mv is not None and mv < L:
                    # 抽样
                    tidx=[u16(kernel,pe+j*2) for j in range(256)]
                    ok=True
                    for i in (0,1,255,128):
                        pp=ts+tidx[i]
                        if pp>=pe or not is_print(kernel[pp]): ok=False; break
                    if ok:
                        results.append((ts,pe,mv,L))
            pos=pe
        else:
            pos+=1
    print("token_table->token_index candidates:", len(results))
    for ts,pe,mv,L in results[:10]:
        print(f"token_table [{hex(ts)}..{hex(pe)}) len={L}  token_index@{hex(pe)} maxv={mv}")

if __name__=="__main__":
    main()
