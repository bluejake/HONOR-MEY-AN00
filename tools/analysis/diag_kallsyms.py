#!/usr/bin/env python3
# 诊断：在裸内核 Image 中定位真正的 kallsyms token_index / token_table，
# 通过"token_table 约束"过滤掉伪候选（256 个单调递增 u16 只是必要条件，不够）。
import os, sys, struct
import numpy as np

ROOT = "D:/MEY-AN00-root-repro"
KERNEL = ROOT + "/analysis/output/kernel_mey_an00.raw"

def is_print(c):
    return c == ord('_') or 32 <= c < 127

def find_token_table_start(kernel, p):
    # 从 p-1 向前回溯，找"最大一段 可打印或 NUL"的连续区域，其起点即 token_table 起点。
    pos = p - 1
    while pos >= 0 and (is_print(kernel[pos]) or kernel[pos] == 0):
        pos -= 1
    return pos + 1  # ts

def main():
    kernel = open(KERNEL, "rb").read()
    n = len(kernel)
    arr = np.frombuffer(kernel, dtype="<u2")
    # 候选：u16==0 且 u16[+1] 在 [1,4096] 之间（放宽 diff 上限，避免漏掉长 token）
    zeros = np.where(arr == 0)[0]
    # 只保留还有 256 元素的
    zeros = zeros[zeros + 256 < len(arr)]
    cands = []
    for p in zeros:
        p = int(p)
        ok = True
        prev = 0
        maxv = 0
        for j in range(256):
            v = arr[p + j]
            if j == 0:
                if v != 0: ok = False; break
            else:
                if v <= prev or v - prev > 4096: ok = False; break
            prev = v; maxv = max(maxv, int(v))
        if not ok:
            continue
        # token_table 约束：p 之前应是一段 可打印/NUL 区域，且 maxv < 该区域长度
        ts = find_token_table_start(kernel, p)
        L = p - ts
        if maxv >= L:
            continue
        # 抽样校验：若干 tidx 指向的位置必须是可打印起始
        bad = False
        for i in (0, 1, 2, 128, 255):
            pos = ts + int(arr[p + i])
            if pos >= p or not is_print(kernel[pos]):
                bad = True; break
        if bad:
            continue
        score = maxv / L if L else 0
        cands.append((p, maxv, L, ts, score))
    cands.sort(key=lambda x: -x[4])
    print("valid candidates:", len(cands))
    for c in cands[:8]:
        p, maxv, L, ts, score = c
        print(f"token_index@{hex(p)} maxv={maxv} tbl_len={L} ts={hex(ts)} score={score:.3f}")

if __name__ == "__main__":
    main()
