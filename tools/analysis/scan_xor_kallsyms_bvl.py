#!/usr/bin/env python3
# Pure-Python scanner for an XOR-obfuscated kallsyms_offsets table in bvl175_Image.
#
# Hypothesis (see project memory 2026-10-12): BVL 6.1.157 kallsyms is obfuscated by a
# per-word (or per-byte repeating) XOR with a constant key K. The kallsyms_offsets array
# holds s32 values, ALL < 0x10000000, so their original high byte (byte 3, LE) is 0.
# After XOR with K, the high byte becomes K[3] uniformly across the whole array -> a long
# run of u32 whose high byte == K[3] (constant). The first entry is offset[0]=0, so the
# first u32 of that run == K (the full 4-byte key). We recover K and, by XORing the run,
# get back the strictly-increasing s32 offsets.
#
# We scan 4 alignments for u32, and report the longest runs with a NON-zero constant high
# byte (and also zero-byte runs that are NOT all-identical, to catch an unobfuscated table
# or a key whose high byte happens to be 0).

import array, sys, time

PATH = "D:/MEY-AN00-root-repro/firmware_bvl/bvl175_Image"
MIN_RUN = 8000          # a real kallsyms table has ~18000 entries; be lenient
WIDTH = 4               # u32 (kallsyms_offsets)

def scan(align, width):
    with open(PATH, "rb") as f:
        data = f.read()
    n = (len(data) - align) // width
    arr = array.array('I' if width == 4 else 'Q')
    arr.frombytes(data[align:align + n * width])
    shift = 8 * (width - 1)
    best = {}            # hb -> (length, start_idx, first_val, minv, maxv)
    cur_hb = -1
    cur_len = 0
    cur_start = 0
    cur_first = 0
    cur_min = 0
    cur_max = 0
    for i, v in enumerate(arr):
        hb = (v >> shift) & 0xff
        if hb == cur_hb:
            cur_len += 1
            if v < cur_min: cur_min = v
            if v > cur_max: cur_max = v
        else:
            if cur_len >= MIN_RUN and cur_max != cur_min:
                rec = best.get(cur_hb)
                if rec is None or cur_len > rec[0]:
                    best[cur_hb] = (cur_len, cur_start, cur_first, cur_min, cur_max)
            cur_hb = hb
            cur_len = 1
            cur_start = i
            cur_first = v
            cur_min = v
            cur_max = v
    if cur_len >= MIN_RUN and cur_max != cur_min:
        rec = best.get(cur_hb)
        if rec is None or cur_len > rec[0]:
            best[cur_hb] = (cur_len, cur_start, cur_first, cur_min, cur_max)
    return best, len(data), align

t0 = time.time()
print(f"file size = {__import__('os').path.getsize(PATH)} bytes")
for align in range(4):
    best, sz, a = scan(align, WIDTH)
    print(f"\n--- u32 align={align} (elapsed {time.time()-t0:.1f}s) ---")
    if not best:
        print("  no runs >= %d with varying values" % MIN_RUN)
        continue
    # sort by length desc
    for hb in sorted(best, key=lambda k: -best[k][0]):
        length, start, first, mn, mx = best[hb]
        # absolute file offset of run start
        foff = a + start * WIDTH
        print(f"  hb=0x{hb:02x} len={length} fileoff=0x{foff:x} first_u32=0x{first:08x} "
              f"min=0x{mn:08x} max=0x{mx:08x}")
        # candidate key check: first entry should equal K; if high byte of K == hb, consistent
        if (first >> 24) & 0xff == hb:
            print(f"      -> first_u32 high byte matches run high byte; candidate K = 0x{first:08x}")
print(f"\ndone in {time.time()-t0:.1f}s")
