#!/usr/bin/env python3
"""纯 Python LZ4 block 解压（无依赖）。用于解 vendor_ramdisk。"""
import sys, struct

def lz4_block_decompress(src, max_out=1<<30):
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        token=<REDACTED>; i += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                b = src[i]; i += 1
                lit_len += b
                if b != 255: break
        out += src[i:i+lit_len]; i += lit_len
        if i >= n: break
        if i + 2 > n: break
        offset = src[i] | (src[i+1] << 8); i += 2
        if offset == 0: break
        match_len = token & 0x0F
        if match_len == 15:
            while True:
                b = src[i]; i += 1
                match_len += b
                if b != 255: break
        match_len += 4
        start = len(out) - offset
        if start < 0: raise ValueError(f'bad offset {offset} at {i}')
        for k in range(match_len):
            out.append(out[start + k])
        if len(out) > max_out: raise ValueError('output too large')
    return bytes(out)

if __name__ == '__main__':
    src = open(sys.argv[1],'rb').read()
    # Android legacy lz4: 可能有 4B 长度前缀 / skippable frame 0x184D2A50
    off = 0
    # 跳过 magic 0x184C2102 (legacy frame) / 0x184D2204 (frame)
    frames = []
    if src[:4] == b'\x02\x21\x4c\x18':           # 0x184C2102 legacy frame magic
        off = 4
        print('[i] legacy lz4 frame magic found, off=4', file=sys.stderr)
        # legacy: followed by sequence of blocks: <4B size LE><data>; 高bit=未压缩
        while off + 4 <= len(src):
            bsz = struct.unpack('<I', src[off:off+4])[0]; off += 4
            if bsz == 0: break
            uncompressed = bsz & 0x80000000
            bsz &= 0x7fffffff
            if bsz == 0 or off + bsz > len(src): break
            blk = src[off:off+bsz]; off += bsz
            if uncompressed:
                frames.append(blk)
            else:
                frames.append(lz4_block_decompress(blk))
        out = b''.join(frames)
    else:
        out = lz4_block_decompress(src)
    open(sys.argv[2],'wb').write(out)
    print(f'[ok] in={len(src)} out={len(out)} -> {sys.argv[2]}')
