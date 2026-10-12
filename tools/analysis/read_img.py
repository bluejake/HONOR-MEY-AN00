#!/usr/bin/env python3
"""从内核裸镜像读任意 image offset 的原始字节（用于核对 .data/.rodata 常量）。"""
import sys
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "..", "output", "kernel_mey_an00.raw")
TEXT = 0xFFFFFFC080000000


def main():
    off = int(sys.argv[1], 0)
    n = int(sys.argv[2], 0) if len(sys.argv) > 2 else 64
    with open(RAW, "rb") as f:
        f.seek(off)
        data = f.read(n)
    print("off=%#x vaddr=%016x len=%d" % (off, TEXT + off, len(data)))
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        words = []
        for j in range(0, len(chunk) - 7, 8):
            words.append("%016x" % struct.unpack_from("<Q", chunk, j)[0])
        print("  +%04x  %-47s  %s" % (i, hexs, " ".join(words)))


main()
