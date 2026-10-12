#!/usr/bin/env python3
"""在 kallsyms 快照里按名字查符号（精确/前缀）。用法: lookup_syms.py name [name...]"""
import re
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
KALL = os.path.join(HERE, "..", "output", "kallsyms_mey_an00.txt")
TEXT = 0xFFFFFFC080000000

pat = re.compile(r"^([0-9a-fA-F]{16})\s+(\S)\s+(\S+)\s*$")


def load():
    out = []
    with open(KALL, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pat.match(line.strip())
            if m:
                out.append((int(m.group(1), 16), m.group(2), m.group(3)))
    return out


def main():
    want = sys.argv[1:]
    syms = load()
    exact = {n: (a, t) for a, t, n in syms}
    for w in want:
        hit = exact.get(w)
        if hit:
            a, t = hit
            print("%-28s %016x  type=%s  off=%#x" % (w, a, t, a - TEXT))
        else:
            print("%-28s (exact miss) prefix:" % w)
            for a, t, n in syms:
                if n.startswith(w):
                    print("    %-40s %016x type=%s off=%#x" % (n, a, t, a - TEXT))


main()
