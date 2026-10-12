#!/usr/bin/env python3
# Validate candidate kallsyms_offsets runs via the structural anchor:
#   offsets[0] de-XORs to 0, and the u32 immediately AFTER the array (kallsyms_num_syms) de-XORs to N.
import array, struct

PATH = "D:/MEY-AN00-root-repro/firmware_bvl/bvl175_Image"

# candidates from scan (fileoff, length, note)
CANDIDATES = [
    (0x1360ec0, 52603, "hb=0x00"),
    (0x13944ac, 37789, "hb=0x01"),
    (0x13b9320, 26215, "hb=0x02"),
]

def read_u32(foff, n):
    with open(PATH, "rb") as f:
        f.seek(foff)
        buf = f.read(n * 4)
    a = array.array('I')
    a.frombytes(buf)
    return a

def validate(foff, N, label):
    # read N+1 u32 (the extra one is kallsyms_num_syms)
    vals = read_u32(foff, N + 1)
    K = vals[0]
    de = [ (v ^ K) & 0xffffffff for v in vals ]
    ok0 = (de[0] == 0)
    okN = (de[N] == N)
    # also report span / how many de-XORed are in [0, 0x4000000)
    inrange = sum(1 for v in de[:N] if v < 0x4000000)
    print(f"[{label}] foff=0x{foff:x} N={N} K=0x{K:08x}")
    print(f"    deXOR[0]={de[0]:#x} (want 0) -> {'OK' if ok0 else 'FAIL'}")
    print(f"    deXOR[N]={de[N]:#x} (want {N}) -> {'OK' if okN else 'FAIL'}")
    print(f"    deXOR values in [0,0x4000000): {inrange}/{N}")
    if ok0 and okN:
        print("    >>> STRONG MATCH: this is kallsyms_offsets (XOR key = 0x%08x)" % K)
    print()

for foff, N, label in CANDIDATES:
    validate(foff, N, label)

# Also test the hb=0 candidate AS-IS (unobfuscated, K=0) in case offsets[0]==0 literally
print("=== as-is (K=0) check on first candidate ===")
vals = read_u32(0x1360ec0, 52604)
print("    as-is[0]=0x%08x  as-is[N]=0x%08x" % (vals[0], vals[52603]))
print("    strictly increasing as-is? checking first 1000...")
inc = all(vals[i] < vals[i+1] for i in range(1000))
print("    first 1000 strictly increasing:", inc)
