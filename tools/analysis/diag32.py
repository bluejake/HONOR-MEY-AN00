#!/usr/bin/env python3
# diag32 - decisive empirical test of the kallsyms compression scheme.
#
# Hypothesis: MEY-AN00 kernel uses the OLD (pre-5.2) kallsyms scheme:
#   * length byte = number of COMPRESSED bytes that follow (no ULEB128)
#   * EVERY following byte is a token index 0..255 into token_index -> token_table
#     (NO 0x80 literal/token distinction)
#   * `skipped_first`: first char of the FIRST token expanded is dropped
#
# We test several variants and pick the one whose decoded names are ~100%
# printable-ASCII (valid kallsyms identifiers). Only a correct scheme yields that.
import struct
KERNEL="D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
P_TOKEN_INDEX=0x14d07e0; TS_TOKEN_TABLE=0x14d0450; MS_MARKERS=0x14cfd88
OFFS_START=0x14d09e0; NS=0x13522c0; N=110992; RELBASE=0xffffffc080000000

kb=open(KERNEL,"rb").read(); K=kb
tidx=[struct.unpack_from("<H",kb,P_TOKEN_INDEX+j*2)[0] for j in range(256)]
token_table=kb[TS_TOKEN_TABLE:P_TOKEN_INDEX]
token_str=[b'']*256
for idx in range(256):
    ti=tidx[idx]; j=ti
    while j<len(token_table) and token_table[j]!=0: j+=1
    token_str[idx]=token_table[ti:j]

# sanity: markers array (u32) right after names region; check consistency
mcnt=(TS_TOKEN_TABLE-MS_MARKERS)//4
markers=[struct.unpack_from("<I",kb,MS_MARKERS+4*i)[0] for i in range(mcnt)]

def decode_old(pos, skip):
    L=K[pos]; pos+=1
    out=bytearray(); end=pos+L; first=True
    while pos<end:
        b=K[pos]; pos+=1
        tok=token_str[b]
        if first and skip:
            first=False
            tok=tok[1:]
        elif first:
            first=False
        out+=tok
    return bytes(out),pos

def decode_new(pos):
    b0=K[pos]
    if b0&0x80:
        L=(b0&0x7f)|(K[pos+1]<<7); pos+=2
    else:
        L=b0; pos+=1
    out=bytearray(); end=pos+L
    while pos<end:
        b=K[pos]; pos+=1
        if b&0x80: out+=token_str[b&0x7f]
        else: out.append(b)
    return bytes(out),pos

def metrics(name, dec):
    pos=NS; bad=0; firsts=[]
    ok_marker=True; mi=0
    for i in range(N):
        nm,pos=dec(pos)
        if i<25: firsts.append((i,nm))
        if not all(32<=c<127 for c in nm): bad+=1
        if (i+1)%256==0:
            mi+=1
            if mi<mcnt and (pos-NS)!=markers[mi]:
                ok_marker=False
    final=pos
    frac=100.0*(N-bad)/N
    print(f"\n=== {name} ===")
    print(f"  non-printable names: {bad}/{N}  ({frac:.3f}% valid)")
    print(f"  markers consistent: {ok_marker}  final==ms: {final==MS_MARKERS}  (final={hex(final)} ms={hex(MS_MARKERS)})")
    print(f"  first 25 symbols:")
    for i,nm in firsts:
        print(f"    [{i:5d}] {nm!r}")
    return frac,ok_marker

metrics("OLD skip_first=True", lambda p: decode_old(p,True))
metrics("OLD skip_first=False", lambda p: decode_old(p,False))
metrics("NEW (current, buggy)", decode_new)
