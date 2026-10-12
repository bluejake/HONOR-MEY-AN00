#!/usr/bin/env python3
import struct, numpy as np
KERNEL="D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
P_TOKEN_INDEX=0x14d07e0; TS_TOKEN_TABLE=0x14d0450; MS_MARKERS=0x14cfd88
OFFS_START=0x14d09e0
kb=open(KERNEL,"rb").read(); K=kb
p=P_TOKEN_INDEX; ts=TS_TOKEN_TABLE
tidx=[struct.unpack_from("<H",kb,p+j*2)[0] for j in range(256)]
token_table=kb[ts:p]
token_str=[b'']*256
for idx in range(256):
    ti=tidx[idx]; j=ti
    while j<len(token_table) and token_table[j]!=0: j+=1
    token_str[idx]=token_table[ti:j]

def decode_all(ns):
    pos=ns; names=[]
    for i in range(110992):
        b0=K[pos]; L=b0; pos+=1
        out=bytearray(); end=pos+L
        while pos<end:
            b=K[pos]; pos+=1
            if b&0x80: out+=token_str[b&0x7f]
            else: out.append(b)
        names.append(bytes(out))
    return names,pos

names,final=decode_all(0x13522c0)
print("decoded",len(names),"final",hex(final))
offsets=[struct.unpack_from("<i",kb,OFFS_START+i*4)[0] for i in range(110992)]
relbase=0xffffffc080000000

idx={}
for i,nm in enumerate(names):
    s=nm[1:].decode('utf-8','replace') if len(nm)>1 else ''
    if s and s not in idx: idx[s]=i

for k in ("_text","init_task","selinux_state","selinux_enforcing","ashmem_miscs","sig_enforce","kallsyms_lookup_name"):
    if k in idx:
        i=idx[k]; a=(relbase+offsets[i])&0xffffffffffffffff
        print(f"  {k:22s} idx={i:6d} off=0x{a-relbase:08x} vaddr={a:016x}")
    else:
        print(f"  {k:22s} NOT FOUND")

# show symbol 0 and a few early ones with their offsets
for i in range(14):
    s=names[i][1:].decode('utf-8','replace') if len(names[i])>1 else ''
    print(f"  sym[{i}] off={offsets[i]:>10d} name={names[i]!r}")
