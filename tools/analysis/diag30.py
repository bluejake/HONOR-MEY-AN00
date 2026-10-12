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

print("tidx[19]=",tidx[19]," -> raw bytes at ts+tidx[19]:", kb[ts+tidx[19]:ts+tidx[19]+8].hex())
print("token_str[19]=",repr(token_str[19]))
# find tokens containing 'ext' and 'con'
ext_idx=[i for i in range(256) if b'ext' in token_str[i]]
con_idx=[i for i in range(256) if b'con' in token_str[i]]
print("tokens containing 'ext':",[(i,repr(token_str[i])) for i in ext_idx])
print("tokens containing 'con':",[(i,repr(token_str[i])) for i in con_idx])
# how many token_str entries are NOT printable ASCII (suspicious)?
bad=[i for i in range(256) if any(c<32 or c>126 for c in token_str[i])]
print("non-printable token entries:",bad[:20],"count",len(bad))

# decode full table from 0x13522c0
pos=0x13522c0; names=[]
for i in range(110992):
    b0=K[pos]; L=b0; pos+=1
    out=bytearray(); end=pos+L
    while pos<end:
        b=K[pos]; pos+=1
        if b&0x80: out+=token_str[b&0x7f]
        else: out.append(b)
    names.append(bytes(out))

offsets=[struct.unpack_from("<i",kb,OFFS_START+i*4)[0] for i in range(110992)]
relbase=0xffffffc080000000
# search for key substrings
for sub in (b'_text',b'text',b'selinux',b'init_task',b'ashmem',b'kallsyms_lookup_name'):
    hits=[i for i,nm in enumerate(names) if sub in nm]
    print(f"\n'{sub.decode()}' appears in {len(hits)} symbols; first few idx/off:")
    for i in hits[:5]:
        a=(relbase+offsets[i])&0xffffffffffffffff
        print(f"    idx={i} off={offsets[i]:>10d} 0x{a-relbase:08x} vaddr={a:016x} name={names[i]!r}")
