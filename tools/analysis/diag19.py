#!/usr/bin/env python3
import struct
KERNEL="D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
P_TOKEN_INDEX=0x14d07e0; TS_TOKEN_TABLE=0x14d0450
kb=open(KERNEL,"rb").read(); K=kb
p=P_TOKEN_INDEX; ts=TS_TOKEN_TABLE
tidx=[struct.unpack_from("<H",kb,p+j*2)[0] for j in range(256)]
token_table=kb[ts:p]
token_str=[b'']*256
for idx in range(256):
    ti=tidx[idx]; j=ti
    while j<len(token_table) and token_table[j]!=0: j+=1
    token_str[idx]=token_table[ti:j]

def decode(pos, lm, tm):
    b0=K[pos]
    if lm=='direct': L=b0; pos+=1
    elif lm=='uleb':
        if b0&0x80: L=(b0&0x7f)|(K[pos+1]<<7); pos+=2
        else: L=b0; pos+=1
    out=bytearray(); end=pos+L
    while pos<end:
        b=K[pos]; pos+=1
        if b&0x80:
            s=token_str[b&0x7f]
            if tm=='skip1': s=s[1:]
            out+=s
        else:
            out.append(b)
    return bytes(out),pos

for base in (0x13521DA, 0x1350000, 0x1340000, 0x1330000):
    print(f"\n=== raw @ {hex(base)} (first 60) ===")
    print(' '.join('%02x'%K[base+i] for i in range(60)))
    for lm in ('uleb','direct'):
        pos=base
        syms=[]
        for i in range(6):
            nm,pos=decode(pos,lm,'full')
            syms.append(nm)
        print(f"  [{lm} full]:", [s.decode('latin1') for s in syms])
