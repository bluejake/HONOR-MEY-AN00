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

def decode_symbol(pos, idxmode):
    b0=K[pos]; L=b0; pos+=1
    out=bytearray(); end=pos+L
    while pos<end:
        b=K[pos]; pos+=1
        if b&0x80:
            i = b if idxmode=='full' else (b&0x7f)
            out+=token_str[i]
        else:
            out.append(b)
    return bytes(out),pos

print("token_str[0x93]=",repr(token_str[0x93])," token_str[19]=",repr(token_str[19]))
print("token_str[0x84]=",repr(token_str[0x84])," token_str[132]=",repr(token_str[132]))

# decode first 16 symbols from 0x13522c0 with both modes
for mode in ('full','low7'):
    print(f"\n=== idxmode={mode} ===")
    pos=0x13522c0
    for i in range(16):
        nm,pos=decode_symbol(pos,mode)
        print(i, repr(nm))
