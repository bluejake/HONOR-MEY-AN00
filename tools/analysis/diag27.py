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

def decode_symbol(pos):
    b0=K[pos]; L=b0; pos+=1
    out=bytearray(); end=pos+L
    while pos<end:
        b=K[pos]; pos+=1
        if b&0x80: out+=token_str[b&0x7f]
        else: out.append(b)
    return bytes(out),pos

print("tidx[19]=",tidx[19]," token_str[19]=",repr(token_str[19]))
print("offsets[0..5]=",[struct.unpack_from("<i",kb,OFFS_START+i*4)[0] for i in range(6)])
print("offsets[-1]=",struct.unpack_from("<i",kb,OFFS_START+(110992-1)*4)[0])

# decode first 40 symbols from 0x13522c0
pos=0x13522c0
for i in range(40):
    nm,pos=decode_symbol(pos)
    print(i, repr(nm))
