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

def decode(pos, lenmode, tokenmode):
    b0=K[pos]
    if lenmode=='direct':
        L=b0; pos+=1
    elif lenmode=='uleb':
        if b0&0x80: L=(b0&0x7f)|(K[pos+1]<<7); pos+=2
        else: L=b0; pos+=1
    elif lenmode=='ff':
        if b0==0xFF: L=struct.unpack_from("<H",K,pos+1)[0]; pos+=3
        else: L=b0; pos+=1
    out=bytearray(); end=pos+L
    while pos<end:
        b=K[pos]; pos+=1
        if b&0x80:
            s=token_str[b&0x7f]
            if tokenmode=='skip1': s=s[1:]
            out+=s
        else:
            out.append(b)
    return bytes(out),pos

START=0x1352aac
for lm in ('direct','uleb','ff'):
    for tm in ('full','skip1'):
        pos=START
        syms=[]
        ok=True
        for i in range(6):
            nm,pos=decode(pos,lm,tm)
            syms.append(nm)
        # check all printable
        printable=all(all(32<=c<127 for c in s) for s in syms)
        print(f"[{lm:6s} {tm:6s}] printable={printable} ::", [s.decode('latin1') for s in syms])
