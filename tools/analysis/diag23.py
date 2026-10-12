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
    b0=K[pos]
    if b0&0x80: L=(b0&0x7f)|(K[pos+1]<<7); pos+=2
    else: L=b0; pos+=1
    out=bytearray(); end=pos+L
    while pos<end:
        b=K[pos]; pos+=1
        if b&0x80: out+=token_str[b&0x7f]
        else: out.append(b)
    return bytes(out),pos

mcnt=(ts-MS_MARKERS)//4
markers=[struct.unpack_from("<I",kb,MS_MARKERS+4*i)[0] for i in range(mcnt)]
arr=np.frombuffer(kb,dtype="<u8")
idxs=np.where(arr==0xffffffc080000000)[0]
for ii in idxs:
    off=int(ii)*8
    if off>OFFS_START:
        Nc=(off-OFFS_START)//4
        if 100000<Nc<130000: N=Nc; break
print("N",N,"mcnt",mcnt,"markers[1]",markers[1])

def validate(pos0):
    pos=pos0; first=None; npass=0
    for i in range(N):
        nm,pos=decode_symbol(pos)
        if i==0: first=nm
        if (i+1)%256==0:
            b=(i+1)//256
            if b<mcnt and (pos-pos0)!=markers[b]:
                return (False,first,pos,npass)
            npass+=1
    return (pos==MS_MARKERS,first,pos,npass)

wins=[]
lo=0x1340000; hi=0x1360000
print(f"scanning [{hex(lo)},{hex(hi)}] ({(hi-lo)} positions) ...")
for pos in range(lo,hi):
    ok,first,fpos,npass=validate(pos)
    if ok:
        wins.append((pos,first,fpos))
        print(">>> WIN ns=",hex(pos),"first=",first,"final=",hex(fpos))
print("total wins:",len(wins))
