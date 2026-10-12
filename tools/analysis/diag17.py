#!/usr/bin/env python3
import struct
KERNEL="D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
P_TOKEN_INDEX=0x14d07e0; TS_TOKEN_TABLE=0x14d0450; MS_MARKERS=0x14cfd88
OFFS_START=0x14d09e0
kb=open(KERNEL,"rb").read(); K=kb
p=P_TOKEN_INDEX; ts=TS_TOKEN_TABLE
tidx=[struct.unpack_from("<H",kb,p+j*2)[0] for j in range(256)]
token_table=kb[ts:p]
# token index interpretation check
nul_count=token_table.count(0)
print("token_table len",len(token_table),"NUL count",nul_count,"tidx max",max(tidx),"min",min(tidx))
# check NUL-terminated consistency: for each i, token_table[tidx[i]] should be non-NUL; next token start after NUL?
bad=0
for i in range(255):
    s=tidx[i]; e=tidx[i+1]
    # token i occupies [s, e)? if packed. Or NUL-terminated: scan NUL.
    seg=token_table[s:e]
    if 0 in seg:  # NUL inside [s,e) means not packed
        pass
print("first 8 tidx:",tidx[:8]," next:",tidx[8:16])

token_str=[b'']*256
for idx in range(256):
    ti=tidx[idx]; j=ti
    while j<len(token_table) and token_table[j]!=0: j+=1
    token_str[idx]=token_table[ti:j]
# do any contain byte>=0x80 ?
has80=[i for i in range(256) if any(b>=0x80 for b in token_str[i])]
print("token entries containing 0x80:",has80[:20],"count",len(has80))

def decode(pos, lm, tm):
    b0=K[pos]
    if lm=='direct': L=b0; pos+=1
    elif lm=='uleb':
        if b0&0x80: L=(b0&0x7f)|(K[pos+1]<<7); pos+=2
        else: L=b0; pos+=1
    elif lm=='ff':
        if b0==0xFF: L=struct.unpack_from("<H",K,pos+1)[0]; pos+=3
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

# markers + N + validate
mcnt=(ts-MS_MARKERS)//4
markers=[struct.unpack_from("<I",kb,MS_MARKERS+4*i)[0] for i in range(mcnt)]
N=(OFFS_START-P_TOKEN_INDEX-512)//4  # approx; we'll get N from relbase later, but for checkpoint use a passed N
# Actually get N properly below.

def validate(pos0, lm, tm, N):
    pos=pos0; first=None
    for i in range(N):
        nm,pos=decode(pos,lm,tm)
        if i==0: first=nm
        if (i+1)%256==0:
            b=(i+1)//256
            if b<mcnt and (pos-pos0)!=markers[b]:
                return (False,first,pos)
    return (pos==MS_MARKERS,first,pos)

# Get N from relbase
arr=np_if_needed=None
import numpy as np
arr=np.frombuffer(kb,dtype="<u8")
idxs=np.where(arr==0xffffffc080000000)[0]
for i in idxs:
    off=int(i)*8
    if off>OFFS_START:
        Nc=(off-OFFS_START)//4
        if 100000<Nc<130000:
            relbase_off=off; N=Nc; break
print("relbase_off",hex(relbase_off),"N",N)

# scan window for '_text' first symbol
win_lo=0x1340000; win_hi=0x1360000
for lm in ('direct','uleb','ff'):
    for tm in ('full','skip1'):
        cands=[]
        for pos in range(win_lo,win_hi):
            nm,_=decode(pos,lm,tm)
            if len(nm)>1 and nm[1:]==b'_text':
                cands.append(pos)
        if cands:
            print(f"\n[{lm} {tm}] '_text' first-symbol candidates:",[hex(c) for c in cands])
            for c in cands:
                ok,first,fpos=validate(c,lm,tm,N)
                print(f"    ns={hex(c)} validate ok={ok} first={first} final={hex(fpos)}==ms?{fpos==MS_MARKERS}")
        else:
            print(f"[{lm} {tm}] no '_text' candidate")
