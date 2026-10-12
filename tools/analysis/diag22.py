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
print("N",N,"mcnt",mcnt)

# all occurrences of the unique timestamp
needle=b'Sun May 31 12:01:53 UTC 2026'
pos=0
occs=[]
while True:
    q=K.find(needle,pos)
    if q<0: break
    occs.append(q); pos=q+1
print("timestamp occurrences:",[hex(o) for o in occs])
# pick the one near 0x1350000
bp=[o for o in occs if 0x1300000<o<0x1380000]
bp=bp[0] if bp else occs[0]
print("using banner at",hex(bp))
i=bp
while i<len(K) and K[i]!=0: i+=1
banner_end=i
print("banner_end=",hex(banner_end))
print("bytes after banner:",' '.join('%02x'%K[banner_end+k] for k in range(24)))

def validate(pos0):
    pos=pos0; first=None
    for i in range(N):
        nm,pos=decode_symbol(pos)
        if i==0: first=nm
        if (i+1)%256==0:
            b=(i+1)//256
            if b<mcnt and (pos-pos0)!=markers[b]:
                return (False,first,pos)
    return (pos==MS_MARKERS,first,pos)

lo=banner_end-128; hi=banner_end+4096
print(f"\nscan [{hex(lo)},{hex(hi)}]")
for pos in range(lo,hi):
    ok,first,fpos=validate(pos)
    if ok:
        print(">>> WIN ns=",hex(pos),"first=",first,"final=",hex(fpos))
        break
else:
    print("no win. sample first-symbol-decodable near banner_end:")
    for pos in range(banner_end-16,banner_end+64,8):
        nm,_=decode_symbol(pos)
        print("  ",hex(pos),nm)
