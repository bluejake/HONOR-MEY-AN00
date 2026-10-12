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

# search for 'T_text' (54 5f 74 65 78 74) and 't_text' (74 5f 74 65 78 74)
for typ,pat in (('T',b'T_text'),('t',b't_text')):
    patb=pat
    pos=0; hits=[]
    while True:
        q=K.find(patb,pos)
        if q<0: break
        hits.append(q); pos=q+1
    print(f"\n=== '{typ}_text' ({patb.hex()}) hits: {[hex(h) for h in hits]} ===")
    for h in hits:
        lb=K[h-1]  # length byte candidate
        print(f"  at name-pos {hex(h)} prev_byte={lb:#04x}")
        # ns = h-1 (length byte), decode symbol 0 and validate
        ok,first,fpos,npass=validate_local(h-1)
        print(f"     ns={hex(h-1)} first={first} final={hex(fpos)} checkpoints_ok={npass==mcnt-1} final==ms={fpos==MS_MARKERS}")

def validate_local(pos0):
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
