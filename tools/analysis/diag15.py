#!/usr/bin/env python3
import struct
import numpy as np

ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
P_TOKEN_INDEX=0x14d07e0; TS_TOKEN_TABLE=0x14d0450; MS_MARKERS=0x14cfd88
OFFS_START=0x14d09e0; RELBASE_OFF=0x153d020

def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]

kb=open(KERNEL,"rb").read()
K=kb
p=P_TOKEN_INDEX; ts=TS_TOKEN_TABLE
tidx=[u16(kb,p+j*2) for j in range(256)]
token_table=kb[ts:p]
print("token_table len",len(token_table),"max tidx",max(tidx))

# build token_str
token_str=[b'']*256
for idx in range(256):
    ti=tidx[idx]
    j=ti
    while j<len(token_table) and token_table[j]!=0: j+=1
    token_str[idx]=token_table[ti:j]
# show first 20 tokens
print("sample token_str[0..15]:", [token_str[i] for i in range(16)])
print("token_str lengths distribution (first 128):", set(len(token_str[i]) for i in range(128)))

def decode_symbol(pos):
    b0=K[pos]
    if b0 & 0x80:
        L=(b0 & 0x7f) | (K[pos+1]<<7); pos+=2
    else:
        L=b0; pos+=1
    out=bytearray(); end=pos+L
    while pos<end:
        b=K[pos]; pos+=1
        if b & 0x80: out+=token_str[b&0x7f]
        else: out.append(b)
    return bytes(out),pos

# 1) sanity: decode first few symbols at 0x1352aac (previously "clean")
print("\n--- decode at 0x1352aac (known clean spot) ---")
pos=0x1352aac
for i in range(8):
    nm,pos=decode_symbol(pos)
    print(i, nm)

# 2) encode T_text and search
pair_to_token={}
for idx in range(128):
    s=token_str[idx]
    if len(s)==2 and s[0]!=0 and s[1]!=0:
        pair_to_token[s]=idx|0x80

def compress_name(name):
    out=bytearray(); pp=0; nn=len(name)
    while pp<nn:
        if pp+1<nn:
            pr=name[pp:pp+2]; tok=pair_to_token.get(pr)
            if tok is not None:
                out.append(tok); pp+=2; continue
        out.append(name[pp]); pp+=1
    L=len(out)
    if L<=0x7f: pre=bytes([L])
    else: pre=bytes([(L&0x7f)|0x80,(L>>7)&0x7f])
    return pre+bytes(out)

for typ in (b'T',b't'):
    pat=compress_name(typ+b'_text')
    print("\nencode",typ+b'_text',"->",pat.hex())
    c=K.find(pat,0x1330000,0x1380000)
    hits=[]
    while c!=-1:
        hits.append(c); c=K.find(pat,c+1,0x1380000)
    print("  hits:",[hex(h) for h in hits])
    for h in hits:
        nm,fpos=decode_symbol(h)
        print("    @",hex(h),"first decoded:",nm,"final_pos:",hex(fpos),"==ms?",fpos==MS_MARKERS)

# 3) quick: does decode at markers-adjacent area look right? show markers[1] region decode from a guessed ns
print("\n--- brute check: decode first symbol at a few candidate positions in [0x1350000,0x1354000] step scan for '_text' ---")
found=[]
for pos in range(0x1350000,0x1354000):
    nm,_=decode_symbol(pos)
    if len(nm)>1 and nm[1:]==b'_text':
        found.append((pos,nm))
print("short-scan '_text' candidates:",[(hex(x),y) for x,y in found])
