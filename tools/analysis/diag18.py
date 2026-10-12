#!/usr/bin/env python3
import struct
KERNEL="D:/MEY-AN00-root-repro/analysis/output/kernel_mey_an00.raw"
P_TOKEN_INDEX=0x14d07e0; TS_TOKEN_TABLE=0x14d0450; MS_MARKERS=0x14cfd88
kb=open(KERNEL,"rb").read(); K=kb
p=P_TOKEN_INDEX; ts=TS_TOKEN_TABLE
tidx=[struct.unpack_from("<H",kb,p+j*2)[0] for j in range(256)]
token_table=kb[ts:p]
token_str=[b'']*256
for idx in range(256):
    ti=tidx[idx]; j=ti
    while j<len(token_table) and token_table[j]!=0: j+=1
    token_str[idx]=token_table[ti:j]
print("=== all 256 token strings ===")
for i in range(256):
    print(i, repr(token_str[i]))

print("\n=== raw bytes at est ns 0x13521DA (first 80) ===")
base=0x13521DA
print(' '.join('%02x'%K[base+i] for i in range(80)))
print("\n=== raw bytes at 0x1340000 (first 80) ===")
base=0x1340000
print(' '.join('%02x'%K[base+i] for i in range(80)))
print("\n=== bytes just before markers: 0x14cfd88-40 .. 0x14cfd88+8 ===")
base=0x14cfd88-40
print(' '.join('%02x'%K[base+i] for i in range(48)))

# show markers region
print("\nmarkers[0..5]=",[struct.unpack_from("<I",kb,MS_MARKERS+4*i)[0] for i in range(6)])
print("markers[430..433]=",[struct.unpack_from("<I",kb,MS_MARKERS+4*i)[0] for i in range(430,434)])
