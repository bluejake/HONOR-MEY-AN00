#!/usr/bin/env python3
# diag10: dump u32 在 token_index 前后，判断 offsets 数组位置。
import struct
ROOT="D:/MEY-AN00-root-repro"
KERNEL=ROOT+"/analysis/output/kernel_mey_an00.raw"
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def u16(b,o): return struct.unpack_from("<H",b,o)[0]

def main():
    kernel=open(KERNEL,"rb").read()
    p=0x14d07e0  # token_index
    print("== before token_index [0x14d07a0, 0x14d07e0) as u32 ==")
    for x in range(0x14d07a0,0x14d07e0,16):
        print(hex(x), [u32(kernel,x+i*4) for i in range(4)])
    print("== token_index head (u16) ==")
    print([u16(kernel,p+i*2) for i in range(16)])
    print("== after token_index [0x14d09e0, 0x14d0b00) as u32 ==")
    for x in range(0x14d09e0,0x14d0b00,16):
        print(hex(x), [u32(kernel,x+i*4) for i in range(4)])

if __name__=="__main__":
    main()
