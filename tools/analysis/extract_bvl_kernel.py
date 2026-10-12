#!/usr/bin/env python3
# extract_bvl_kernel.py - 从 boot-6.1.img 抽出并解压内核, 或从 bvl175_Image 的 gzip 流解压
# 产出裸 arm64 Image 供 kallsyms 恢复.
import struct, zlib, sys, os

ROOT="D:/MEY-AN00-root-repro"
BOOT=ROOT+"/firmware_bvl/boot-6.1.img"
IMG =ROOT+"/firmware_bvl/bvl175_Image"
OUT =ROOT+"/analysis/output/bvl_kernel_raw.bin"

def try_gunzip(data):
    try:
        return zlib.decompress(data, 16+zlib.MAX_WBITS)
    except Exception as e:
        return None

def try_lz4(data):
    try:
        import lz4.block
        return lz4.block.decompress(data, uncompressed_size=200<<20)
    except Exception:
        return None

def extract_from_boot():
    d=open(BOOT,"rb").read()
    if d[:8]!=b"ANDROID!":
        print("boot-6.1.img 无 ANDROID! magic, 头:",d[:8]); return None
    kernel_size=struct.unpack_from("<I",d,8)[0]
    # ramdisk_size @12, header_size @20, header_version @40
    header_size=struct.unpack_from("<I",d,20)[0] or 4096
    hv=struct.unpack_from("<I",d,40)[0]
    koff=header_size
    print("boot header_version=%d kernel_size=%d koff=%d"%(hv,kernel_size,koff))
    blob=d[koff:koff+kernel_size]
    print("kernel blob[:4]=",blob[:4].hex())
    raw=try_gunzip(blob)
    if raw: print("gzip 解压成功, raw size=",len(raw)); return raw
    raw=try_lz4(blob)
    if raw: print("lz4 解压成功, raw size=",len(raw)); return raw
    print("boot kernel 未压缩或未知压缩"); return blob

def extract_from_img_gzip():
    d=open(IMG,"rb").read()
    # 找 gzip 流起点 (0x8db50 附近), 逐字节尝试自该偏移解压
    off=d.find(b"\x1f\x8b")
    print("bvl175_Image gzip 流 @",hex(off))
    while off!=-1:
        raw=try_gunzip(d[off:])
        if raw and len(raw)>1<<20:
            print("gzip 解压成功 @%s raw size=%d"%(hex(off),len(raw))); return raw
        off=d.find(b"\x1f\x8b", off+1)
        if off>1<<20: break
    print("bvl175_Image 内未找到可解压的 gzip 流")
    return None

def main():
    raw=extract_from_boot()
    if raw is None:
        raw=extract_from_img_gzip()
    if raw is None:
        print("FAIL: 两种源都无法解压内核"); sys.exit(1)
    open(OUT,"wb").write(raw)
    print("wrote",OUT,"size",len(raw))
    print("raw head[:16]=",raw[:16].hex())

if __name__=="__main__":
    main()
