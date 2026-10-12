import hashlib, struct, os
BOOT = r"analysis/output/c_line/image/boot.img"
MEY  = r"analysis/scratch/Image-mey"
# boot.img: page_size 通常 4096, header v4 -> kernel @ header_size(1584) 对齐
d = open(BOOT,'rb').read(8192)
print('magic   =', d[:8])
ks,ka,rs,ra = struct.unpack_from('<IIII', d, 8)
os_ver, os_lvl = struct.unpack_from('<II', d, 24)
print('kernel_size=%d ramdisk_size=%d' % (ks, rs))
print('os_version=%d os_patch_level=0x%x' % (os_ver, os_lvl))
# v4 header_size at offset 1644 in v3+ layout? try both
for off in (1636, 1640, 1644, 1648):
    v, = struct.unpack_from('<I', d, off)
    if 1000 < v < 100000:
        print('  possible header_size @%d = %d' % (off, v))
# page size
pg = 4096
hdr = 1584
koff = ((hdr + pg - 1)//pg)*pg
print('kernel offset guess =', koff)
dd = open(BOOT,'rb').read(koff + ks)
kern = dd[koff:koff+ks]
mey = open(MEY,'rb').read()
print('C-line kernel len = %d' % len(kern))
print('Image-mey    len = %d' % len(mey))
print('sha256 C-line-kernel = %s' % hashlib.sha256(kern).hexdigest())
print('sha256 Image-mey     = %s' % hashlib.sha256(mey).hexdigest())
print('IDENTICAL =', hashlib.sha256(kern).hexdigest() == hashlib.sha256(mey).hexdigest())
# also compare header of kernel
print('C-line kern[:32] =', kern[:32].hex())
print('Image-mey [:32]  =', mey[:32].hex())
