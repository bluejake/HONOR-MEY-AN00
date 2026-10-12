"""纯 Python Android sparse image -> raw 转换器 (只支持 sparse v1, 无 CRC 的 CHUNK_TYPE_RAW/FILL/DONT_CARE)。

用法: sparse2raw.py <in.img> <out.raw>
"""
import struct
import sys
import os

CHUNK_TYPE_RAW = 0xCAC1
CHUNK_TYPE_FILL = 0xCAC2
CHUNK_TYPE_DONT_CARE = 0xCAC3
CHUNK_TYPE_CRC32 = 0xCAC4


def convert(inp, outp):
    fin = open(inp, 'rb')
    hdr = fin.read(28)
    magic, major, minor, fhs, chs = struct.unpack_from('<IHHHH', hdr, 0)
    blk_sz, total_blks, total_chunks = struct.unpack_from('<III', hdr, 12)
    assert magic == 0xED26FF3A, 'bad magic %08x' % magic
    assert major == 1, 'unsupported sparse major %d' % major
    if fhs > 28:
        fin.read(fhs - 28)
    fout = open(outp, 'wb')
    written = 0
    for i in range(total_chunks):
        ch = fin.read(12)
        if len(ch) < 12:
            print('[!] truncated chunk header at #%d' % i)
            break
        ctype, rsvd, csz, tot = struct.unpack_from('<HHII', ch, 0)
        if ctype == CHUNK_TYPE_RAW:
            data = fin.read(csz * blk_sz)
            if len(data) != csz * blk_sz:
                print('[!] truncated raw chunk #%d' % i)
                break
            fout.write(data)
            written += len(data)
        elif ctype == CHUNK_TYPE_FILL:
            fill = fin.read(4)
            fout.write(fill * (csz * blk_sz // 4))
            written += csz * blk_sz
        elif ctype == CHUNK_TYPE_DONT_CARE:
            fout.seek(csz * blk_sz, os.SEEK_CUR)
            written += csz * blk_sz
        elif ctype == CHUNK_TYPE_CRC32:
            fin.read(4)
        else:
            print('[!] unknown chunk type %08x at #%d' % (ctype, i))
            break
    fout.close()
    fin.close()
    print('chunks_done=%d blocks_written=%d bytes=%d (%.2f GB)' % (i + 1, written // blk_sz, written, written / 1024 ** 3))


if __name__ == '__main__':
    convert(sys.argv[1], sys.argv[2])
