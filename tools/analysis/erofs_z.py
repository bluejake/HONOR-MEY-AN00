#!/usr/bin/env python3
"""EROFS ds=3 (compressed compact index) 解析 + LZ4 解压 —— 2026-10-04

依据 kernel fs/erofs/erofs_fs.h：
  struct z_erofs_map_header {          /* 8B */
      union { __le32 h_fragmentoff;     /* 或 */
              struct { __le16 h_reserved1; __le16 h_idata_size; } };
      __le16 h_advise;
      __u8   h_algorithmtype;           /* bit0-3 = head1, bit4-7 = head2 */
      __u8   h_clusterbits;             /* bit0-2 = lclusterbits-12; bit7 = fragment */
  };
  struct z_erofs_lcluster_index {      /* 8B */
      __le16 di_advise;
      __le16 di_clusterofs;
      union { __le32 blkaddr; __le16 delta[2]; } di_u;
  };

di_advise 低 2 bit = lcluster type（PLAIN=0/HEAD1=1/NONHEAD=2/HEAD2=3）
Z_EROFS_LI_PARTIAL_REF = 1<<15
Z_EROFS_LI_D0_CBLKCNT   = 1<<11

LZ4：EROFS 用 lz4 "0PADDING"（旧格式，输入按 4KB 块填充）；无 frame 头，直接 block 解压。
本脚本先做结构自检 + 打印每个 pcluster 的 mapping，再尝试解压。
"""
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from erofs import Erofs  # noqa

Z_LCLUSTER_TYPE_MASK = 0x3
TYPE_PLAIN = 0
TYPE_HEAD1 = 1
TYPE_NONHEAD = 2
TYPE_HEAD2 = 3
ADVISE_COMPACTED_2B = 0x0001
ADVISE_BIG_PCLUSTER_1 = 0x0002
ADVISE_BIG_PCLUSTER_2 = 0x0004
ADVISE_INLINE_PCLUSTER = 0x0008
ADVISE_INTERLACED_PCLUSTER = 0x0010
ADVISE_FRAGMENT_PCLUSTER = 0x0020
LI_PARTIAL_REF = (1 << 15)
LI_D0_CBLKCNT = (1 << 11)


def lz4_decompress_block(src, expected):
    """LZ4 block 解压（无 frame 头，纯 LZ4 block format）。"""
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        token=<REDACTED>
        i += 1
        lit_len = token >> 4
        if lit_len == 15:
            while i < n:
                b = src[i]
                i += 1
                lit_len += b
                if b != 255:
                    break
        if i + lit_len > n:
            break
        out += src[i:i + lit_len]
        i += lit_len
        if i + 2 > n:
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        if off == 0:
            break
        match_len = token & 0xF
        if match_len == 15:
            while i < n:
                b = src[i]
                i += 1
                match_len += b
                if b != 255:
                    break
        match_len += 4
        start = len(out) - off
        if start < 0:
            break
        for _ in range(match_len):
            out.append(out[start])
            start += 1
        if len(out) >= expected:
            break
    return bytes(out[:expected])


def dump_z_info(raw_path, path_in_fs):
    e = Erofs(raw_path)
    nid = e.resolve(path_in_fs) if hasattr(e, "resolve") else None
    if nid is None:
        print("resolve not available; use erofs_walk.resolve")
        return
    ino = e.inode_at(nid)
    print(f"=== {path_in_fs}  nid={nid}")
    print(f"  mode={ino['mode']:o} size={ino['size']} datasource={ino['datasource']} "
          f"u={ino['u']:#x} xattr={ino['xattr']} inode_off={ino['inode_off']:#x}")
    ds = ino["datasource"]
    if ds not in (1, 3):
        data, inline = e.file_data(ino)
        print(f"  (非压缩 ds={ds}, 直接得到 {len(data)} 字节)")
        return data
    # 压缩：metadata 起点 = inode 之后（含 xattr），再往下是 compacted index
    xattr_sz = e._xattr_size(ino["xattr"])
    idx_start = ino["inode_off"] + ino.get("inode_hdr", 32) + xattr_sz
    # 前 8 字节是 map header（对 ds=3）
    mh = e.read_at(idx_start, 8)
    frag_off, idata_sz = struct.unpack_from("<II", mh, 0)
    h_advise = struct.unpack_from("<H", mh, 4)[0]
    h_alg = mh[6]
    h_clu = mh[7]
    lclusterbits = (h_clu & 7) + 12
    fragment = bool(h_clu & 0x80)
    print(f"  map_header: fragoff/idatasize={frag_off:#x} h_advise={h_advise:#x} "
          f"alg_h1={h_alg & 0xF} alg_h2={(h_alg >> 4) & 0xF} lclusterbits={lclusterbits} "
          f"fragment={fragment}")
    lcluster_sz = 1 << lclusterbits
    n_lcluster = (ino["size"] + lcluster_sz - 1) // lcluster_sz
    print(f"  lcluster_sz={lcluster_sz} n_lcluster={n_lcluster}")

    # compact index blob
    blob_len = e._compacted_blob_size(ino) if hasattr(e, "_compacted_blob_size") else None
    if blob_len:
        print(f"  compacted index blob = {blob_len} bytes "
              f"({blob_len/8:.1f} entries)")
        idx_blob = e.read_at(idx_start + 8, blob_len)
        for i in range(min(blob_len // 8, 16)):
            adv, cfs, u = struct.unpack_from("<HHBx I", idx_blob + b"\0\0\0\0", i * 8)
            d0 = u & 0xFFFF
            d1 = (u >> 16) & 0xFFFF
            t = adv & Z_LCLUSTER_TYPE_MASK
            tn = {0: "PLAIN", 1: "HEAD1", 2: "NONHEAD", 3: "HEAD2"}[t]
            print(f"    [{i:3d}] advise={adv:#06x}({tn}) clusterofs={cfs:#06x} "
                  f"blkaddr={u:#010x} d0={d0} d1={d1}")
    return None


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    dump_z_info(sys.argv[1], sys.argv[2])
