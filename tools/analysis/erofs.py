"""EROFS 只读解析器（最小子集）：读超级块 -> 走 root nid -> 递归列目录 -> 支持按需提取文件。

EROFS on-disk 布局（block = 1<<blkszbits）：
  superblock @ 1024  (128 B)
  实际镜像数据从 0 开始；meta block 起始由 superblock 里的字段决定：
  struct erofs_super_block {
     __le32 magic;        // 0
     __le32 checksum;     // 4
     __le32 feature_compat;//8
     __le8  blkszbits;    // 12
     __le8  sb_extslots;  // 13
     __le16 root_nid;     // 14
     __le64 inos;         // 16
     __le64 build_time;   // 24
     __le32 build_time_nsec;//32
     __le32 blocks;       // 36
     __le32 meta_blkaddr; // 40
     __le32 xattr_blkaddr;// 44
     __le8  uuid[16];     // 48
     __le8  volume_name[16]; // 64
     ...
  }
  (注意：root_nid 是 u16 在 offset 14，blocks/meta_blkaddr 在 36/40)
"""
import struct
import sys
import os

FT_UNKNOWN = 0
FT_REG_FILE = 1
FT_DIR = 2
FT_CHRDEV = 3
FT_BLKDEV = 4
FT_FIFO = 5
FT_SOCK = 6
FT_SYMLINK = 7

FT_NAMES = {0: 'UNK', 1: '-', 2: 'd', 3: 'c', 4: 'b', 5: 'p', 6: 's', 7: 'l'}


class Erofs:
    def __init__(self, path):
        self.f = open(path, 'rb')
        self.f.seek(1024)
        sb = self.f.read(128)
        self.sb_raw = sb
        # 官方 struct erofs_super_block 布局（已逐字节核对）：
        #  +0  magic u32 / +4 checksum u32 / +8 feature_compat u32
        #  +12 blkszbits u8 / +13 sb_extslots u8 / +14 root_nid u16
        #  +16 inos u64 / +24 build_time u64 / +32 build_time_nsec u32
        #  +36 blocks u32 / +40 meta_blkaddr u32 / +44 xattr_blkaddr u32
        #  +48 uuid[16] / +64 volume_name[16] / ... / +84 feature_incompat u32
        magic = struct.unpack_from('<I', sb, 0)[0]
        assert magic == 0xE0F5E1E2, 'bad erofs magic %08x' % magic
        self.blkszbits = sb[12]
        self.sb_extslots = sb[13]
        self.root_nid = struct.unpack_from('<H', sb, 14)[0]
        self.inos = struct.unpack_from('<Q', sb, 16)[0]
        self.blocks = struct.unpack_from('<I', sb, 36)[0]
        self.meta_blkaddr = struct.unpack_from('<I', sb, 40)[0]
        self.xattr_blkaddr = struct.unpack_from('<I', sb, 44)[0]
        self.feat_compat = struct.unpack_from('<I', sb, 8)[0]
        self.feat_incompat = struct.unpack_from('<I', sb, 84)[0]
        self.blk_sz = 1 << self.blkszbits
        # EROFS 的 block0 = offset 0（superblock @1024 在 block 0 内）
        self.base = 0

    def block_off(self, blk):
        return self.base + blk * self.blk_sz

    def read_at(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    # ---- inode ----
    # EROFS compact inode (32 B) 布局（已逐字节核对本镜像）：
    #  +0  i_format u16   (bit0 = version, bit1..3 = datasource)
    #  +2  i_xattr_icount u16
    #  +4  i_mode u16
    #  +6  i_nlink u16
    #  +8  i_size u32
    #  +12 i_reserved u32
    #  +16 i_u u32        (datasource==0 ? blkaddr : nid / rdev)
    #  +20 i_ino u32
    #  +24 i_uid u16
    #  +26 i_gid u16
    #  +28 i_reserved2 u32
    # data source: 0=FLAT_PLAIN/COMPRESSED 的 blkaddr；1=FLAT_COMPRESSION 的 startblk；
    #              2=INODE (内联在 inode 之后)；3=TAILPACKING (blkaddr+nid)
    DS_FLAT_PLAIN = 0
    DS_COMPRESSED_FULL = 1
    DS_INODE = 2
    DS_COMPRESSED_COMPACT = 3

    def inode_size(self, version):
        # version 0 = erofs_inode_compact (32 B) ; version 1 = erofs_inode_extended (64 B)
        return 64 if version else 32

    def inode_off(self, nid, version=0):
        per_blk = self.blk_sz // 32
        return self.block_off(self.meta_blkaddr + nid // per_blk) + (nid % per_blk) * 32

    def inode_at(self, nid):
        off = self.inode_off(nid)
        d = self.read_at(off, 64)
        i_format = struct.unpack_from('<H', d, 0)[0]
        version = i_format & 1
        datasource = (i_format >> 1) & 7
        if version == 0:
            # erofs_inode_compact (32 B)
            i_xattr = struct.unpack_from('<H', d, 2)[0]
            i_mode = struct.unpack_from('<H', d, 4)[0]
            i_nlink = struct.unpack_from('<H', d, 6)[0]
            i_size = struct.unpack_from('<I', d, 8)[0]
            i_u = struct.unpack_from('<I', d, 16)[0]
            ino = struct.unpack_from('<I', d, 20)[0]
            uid = struct.unpack_from('<H', d, 24)[0]
            gid = struct.unpack_from('<H', d, 26)[0]
            hdr = 32
        else:
            # erofs_inode_extended (64 B):
            #  +0  i_format u16 / +2 i_xattr_icount u16 / +4 i_mode u16
            #  +6  i_reserved u16 / +8 i_size u64 / +16 i_u u32 / +20 i_ino u32
            #  +24 i_uid u32 / +28 i_gid u32 / +32 i_mtime u64 / +40 i_mtime_nsec u32
            #  +44 i_nlink u32 / +48 i_reserved2[16]
            i_xattr = struct.unpack_from('<H', d, 2)[0]
            i_mode = struct.unpack_from('<H', d, 4)[0]
            i_size = struct.unpack_from('<Q', d, 8)[0]
            i_u = struct.unpack_from('<I', d, 16)[0]
            ino = struct.unpack_from('<I', d, 20)[0]
            uid = struct.unpack_from('<I', d, 24)[0]
            gid = struct.unpack_from('<I', d, 28)[0]
            i_nlink = struct.unpack_from('<I', d, 44)[0]
            hdr = 64
        return dict(nid=nid, version=version, datasource=datasource, fmt=datasource,
                    xattr=i_xattr, mode=i_mode, nlink=i_nlink, size=i_size,
                    u=i_u, ino=ino, uid=uid, gid=gid, inode_off=off, inode_hdr=hdr, raw=d)

    def _xattr_size(self, icount):
        """erofs_xattr_ibody_size(): 12 + 4*(icount-1)  [kernel fs/erofs/erofs_fs.h:245]

        ★ 2026-10-04 修正：此前误用 `(icount-1)*12 + 4`，只有 icount==2 时巧合相等。
          内核真值：sizeof(erofs_xattr_ibody_header)=4 已含在 12 的 e_name_len 区，
          实际公式为 12 + 4*(icount-1)，即每多一个 xattr_icount 加 4 字节。
          实证：/bin/tcmd icount=12 -> xattr_isize=56 (非 136)，据此 ebase 才落在
          0x120ae20，map header h_advise=0x0001 正确可读。
        """
        if icount <= 0:
            return 0
        return 12 + 4 * (icount - 1)

    def file_data(self, ino):
        """返回 (data, is_inline)。inline 时从 inode 之后读取。

        ★ 实测校准（vendor.img root nid=53, xattr_icount=2）：
          inline 数据起点 = inode_off + 32 + xattr_size
          其中 xattr_size = (icount-1)*12 + 4  （4B erofs_xattr_ibody_header + 每 entry 12B）
          icount=2 → 12+4 = 16 ✓（实测 delta=16 时 nid=53/nameoff=228 完全正确）
          ⇒ **inline meta 的 4 字节已包含在 xattr_size 内，不可重复相加**
        """
        size = ino['size']
        ds = ino['datasource']
        if ds == self.DS_INODE:
            # ★★★★ 2026-10-04 最终修正（与内核 data.c:erofs_map_blocks_flatmode 逐行对齐）
            #   EROFS_INODE_FLAT_INLINE 的真值布局：**前 (nblocks-1) 个整块来自
            #   i_u.raw_blkaddr 的连续物理块；只有最后一块是 inline（在 inode 之后）**。
            #   此前实现把 inline 放在最前，导致多块目录/文件全部解析错误。
            #
            #   内核 fs/erofs/data.c:
            #     nblocks  = erofs_iblks(inode) = DIV_ROUND_UP(i_size, blksz)
            #     lastblk  = nblocks - tailendpacking      // tailendpacking = true
            #     if (offset < erofs_pos(lastblk))          // 非末块
            #         m_pa   = erofs_pos(vi->raw_blkaddr) + m_la
            #         m_plen = 块尾 - offset
            #     else                                      // 末块 = inline
            #         m_pa   = erofs_iloc(inode) + inode_isize + xattr_isize
            #                  + erofs_blkoff(offset)
            #         // 且必须不跨元数据块边界，否则 EFSCORRUPTED
            BS = self.blk_sz
            iblks = (size + BS - 1) // BS if size else 0
            lastblk = iblks - 1
            if lastblk < 0:
                return b'', True
            out = bytearray()
            for la in range(0, size, BS):
                blkidx = la // BS
                n = min(BS, size - la)
                if blkidx < lastblk:
                    pa = self.block_off(ino['u']) + la
                else:
                    pa = (ino['inode_off'] + ino.get('inode_hdr', 32)
                          + self._xattr_size(ino['xattr'])
                          + (la - lastblk * BS))
                out += self.read_at(pa, n)
            return bytes(out[:size]), True
        elif ds in (self.DS_FLAT_PLAIN, self.DS_COMPRESSED_FULL):
            blkaddr = ino['u']
            n = (size + self.blk_sz - 1) // self.blk_sz
            out = b''
            for i in range(n):
                out += self.read_at(self.block_off(blkaddr + i), self.blk_sz)
            return out[:size], False
        elif ds == self.DS_COMPRESSED_COMPACT:
            # 需要 z_erofs 解压，暂不支持
            raise NotImplementedError('compressed compact data (datasource=3)')
        else:
            raise NotImplementedError('datasource=%d' % ds)

    def ftype(self, mode):
        return (mode >> 12) & 0xF

    def list_dir(self, nid):
        """解析 EROFS 目录。

        ★★ 实测校准（vendor.img, feature_incompat=0xffff）：
          inline 数据起点 = inode_off + 32 + xattr_size，其中 xattr_size=(icount-1)*12+4
          dirent = 12 字节，**标准 EROFS 布局**：
             +0  nid      u64
             +8  nameoff  u16
             +10 file_type u8
             +11 reserved  u8
          名字区紧跟在所有 dirent 之后；名字**不以 \\0 终止**，
          长度 = 下一个 dirent 的 nameoff − 本 dirent 的 nameoff（最后一条到目录 size）。
          (注意：根目录 nid 恰好都很小，早期误判为 u32 布局；/bin 出现
            nid=0x01faa97c 才确认是 u64。）

        ★★★★ 2026-10-04 最终修正（与内核 namei.c 逐行对齐）：
          内核 `fs/erofs/namei.c`:
              #define nameoff_from_disk(off, sz) (le16_to_cpu(off) & ((sz) - 1))
              const int nameoff  = nameoff_from_disk(de->nameoff, bsz);   // bsz = 4096
              const int ndirents = nameoff / sizeof(*de);                 // sizeof = 12
              dname.name = (u8*)de + nameoff;
              dname.end  = (ndirents == 1) ? (u8*)de + bsz
                          : (u8*)de + nameoff_from_disk(de[1].nameoff, bsz);
          且 `erofs_find_target_block()` **对每个 4096 字节块独立二分**
          （`erofs_iblks(dir)` 个块，每块各自从偏移 0 开始）。
          ⇒ **nameoff 是"块内偏移"，必须 `& (blk_sz-1)` 掩码**；每个 blk_sz 段是
            一个独立目录单元：`[dirent 数组 (first_nameoff 字节)] [名字区]`。
          此前实现把整个目录当一个连续单元 ⇒ 只解析第 0 段（/system/bin 只 55 条）。
        """
        ino = self.inode_at(nid)
        data, inline = self.file_data(ino)
        size = ino['size']
        total = len(data)
        if size:
            total = min(total, size)
        BS = self.blk_sz
        entries = []
        for base in range(0, max(total, 1), BS):
            seg = data[base:base + BS]
            if len(seg) < 12:
                break
            first_nameoff = struct.unpack_from('<H', seg, 8)[0] & (BS - 1)
            if first_nameoff < 12 or first_nameoff % 12 != 0 or first_nameoff > len(seg):
                continue
            nd = first_nameoff // 12
            raw_ents = []
            for i in range(nd):
                o = i * 12
                nid_e = struct.unpack_from('<Q', seg, o)[0]
                nameoff = struct.unpack_from('<H', seg, o + 8)[0] & (BS - 1)
                ftype = seg[o + 10]
                if nid_e == 0:
                    break
                raw_ents.append((nid_e, nameoff, ftype))
            for i, (nid_e, nameoff, ftype) in enumerate(raw_ents):
                if i + 1 < len(raw_ents):
                    end = raw_ents[i + 1][1]
                    if end <= nameoff:
                        end = len(seg)
                else:
                    end = len(seg)
                z = seg.find(b'\x00', nameoff)
                if 0 < z < end:
                    end = z
                if end > nameoff + 255:
                    end = nameoff + 255
                if nameoff >= len(seg) or end > len(seg) or end <= nameoff:
                    continue
                nm = seg[nameoff:end].decode('utf-8', 'replace')
                if nm in ('.', '..'):
                    continue
                entries.append((nid_e, ftype, nm))
        return ino, entries

    def read_file(self, nid):
        ino = self.inode_at(nid)
        data, inline = self.file_data(ino)
        return data


if __name__ == '__main__':
    p = sys.argv[1]
    e = Erofs(p)
    print('blk_sz=%d root_nid=%d meta_blkaddr=%d inos=%d' % (e.blk_sz, e.root_nid, e.meta_blkaddr, e.inos))
    print('feature_compat=%08x' % struct.unpack_from('<I', e.sb_raw, 8)[0])
    print('feature_incompat=%08x' % e.feat_incompat)
    print('uuid=%s' % e.sb_raw[48:64].hex())
    print('volume_name=%r' % e.sb_raw[64:80].rstrip(b'\x00'))
