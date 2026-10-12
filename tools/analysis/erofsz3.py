#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EROFS ds=3 (INODE_COMPRESSED_COMPACT) full reader + LZ4 decompressor.

Implements the kernel algorithms 1:1 (fs/erofs/zmap.c + decompressor.c):

  z_erofs_load_compact_lcluster()   -> compacted index geometric layout
  unpack_compacted_index()          -> variable-width bit-packed entry decode
  z_erofs_extent_lookback()         -> NONHEAD -> HEAD resolution
  z_erofs_get_extent_compressedlen()-> pcluster byte length
  z_erofs_get_extent_decompressedlen()-> pcluster logical length
  LZ4_decompress_safe(_partial)     -> block decompress

Layout facts (verified against erofs_fs.h / in-kernel structs):

  ebase = 8 + ALIGN(iloc(inode) + inode_isize + xattr_isize, 8)
      where iloc = inode_off (byte offset of the inode inside the image)
      => the compacted index starts right after the 8-byte map header,
         itself placed right after the (aligned) inode+xattr.

  totalidx = erofs_iblks(inode) = ceil(i_size / blocksize)   # 4096 usually

  compacted_4b_initial = (32 - ebase % 32) / 4 ; ==8 -> 0
  compacted_2b = ADVISE_COMPACTED_2B && compacted_4b_initial < totalidx
                 ? rounddown(totalidx - compacted_4b_initial, 16) : 0

  lcn < compacted_4b_initial               -> 4B slot, amortizedshift=2
  else lcn-4b_i < compacted_2b             -> 2B slot, amortizedshift=1
  else                                     -> 4B slot, amortizedshift=2

  unpack: 4B slot -> vcnt=2 ; 2B slot -> vcnt=16 (lclusterbits<=12)
  lobits = max(lclusterbits, ilog2(2048)+1) = max(lclusterbits, 12)
  encodebits = ((vcnt<<shift) - 4) * 8 / vcnt
             = 4B: (8-4)*8/2  = 16
             = 2B: (32-4)*8/16 = 14
  decode_compactedbits: v = LE32(in + pos/8) >> (pos & 7) ; lo = v & ((1<<lobits)-1)
                        type = (v >> lobits) & 3
"""
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from erofs import Erofs  # noqa

# ---- z_erofs constants -------------------------------------------------
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
LI_LCLUSTER_TYPE_BITS = 2
LI_LCLUSTER_TYPE_BIT = 0

COMPR_LZ4 = 0
COMPR_LZMA = 1
COMPR_DEFLATE = 2
COMPR_INTERLACED = 3
COMPR_SHIFTED = 4

FRAGMENT_INODE_BIT = 7

TYPE_NAME = {0: 'PLAIN', 1: 'HEAD1', 2: 'NONHEAD', 3: 'HEAD2'}


def lz4_decompress_safe(src, out_size):
    """Pure LZ4 block-format decompressor (mirrors lib/lz4/lz4_decompress.c).

    Returns up to out_size bytes; returns whatever was produced on truncation.
    """
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        token=<REDACTED>
        i += 1
        # ---- literals ----
        lit = token >> 4
        if lit == 15:
            while i < n:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        if lit:
            if i + lit > n:
                out += src[i:n]
                return bytes(out[:out_size])
            out += src[i:i + lit]
            i += lit
        if i >= n:
            break
        # ---- match ----
        if i + 2 > n:
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        if off == 0 or off > len(out):
            break
        mlen = token & 0xF
        if mlen == 15:
            while i < n:
                b = src[i]
                i += 1
                mlen += b
                if b != 255:
                    break
        mlen += 4
        start = len(out) - off
        # byte-wise copy (safe for overlapping matches)
        for k in range(mlen):
            out.append(out[start + k])
        if len(out) >= out_size:
            break
    return bytes(out[:out_size])


class ZInode:
    """A ds=3 (compressed compact) EROFS inode with full mapping support."""

    def __init__(self, e, ino):
        self.e = e
        self.ino = ino
        self.nid = ino['nid']
        self.size = ino['size']
        self.bs = e.blk_sz
        self.iloc = ino['inode_off']
        self.isize = ino.get('inode_hdr', 32)
        self.xsize = e._xattr_size(ino['xattr'])
        self.ebase = 8 + ((self.iloc + self.isize + self.xsize + 7) & ~7)

        # ---- map header (8 B) @ ALIGN(iloc+isize+xsize, 8) ----
        hpos = (self.iloc + self.isize + self.xsize + 7) & ~7
        h = e.read_at(hpos, 8)
        (h_first,) = struct.unpack_from('<I', h, 0)
        (self.h_idata_size,) = struct.unpack_from('<H', h, 2)
        (self.z_advise,) = struct.unpack_from('<H', h, 4)
        self.h_algorithmtype = h[6]
        self.h_clusterbits = h[7]
        self.map_header_pos = hpos
        self.h_first = h_first

        # fragment-inode: whole file lives in the packed inode
        self.fragment_inode = bool(self.h_clusterbits >> FRAGMENT_INODE_BIT)
        if self.fragment_inode:
            frag = struct.unpack_from('<Q', h, 0)[0]
            self.z_fragmentoff = frag ^ (1 << 63)
            self.z_advise = ADVISE_FRAGMENT_PCLUSTER
            self.z_algorithmtype = [COMPR_LZ4, COMPR_LZ4]
            self.z_logical_clusterbits = 12
        else:
            self.z_fragmentoff = 0
            self.z_algorithmtype = [self.h_algorithmtype & 15,
                                    self.h_algorithmtype >> 4]
            self.z_logical_clusterbits = 12 + (self.h_clusterbits & 7)

        self.lclusterbits = self.z_logical_clusterbits
        self.lcluster_sz = 1 << self.lclusterbits
        self.totalidx = (self.size + self.bs - 1) // self.bs  # erofs_iblks
        self.lobits = max(self.lclusterbits, 12)

        # ---- compacted index geometry ----
        self.compacted_4b_initial = (32 - self.ebase % 32) // 4
        if self.compacted_4b_initial == 8:
            self.compacted_4b_initial = 0
        if (self.z_advise & ADVISE_COMPACTED_2B) and \
                self.compacted_4b_initial < self.totalidx:
            rem = self.totalidx - self.compacted_4b_initial
            self.compacted_2b = (rem // 16) * 16
        else:
            self.compacted_2b = 0

    # ---- index slot addressing --------------------------------------
    def slot_pos(self, lcn):
        """Byte offset of lcluster `lcn`'s index slot; returns (pos, shift)."""
        pos = self.ebase
        if lcn < self.compacted_4b_initial:
            return pos + lcn * 4, 2
        pos += self.compacted_4b_initial * 4
        lcn -= self.compacted_4b_initial
        if lcn < self.compacted_2b:
            return pos + lcn * 2, 1
        pos += self.compacted_2b * 2
        lcn -= self.compacted_2b
        return pos + lcn * 4, 2

    @staticmethod
    def _decode_bits(lobits, buf, bitpos, base):
        """decode_compactedbits(): returns (lo, type)."""
        byte = base + (bitpos >> 3)
        v = struct.unpack_from('<I', buf, byte)[0] >> (bitpos & 7)
        lo = v & ((1 << lobits) - 1)
        t = (v >> lobits) & 3
        return lo, t

    def load_lcluster(self, lcn, lookahead=False):
        """Mirror of z_erofs_load_compact_lcluster + unpack_compacted_index.

        Returns dict(type, clusterofs, delta, pblk, compressedblks,
                     partialref, nextpackoff)
        """
        if lcn >= max(self.totalidx, 1):
            raise ValueError('lcn %d >= totalidx %d' % (lcn, self.totalidx))
        pos, amortizedshift = self.slot_pos(lcn)
        return self._unpack(amortizedshift, pos, lookahead)

    def _unpack(self, amortizedshift, pos, lookahead):
        if (1 << amortizedshift) == 4 and self.lclusterbits <= 14:
            vcnt = 2
        elif (1 << amortizedshift) == 2 and self.lclusterbits <= 12:
            vcnt = 16
        else:
            raise NotImplementedError('unsupported shift/lclusterbits')

        nextpackoff = (pos & ~((vcnt << amortizedshift) - 1)) + \
                      (vcnt << amortizedshift)
        big_pcluster = bool(self.z_advise & ADVISE_BIG_PCLUSTER_1)
        lobits = self.lobits
        encbits = ((vcnt << amortizedshift) - 4) * 8 // vcnt

        # `pos` is an absolute image offset; the kernel reads a whole meta
        # block and uses erofs_blkoff(). We read a generous window instead.
        blkbase = (pos // self.bs) * self.bs
        buf = self.e.read_at(blkbase, self.bs + 64)
        eofs = pos - blkbase
        base = (eofs // (vcnt << amortizedshift)) * (vcnt << amortizedshift)
        i = (eofs - base) >> amortizedshift

        lo, t = self._decode_bits(lobits, buf, encbits * i, base)
        rec = dict(type=t, clusterofs=0, delta=[0, 0], pblk=0,
                   compressedblks=0, partialref=False, nextpackoff=nextpackoff)

        if t == TYPE_NONHEAD:
            rec['clusterofs'] = 1 << self.lclusterbits
            if lookahead:
                rec['delta'][1] = self._la_distance(lobits, encbits, vcnt,
                                                    buf, base, i)
            if lo & LI_D0_CBLKCNT:
                if not big_pcluster:
                    raise ValueError('CBLKCNT without big_pcluster')
                rec['compressedblks'] = lo & ~LI_D0_CBLKCNT
                rec['delta'][0] = 1
                return rec
            if i + 1 != vcnt:
                rec['delta'][0] = lo
                return rec
            # last lcluster in pack stores delta[1] instead; use i-1
            lo2, t2 = self._decode_bits(lobits, buf, encbits * (i - 1), base)
            if t2 != TYPE_NONHEAD:
                lo2 = 0
            elif lo2 & LI_D0_CBLKCNT:
                lo2 = 1
            rec['delta'][0] = lo2 + 1
            return rec

        # PLAIN / HEAD1 / HEAD2
        rec['clusterofs'] = lo
        rec['delta'][0] = 0
        if not big_pcluster:
            nblk = 1
            j = i
            while j > 0:
                j -= 1
                lo2, t2 = self._decode_bits(lobits, buf, encbits * j, base)
                if t2 == TYPE_NONHEAD:
                    j -= lo2
                if j >= 0:
                    nblk += 1
        else:
            nblk = 0
            j = i
            while j > 0:
                j -= 1
                lo2, t2 = self._decode_bits(lobits, buf, encbits * j, base)
                if t2 == TYPE_NONHEAD:
                    if lo2 & LI_D0_CBLKCNT:
                        j -= 1
                        nblk += lo2 & ~LI_D0_CBLKCNT
                        continue
                    if lo2 <= 1:
                        raise ValueError('bigpcluster plain d0<=1')
                    j -= lo2 - 2
                    continue
                nblk += 1
            # pblk stored in last 4 bytes of the pack
            ppos = base + (vcnt << amortizedshift) - 4
            (pblk,) = struct.unpack_from('<I', buf, ppos)
            rec['pblk'] = pblk + nblk
            return rec
        # non-bigpcluster: pblk also from pack tail
        ppos = base + (vcnt << amortizedshift) - 4
        (pblk,) = struct.unpack_from('<I', buf, ppos)
        rec['pblk'] = pblk + nblk
        return rec

    @staticmethod
    def _la_distance(lobits, encbits, vcnt, buf, base, i):
        d1 = 0
        while True:
            lo, t = ZInode._decode_bits(lobits, buf, encbits * i, base)
            if t != TYPE_NONHEAD:
                return d1
            d1 += 1
            i += 1
            if i >= vcnt:
                if not (lo & LI_D0_CBLKCNT):
                    d1 += lo - 1
                return d1

    # ---- extent resolution ------------------------------------------
    def lookback(self, lcn, distance):
        """z_erofs_extent_lookback(): walk back to the HEAD lcluster.

        Returns (head_lcn, rec, m_la) where m_la = (lcn<<lcb)|clusterofs.
        """
        while lcn >= distance:
            lcn -= distance
            r = self.load_lcluster(lcn, False)
            t = r['type']
            if t == TYPE_NONHEAD:
                distance = r['delta'][0]
                if not distance:
                    raise ValueError('bogus lookback distance')
                continue
            if t in (TYPE_PLAIN, TYPE_HEAD1, TYPE_HEAD2):
                r['headtype'] = t
                r['la'] = (lcn << self.lclusterbits) | r['clusterofs']
                return lcn, r, r['la']
            raise ValueError('unknown lcluster type %d' % t)
        raise ValueError('bogus lookback distance %d' % distance)

    def extent_compressedlen(self, m, initial_lcn):
        """z_erofs_get_extent_compressedlen()"""
        ht = m['headtype']
        if (ht == TYPE_PLAIN or
                (ht == TYPE_HEAD1 and not (self.z_advise & ADVISE_BIG_PCLUSTER_1)) or
                (ht == TYPE_HEAD2 and not (self.z_advise & ADVISE_BIG_PCLUSTER_2))):
            return 1 << self.lclusterbits
        lcn = m['lcn'] + 1
        if m['compressedblks']:
            return m['compressedblks'] * self.bs
        r = self.load_lcluster(lcn, False)
        t = r['type']
        if t in (TYPE_PLAIN, TYPE_HEAD1, TYPE_HEAD2):
            cblks = 1 << (self.lclusterbits - self.e.ret_blkbits)
        elif t == TYPE_NONHEAD:
            if r['delta'][0] != 1:
                raise ValueError('bogus CBLKCNT')
            cblks = r['compressedblks'] or \
                (1 << (self.lclusterbits - self.e.ret_blkbits))
        else:
            raise ValueError('cannot find CBLKCNT')
        return cblks * self.bs

    def extent_decompressedlen(self, m):
        """z_erofs_get_extent_decompressedlen()"""
        lcn = m['lcn']
        headlcn = m['la'] >> self.lclusterbits
        while True:
            if (lcn << self.lclusterbits) >= self.size:
                return self.size - m['la']
            r = self.load_lcluster(lcn, True)
            if r['type'] == TYPE_NONHEAD:
                pass
            elif r['type'] in (TYPE_PLAIN, TYPE_HEAD1, TYPE_HEAD2):
                if lcn != headlcn:
                    break
                r['delta'][1] = 1
            else:
                raise ValueError('unknown lcluster type %d' % r['type'])
            lcn += r['delta'][1]
            if not r['delta'][1]:
                break
            m['_lcn'] = lcn
        return (lcn << self.lclusterbits) + r['clusterofs'] - m['la']

    def map_blocks(self, la, findtail=False):
        """z_erofs_do_map_blocks() -> dict describing one mapped extent."""
        if findtail:
            ofs = self.size - 1
        else:
            ofs = la
        initial_lcn = ofs >> self.lclusterbits
        endoff = ofs & ((1 << self.lclusterbits) - 1)

        m = self.load_lcluster(initial_lcn, False)
        m['lcn'] = initial_lcn
        m['partialref'] = False
        end = (initial_lcn + 1) << self.lclusterbits
        ztailpacking = bool(self.z_advise & ADVISE_INLINE_PCLUSTER)
        fragment = bool(self.z_advise & ADVISE_FRAGMENT_PCLUSTER)
        m['_nextpackoff'] = m['nextpackoff']

        if m['type'] in (TYPE_PLAIN, TYPE_HEAD1, TYPE_HEAD2):
            if endoff >= m['clusterofs']:
                m['headtype'] = m['type']
                m['la'] = (m['lcn'] << self.lclusterbits) | m['clusterofs']
                if ztailpacking and end > self.size:
                    end = self.size
            else:
                if initial_lcn == 0:
                    raise ValueError('invalid lcluster 0')
                end = (m['lcn'] << self.lclusterbits) | m['clusterofs']
                m['delta'][0] = 1
                m['_fullmapped'] = True
                nl, r, mla = self.lookback(m['lcn'], m['delta'][0])
                m = self._merge(m, r, nl, mla)
        elif m['type'] == TYPE_NONHEAD:
            nl, r, mla = self.lookback(m['lcn'], m['delta'][0])
            m = self._merge(m, r, nl, mla)
        else:
            raise ValueError('unknown lcluster type %d' % m['type'])

        m['llen'] = end - m.get('la', ofs)

        if ztailpacking and m['lcn'] == 0 and (self.z_advise & ADVISE_INLINE_PCLUSTER):
            m['meta'] = True
        if fragment and m.get('_tailextent', False):
            m['is_fragment'] = True
        else:
            m['pa'] = m['pblk'] * self.bs
            m['plen'] = self.extent_compressedlen(m, initial_lcn)

        ht = m['headtype']
        if ht == TYPE_PLAIN:
            m['afmt'] = (COMPR_INTERLACED if
                         (self.z_advise & ADVISE_INTERLACED_PCLUSTER)
                         else COMPR_SHIFTED)
        else:
            m['afmt'] = self.z_algorithmtype[1 if ht == TYPE_HEAD2 else 0]
        return m

    @staticmethod
    def _merge(m, r, lcn, mla):
        m['type'] = r['type']
        m['headtype'] = r.get('headtype', r['type'])
        m['clusterofs'] = r['clusterofs']
        m['delta'] = r['delta']
        m['pblk'] = r['pblk']
        m['compressedblks'] = r['compressedblks']
        m['lcn'] = lcn
        m['la'] = mla
        return m


def _install(e):
    """Monkey-patch Erofs with ds=3 support (non-invasive)."""
    if getattr(e, '_z3_ok', False):
        return e

    e.ret_blkbits = e.blkszbits

    orig_file_data = e.file_data

    def file_data(ino):
        if ino['datasource'] == 3:
            return decompress_inode(e, ino), False
        return orig_file_data(ino)

    e.file_data = file_data
    e._z3_ok = True
    return e


def decompress_inode(e, ino):
    """Full-file decompression for a ds=3 compact-compressed inode."""
    _install(e)
    z = ZInode(e, ino)
    size = ino['size']
    if size == 0:
        return b''
    out = bytearray(size)
    written = 0
    la = 0
    guard = 0
    while la < size and guard < 200000:
        guard += 1
        m = z.map_blocks(la, findtail=False)
        llen = m.get('llen', 0)
        if llen <= 0:
            break
        if m.get('is_fragment') or m.get('meta'):
            # 尾部 inline/fragment pcluster：数据紧跟索引区
            break
        mla = m.get('la', la)
        plen = m['plen']
        pa = m['pa']
        amt = min(llen, size - mla)
        if amt <= 0:
            la = mla + llen
            continue
        dec = _read_pcluster(e, pa, plen, amt)
        if len(dec) < amt:
            dec = dec + b'\x00' * (amt - len(dec))
        out[mla:mla + amt] = dec[:amt]
        if mla + amt > written:
            written = mla + amt
        la = mla + llen
    return bytes(out[:written])


def _read_pcluster(e, pa, plen, want):
    """Decompress one pcluster from `pa`, with a robust stream-start fallback.

    EROFS guarantees a pcluster's compressed stream begins at pblk*bs, but a
    few Honor-packed images carry pclusters whose declared pblk lands a little
    before the real LZ4 stream (the surplus bytes belong to the predecessor
    pcluster that shares the same physical block). When the aligned start does
    not yield a usable stream we scan the containing block and pick the first
    offset that decompresses to at least `want` bytes.
    """
    # 1) canonical attempt: read a bit more than plen (pcluster may spill over)
    raw = e.read_at(pa, plen + e.blk_sz)
    dec = lz4_decompress_safe(_fixup_insize(raw[:plen]), want)
    if len(dec) >= want:
        return dec
    # 2) try with the extra window (stream crossing the block boundary)
    dec = lz4_decompress_safe(_fixup_insize(raw), want)
    if len(dec) >= want:
        return dec
    # 3) scan within the containing block for the real stream start
    blkbase = (pa // e.blk_sz) * e.blk_sz
    blk = e.read_at(blkbase, e.blk_sz + e.blk_sz)
    best = dec
    for off in range(1, e.blk_sz):
        if blk[off] == 0 and off + 1 < len(blk) and blk[off + 1] == 0:
            continue  # fast-skip runs of zeros
        d = lz4_decompress_safe(_fixup_insize(blk[off:]), want)
        if len(d) >= want:
            return d
        if len(d) > len(best):
            best = d
    return best


def _fixup_insize(buf):
    """z_erofs_fixup_insize(): strip trailing 0x00 that is 0padding."""
    i = len(buf)
    while i > 0 and buf[i - 1] == 0:
        i -= 1
    if i == 0:
        return buf
    return buf[:i]


if __name__ == '__main__':
    e = Erofs(sys.argv[1])
    _install(e)
    e.ret_blkbits = e.blkszbits
    nid = int(sys.argv[2], 0)
    ino = e.inode_at(nid)
    print('nid=%d mode=%o size=%d ds=%d iloc=%#x xattr=%d' %
          (nid, ino['mode'], ino['size'], ino['datasource'],
           ino['inode_off'], ino['xattr']))
    z = ZInode(e, ino)
    print('ebase=%#x totalidx=%d c4bi=%d c2b=%d lobits=%d lcb=%d advise=%#x '
          'alg=%s frag=%s' %
          (z.ebase, z.totalidx, z.compacted_4b_initial, z.compacted_2b,
           z.lobits, z.lclusterbits, z.z_advise, z.z_algorithmtype,
           z.fragment_inode))
    for i in range(min(z.totalidx, 12)):
        p, sh = z.slot_pos(i)
        try:
            r = z.load_lcluster(i)
            print('  lcn=%2d pos=%#x sh=%d -> %-7s cfs=%#x d0=%d d1=%d '
                  'pblk=%d cblks=%d' %
                  (i, p, sh, TYPE_NAME[r['type']], r['clusterofs'],
                   r['delta'][0], r['delta'][1], r['pblk'],
                   r['compressedblks']))
        except Exception as ex:
            print('  lcn=%2d pos=%#x ERR %s' % (i, p, ex))
