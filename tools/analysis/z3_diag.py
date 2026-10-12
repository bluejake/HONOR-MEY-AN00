#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
z3_diag.py — 诊断 EROFS ds=3 (INODE_COMPRESSED_COMPACT) 文件"全零"现象的根因。

用法:
  python z3_diag.py <raw.img> <path1> [<path2> ...]

输出每个文件的:
  - inode 元数据 (mode/size/ds/inode_off)
  - map_blocks 逐 lcluster 记录 (lcn/headtype/pblk/compressedblks/llen/pa)
  - 物理块内容前 32 字节 hex (判断是否真零)
  - 是否 head cluster 出现异常 (cfs/pblk 越界)
"""
import sys, struct, os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import erofs as E
import erofsz3 as Z

TYPE_NAME = {0: 'PLAIN', 1: 'HEAD1', 2: 'NONHEAD', 3: 'HEAD2'}


def resolve(e, p):
    cur = e.root_nid
    for nm in [x for x in p.split('/') if x]:
        f = None
        for nid, ft, name in e.list_dir(cur)[1]:
            if name == nm:
                f = nid
                break
        if f is None:
            return None
        cur = f
    return cur


def diag(img, paths):
    e = E.Erofs(img)
    Z._install(e)
    print('=' * 78)
    print('IMAGE %s  blkbits=%d blksz=%d meta=%#x root=%d' %
          (img, e.blkszbits, e.blk_sz, e.meta_blkaddr, e.root_nid))
    print('=' * 78)
    for p in paths:
        c = resolve(e, p)
        if c is None:
            print('[MISS] %s' % p)
            continue
        ni = e.inode_at(c)
        print('\n### %s  nid=%d' % (p, c))
        print('    mode=%o size=%d ds=%d inode_off=%#x hdr=%d' % (
            ni['mode'], ni['size'], ni['datasource'], ni['inode_off'], ni['inode_hdr']))
        if ni['datasource'] != 3:
            print('    ds != 3, skip detail')
            continue
        try:
            z = Z.ZInode(e, ni)
        except Exception as ex:
            print('    ZInode() FAILED: %r' % (ex,))
            continue
        print('    ebase=%#x totalidx=%d c4bi=%d c2b=%d lcb=%d lobits=%d advise=%#x frag=%s' % (
            z.ebase, z.totalidx, z.compacted_4b_initial, z.compacted_2b,
            z.lclusterbits, z.lobits, z.z_advise, z.fragment_inode))
        la = 0
        guard = 0
        while la < ni['size'] and guard < 64:
            guard += 1
            try:
                m = z.map_blocks(la, findtail=False)
            except Exception as ex:
                print('    map_blocks(%d) FAILED: %r' % (la, ex))
                break
            llen = m.get('llen', 0)
            pa = m.get('pa', -1)
            plen = m.get('plen', -1)
            head = m.get('headtype', -1)
            hx = ''
            if pa is not None and pa >= 0:
                raw = e.read_at(pa, min(32, plen if plen > 0 else 32))
                hx = raw.hex()
            print('    la=%-8d -> lcn=%-6d ht=%-6s llen=%-6d pblk=%-7s plen=%-5d pa=%#x  %s' % (
                m.get('la', la), la >> z.lclusterbits, TYPE_NAME.get(head, str(head)),
                llen, m.get('pblk', -1), plen, pa, hx))
            if llen <= 0:
                break
            la = m.get('la', la) + llen
        # 完整解压
        try:
            d, _ = _full(e, z, ni['size'])
            print('    === full decompress: %d bytes, all-zero=%s' % (len(d), d == b'\x00' * len(d)))
        except Exception as ex:
            print('    === full decompress FAILED: %r' % (ex,))


def _full(e, z, size):
    out = bytearray(size)
    la = 0
    guard = 0
    while la < size and guard < 200000:
        guard += 1
        m = z.map_blocks(la, findtail=False)
        llen = m.get('llen', 0)
        if llen <= 0:
            break
        if m.get('is_fragment') or m.get('meta'):
            break
        mla = m.get('la', la)
        comp = Z._fixup_insize(e.read_at(m['pa'], m['plen']))
        amt = min(llen, size - mla)
        if amt <= 0:
            la = mla + llen
            continue
        dec = Z.lz4_decompress_safe(comp, amt)
        if len(dec) < amt:
            dec = dec + b'\x00' * (amt - len(dec))
        out[mla:mla + amt] = dec[:amt]
        la = mla + llen
    return bytes(out), None


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    diag(sys.argv[1], sys.argv[2:])
