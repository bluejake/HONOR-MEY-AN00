"""EROFS 目录树遍历 + 按需提取。

用法:
  erofs_walk.py <raw> list [path]        # 列目录（默认 /）
  erofs_walk.py <raw> find <substr>      # 按名字子串查找
  erofs_walk.py <raw> dump <path> <out>  # 提取文件
"""
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from erofs import Erofs, FT_NAMES

FT_DIR = 2
FT_SYMLINK = 7
FT_REG = 1


def walk(e, nid, path, maxdepth, depth=0, out=None):
    """DFS 遍历，回调 out(path, nid, ftype, size, mode)"""
    if depth > maxdepth:
        return
    ino, entries = e.list_dir(nid)
    for cnid, ftype, name in entries:
        if name in ('.', '..'):
            continue
        cpath = path.rstrip('/') + '/' + name
        try:
            cino = e.inode_at(cnid)
        except Exception as ex:
            continue
        size = cino['size']
        mode = cino['mode']
        if out:
            out(cpath, cnid, ftype, size, mode, cino)
        if ftype == FT_DIR:
            walk(e, cnid, cpath, maxdepth, depth + 1, out)


def resolve(e, path):
    path = path.strip('/')
    if not path:
        return e.root_nid
    nid = e.root_nid
    for seg in path.split('/'):
        if not seg:
            continue
        ino, entries = e.list_dir(nid)
        found = [x for x in entries if x[2] == seg]
        if not found:
            return None
        nid = found[0][0]
    return nid


def main():
    raw = sys.argv[1]
    cmd = sys.argv[2]
    e = Erofs(raw)
    if cmd == 'list':
        p = sys.argv[3] if len(sys.argv) > 3 else '/'
        nid = resolve(e, p)
        if nid is None:
            print('not found: %s' % p); return
        ino, entries = e.list_dir(nid)
        print('# %s (nid=%d, %d entries, inode.size=%d)' % (p, nid, len(entries), ino['size']))
        for cnid, ftype, name in entries:
            if name in ('.', '..'):
                continue
            try:
                ci = e.inode_at(cnid)
                print('%s %6o %10d idx=%d %s' % (FT_NAMES.get(ftype, '?'), ci['mode'] & 0o7777, ci['size'], cnid, name))
            except Exception as ex:
                print('? ? ? %s (%s)' % (name, ex))
    elif cmd == 'find':
        pat = sys.argv[3].lower()
        hits = []

        def cb(p, nid, ft, size, mode, ino):
            if pat in p.lower():
                hits.append((p, ft, size, mode, nid))
        walk(e, e.root_nid, '', 12, 0, cb)
        for p, ft, size, mode, nid in hits:
            print('%s %s %10d nid=%d' % (FT_NAMES.get(ft, '?'), p, size, nid))
        print('# total %d hits' % len(hits))
    elif cmd == 'dump':
        p, outp = sys.argv[3], sys.argv[4]
        nid = resolve(e, p)
        if nid is None:
            print('not found'); return
        data = e.read_file(nid)
        os.makedirs(os.path.dirname(outp), exist_ok=True) if os.path.dirname(outp) else None
        open(outp, 'wb').write(data)
        print('dumped %s -> %s (%d bytes)' % (p, outp, len(data)))
    elif cmd == 'tree':
        p = sys.argv[3] if len(sys.argv) > 3 else '/'
        nid = resolve(e, p)

        def cb2(pp, n, ft, sz, md, ino):
            print('%s %s %10d nid=%d' % (FT_NAMES.get(ft, '?'), pp, sz, n))
        walk(e, nid, p.rstrip('/'), 6, 0, cb2)


if __name__ == '__main__':
    main()
