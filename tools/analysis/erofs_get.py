#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""erofs_get.py —— 支持 ds=3 压缩的 EROFS 提取 CLI（2026-10-04）

用法：
    erofs_get.py <raw.img> list   <path>
    erofs_get.py <raw.img> dump   <path> <outfile>
    erofs_get.py <raw.img> tree   [path] [maxdepth]
    erofs_get.py <raw.img> find   <regex>
    erofs_get.py <raw.img> scan   <outfile> [regex]     # 只按路径名匹配
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from erofs import Erofs, FT_NAMES  # noqa
import erofsz3  # noqa


def open_fs(p):
    e = Erofs(p)
    erofsz3._install(e)
    return e


# ---------- 路径 -> nid 解析（缓存） ----------
class Resolver:
    def __init__(self, e):
        self.e = e
        self.cache = {}

    def resolve(self, path):
        """支持 '/a/b/c'、相对路径、以及 0x... 形式的直接 nid。"""
        path = path.strip()
        if path.startswith('0x') or path.isdigit():
            return int(path, 0)
        if path in self.cache:
            return self.cache[path]
        parts = [p for p in path.split('/') if p not in ('', '.')]
        nid = self.e.root_nid
        cur = ''
        for part in parts:
            if part == '..':
                continue
            try:
                _, ents = self.e.list_dir(nid)
            except Exception:
                return None
            hit = None
            for cn, ft, nm in ents:
                if nm == part:
                    hit = cn
                    break
            if hit is None:
                return None
            nid = hit
            cur += '/' + part
        self.cache[path] = nid
        return nid

    def stat(self, path):
        nid = self.resolve(path)
        if nid is None:
            return None
        return self.e.inode_at(nid)


def cmd_list(e, r, p):
    nid = r.resolve(p)
    if nid is None:
        print('not found:', p)
        return 1
    ino, ents = e.list_dir(nid)
    print('# %s (nid=%d, %d entries, inode.size=%d)' %
          (p, nid, len(ents), ino['size']))
    for cn, ft, nm in sorted(ents, key=lambda x: x[2]):
        ci = e.inode_at(cn)
        print('%s %6o %10d idx=%-10d %s%s' %
              (FT_NAMES.get(ft, '?'), ci['mode'] & 0xFFF, ci['size'], cn,
               nm, '/' if ft == 2 else ''))
    return 0


def cmd_dump(e, r, p, outp):
    nid = r.resolve(p)
    if nid is None:
        print('not found:', p)
        return 1
    ino = e.inode_at(nid)
    try:
        data, inline = e.file_data(ino)
    except Exception as ex:
        print('dump %s FAILED: %r' % (p, ex))
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(outp)), exist_ok=True)
    with open(outp, 'wb') as f:
        f.write(data)
    print('dumped %s -> %s (%d/%d bytes%s)' %
          (p, outp, len(data), ino['size'], ', inline' if inline else ''))
    return 0


def cmd_tree(e, r, p, maxdepth):
    nid = r.resolve(p)
    if nid is None:
        print('not found:', p)
        return 1
    lines = []

    def rec(n, pre, depth):
        if depth > maxdepth:
            return
        try:
            ino, ents = e.list_dir(n)
        except Exception:
            return
        ents = sorted(ents, key=lambda x: (x[1] != 2, x[2]))
        for i, (cn, ft, nm) in enumerate(ents):
            last = (i == len(ents) - 1)
            try:
                ci = e.inode_at(cn)
                sz = ci['size']
            except Exception:
                sz = -1
            lines.append('%s%s%s %s [%d]' %
                         (pre, '└── ' if last else '├── ', nm,
                          '/' if ft == 2 else '', sz))
            if ft == 2:
                rec(cn, pre + ('    ' if last else '│   '), depth + 1)

    lines.append(p + '/')
    rec(nid, '', 1)
    print('\n'.join(lines))
    return 0


def cmd_find(e, r, rx):
    pat = re.compile(rx)
    out = []

    def walk(n, path, depth=0):
        if depth > 16:
            return
        try:
            ino, ents = e.list_dir(n)
        except Exception:
            return
        for cn, ft, nm in ents:
            p = path + '/' + nm
            if pat.search(p):
                try:
                    ci = e.inode_at(cn)
                    out.append('%s %d ds=%d' % (p, ci['size'], ci['datasource']))
                except Exception:
                    out.append(p)
            if ft == 2:
                walk(cn, p, depth + 1)

    walk(e.root_nid, '')
    for x in sorted(out):
        print(x)
    print('# total %d' % len(out))
    return 0


def cmd_scan(e, r, outp, rx):
    pat = re.compile(rx) if rx else None
    nfile = ndir = nmatch = 0
    rows = []

    def walk(n, path, depth=0):
        nonlocal nfile, ndir, nmatch
        if depth > 16:
            return
        try:
            ino, ents = e.list_dir(n)
        except Exception:
            return
        for cn, ft, nm in ents:
            p = path + '/' + nm
            try:
                ci = e.inode_at(cn)
            except Exception:
                continue
            isdir = (ft == 2)
            if isdir:
                ndir += 1
            else:
                nfile += 1
            if pat and pat.search(p):
                nmatch += 1
                rows.append('%s %s %10d mode=%o nid=%d ds=%d' %
                            ('d' if isdir else '-', p, ci['size'],
                             ci['mode'], cn, ci['datasource']))
            if isdir:
                walk(cn, p, depth + 1)

    walk(e.root_nid, '')
    with open(outp, 'w', encoding='utf-8') as f:
        f.write('# %s  files=%d dirs=%d matched=%d\n' %
                (r.e.f.name, nfile, ndir, nmatch))
        f.write('\n'.join(rows) + '\n')
    print('files=%d dirs=%d matched=%d -> %s' %
          (nfile, ndir, nmatch, outp))
    return 0


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    img, cmd = sys.argv[1], sys.argv[2]
    e = open_fs(img)
    r = Resolver(e)
    try:
        if cmd == 'list':
            return cmd_list(e, r, sys.argv[3])
        if cmd == 'dump':
            return cmd_dump(e, r, sys.argv[3], sys.argv[4])
        if cmd == 'tree':
            return cmd_tree(e, r, sys.argv[3] if len(sys.argv) > 3 else '/',
                            int(sys.argv[4]) if len(sys.argv) > 4 else 3)
        if cmd == 'find':
            return cmd_find(e, r, sys.argv[3])
        if cmd == 'scan':
            return cmd_scan(e, r, sys.argv[3],
                            sys.argv[4] if len(sys.argv) > 4 else None)
    except IndexError:
        print(__doc__)
        return 1
    print(__doc__)
    return 1


if __name__ == '__main__':
    sys.exit(main())
