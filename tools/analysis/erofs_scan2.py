"""EROFS 全树扫描 v2：只按路径名匹配（不读文件内容），输出干净清单。

用法: erofs_scan2.py <raw> <out.txt> [regex]
"""
import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from erofs import Erofs

FT_DIR = 2
FT_SYM = 7


def main():
    raw = sys.argv[1]
    outp = sys.argv[2] if len(sys.argv) > 2 else None
    pat = sys.argv[3] if len(sys.argv) > 3 else r'(honor|hihonor|hn[_.]|scm|tsa|\brcc\b|kernel_stp|hievent|ogki)'
    rx = re.compile(pat, re.I)
    e = Erofs(raw)
    rows = []
    stack = [(e.root_nid, '')]
    nfiles = ndirs = 0
    while stack:
        nid, path = stack.pop()
        try:
            ino, entries = e.list_dir(nid)
        except Exception:
            continue
        for cnid, ftype, name in entries:
            cpath = path.rstrip('/') + '/' + name
            if ftype == FT_DIR:
                ndirs += 1
                stack.append((cnid, cpath))
            else:
                nfiles += 1
            if rx.search(name):
                try:
                    ci = e.inode_at(cnid)
                    rows.append((cpath, ftype, ci['size'], ci['mode'], cnid, ci['datasource']))
                except Exception:
                    rows.append((cpath, ftype, -1, 0, cnid, -1))
            # 目录名命中也要记录
            elif ftype == FT_DIR and rx.search(cpath):
                try:
                    ci = e.inode_at(cnid)
                    rows.append((cpath + '/', FT_DIR, ci['size'], ci['mode'], cnid, ci['datasource']))
                except Exception:
                    pass
    print('total files=%d dirs=%d  matched=%d' % (nfiles, ndirs, len(rows)))
    lines = ['# %s  files=%d dirs=%d matched=%d' % (raw, nfiles, ndirs, len(rows))]
    for cpath, ft, size, mode, cnid, ds in sorted(rows):
        if ft == FT_DIR:
            t = 'd'
        elif ft == FT_SYM:
            t = 'l'
        else:
            t = '-'
        line = '%s %-72s %10d mode=%o nid=%d ds=%d' % (t, cpath, size, mode, cnid, ds)
        lines.append(line)
    txt = '\n'.join(lines)
    print(txt[:20000])
    if outp:
        open(outp, 'w', encoding='utf-8').write(txt)
        print('written:', outp)


if __name__ == '__main__':
    main()
