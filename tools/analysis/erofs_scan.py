"""EROFS 全树扫描：找荣耀私有 so / 内核交互组件。

用法: erofs_scan.py <raw> <out.txt>
"""
import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from erofs import Erofs

FT_DIR = 2
FT_SYM = 7

PATTERNS = [
    re.compile(r'honor', re.I),
    re.compile(r'hihonor', re.I),
    re.compile(r'^hn[_\.]', re.I),
    re.compile(r'hn_'),
    re.compile(r'hw_?[a-z]*(honor|hn)'),
]

# 感兴趣的内核交互关键字（hal / daemon / service / props）
INTEREST = re.compile(r'(honor|hihonor|hn_|scm|tsa|rcc|stp|kernel_stp|hievent|vmap|ogki)', re.I)


def main():
    raw = sys.argv[1]
    outp = sys.argv[2] if len(sys.argv) > 2 else None
    e = Erofs(raw)
    results = []
    stack = [(e.root_nid, '')]
    seen = 0
    while stack:
        nid, path = stack.pop()
        try:
            ino, entries = e.list_dir(nid)
        except Exception:
            continue
        for cnid, ftype, name in entries:
            cpath = path.rstrip('/') + '/' + name
            seen += 1
            if INTEREST.search(name) or INTEREST.search(cpath):
                try:
                    ci = e.inode_at(cnid)
                    results.append((cpath, ftype, ci['size'], ci['mode'], cnid, ci['datasource']))
                except Exception:
                    pass
            if ftype == FT_DIR:
                stack.append((cnid, cpath))
    print('scanned entries=%d  matched=%d' % (seen, len(results)))
    lines = ['# %s  scanned=%d matched=%d' % (raw, seen, len(results))]
    for cpath, ft, size, mode, cnid, ds in sorted(results):
        line = '%s %s %10d mode=%o nid=%d ds=%d' % (
            {1: '-', 2: 'd', 7: 'l'}.get(ft, '?'), cpath, size, mode, cnid, ds)
        print(line)
        lines.append(line)
    if outp:
        open(outp, 'w', encoding='utf-8').write('\n'.join(lines))
        print('written:', outp)


if __name__ == '__main__':
    main()
