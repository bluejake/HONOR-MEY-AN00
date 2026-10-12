#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""honor_extract.py — 批量提取荣耀私有 init/脚本/配置，并做内容级风险扫描。

用法:
  python honor_extract.py <raw.img> <outdir> [maxfiles]

扫描全部 ds!=0 的文件，按后缀筛选 .rc/.sh/.xml/.conf 等，落盘并分类统计。
"""
import sys, os, re

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import erofs as E
import erofsz3 as Z

INTEREST_EXT = ('.rc', '.sh', '.xml', '.conf', '.prop', '.json', '.cfg', '.txt')
INTEREST_DIR = ('/etc/init/', '/bin/', '/etc/permissions/', '/etc/sysconfig/',
                '/etc/security/', '/etc/selinux/', '/etc/handheld_core_hardware')

RISK_PATTERNS = {
    'root_service': re.compile(r'^\s*user\s+root\b', re.M),
    'root_user_group': re.compile(r'^\s*(user|group)\s+root\b', re.M),
    'setprop_write': re.compile(r'^\s*setprop\s+(\S+)', re.M),
    'sysfs_write': re.compile(r'write\s+/sys/', re.M),
    'proc_write': re.compile(r'write\s+/proc/', re.M),
    'world_writable_dir': re.compile(r'mkdir\s+\S+\s+0?777', re.M),
    'chmod_777': re.compile(r'chmod\s+0?777', re.M),
    'chown_root': re.compile(r'chown\s+root\b', re.M),
    'exec_bin': re.compile(r'/system/bin/(sh|toolbox|toybox)', re.M),
    'keycodes': re.compile(r'^\s*keycodes\b', re.M),
    'on_prop_trigger': re.compile(r'^on\s+property:', re.M),
}


def walk(e, nid, path, out, stats, maxfiles):
    try:
        d, entries = e.list_dir(nid)
    except Exception:
        return
    for cnid, ft, name in entries:
        if name in ('.', '..'):
            continue
        p = path.rstrip('/') + '/' + name
        # EROFS erofs_filetype: 1=REG 2=DIR 3=CHR 4=BLK 5=FIFO 6=SOCK 7=SYMLINK
        if ft == 2:
            walk(e, cnid, p, out, stats, maxfiles)
        elif ft == 1 and len(out) < maxfiles:
            try:
                ni = e.inode_at(cnid)
                if ni['mode'] & 0o170000 == 0o100000:
                    low = name.lower()
                    if low.endswith(INTEREST_EXT) or any(k in p for k in INTEREST_DIR):
                        data, _ = e.file_data(ni)
                        out.append((p, ni['size'], data))
            except Exception:
                pass


def main():
    img, outdir = sys.argv[1], sys.argv[2]
    maxfiles = int(sys.argv[3]) if len(sys.argv) > 3 else 4000
    os.makedirs(outdir, exist_ok=True)
    e = E.Erofs(img)
    Z._install(e)
    out = []
    walk(e, e.root_nid, '', out, {}, maxfiles)
    print('collected %d candidate files from %s' % (len(out), img))

    hits = []
    for p, sz, data in out:
        txt = data.decode('utf-8', 'replace')
        found = {}
        for k, pat in RISK_PATTERNS.items():
            m = pat.findall(txt)
            if m:
                found[k] = m if k in ('setprop_write',) else len(m)
        if found:
            hits.append((p, sz, found))
            safe = p.replace('/', '_').lstrip('_')
            with open(os.path.join(outdir, safe), 'wb') as f:
                f.write(data)

    print('\n=== files with risk signals: %d ===' % len(hits))
    for p, sz, found in sorted(hits, key=lambda x: -x[1]):
        print('%-70s %7d  %s' % (p, sz, found))

    # 汇总 root 服务
    print('\n=== root-run services (user root) ===')
    for p, sz, data in out:
        if not p.endswith('.rc'):
            continue
        txt = data.decode('utf-8', 'replace')
        for m in re.finditer(r'service\s+(\S+)\s+(\S+)(.*?)(?=\n\s*(?:service |on |import )|\Z)',
                             txt, re.S):
            body = m.group(3)
            if re.search(r'^\s*user\s+root\b', body, re.M):
                print('  %-34s %-40s' % (m.group(1), m.group(2)))


if __name__ == '__main__':
    main()
