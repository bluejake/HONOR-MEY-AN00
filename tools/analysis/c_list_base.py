import zipfile, os
B = r"D:/MEY-AN00-root-repro/analysis/output/c_line/update_sd_base.zip"
print('size =', os.path.getsize(B))
z = zipfile.ZipFile(B)
infos = z.infolist()
print('entries =', len(infos))
from collections import defaultdict
agg = defaultdict(lambda: [0,0])
for i in infos:
    parts = i.filename.split('/')
    key = parts[0] + '/' + (parts[1] if len(parts)>1 else '')
    agg[key][0] += 1; agg[key][1] += i.file_size
for k in sorted(agg):
    print('  %6d files %14d B  %s' % (agg[k][0], agg[k][1], k))
print()
print('=== 前 50 个条目 ===')
for i in infos[:50]:
    print('  %14d  %s' % (i.file_size, i.filename))
