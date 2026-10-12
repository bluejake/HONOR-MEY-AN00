import zipfile, sys
Z = r"<HOME>/WorkBuddy/2026-09-26-09-04-37/MEY-AN00 10.0.0.175(C00E170R404P2)_Firmware_MagicOS 10.0_0501AJAB.zip"
z = zipfile.ZipFile(Z)
infos = z.infolist()
print('total entries:', len(infos))
# top-level dirs aggregation
from collections import defaultdict
agg = defaultdict(lambda: [0,0])
for i in infos:
    parts = i.filename.split('/')
    key = parts[0] + '/' + (parts[1] if len(parts)>1 else '')
    agg[key][0] += 1
    agg[key][1] += i.file_size
for k in sorted(agg):
    print('  %8d files  %14d B  %s' % (agg[k][0], agg[k][1], k))
