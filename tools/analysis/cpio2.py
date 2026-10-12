import struct, os, io, sys

SRC = sys.argv[1] if len(sys.argv) > 1 else 'analysis/output/b_line/vendor_ramdisk.cpio'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'analysis/output/b_line/cpio_index.txt'
KODIR = 'analysis/output/b_line/kos'

n = os.path.getsize(SRC)
d = open(SRC, 'rb').read()
print('file size = %d' % n, flush=True)

entries = []
off = 0
bad = 0
while off + 110 <= n:
    if d[off:off+6] != b'070701':
        bad += 1
        if bad <= 10:
            print('  [BAD] off=%d bytes=%r' % (off, d[off:off+16]), flush=True)
        nxt = d.find(b'070701', off + 1)
        if nxt < 0:
            break
        off = nxt
        continue
    hdr = struct.unpack('<13I', d[off+6:off+6+52])
    (ino, mode, uid, gid, nlink, mtime, fsize, dmaj, dmin, rmaj, rmin, namesize, chksum) = hdr
    if namesize == 0 or namesize > 4096:
        bad += 1
        if bad <= 10:
            print('  [BADSZ] off=%d namesize=%d' % (off, namesize), flush=True)
        nxt = d.find(b'070701', off + 1)
        if nxt < 0:
            break
        off = nxt
        continue
    raw = d[off+110:off+110+namesize]
    if len(raw) < namesize:
        break
    name = raw[:-1].decode('utf-8', 'replace') if raw.endswith(b'\x00') else raw.decode('utf-8', 'replace')
    if name == 'TRAILER!!!':
        entries.append((off, mode, fsize, name))
        print('  [TRAILER] off=%d total=%d' % (off, len(entries)), flush=True)
        break
    entries.append((off, mode, fsize, name))
    off = off + ((110 + namesize + 3) & ~3) + ((fsize + 3) & ~3)
    if len(entries) % 1000 == 0:
        print('  ... %d entries off=%d' % (len(entries), off), flush=True)

print('total entries = %d (bad=%d)' % (len(entries), bad), flush=True)

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with io.open(OUT, 'w', encoding='utf-8', newline='\n') as f:
    f.write('# off mode fsize name\n')
    for e in entries:
        f.write('%d %o %d %s\n' % (e[0], e[1], e[2], e[3]))

kos = [e for e in entries if e[3].endswith('.ko')]
print('*.ko count = %d' % len(kos), flush=True)
for e in kos:
    print('  KO %9d off=%d  %s' % (e[2], e[0], e[3]), flush=True)

os.makedirs(KODIR, exist_ok=True)
for off_, mode, fsize, name in kos:
    ns = len(name.encode('utf-8')) + 1
    do = off_ + ((110 + ns + 3) & ~3)
    with open(os.path.join(KODIR, os.path.basename(name)), 'wb') as g:
        g.write(d[do:do+fsize])
print('extracted %d ko -> %s' % (len(kos), KODIR), flush=True)
