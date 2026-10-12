#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Firmware one-shot extractor: honor dload zip -> init + libc++.so
Reuses all format knowledge from the 150 firmware run:
  outer zip -> update_sd_base.zip -> image/system.img (honor sparse variant,
  28B header / 12B chunk header HHII, payload = total_sz - 12) -> raw ext4
  (EROFS superblock at 0x400) -> erofs_get.py dump.

Usage: fw_extract.py <outer_zip> <workdir> <out_prefix>
Produces: <workdir>/<prefix>_init, <workdir>/<prefix>_libcxx.so
"""
import zipfile, struct, os, sys, time, subprocess

outer_zip = sys.argv[1]
workdir = sys.argv[2]
prefix = sys.argv[3]
os.makedirs(workdir, exist_ok=True)

SCRIPTS = r'D:\MEY-AN00-root-repro\analysis\scripts'
PY = sys.executable

def log(s):
    print(f'[{time.time()-t0:5.0f}s] {s}', flush=True)

t0 = time.time()

# ---------- 1. locate inner base zip ----------
z = zipfile.ZipFile(outer_zip)
inner = [n for n in z.namelist() if n.endswith('update_sd_base.zip')]
if not inner:
    # some packages ship images directly
    imgs = [n for n in z.namelist() if n.endswith('/system.img')]
    if imgs:
        log(f'direct system.img in outer zip: {imgs[0]}')
        inner_name = None
        system_src = (z, imgs[0])
    else:
        raise SystemExit('no update_sd_base.zip nor system.img in outer zip')
else:
    inner_name = inner[0]
    log(f'inner base zip: {inner_name}')

# ---------- 2. extract inner base zip ----------
base_zip = os.path.join(workdir, 'update_sd_base.zip')
if inner_name:
    log('extracting inner base zip ...')
    with z.open(inner_name) as src, open(base_zip, 'wb') as dst:
        while True:
            chunk = src.read(16 * 1024 * 1024)
            if not chunk:
                break
            dst.write(chunk)
    log(f'extracted {os.path.getsize(base_zip)/2**30:.2f} GiB')

# ---------- 3. locate system.img (sparse) ----------
zb = zipfile.ZipFile(base_zip)
img_name = [n for n in zb.namelist() if n.endswith('/system.img')][0]
sparse_img = os.path.join(workdir, 'system_sparse.img')
log(f'extracting {img_name} ...')
with zb.open(img_name) as src, open(sparse_img, 'wb') as dst:
    while True:
        chunk = src.read(16 * 1024 * 1024)
        if not chunk:
            break
        dst.write(chunk)
log(f'extracted {os.path.getsize(sparse_img)/2**30:.2f} GiB')

# ---------- 4. sparse -> raw (honor variant: 28B hdr / 12B chunk hdr HHII / payload=tsz-12) ----------
d = open(sparse_img, 'rb').read(128)
magic = struct.unpack_from('<I', d)[0]
major = struct.unpack_from('<H', d, 4)[0]
minor = struct.unpack_from('<H', d, 6)[0]
fhs = struct.unpack_from('<H', d, 8)[0]
chs = struct.unpack_from('<H', d, 10)[0]
blk_sz = struct.unpack_from('<I', d, 12)[0]
total_blks = struct.unpack_from('<I', d, 16)[0]
total_chunks = struct.unpack_from('<I', d, 20)[0]
assert magic == 0xED26FF3A, hex(magic)
log(f'sparse: blk={blk_sz} blks={total_blks} chunks={total_chunks}')

raw_img = os.path.join(workdir, 'system_raw.img')
fin = open(sparse_img, 'rb')
fin.seek(fhs)
out = open(raw_img, 'wb')
raw_pos = 0
for c in range(total_chunks):
    ch = fin.read(12)
    ct, res, csz, tsz = struct.unpack('<HHII', ch)
    if ct == 0xCAC1:
        out.write(fin.read(tsz - 12))
        raw_pos += csz * blk_sz
    elif ct == 0xCAC2:
        fill = fin.read(4)
        out.write(fill * (csz * blk_sz // 4))
        raw_pos += csz * blk_sz
    elif ct == 0xCAC3:
        out.write(b'\0' * (csz * blk_sz))
        raw_pos += csz * blk_sz
    elif ct == 0xCAC4:
        fin.read(4)
    else:
        raise SystemExit(f'unknown chunk {ct:#x} at {c}')
    if c % 10 == 0:
        log(f'  sparse chunk {c}/{total_chunks} raw={raw_pos/2**30:.2f}G')
out.close()
fin.close()
log(f'raw done: {os.path.getsize(raw_img)/2**30:.2f} GiB')

# ---------- 5. EROFS sanity ----------
d = open(raw_img, 'rb').read(0x410)
sb = d[0x400:0x408]
log(f'EROFS magic @0x400: {sb.hex()} (expect e2e1f5e0...)')

# ---------- 6. extract init + libc++ via erofs_get ----------
for path, outname in [('/system/bin/init', f'{prefix}_init'),
                      ('/system/lib64/libc++.so', f'{prefix}_libcxx.so')]:
    r = subprocess.run([PY, os.path.join(SCRIPTS, 'erofs_get.py'), raw_img,
                        'dump', path, os.path.join(workdir, outname)],
                       capture_output=True, text=True,
                       env={**os.environ, 'MSYS_NO_PATHCONV': '1'})
    tail = (r.stdout or r.stderr).strip().splitlines()[-1:] or ['(no output)']
    log(f'  {path}: {tail[0]}')

log('DONE')
