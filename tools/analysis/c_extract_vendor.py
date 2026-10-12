import zipfile, os, time
B = r"D:/MEY-AN00-root-repro/analysis/output/c_line/update_sd_base.zip"
OUT = r"D:/MEY-AN00-root-repro/analysis/output/c_line/image"
z = zipfile.ZipFile(B)
t0 = time.time()
for name in ["image/vendor.img", "image/vendor_dlkm.img", "image/system_dlkm.img",
             "image/kpatch.img", "image/odm.img"]:
    base = os.path.basename(name)
    dst = os.path.join(OUT, base)
    info = z.getinfo(name)
    if os.path.exists(dst) and os.path.getsize(dst) == info.file_size:
        print('SKIP %s' % base, flush=True); continue
    print('extracting %s (%.2f GB) ...' % (base, info.file_size/1e9), flush=True)
    with z.open(name) as s, open(dst, 'wb') as f:
        while True:
            b = s.read(1 << 23)
            if not b: break
            f.write(b)
    print('  ok %s (%.1fs)' % (base, time.time()-t0), flush=True)
print('DONE %.1fs' % (time.time()-t0), flush=True)
