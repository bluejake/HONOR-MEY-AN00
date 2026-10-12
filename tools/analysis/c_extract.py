import zipfile, os, time, sys
Z = r"<HOME>/WorkBuddy/2026-09-26-09-04-37/MEY-AN00 10.0.0.175(C00E170R404P2)_Firmware_MagicOS 10.0_0501AJAB.zip"
OUT = r"D:/MEY-AN00-root-repro/analysis/output/c_line"
os.makedirs(OUT, exist_ok=True)
t0 = time.time()
z = zipfile.ZipFile(Z)
targets = [
    "Software/dload/update_sd_base.zip",
    "Software/dload/MEY-AN00_all_cn/update_sd_cust_MEY-AN00_all_cn.zip",
    "Software/dload/MEY-AN00_all_cn/update_sd_preload_MEY-AN00_all_cn_R404.zip",
]
for name in targets:
    base = os.path.basename(name)
    dst = os.path.join(OUT, base)
    if os.path.exists(dst) and os.path.getsize(dst) == z.getinfo(name).file_size:
        print('SKIP (exists) %s' % base, flush=True); continue
    print('extracting %s (%d B) ...' % (base, z.getinfo(name).file_size), flush=True)
    with z.open(name) as src, open(dst, 'wb') as f:
        n = 0
        while True:
            b = src.read(1 << 22)
            if not b: break
            f.write(b); n += len(b)
    print('  done %s -> %d B  (%.1fs)' % (base, n, time.time()-t0), flush=True)
print('ALL DONE in %.1fs' % (time.time()-t0), flush=True)
