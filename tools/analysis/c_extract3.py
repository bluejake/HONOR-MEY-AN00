import zipfile, os, time
B = r"D:/MEY-AN00-root-repro/analysis/output/c_line/update_sd_base.zip"
OUT = r"D:/MEY-AN00-root-repro/analysis/output/c_line/image"
os.makedirs(OUT, exist_ok=True)
z = zipfile.ZipFile(B)
names = set(z.namelist())
targets = ["SOFTWARE_VER.mbn", "SOFTWARE_VER_LIST.mbn", "UPT_VER.tag", "SD_update.tag",
           "full_mainpkg.tag", "erase_partitions_list.tag",
           "image/version.img", "image/boot.img", "image/vendor_boot.img", "image/init_boot.img",
           "gpt_both0.bin", "PTABLE_SUPER.mbn"]
t0 = time.time()
for name in targets:
    if name not in names:
        print('MISSING %s' % name, flush=True); continue
    base = os.path.basename(name)
    dst = os.path.join(OUT, base)
    info = z.getinfo(name)
    if os.path.exists(dst) and os.path.getsize(dst) == info.file_size:
        print('SKIP %s' % base, flush=True); continue
    print('extracting %s (%d B) ...' % (base, info.file_size), flush=True)
    with z.open(name) as s, open(dst, 'wb') as f:
        while True:
            b = s.read(1 << 22)
            if not b: break
            f.write(b)
    print('  ok %s (%.1fs)' % (base, time.time()-t0), flush=True)
print('DONE %.1fs' % (time.time()-t0), flush=True)
