#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parallel firmware pull (4 concurrent x 16 conn = 64 threads effect):
download ALL >=150 firmwares, extract init/libc++, build the universal
device config library for the multi-device APK."""
import json, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

MANIFEST = r'D:\MEY-AN00-root-repro\adapt_manifest.json'
BASE = r'D:\MEY-AN00-root-repro\adapt_batch'
SCRIPTS = r'D:\MEY-AN00-root-repro\analysis\scripts'
DFW = r'D:\MEY-AN00-root-repro\analysis\scratch\DFWarm'
ARIA = r'D:\MEY-AN00-root-repro\toolchain\aria2\aria2-1.37.0-win-64bit-build1\aria2c.exe'
PY = sys.executable

os.makedirs(BASE, exist_ok=True)
manifest = json.load(open(MANIFEST))

def log(s):
    print(f'[{time.strftime("%H:%M:%S")}] {s}', flush=True)

# build job list: skip ones already extracted (init sample exists)
jobs = []
for model, entries in manifest.items():
    for e in entries:
        ver = e['ver']
        prefix = f'{model}_{ver}'
        init_p = os.path.join(BASE, model, str(ver), f'{prefix}_init')
        if os.path.exists(init_p):
            log(f'skip {prefix} (already extracted)')
            continue
        jobs.append((model, ver, e['url']))
log(f'total jobs to process: {len(jobs)}')

def process(job):
    model, ver, url = job
    prefix = f'{model}_{ver}'
    wd = os.path.join(BASE, model, str(ver))
    os.makedirs(wd, exist_ok=True)
    zip_path = os.path.join(wd, 'fw.zip')
    try:
        if not os.path.exists(zip_path) or os.path.getsize(zip_path) < 1024*1024*1024:
            subprocess.run([ARIA, '-x', '16', '-s', '16', '-k', '1M', '--check-certificate=false',
                            '-d', wd, '-o', 'fw.zip', url], capture_output=True, timeout=3600)
        if not os.path.exists(zip_path) or os.path.getsize(zip_path) < 1024*1024*1024:
            return (prefix, 'DOWNLOAD_FAIL')
        r = subprocess.run([PY, os.path.join(SCRIPTS, 'fw_extract.py'), zip_path, wd, prefix],
                           capture_output=True, text=True)
        init_p = os.path.join(wd, f'{prefix}_init')
        if not os.path.exists(init_p):
            return (prefix, 'EXTRACT_FAIL')
        return (prefix, 'OK')
    except Exception as ex:
        return (prefix, f'ERR:{ex}')

# 4 concurrent downloads (each 16 connections = 64 threads total)
with ThreadPoolExecutor(max_workers=4) as pool:
    for prefix, status in pool.map(process, jobs):
        log(f'{prefix}: {status}')

# sequential analysis over all samples
log('=== dual-symbol analysis over all samples ===')
summary = {}
import glob
samples = sorted(glob.glob(os.path.join(BASE, '*', '*', '*_init')))
samples += [r'D:/MEY-AN00-root-repro/firmware_150/init_150',
            r'D:/MEY-AN00-root-repro/firmware_170_dnn/dnn170_init']
a2 = os.path.join(DFW, 'init_analyze2.py')
a2i = os.path.join(DFW, 'init_analyze2_ios.py')
for p in samples:
    label = os.path.basename(p)
    row = {}
    for name, script in [('sentry', a2), ('iosinit', a2i)]:
        r = subprocess.run([PY, script, p, label], capture_output=True, text=True)
        calls = [l for l in (r.stdout or '').splitlines() if 'bl call sites' in l]
        row[name] = calls[0].split(': ')[-1] if calls else '?'
    summary[label] = row
    print(f"{label:26s} sentry={row['sentry']:12s} iosinit={row['iosinit']}", flush=True)

json.dump(summary, open(os.path.join(BASE, 'init_analysis_summary.json'), 'w'), indent=1)
log(f'=== ALL DONE: {len(summary)} init samples analyzed, summary saved ===')
