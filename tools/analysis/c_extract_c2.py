#!/usr/bin/env python3
"""C 线续：从 update_sd_base.zip 按需提取镜像（2026-10-04 第二轮）

用法：
  python c_extract_c2.py <entry1> [entry2 ...]
  例： python c_extract_c2.py image/system_ext.img image/keymint.mbn

输出到 analysis/output/c_line/image/
"""
import os
import sys
import zipfile

ROOT = r"D:\MEY-AN00-root-repro"
ZIP = os.path.join(ROOT, "analysis", "output", "c_line", "update_sd_base.zip")
OUTDIR = os.path.join(ROOT, "analysis", "output", "c_line", "image")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    os.makedirs(OUTDIR, exist_ok=True)
    z = zipfile.ZipFile(ZIP)
    names = set(z.namelist())
    for arg in sys.argv[1:]:
        # 允许省略 image/ 前缀
        cand = [arg, "image/" + arg]
        entry = next((c for c in cand if c in names), None)
        if entry is None:
            print(f"[MISS] {arg}  (候选: {cand})")
            continue
        info = z.getinfo(entry)
        out = os.path.join(OUTDIR, os.path.basename(entry))
        if os.path.exists(out) and os.path.getsize(out) == info.file_size:
            print(f"[SKIP] {entry} 已存在 ({info.file_size:,} B)")
            continue
        print(f"[EXTRACT] {entry}  {info.file_size:,} B -> {out}")
        with z.open(entry) as src, open(out, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                dst.write(chunk)
        got = os.path.getsize(out)
        print(f"  done: {got:,} B  match={got == info.file_size}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
