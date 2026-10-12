cmake_minimum_required(VERSION 3.22)
project(exp C)

# Clean BVL-Root native lib. NO DirtyFrag / 43284 sources:
#   - no df_cli.c / df_probe_jni.c / dirtyfrag.h / splicehelper
#   - no libcxx.S (43284 shellcode) / asm_str.c (43284 asm-string fill)
#   - no exp_cli / dfprobe standalone targets
add_library(exp SHARED
    exp.c
    bvl_43499.c)

find_library(log-lib log)
target_link_libraries(exp ${log-lib})

# CVE-2026-64560 (posix-cpu-timers UAF) is architecturally dead on BVL (H207)
# and has been REMOVED from this tree: race64560_jni.c and bvl_64560_race.c
# are deleted. The 43499 harness (bvl_43499.c) replaces them.
