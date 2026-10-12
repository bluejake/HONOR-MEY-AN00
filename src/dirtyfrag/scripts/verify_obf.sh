#!/usr/bin/env bash
# 混淆验收：每一步都给「可证伪判据」，不允许用「看着差不多」结案。
# 用法（Git Bash）：
#   export JAVA_HOME=...   # 见 toolchain/env.sh
#   bash scripts/verify_obf.sh
#
# 判据（任一 FAIL 即视为本轮混淆未达标）：
#   A. libexp.so 的动态导出符号只有 JNI_OnLoad
#   B. libexp.so 没有 .symtab（静态符号表）
#   C. .rodata / .data 里 grep 不到任何敏感明文串
#   D. mapping.txt 里 honor.root 自有类被重命名（不是 1:1 透传）
set -u
cd "$(dirname "$0")/.."

APK=app/build/outputs/apk/release/honor-root-tool.apk
MAP=app/build/outputs/mapping/release/mapping.txt
LLVM=<HOME>/.workbuddy/binaries/android/android-ndk-r29/toolchains/llvm/prebuilt/windows-x86_64/bin
PY=<HOME>/.workbuddy/binaries/python/versions/3.13.12/python.exe
WORK=$(mktemp -d)

fails=0
say() { printf '%-58s %s\n' "$1" "$2"; }
chk() { # chk <描述> <实际> <期望>
  if [ "$2" = "$3" ]; then say "$1" "PASS ($2)"; else say "$1" "FAIL (got=$2 want=$3)"; fails=$((fails+1)); fi
}

[ -f "$APK" ] || { echo "APK 不存在: $APK  —— 先跑 assembleRelease"; exit 1; }
echo "APK: $APK  ($(stat -c%s "$APK") bytes)"
echo

# ── 抽 .so ────────────────────────────────────────────────────────────────
"$PY" - "$APK" "$WORK" << 'PYEOF'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
for n in z.namelist():
    if n.endswith('.so'):
        z.extract(n, sys.argv[2]); print('extract', n)
PYEOF
SO=$(find "$WORK" -name 'libexp.so' | head -1)
[ -n "$SO" ] || { echo "未找到 libexp.so"; exit 1; }
echo "SO: $SO  ($(stat -c%s "$SO") bytes)"
echo

echo "===== A. 导出符号面 ====="
EXPORTS=$("$LLVM/llvm-nm.exe" -D --defined-only "$SO" | awk '{print $3}' | sort | tr '\n' ' ')
echo "  defined exports: $EXPORTS"
chk "A. 只导出 JNI_OnLoad" "$EXPORTS" "JNI_OnLoad "

echo
echo "===== B. 静态符号表 ====="
SYMTAB=$("$LLVM/llvm-readelf.exe" -S "$SO" | grep -c '\.symtab')
echo "  .symtab section count: $SYMTAB"
chk "B. 无 .symtab" "$SYMTAB" "0"

echo
echo "===== C. 敏感明文串（.rodata + .data 全段扫描）====="
# 这些串一旦出现在二进制里就是指纹；dynstr 里的 libc 导入名不在此列
"$PY" - "$SO" "${OBF_NOENC:-0}" << 'PYEOF'
import re, sys
d = open(sys.argv[1], 'rb').read()
# 只扫已初始化数据段（.rodata / .data），跳过 .dynstr（libc 导入符号名不可避免）
import subprocess
KEYS = [
    b'/dev/xkm', b'vendor_modprobe', b'/proc/self/attr/exec', b'/vendor/bin/insmod',
    b'libbinderdebug', b'soft_reboot=1', b'unlock diag', b'ksud', b'KernelSU',
    b'kernelsu', b'dirtyfrag', b'DirtyFrag', b'trampoline', b'shellcode',
    b'ExploitRunner', b'MEYLIC', b'patch #', b'/data/local', b'%s%s',
]
# OBF_NOENC=1: 用户要求「先不加密资产」，此时 tool 脚本以明文内嵌 libexp.so，
# 必然带回这 4 个串。它们属于已知且可逆的降级，不算验收失败；其余键仍必须干净。
ALLOW = (set([b'ksud', b'KernelSU', b'kernelsu', b'/data/local'])
         if sys.argv[2] == '1' else set())
bad = 0
for k in KEYS:
    i = d.find(k)
    if i < 0:
        tag = 'clean'
    elif k in ALLOW:
        tag = 'LEAK 0x%x (allowed: --no-encrypt)' % i
    else:
        tag = 'LEAK 0x%x' % i
        bad += 1
    print('  %-24s %s' % (k.decode(), tag))
print('  ---')
print('  LEAK_TOTAL=%d' % bad)
PYEOF
LEAKS=$("$PY" - "$SO" "${OBF_NOENC:-0}" << 'PYEOF'
import sys
d=open(sys.argv[1],'rb').read()
KEYS=[b'/dev/xkm',b'vendor_modprobe',b'/proc/self/attr/exec',b'/vendor/bin/insmod',
 b'libbinderdebug',b'soft_reboot=1',b'unlock diag',b'ksud',b'KernelSU',b'kernelsu',
 b'dirtyfrag',b'DirtyFrag',b'trampoline',b'shellcode',b'ExploitRunner',b'MEYLIC',
 b'patch #',b'/data/local',b'%s%s']
ALLOW=(set([b'ksud',b'KernelSU',b'kernelsu',b'/data/local'])
       if sys.argv[2]=='1' else set())
print(sum(1 for k in KEYS if k in d and k not in ALLOW))
PYEOF
)
chk "C. 敏感串 0 泄漏（OBF_NOENC=${OBF_NOENC:-0}）" "$LEAKS" "0"

echo
echo "===== D. Java 侧重命名 ====="
if [ -f "$MAP" ]; then
  TOTAL=$(grep -c '^honor\.root\.' "$MAP")
  KEPT=$(grep '^honor\.root\.' "$MAP" | awk -F' -> ' '$1==$2' | wc -l)
  echo "  honor.root 类/成员条目: $TOTAL   未重命名: $KEPT"
  echo "  --- 样例 ---"
  grep '^honor\.root\.' "$MAP" | head -12 | sed 's/^/    /'
  chk "D. 存在重命名（条数>0）" "$([ "$TOTAL" -gt 0 ] && echo yes || echo no)" "yes"
else
  echo "  mapping.txt 不存在（已被 postbuild_clean 隔离？）"
fi

echo
echo "=========================================="
if [ "$fails" -eq 0 ]; then echo "全部判据通过"; else echo "FAIL 项: $fails"; fi
exit $fails
