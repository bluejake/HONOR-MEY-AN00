#!/usr/bin/env bash
# ============================================================
# 复现编译 cve-2026-98260-uid0（字节级可复现，2026-11-07 实测）
#
# 实测结论：
#   NDK 27.0.12077973 (r27)  -> md5 3e68cb01...  ✅ 与现役 payload 逐字节相同
#   NDK 27.2.12479018 (r27c) -> md5 4a5849d4...  ❌ 仅 6 字节差异，
#                              全是 .note.android.ident 里的 NDK 版本串
#                              (r27 / 12077973 vs r27c / 12479018)，代码零差异
#   => 必须锁定 NDK 27.0.12077973，写 "r27+" 会得到不同产物。
#
# 用法： ANDROID_NDK_HOME=/path/to/ndk/27.0.12077973 sh build.sh
# 产物： 本目录 cve-2026-98260-uid0.rebuilt（不覆盖现役 payload）
# ============================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/upstream/cve-2026-98260.c"
OUT="${1:-$HERE/cve-2026-98260-uid0.rebuilt}"
API="${ANDROID_API:-35}"
WANT_MD5="3e68cb01fba10447b0a34361b1326fac"
WANT_SHA256="7842ea6a96285f4ca3275776a9306f08b8c9404fb1eb99dd4cafcf362537ec80"

[ -f "$SRC" ] || { echo "[STOP] 缺少源码: $SRC"; exit 1; }
: "${ANDROID_NDK_HOME:?请设置 ANDROID_NDK_HOME 指向 NDK 27.0.12077973}"

# 版本核对（本机实测：版本串会进入 ELF note，直接影响 md5）
REV=""
if [ -f "$ANDROID_NDK_HOME/source.properties" ]; then
    REV="$(sed -n 's/^Pkg.Revision[[:space:]]*=[[:space:]]*//p' "$ANDROID_NDK_HOME/source.properties" | tr -d '\r')"
fi
echo "[ndk] Pkg.Revision = ${REV:-unknown}"
if [ -n "$REV" ] && [ "$REV" != "27.0.12077973" ]; then
    echo "[WARN] 当前 NDK 不是 27.0.12077973，产物 md5 将不匹配（仅 NDK 版本串不同，代码等价）。"
fi

# 上游 build.sh 只判断 linux/darwin；这里补 Windows（Git Bash / MSYS）
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) HOST=windows-x86_64 ;;
    Linux)                 HOST=linux-x86_64 ;;
    Darwin)                HOST=darwin-x86_64 ;;
    *) echo "[STOP] 无法识别宿主平台: $(uname -s)"; exit 1 ;;
esac
BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST/bin"
CC="$BIN/aarch64-linux-android$API-clang"
STRIP="$BIN/llvm-strip"
[ -f "$STRIP.exe" ] && STRIP="$STRIP.exe"
[ -x "$CC" ] || [ -f "$CC" ] || { echo "[STOP] 找不到编译器: $CC"; exit 1; }

echo "[cc ] $CC"
# 与上游 build.sh 完全一致的 flags（含 -pthread / -D_GNU_SOURCE / -g，strip 会去掉调试段）
"$CC" -std=gnu11 -O2 -g -static -pthread -D_GNU_SOURCE \
      -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
      "$SRC" -o "$OUT"
"$STRIP" --strip-all "$OUT"

GOT_MD5="$(md5sum "$OUT" | awk '{print $1}')"
GOT_SHA="$(sha256sum "$OUT" | awk '{print $1}')"
echo "[out] $OUT ($(wc -c < "$OUT") bytes)"
echo "[md5] $GOT_MD5"
echo "[sha] $GOT_SHA"
if [ "$GOT_MD5" = "$WANT_MD5" ] && [ "$GOT_SHA" = "$WANT_SHA256" ]; then
    echo "[OK ] 字节级可复现：与现役 payload 完全一致。"
else
    echo "[WARN] 哈希不匹配。最常见原因 = NDK 版本不是 27.0.12077973；"
    echo "       换版本只改 .note.android.ident 的版本串，代码体不受影响。"
    echo "       可证伪判据：cmp -l 现役产物与本产物，差异应仅落在偏移 652-720。"
fi
