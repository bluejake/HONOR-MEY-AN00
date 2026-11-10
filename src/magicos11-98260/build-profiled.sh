#!/usr/bin/env bash
# ============================================================
# 编译 profile 驱动版 payload（cve-2026-98260-uid0-profiled）
#
# 与 build.sh 的区别：
#   build.sh          编译「硬编码常量」版，字节级可复现（md5 3e68cb01...）
#   build-profiled.sh 编译「运行时可覆盖」版，启动时读 profile
#
# profile 查找顺序：
#   1) $CVE98260_PROFILE
#   2) /data/local/tmp/98260-profile.conf
#   3) 都没有 -> 使用编译期默认值（与硬编码版行为一致）
#
# 注意：本版**不保证字节级可复现**（多了一个解析器），哈希随编译器版本变化。
#
# 用法： ANDROID_NDK_HOME=/path/to/ndk/27.0.12077973 sh build-profiled.sh [输出路径]
# ============================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/profiled/cve-2026-98260-profiled.c"
OUT="${1:-$HERE/profiled/cve-2026-98260-uid0-profiled}"
API="${ANDROID_API:-35}"

[ -f "$SRC" ] || { echo "[STOP] 缺少源码: $SRC"; exit 1; }
: "${ANDROID_NDK_HOME:?请设置 ANDROID_NDK_HOME 指向 NDK（建议 27.0.12077973）}"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) HOST=windows-x86_64 ;;
    Linux)                 HOST=linux-x86_64 ;;
    Darwin)                HOST=darwin-x86_64 ;;
    *) echo "[STOP] 无法识别宿主平台: $(uname -s)"; exit 1 ;;
esac
BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST/bin"
CC="$BIN/aarch64-linux-android$API-clang"
STRIP="$BIN/llvm-strip"
[ -f "$CC.cmd" ] && CC="$CC.cmd"
[ -f "$STRIP.exe" ] && STRIP="$STRIP.exe"
[ -x "$CC" ] || [ -f "$CC" ] || { echo "[STOP] 找不到编译器: $CC"; exit 1; }

echo "[cc ] $CC"
# 与 build.sh 完全相同的 flags（保证行为一致，只多了解析器代码）
"$CC" -std=gnu11 -O2 -g -static -pthread -D_GNU_SOURCE \
      -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
      "$SRC" -o "$OUT"
"$STRIP" --strip-all "$OUT"

echo "[out] $OUT ($(wc -c < "$OUT") bytes)"
echo "[md5] $(md5sum "$OUT" | awk '{print $1}')"
echo "[sha] $(sha256sum "$OUT" | awk '{print $1}')"
echo
echo "运行前把 profile 放到 /data/local/tmp/98260-profile.conf（或用 CVE98260_PROFILE 指定）。"
echo "日志里出现 \"[prof] ... -> N field(s) applied\" 表示 profile 已生效；"
echo "无该行 = 没找到 profile，走编译期默认值。"
