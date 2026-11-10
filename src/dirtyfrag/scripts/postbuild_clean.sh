#!/usr/bin/env bash
# 交付前剥面包屑：mapping.txt / 调试符号 / 中间产物一律不随包走。
# 用法: bash scripts/postbuild_clean.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/app/build/outputs"
QUARANTINE="$ROOT/../obf_private_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$QUARANTINE"

echo "[1/4] 收走 R8 反解表（绝不能随包：10MB 反解表 = 送给逆向者的地图）"
for m in "$OUT"/mapping/*/mapping.txt; do
  [ -f "$m" ] || continue
  cp "$m" "$QUARANTINE/"
  rm -f "$m"
  echo "      moved: $m"
done

echo "[2/4] 清掉 native 调试符号与中间产物"
rm -rf "$OUT/native-debug-symbols" "$ROOT/app/build/intermediates/cmake"/*/obj 2>/dev/null || true
find "$OUT" -name "*.sym" -delete 2>/dev/null || true

echo "[3/4] 校验产物"
APK="$(ls "$OUT"/apk/release/*.apk 2>/dev/null | head -1)"
[ -n "$APK" ] || { echo "      !! 未找到 APK"; exit 1; }
echo "      APK: $APK ($(stat -c%s "$APK") bytes)"

echo "[4/4] 自查：APK 内不得残留反解表/源码"
if unzip -l "$APK" 2>/dev/null | grep -qiE "mapping\.txt|\.java$|\.c$|\.h$"; then
  echo "      !! 发现残留，请检查"; unzip -l "$APK" | grep -iE "mapping\.txt|\.java$|\.c$|\.h$"
else
  echo "      clean"
fi
echo "敏感文件已归档到: $QUARANTINE"
