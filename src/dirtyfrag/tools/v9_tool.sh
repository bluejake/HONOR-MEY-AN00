#!/system/bin/sh
# SysTool Universal - uid 0 UMH payload: full diagnostics + multi-path KSU load
# v5 (MEY-AN00 patch): allow_shell=1 everywhere (shell su fix), [E] made
#                      conditional on module-absent to avoid tearing a live KO.
# v6 (license build):  [H] silent manager install + [I] module installs.
# v7 (MEY fix):        [I] moved AFTER [D] - DEAD ON ARRIVAL, see v8.
# v8 (MEY fix):        Measured on device (boot ff1bf964): `ksud late-load`
#                      RESTORES SELinux enforcing when it finishes. The UMH
#                      child runs in u:r:kernel, which has no exec/search/
#                      create rights under enforcing (all dontaudit'd - runcon
#                      test: exec sh itself is denied), so EVERYTHING after
#                      [D] silently no-ops. The block's stdout fd is opened at
#                      `{` while still permissive, so LOG1 is the app-readable
#                      $DB/files/tool.log and the app polls it for
#                      KSU_STATE_OK / KSU_STATE_FAIL. VERIFIED on boot
#                      d0a0a663: app reported ***SUCCESS***, su uid=0/u:r:ksu:s0.
# v9 (MEY fix):        (1) USER DECISION: vector is no longer installed -
#                      zygisk-next only. (2) v8's `su ... &` died with
#                      "su: inaccessible or not found": it exec'd BEFORE the
#                      kernelsu KO was loaded, so the KSU sucompat hook (which
#                      fakes /system/bin/su for stat/exec) did not exist yet.
#                      A backgrounded waiter sh polls "KO live AND enforce
#                      still 0" and execs su inside that gap. VERIFIED: the
#                      waiter DID reach su on boot cd7f6f4d.
# v10 (MEY fix):       MEASURED on boot cd7f6f4d: late-load(2) KILLS the
#                      session. ksud late-load on an already-loaded kernel
#                      reloads (rmmod+insmod) the KO; the fresh instance did
#                      not survive (kernelsu absent from /proc/modules,
#                      enforcing back to 1, su "not found" within 3 min, all
#                      with UNCHANGED boot_id - no reboot involved).
#                      late-load(2) is therefore REMOVED. A zygisk-next zip
#                      installed to modules_update is applied automatically by
#                      the FIRST late-load of the NEXT boot; if zygisk-next is
#                      already present the su block is a no-op.
DB=/data/user_de/0/honor.root
LOG1="$DB/files/tool.log"
TMPERR=/data/local/tmp/tool_pw.err
API=$(uname -r | sed -n 's/.*android\([0-9]*\)-.*/\1/p')
KV=$(uname -r | cut -d. -f1-2)
KMI="android${API}-${KV}"
KO="$DB/kernelsu-${KMI}.ko"
# [I-S0] privileged payload, written while still permissive (u:r:kernel has
# create on the app dir only inside that window). su (u:r:ksu:s0) runs it.
cat > "$DB/files/su_block.sh" <<'EOF'
#!/system/bin/sh
DB=/data/user_de/0/honor.root
echo "-- [I] module install via su (ksu domain) --"
if [ -d "/data/adb/modules/zygisksu" ] || [ -d "/data/adb/modules_update/zygisksu" ]; then
  echo "zygisk-next already present (zygisksu), nothing to do"
  exit 0
fi
if [ -f "$DB/zygisk-next.zip" ]; then
  /data/adb/ksu/bin/ksud module install "$DB/zygisk-next.zip" 2>&1
  echo "zygisk-next install rc=$?"
else
  echo "zygisk-next.zip not staged"
fi
# v10: NO second late-load here. Measured on cd7f6f4d it reloads (rmmod+
# insmod) the live KO and loses the session. modules_update is applied by
# the FIRST late-load of the next boot.
echo "su block done (no late-load(2) by design, see v10)"
EOF
# [I-S] window waiter: the sucompat hook exists once the KO is live, and
# enforcing is still 0 until late-load finishes - exec su inside that gap.
sh -c '
  n=0
  while [ $n -lt 300 ]; do
    grep -q kernelsu /proc/modules 2>/dev/null && [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = "0" ] && break
    sleep 0.3
    n=$((n+1))
  done
  grep -q kernelsu /proc/modules 2>/dev/null && exec /system/bin/su -c "sh /data/user_de/0/honor.root/files/su_block.sh"
  echo "waiter timeout: KO never went live"
' > "$DB/files/su_block.log" 2>&1 &
{
  echo "=== tool v10 (MEY patch): KSU late-load + su-waiter module install ==="
  echo "time: $(date) | uname: $(uname -r)"
  echo "kmi: $KMI | ko: $KO"
  echo ""
  echo "-- [A] verdict lens (primary success criteria) --"
  echo "uid0: $(id -u)"
  echo "enforce: $(getenforce 2>&1)"
  if echo tool-protected-write-ok > /data/adb/tool_write_test 2>"$TMPERR"; then
    echo "protected_write: OK"
    rm -f /data/adb/tool_write_test
  else
    echo "protected_write: FAIL ($(cat "$TMPERR" 2>/dev/null))"
  fi
  rm -f "$TMPERR"
  echo ""
  echo "-- [B] staged files --"
  ls -la "$DB" 2>&1
  echo ""
  echo "-- [C] install ksud from staged ksu-daemon --"
  if [ -f "$DB/ksu-daemon" ]; then
    mkdir -p /data/adb/ksu/bin /data/adb/ksu/log
    cp "$DB/ksu-daemon" /data/adb/ksu/bin/ksud
    chmod 755 /data/adb/ksu/bin/ksud
    echo "installed: $(ls -la /data/adb/ksu/bin/ksud 2>&1)"
    md5sum "$DB/ksu-daemon" /data/adb/ksu/bin/ksud 2>&1
  else
    echo "ksu-daemon not staged"
  fi
  echo ""
  echo "-- [H] manager probe (binder-less UMH: expected to fail, app installs it) --"
  if [ -f "$DB/manager.apk" ]; then
    if pm path me.weishu.kernelsu >/dev/null 2>&1; then
      echo "manager already installed, skip"
    else
      pm install -r "$DB/manager.apk" 2>&1
      echo "pm install rc=$? (non-zero is expected here)"
    fi
  else
    echo "manager.apk not staged"
  fi
  echo ""
  echo "-- [D] ksud late-load (--allow-shell: pass allow_shell=1 to insmod) --"
  LDRC=-1
  if [ -x /data/adb/ksu/bin/ksud ]; then
    RUST_LOG=trace /data/adb/ksu/bin/ksud late-load --package-name me.weishu.kernelsu --allow-shell 2>&1
    LDRC=$?
    echo "late-load rc=$LDRC"
  else
    echo "ksud not installed"
    LDRC=127
  fi
  echo ""
  echo "-- [E] fallback insmod (only meaningful if late-load failed AND" \
       "enforcing was never restored by ksud) --"
  if [ "$LDRC" != 0 ]; then
    if [ -f "$KO" ]; then
      if grep -q kernelsu /proc/modules 2>/dev/null; then
        echo "kernelsu already live, skip fallback insmod"
      else
        insmod "$KO" allow_shell=1 2>&1
        echo "raw insmod rc=$? (expected fail if CRC mismatch)"
      fi
    else
      echo "staged KO missing for $KMI"
    fi
  else
    echo "late-load succeeded, fallback not needed"
  fi
  echo ""
  # Success verdict for the app: it polls LOG1 for these lines.
  if [ "$LDRC" = 0 ]; then
    echo "KSU_STATE_OK"
  else
    echo "KSU_STATE_FAIL:$LDRC"
  fi
  echo "=== tool done ==="
} > "$LOG1" 2>&1
exit 0
