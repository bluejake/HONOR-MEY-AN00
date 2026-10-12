# BVL-Root

Independent root project for **Honor Magic6 Pro (BVL-AN16)**, firmware
**10.0.0.175 (C00E175R110P8)**, Android 16 / MagicOS 10.0.0,
kernel **6.1.157-android14-11-g7d3922fade43** (4K pages, SM8735).

> This is a **clean, 43284-free** project. It does NOT contain the DirtyFrag
> (CVE-2026-43284) exploit or any of its assets. The previous `bvl-line`
> attempt (which carried DirtyFrag pollution) was deleted and rebuilt from
> scratch; the now-dead CVE-2026-64560 line was also removed.

## Root strategy

| Component | Status | Notes |
|-----------|--------|-------|
| CVE-2026-43284 (DirtyFrag) | **DEAD on BVL** | xfrm EACCES, capbnd=0, user_ns=no, MSG_SPLICE_PAGES not backported to 6.1. Not used. |
| CVE-2026-43500 (RxRPC) | DEAD | `CONFIG_AF_RXRPC is not set`. |
| CVE-2026-64560 (posix-cpu-timers UAF) | **DEAD (architecturally)** | H207: `flush_signal_handlers` / `do_cpu_nanosleep` / `timer_settime` all hard-bound to `current` ⇒ no cross-process reachability. Removed from tree. |
| CVE-2026-43499 (GhostLock / rt_mutex) | **PRIMARY vector** | Proven on MEY-AN00 (same SM8735 SoC, 6.6.118, H232–H243). BVL 6.1.157 < disputed 6.1.175 fix; AOSP common 6.1.177 has no 43499 fix marker ⇒ BVL unpatched. |
| KernelSU-Next `android14-6.1` KO | **Loader present** | `app/src/main/assets/kernelsu-android14-6.1.ko`. Same KMI as BVL (`android14-6.1`). |

Flow: win the CVE-2026-43499 rt_mutex primitive (futex PI waiter + pselect6
stack-spray trigger; the actual R/W win is ported from the honor-BVL-AN16
reference in Phase 2) → gain root-capable state → `n1` insmods the staged KSU
KO and polls `/proc/modules` for the `kernelsu` marker.

## Reference exploit (prior-known-good)

The decisive asset is **`refs/cve-2026-43499-honor`**: a *compile-complete,
device-generated* CVE-2026-43499 exploit whose `targets/honor-BVL-AN16/target.h`
was produced from the BVL boot.img BTF/kallsyms. It already carries verified
BVL offsets (kernel base `0xffffffc008000000` ⇒ KASLR slide == 0, `INIT_TASK`,
`SELINUX_ENFORCING`, `SECURITY_HOOK_HEADS`, `KMALLOC_CACHES`, `ANON_PIPE_BUF_OPS`,
and verified `rt_mutex_waiter` / `task_struct` layouts). Those offsets have been
harvested into `bvl_43499.h`. Phase 2 ports that reference's staged win
primitive (slide-leak + pipe-buffer physrw + fake-fops CFI staging + cred/selinux
patch) into this APK's JNI harness.

## Project layout

```
app/src/main/java/honor/root/
    ExploitRunner.java   native bridge (n0 license / n1 ksu-load / n7 43499 harness)
    MainActivity.java    minimal UI (run harness / load KSU)
app/src/main/jni/
    exp.c                JNI hub: n0, n1 (KSU loader), n7 (43499 harness)
    bvl_43499.c          CVE-2026-43499 trigger scaffold (waiter+owner+consumer + pselect spray)
    bvl_43499.h          verified BVL 6.1.157 offsets (harvested from honor target.h)
    bvl_config.h         BVL device profile
    reporter.h           simple reporting bridge
    CMakeLists.txt       build (no 43284 / 64560 / libcxx.S / splicehelper)
app/src/main/assets/
    kernelsu-android14-6.1.ko   KSU KO to insmod
```

## Build

NDK r27 (or r29) + CMake. Standard Android Studio / gradle build:

```
./gradlew assembleDebug
```

The native lib `libexp.so` is built from `exp.c` + `bvl_43499.c`.

## What works vs. what's next

**Done / in this tree**
- CVE-2026-43499 **trigger scaffold** (`bvl_43499.c`): futex PI waiter/owner/consumer
  threads, `FUTEX_CMP_REQUEUE_PI` routing, pselect6 stack-spray canvas — faithfully
  ported from the proven honor `main.c`. SAFE to run as a diagnostic (corruption
  fire gated behind `BVL43499_UNSAFE_FIRE`, off by default).
- **Verified BVL offsets** harvested into `bvl_43499.h` (no more guessed [CALIB]).
- Direct KSU loader `n1`: insmod staged KO + poll `/proc/modules` + optional `ksud late-load`.
- Clean JNI registration (n0 / n1 / n7), no DirtyFrag / 64560 code, no OBF/asset-encryption coupling.

**Phase 2 (not yet wired — the actual root)**
1. **Win primitive port**: bring the honor-BVL-AN16 reference's staged chain
   (`slide.c` KASLR slide-leak via ashmem/configfs, `pipe.c` pipe-buffer physrw,
   `fops.c` fake-fops CFI staging, `root.c` cred/selinux patch) into `bvl_43499.c`,
   behind a controlled stack layout. Then `BVL43499_UNSAFE_FIRE` becomes the real
   escalation, not a panic.
2. **KSU KO vermagic**: bundled KO vermagic is `6.1.166-dirty`; BVL's is
   `6.1.157-android14-11-...`. `MODVERSIONS` `same_magic` compares the KMI suffix,
   so a vermagic rewrite (or a KO built against BVL's exact tree) is required
   before `insmod` succeeds. Add a small patcher or rebuild the KO.
3. **Hardening** (OBF string table, asset encryption, license_kit, R8): the
   DirtyFrag hardening stack is intentionally NOT carried over — re-apply per the
   project "iron-law" only after the exploit chain is verified on-device.
4. **ksud / manager assets**: `ksud` binary + manager APK to be added to
   `assets/` for full KSU supervisor bring-up (optional; `insmod` alone gives
   `/proc/modules` `kernelsu`).
