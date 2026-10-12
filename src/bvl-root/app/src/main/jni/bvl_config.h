#pragma once

/* BVL-AN16 (Honor Magic6 Pro) device profile.
 *
 * Firmware : 10.0.0.175 (C00E175R110P8)
 * Android  : 16 / MagicOS 10.0.0
 * Kernel   : 6.1.157-android14-11-g7d3922fade43  (4K pages, SM8735)
 * KMI      : android14-6.1
 *
 * Exploit vector : CVE-2026-43499 (GhostLock / rt_mutex)
 *   Proven on MEY-AN00 (same SM8735 SoC, 6.6.118, H232-H243). BVL 6.1.157 is
 *   older than the disputed 6.1.175 fix and AOSP common 6.1.177 carries no
 *   43499 fix marker => BVL is unpatched. Verified offsets live in bvl_43499.h
 *   (harvested from the honor-BVL-AN16 target.h, built from BVL boot.img BTF).
 *
 *   CVE-2026-64560 (posix-cpu-timers UAF) is ARCHITECTURALLY DEAD on BVL (H207)
 *   and has been removed from this tree. CVE-2026-43284 (DirtyFrag) is DEAD
 *   (xfrm EACCES / capbnd=0 / MSG_SPLICE_PAGES not backported) - never ref'd.
 *
 * Root payload   : KernelSU-Next KO for android14-6.1
 *   bundled asset: kernelsu-android14-6.1.ko (vermagic 6.1.166-dirty)
 *   NOTE: vermagic must be rewritten to match BVL's release before insmod.
 */
#define BVL_KMI                "android14-6.1"
#define BVL_KERNEL_RELEASE     "6.1.157-android14-11-g7d3922fade43"
#define BVL_KO_ASSET           "kernelsu-android14-6.1.ko"

/* CVE-2026-43284 (DirtyFrag) is DEAD on this device — never referenced. */
