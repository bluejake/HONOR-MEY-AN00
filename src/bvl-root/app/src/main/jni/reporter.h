/* Clean reporting bridge (no OBF / no asset encryption — dev build).
 * Mirrors the DirtyFrag reporter semantics without the hardening coupling. */
#pragma once

#include <jni.h>
#include <stdarg.h>
#include <stdio.h>

struct Reporter {
    JNIEnv *env;
    jobject  obj;
};

/* Set once in JNI_OnLoad: the ExploitRunner.report(String) method id. */
extern jmethodID report_mid;

static void reportln(struct Reporter *r, const char *fmt, ...) {
    if (!r || !r->env || !report_mid) return;
    va_list va;
    va_start(va, fmt);
    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    if (n < 0) return;
    if ((size_t)n >= sizeof(buf)) n = (int)sizeof(buf) - 1;
    size_t i = (size_t)n;
    if (i + 1 < sizeof(buf)) { buf[i] = '\n'; buf[i + 1] = 0; }

    jstring s = (*r->env)->NewStringUTF(r->env, buf);
    (*r->env)->CallVoidMethod(r->env, r->obj, report_mid, s);
    (*r->env)->ExceptionClear(r->env);
    (*r->env)->DeleteLocalRef(r->env, s);
}

/* REPORTLN requires a local `struct Reporter *reporter` in scope. */
#define REPORTLN(fmt, ...) reportln(reporter, fmt __VA_OPT__(,) __VA_ARGS__)
