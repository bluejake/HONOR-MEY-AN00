#pragma once
#include <jni.h>

struct Reporter { JNIEnv *env; jobject obj; };

void reportfmt(struct Reporter *r, const char *fmt, ...) __attribute__((__format__(printf, 2, 3)));
/* 运行时追加换行：fmt 现在来自 OBF() 解密结果，无法再做字面量拼接 */
void reportln(struct Reporter *r, const char *fmt, ...) __attribute__((__format__(printf, 2, 3)));
#define REPORTLN(fmt, ...) reportln(reporter, fmt __VA_OPT__(,) __VA_ARGS__)
