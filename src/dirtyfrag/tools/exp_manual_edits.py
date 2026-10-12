"""字符串外迁前的手工改造：把文件作用域的字符串常量改成运行时构造。"""
import io, re, sys
p = "app/src/main/jni/exp.c"
s = io.open(p, encoding='utf-8').read()
o = s

# 1) g_methods（含包名签名）: 文件作用域常量数组 -> 运行时填充
s = s.replace('''static const JNINativeMethod g_methods[] = {
    { "n0", "(Lhonor/root/IReporter;[B[BLjava/lang/String;)Z", (void *)n0 },
    { "n1", "(Lhonor/root/IReporter;Ljava/lang/String;II[B[BIIZ)I", (void *)n1 },
};''', 'static JNINativeMethod g_methods[2];')
s = s.replace('''    jclass runner = (*env)->FindClass(env, "honor/root/ExploitRunner");
    if ((*env)->RegisterNatives''', '''    jclass runner = (*env)->FindClass(env, "honor/root/ExploitRunner");
    g_methods[0].name = "n0";
    g_methods[0].signature = "(Lhonor/root/IReporter;[B[BLjava/lang/String;)Z";
    g_methods[0].fnPtr = (void *)n0;
    g_methods[1].name = "n1";
    g_methods[1].signature = "(Lhonor/root/IReporter;Ljava/lang/String;II[B[BIIZ)I";
    g_methods[1].fnPtr = (void *)n1;
    obf_init_runtime();
    obf_fill(kCrashDump, sizeof(kCrashDump), "/apex/com.android.runtime/bin/crash_dump64");
    if ((*env)->RegisterNatives''')

# 2) kCrashDump: 常量数组 -> 运行时填充，并把声明提到 JNI_OnLoad 之前
s = s.replace('static const char kCrashDump[] = "/apex/com.android.runtime/bin/crash_dump64";\n', '')
s = s.replace('static jmethodID report_mid;', 'static jmethodID report_mid;\nstatic char kCrashDump[64];', 1)

# 3) reportfmt 补 va_end
s = s.replace('char buf[1024]; vsnprintf(buf, sizeof(buf), fmt, va);\n    jstring s',
              'char buf[1024]; vsnprintf(buf, sizeof(buf), fmt, va); va_end(va);\n    jstring s')

io.open(p, 'w', encoding='utf-8').write(s)
print("manual edits applied, delta bytes =", len(s) - len(o))
