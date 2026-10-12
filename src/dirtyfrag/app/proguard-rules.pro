# ============================================================
# honor.root 定向 keep
# 原则：只保「被 native 按名查找」和「被清单引用」的类，其余全部交 R8 重命名。
# 旧的通配 keep（-keep class honor.root.** { *; }）已删除——它让 R8 对我们
# 自己的代码零混淆，jadx 打开几乎是 1:1 源码。
# ============================================================

# --- JNI 入口：exp.c 用 FindClass("honor/root/ExploitRunner") + RegisterNatives(n0/n1) ---
-keepclasseswithmembernames,includedescriptorclasses class honor.root.ExploitRunner {
    native <methods>;
}

# --- JNI 回调：exp.c 用 FindClass("honor/root/IReporter") + GetMethodID("report") ---
-keep class honor.root.IReporter
-keepclassmembers class honor.root.IReporter {
    void report(java.lang.String);
}

# --- 清单入口 ---
-keep class honor.root.MainActivity
-keep class honor.root.BootReceiver

# --- ViewBinding 生成类（反射实例化）---
-keep class honor.root.databinding.** { *; }

# 其余（LicenseManager、自定义 View 等）全部允许重命名

# ---------------- 加固选项 ----------------
-overloadaggressively
-allowaccessmodification
-useuniqueclassmembernames
-repackageclasses 'O0o'
-obfuscationdictionary dict/obfuscation.txt
-classobfuscationdictionary dict/class.txt
-packageobfuscationdictionary dict/package.txt

# 抹掉调试信息：堆栈不再暴露行号与源文件名
-renamesourcefileattribute ''
-keepattributes Exceptions,InnerClasses,Signature,Deprecated,*Annotation*,EnclosingMethod

-dontwarn honor.root.**
