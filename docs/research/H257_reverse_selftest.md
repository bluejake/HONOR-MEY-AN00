# H257 · v1.1 APK 攻击者视角逆向自测报告

日期：2026-10-08 · 对象：`releases/honor-root-tool-v1.1-feedback.apk`（md5 48040edd）
工具：aapt2/dexdump/build-tools 35 + llvm-nm/objdump/strings (NDK r27c) + python dex 直读
视角：模拟攻击者拿到 APK 后的完整静态分析流程（无设备、无激活码）

## 1. 攻击者第一眼（元信息层）

| 项 | 攻击者所得 | 评级 |
|---|---|---|
| 包名/版本 | `honor.root` 1.1(2)，label「荣耀提权工具」 | 定性明确：root 工具 |
| 权限 | 仅 INTERNET + RECEIVE_BOOT_COMPLETED + WAKE_LOCK + 自定义权限 | ★ 最小权限面，无迹可循 |
| 组件 | MainActivity / BootReceiver（keep 名单，原名可见） | 仅入口，无逻辑 |

## 2. dex 层（classes.dex 1.2MB）

- **963 个类**全部位于 `LO0o/` 包下，名字为字典混淆（`B0BG9QJ2`/`BBJ91S0S`…），jadx 打开≈天书。
- 字符串池 7,460 条（去重），按敏感度分级实测：

| 级别 | 发现 | 攻击者价值 |
|---|---|---|
| 🔴 中高 | **KSU 装卸 shell 命令串明文**：`rm -rf /data/adb/ksu /data/adb/ksud ...`、`'; rm -f /data/user_de/0/honor.root/ksud`、`ksud staged`、`kernelsu_loaded=`、root probe 命令 `ls -la /data/adb/modules; /data/adb/ksu/bin/ksud -V; ls -l /dev/xkm*` | 暴露「本工具 = KernelSU 装载器」+ 落盘路径。KernelSU 本身公开，但这是行为指纹 |
| 🟡 低 | `/proc/modules`、`/proc/sys/kernel/random/boot_id` | root 判活逻辑，功能必需 |
| 🟡 低 | `/data/misc/profiles/...` | ART baseline profile 标准件（AGP 生成），非我方逻辑 |
| 🟢 零 | URL/域名/webhook/企微、密钥/证书/HKDF、CVE 号、内核符号 | **零命中** |

- 混淆确认：`honor.root.FeedbackSender -> O0o.qzQ0G`（mapping.txt）；保留原名者均为 keep 名单（JNI 入口/清单组件/XML 引用 View）。

## 3. native 层（lib/arm64-v8a/libexp.so）

| 项 | 实测 | 评级 |
|---|---|---|
| 导出符号 | **仅 `JNI_OnLoad`** —— 动态注册使 n0/n1 不进符号表 | ★ 隐藏生效 |
| 🔴 路标串 | **`vmsplice`、`splice`** 两个 syscall 名明文躺在 .rodata | 最强单点线索：指向 splice 类内核路径。离复现 CVE 仍极远（无偏移/无结构/无触发逻辑），但对专业攻击者是高质量方向标 |
| 🟡 生态串 | `me.bmax.apatch`（竞品包名）、`/dev/xkm`（KSU 设备节点） | 暴露与 root 生态关联 |
| 🟡 行为指纹 | 导入表 `socket/bind/connect + fork/execl/dup2 + fopen/open/read` | 攻击者可推断「native 联网+起进程+读文件」；消除需 inline syscall（P3 大工程） |
| 🟢 内核符号 | esp_input/rb_erase/init_cred/commit_creds 等 | **零命中** |
| 🟢 命令串 | insmod/rmmod/mount/setenforce | 零命中（UMH 脚本全在加密资产内） |

## 4. 资源层（resources.arsc）

全为 Material 库标准串（Cancel/Loading/路径数据）+ 我方中文 UI 串（用户可见文案，保留合理）。**零逻辑泄露**。

## 5. assets 层

| 文件 | 状态 |
|---|---|
| O0l0O/O0l1O/O101O/O110O/O11OO/Ol00O/Ol01O/Ol10O/Ol1lO/Oll0O/O1l0O/payload.bin | 全密文（ASSET_MAGIC/DFENCRT10 头验证）——7 KO + daemon + UMH + webhook 配置 |
| manager.apk / zygisk-next.zip | 明文 = KernelSU Manager / Zygisk Next **开源原件**，非我方信息 |

## 6. 结论：攻击者能拼出 vs 拿不到

**能拼出的故事**：「中文 root 工具，装/卸 KernelSU（有具体路径与命令），native 层疑似用 splice 类 syscall 做内核动作，激活码保护其资产（结构不可见），有企微反馈通道（内容加密不可见）。」

**拿不到**：漏洞具体原理（无 43284/ESP/skb 痕迹）、KO 任何字节、UMH 脚本、webhook key、激活体系结构、设备绑定方式。

**判据**：本报告所有「零命中」均可复现——对 APK 任一文件跑上述模式串即验。

## 7. 修复建议（按性价比）

1. **P0·native 串 OBF 补漏**：`vmsplice`/`splice`/`me.bmax.apatch`/`/dev/xkm` 四串过 OBF 宏（工程量小，收益最大）
2. **P0·dex 串 OBF**：KSU 装卸命令串改运行时解密（拼装自加密资产或 OBF 表）
3. P2·导入表行为指纹：inline syscall 直调（工程大，建议评估后再做）
4. 保留现状：/proc/modules、boot_id、中文 UI 串（功能必需）
