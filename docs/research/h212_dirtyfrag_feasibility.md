# H212 · CVE-2026-43284（DirtyFrag）对 MEY-AN00 的可行性判定

> 日期：2026-10-06 · 设备：MEY-AN00（Honor 500，Android 16，`ro.board.platform=sun`）
> 内核：`6.6.118-android15-8-gf17133276a57-abogki518694926-4k` · BL 锁定 · shell uid 2000
> 本轮 boot 消耗：**0**（全部为只读探针 + 本地反汇编/符号审计）
> 当前 boot_id：`29f3e5f1-4c62-4f63-bd54-8bc5bc771a1a`（设备在本轮会话前已重启，旧 `ba30251b` 已失效）

---

## 0. 结论

**GREEN —— 静态可查的全部前置条件在本机均满足。**

DirtyFrag（`woshigenm/DirtyFrag` fork，血缘：V4bel/dirtyfrag 原版 + DFRoot + polygraphene/DFReroot + combeng6th/DirtyInit）是本项目当前**唯一**同时具备「完整工具链（含 android15-6.6 预编译件）、确定性触发、失败不 panic、页缓存污染重启即清」的提权线。项目三条成功判据由链路设计直接覆盖：uid==0（init/KO/UMH 全程）、`getenforce` Permissive（KO 写 `selinux_state=false`）、受保护写成功（uid 0 后任意）。

| 环节 | 置信度 |
|---|---|
| 漏洞在本机内核成立（sink 未修复） | ★ **汇编已证**（esp6_input 反汇编） |
| 环境前提（符号/文件/标签/域） | ★ **实测**（设备探针 + kallsyms + 本地镜像） |
| 端到端提权 | **待实测**（需安装 APK 运行一发） |

---

## 1. CVE-2026-43284 要点

| 项 | 值 |
|---|---|
| 根因 | `MSG_SPLICE_PAGES` 把管道页挂进 UDP skb 时漏设 `SKBFL_SHARED_FRAG`；ESP input 对「未克隆非线性 skb」走无 COW 快路径，**AES-CBC 原地解密直接写进页缓存页** |
| 原语 | `IV = AES_ECB_DEC(key, current_content) ⊕ desired_content` ⇒ 对 16 字节对齐页缓存块的任意改写（无需写权限、无 COW） |
| 引入 | v6.5（commit 7da0dde68486）；更早内核走 splice 旧路径变体 |
| 修复 | mainline `f4c50a4034e6`；6.6 stable 修复于 **6.6.138** |
| **本机** | **6.6.118 < 6.6.138 ⇒ 在受影响窗口内** |
| 特性 | 确定性逻辑漏洞、无竞态、**失败不 panic**、成功率极高（V4bel 自述）；污染靠 `drop_caches`/重启清除 |
| KMI 实测 | DirtyFrag 矩阵 `android15-6.6 = verified`；`android14-6.1` 才是意外缓解（V4bel issue 23） |

---

## 2. 本机证据表

### 2.1 内核侧

| # | 项 | 结果 | 依据与标注 |
|---|---|---|---|
| K1 | esp6_input 快路径判定 | 仅 `skb->data_len`(d970) 与 `shinfo->frag_list`(d988) 两个条件；**无 `shinfo->flags`（SHARED_FRAG 位）的加载与测试**；非线性无 frag_list → db40 → 读 `shinfo->nr_frags` 直接进 aead 原地解密构造 | ★ **汇编已证**：`dis_mey.py` @`0xffffffc08101d8bc`，关键块 d970-d988、db40；`skb_cow_data`(0xffffffc0806cd878) 仅 frag_list 非空才调用 |
| K2 | ESP 子系统内建 | `esp4_init`+`__initcall__kmod_esp4`（v4 内建）、`esp6_input/output_head`（v6 内建）、`xfrm_user_rcv_msg`、506 个 xfrm 符号 | ★ 实测（kallsyms） |
| K3 | KO 所需内核符号 | `selinux_state`、`register_kprobe`、`kallsyms_lookup_name`、`call_usermodehelper_setup`、`call_usermodehelper_exec` 全部存在 | ★ 实测（kallsyms） |
| K4 | DEFEX | `task_defex_enforce` / `task_defex_user_exec` / 任何 `defex` 变体 **0 命中** ⇒ 本机无 Samsung 式 DEFEX；KO 的两个 defex kprobe 会 `pr_err` 后继续，**不阻塞** | ★ 实测（kallsyms 全量 grep） |
| K5 | XFRM 活跃 | `/proc/net/xfrm_stat` shell 可读 | ★ 实测（设备） |

### 2.2 设备/文件侧（全部 ★ 实测）

| # | 项 | 结果 |
|---|---|---|
| D1 | crash_dump64 | `/apex/com.android.runtime/bin/crash_dump64` **存在**，533,112 B，标签 `u:object_r:crash_dump_exec:s0` —— 与 fork 常量 `kCrashDump` **逐字一致** |
| D2 | hook 目标 | `/system/lib64/libc++.so` 存在（1,049,704 B）；hook 符号 `_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_` 在动态符号表 **@ 0xa89f8**（llvm-nm -D，已拉回 `analysis/scratch/libcpp_mey.so`） |
| D3 | vendor KO 目标 | 三候选全在 vendor.img：`lib64/libbinderdebug.so` **86,656 B**（Java 首选）、`lib64/libstagefright_aidl_bufferpool2.so` 186,312 B、`lib64/libstagefrighthw.so` 51,632 B；KO 仅 7,896 B ⇒ 容量充足（shell ls 因 vendor_file SELinux 显示 EACCES，存在性以本地 EROFS 清单为准） |
| D4 | insmod | `/vendor/bin/insmod → toybox_vendor` 存在 |
| D5 | 平台身份 | `ro.board.platform=sun`、Android 16 —— **记忆中「SM8735」作废** |

### 2.3 仓库侧（仓库事实，`analysis/scratch/DirtyFrag/`）

| # | 项 | 结果 |
|---|---|---|
| R1 | 预编译件 | 自带 `android15-6.6` 全套：`dirtyfrag-android15-6.6.ko`（7,896 B）+ `kernelsu-android15-6.6.ko`（316,224 B）+ `ksu-daemon`（6.3 MB）+ `dfsh` 脚本；KO 按 `uname`（android15 + 6.6）自动选型，本机命中 |
| R2 | vermagic | `6.6.127-4k-g46a034eca005-dirty SMP preempt mod_unload modversions aarch64` —— 版本串不同但 **modversions 模式内核做 flags-only 比对**（H211 已证），flags 与本机 GKI 一致 ⇒ 可过；残余风险 = 符号 CRC 变化（见 §4） |
| R3 | UMH 命令 | KO 内嵌确认：`/system/bin/sh -c "/data/user_de/0/df.root/dfsh late-load --package-name me.weishu.kernelsu --ro-partitions && touch /dev/dfm0 || touch /dev/dfm1"` —— 包名硬编码 `df.root`，与 app 的 device-protected staging 路径一致 |
| R4 | 构建入口 | `build.sh` → `gradlew :app:assembleRelease`；keystore 及口令公开在仓库内（commit 明言），可本地出 APK |

---

## 3. 链路全图（fork 实现）

| 步 | 动作 | 域/上下文 |
|---|---|---|
| 1 | app 经 `IpSecManager` 建 UdpEncapsulationSocket + SPI + AES-CBC/HMAC-SHA256(128b) transport（127.0.0.1，IPv4） | untrusted_app → system_server 代做 xfrm_user |
| 2 | CVE 原语一发 16B 写：`splice(file)→pipe→vmsplice(hdr+ICV)→splice(pipe→UDP encap sock)`，内核 ESP input 原地解密写页缓存 | untrusted_app |
| 3 | patch#1：splicehelper 覆盖 crash_dump64 页缓存（系统文件直 splice，`pread` 校验落地） | untrusted_app |
| 4 | exec crash_dump64 → **crash_dump 域**跑 splicehelper（可读 vendor_file） | crash_dump |
| 5 | patch#2：经 bridge 把 dirtyfrag.ko 写进 `/vendor/lib64/libbinderdebug.so` 页缓存（写前先经 bridge 读原内容算 IV） | crash_dump |
| 6 | hook `/system/lib64/libc++.so`：shellcode 写入空白区 + `ostream::sentry` 处 B 跳板 | untrusted_app |
| 7 | `createOrphanProcess` 双 fork → 孤儿被 init 收割 → **init (uid=0, tid=1)** 走到被 hook 符号 | init |
| 8 | shellcode：验 uid/tid → `/dev/df` 一次性互斥 → worker 写 `/proc/self/attr/exec = u:r:vendor_modprobe:s0` → exec `/vendor/bin/insmod /vendor/lib64/libbinderdebug.so` | vendor_modprobe, uid 0 |
| 9 | KO init：`selinux_state=false`（**全局 Permissive**）→ defex kprobe（本机无符号，跳过）→ UMH `sh -c dfsh ...` → 返回 `-E2BIG` 自卸载 | kernel 上下文，uid 0 |
| 10 | dfsh（uid 0）：诊断 + KSU 装载 + **任意我们的命令**；marker `/dev/dfm0/1` | uid 0（kernel UMH） |
| 11 | 清理：恢复 libc++.so 跳板/壳码页缓存 + `fadvise_drop(crash_dump64)` | untrusted_app |

---

## 4. 已识别风险与对策

| 风险 | 等级 | 说明与对策 |
|---|---|---|
| **dfsh v3 版本偏移** | 高（只影响 KSU 段） | assets/dfsh 调 `/data/adb/ksu/bin/ksud`（新设备不存在）且恒 `exit 0`（dfm0 标记失真）。⇒ **自建 APK 必改 dfsh**：先 `mkdir -p /data/adb/ksu/bin && cp $DB/ksu-daemon /data/adb/ksu/bin/ksud` 再 late-load；或首跑先纯诊断（uid-0 窗口本身已足够研究红利） |
| KO 符号 CRC | 低-中 | KO 构建于 6.6.127 GKI，本机 6.6.118；modversions CRC 若有符号变化 → insmod 报 "disagrees about version"。兜底：用本机源码树自建 KO（改符号名沿用 BVL 23 字节适配法） |
| init 是否调用 ostream::sentry | 低 | 同族 Honor（YLP-W00，6.12）fork 实测通过；运行时以 `/dev/df` marker 观察 |
| untrusted_app→IpSecService / crash_dump 读 vendor_file | 低 | AOSP 标准 sepolicy；Samsung + Honor 多机型已验证；失败在 patch#1/#2 日志即暴露 |
| 页缓存污染 | 低 | 失败不 panic；cleanup 自动恢复 libc++.so 与 crash_dump64；残余污染重启即清 |

---

## 5. 与 dc15 包 / CVE-2026-43499 的关系（本轮前半段成果）

1. **dc15 包（`<HOME>/WorkBuddy/2026-09-26-09-04-37/dc15_repro/`）与本机为同一内核二进制**：`/proc/version` 逐字一致（含构建时间戳 `Sun May 31 12:01:53 UTC 2026`），kallsyms 13 符号点查全中（`__arm64_sys_futex@0x119ad8`、`futex_wait_requeue_pi@0x958e1c`、`rt_mutex_adjust_pi@0x1081438`、`worker_thread+0x17c=0x185864`、`random_table@0x229af90`、`__arm64_sys_rt_sigreturn@0x49b2e4` 等）。
2. 其 MEP-AN00 交接文档（984 行，2026-09-22~23 实测时间线）记录：fpsimd 偏移修正 0x120 后 **sigreturn 510B 种植确证落地悬垂槽**（blanket=120 闸门匹配 ⇒ 存活）、**伪造 waiter 被 PI walk 完整安全穿越**（TABLE 形存活）；卡点仅在写原语的「结果侧验证」（CFI 读回不可信）。
3. 这与本会话 H209/H210 的「43499 全线闭合」正面冲突：
   - H209 的「全树无消费者」扫描只看 syscall 入口对栈字节的**直接读**——PI walk 经 `task->pi_blocked_on` 悬垂指针的**链式解引用消费**在该口径下结构性不可见；
   - H210 路线 S 的 W0∈{0x230,0x280} 账本与实证悬垂几何（requeue_pi EDEADLK 回滚，word0 @ depth **0x1b0**，[0x148,0x1b0]）不符，疑似建错了悬垂形成路径。
4. ⇒ **43499 判定由「全线闭合」降级为「待对账」**。对账有科学价值（同二进制、可复用其 fault 通道 log.db 与判据），但工程优先级让位 DirtyFrag（确定性 vs 25-30% 概率 + panic 赌博）。

---

## 6. 下一步（按序）

1. **自建 APK**：`build.sh`（gradle assembleRelease，keystore 公开）+ 修补 `assets/dfsh`（加 ksud 安装步；或首跑保持诊断模式直接产 dfsh.log）。
2. `adb install` → 点运行 → 观察报告输出、`/dev/df*` markers、`/data/local/tmp/dfsh.log`。
3. **判据核验**（dfsh 内置）：`id -u` == 0、`getenforce` == Permissive、受保护写（如写 `/data/adb/`）。
4. **研究红利**：uid-0 窗口内抓 kallsyms 全量、dmesg、root-only 采样，喂回本项目基线与 H209/H210 对账。
5. KSU 段修补后做持久化（每 boot 重打 / autorun）。
6. 纪律不变：失败不 panic ⇒ 不受「一 boot 一发」硬约束，但每次运行后建议重启清页缓存；所有运行时结论仍以 `boot_id` + `history.log` 独立透镜记录。

---

## 附：本轮产物路径

- 仓库克隆：`D:/MEY-AN00-root-repro/analysis/scratch/DirtyFrag/`
- 本机 libc++.so：`D:/MEY-AN00-root-repro/analysis/scratch/libcpp_mey.so`
- dc15 包源码展开：`<HOME>/WorkBuddy/2026-09-26-09-04-37/dc15_repro/src/`（105 文件）+ 三份交接 md
- 反汇编证据：`dis_mey.py ffffffc08101d8bc`（esp6_input，0x500B）、`dis_mey.py ffffffc08101db40`（db40 快路径）
