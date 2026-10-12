# H253 · MagicOS 11 升级裁决：能否回滚 / 漏洞是否被修

**日期**：2026-10-08
**设备**：MEY-AN00（Honor 500）· `sun` · Android 16 (SDK 36) · 序列 `A22C026319001339`
**当前系统**：`MEY-AN00 10.0.0.175(C00E170R201P2)` · 内核 `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` · slot `_b` · `ro.boot.flash.locked=1`
**推送目标**：`MEY-AN00 11.0.0.109(SP8C00E109R201P1)` · `update_base.zip` 3,292,135,379 B · versionId `920846`

---

## 0. 结论速览

| 问题 | 结论 | 强度 |
|---|---|---|
| **升级后能自助回滚吗？** | **不能**。BL 锁死无 fastboot；两槽内容完全相同（无旧固件可退）；官方仅支持"服务中心 + 上一大版本最新正式版 + 清空数据" | `[已实测]`+官方政策 |
| ARB 会拦降级吗？ | **不会**。设备 20 个 vbmeta + 包内 12 个 vbmeta 的 `rollback_index` **全为 0**，本次更新也未抬高 | `[已实测]` |
| **DirtyFrag（CVE-2026-43284）还能用吗？** | **不能，已被修**。`esp_input()`/`esp6_input()` 加了 `!skb_has_shared_frag(skb)` 守卫 | `[汇编已证]`+`[源码对账]` ★★★★★ |
| **rt_mutex（CVE-2026-43499）还能用吗？** | **不能，已被修**。`remove_waiter()` 从 `current` 改为 `waiter->task` | `[汇编已证]`+`[源码对账]` ★★★★★ |
| CVE-2026-64560 被修了吗？ | **没有**。`release_task()` 指令级等价（382→382 条，仅 1 处 rodata 页偏移变化） | `[汇编已证]` ★★★★☆ |
| 升级后内核变成 6.6.12x 了吗？ | **没有，仍是 6.6.118**，但是**全量重建**（build id 变、80.53% 字节不同） | `[已实测]` ★★★★★ |
| 现成 KO 升级后还能 insmod 吗？ | **不能**。vermagic 含 SCM 串，逐 build 绑定；须原地改写 vermagic（等长，可行） | `[汇编已证]` ★★★★★ |
| 当前 root 状态 | **已失效**。boot `cd7f6f4d` 下 `/proc/modules` 无 `kernelsu`、`/system/bin/su` 不存在 ⇒ **root 是"每次重启要重跑"的易失态** | `[已实测]` |

**一句话**：**升级 = 永久失去目前唯一可用的 root 原语，且没有任何自助回滚通道。**

---

## 1. 升级包是什么（离线取证）

`/data/user_de/0/com.hihonor.ouc/databases/hnouc.db` 的 `firmwares` 表（3 行）：

| 包 | 类型 | 大小 | versionId | md5 | fw_state |
|---|---|---|---|---|---|
| `update_base.zip` | 13 (BASE) | 3.29 GB | 920846 | `A504D71964AFC4DDD7085E8466FEEE620AE595767C48D13B60CA29F97C3A3D94` | 0 |
| CUST | 14 | 55.97 kB | 909318 | `B89506F44C7DC8EA633F2801A3F09C19F97457F8BC7A76A7B2988071646E59CA` | 0 |
| PRELOAD | 15 | 448 kB | 909334 | `48969AA8195BB771B94C36CE1C32D769FE719183537C5B3051763BF3D8020194` | 0 |

- URL：`http://update-mobile.hihonorcdn.com/TDS/data/bl/files/v920846/f1/full/update_base.zip`（HTTP 200 + `Accept-Ranges: bytes`）
- **VAB 参数**：`fw_vab_switch_slot_on_reboot=1`、`fw_vab_power_wash=0`（**不清数据**）、`fw_vab_cow_size=12,606,148,608`（约 12.6 GB COW 空间）
- `fw_state=0` ⇒ 用户侧**尚未下载/执行**本次更新
- 包内 `VERSION.mbn` = `MEY-LGRP1-CHN 11.0.0.109(SP8)`；`SOFTWARE_VER.mbn` = `base_version:MEY-LGRP1-CHN 11.0.0.109`

**重要订正**：联网资料称 "MagicOS 11 = Android 17 / GKI 6.12"。**对本机不成立** —— 我们从包内 `payload.bin` 重建出的新内核仍是 **6.6.118**（详见 §3）。Android 17 的说法应属其它机型/其它批次。

---

## 2. 问题一：升级后能否回滚

### 2.1 ARB（防回滚）没有启用，也没有被抬高 —— 但这不构成回滚通道

| 对象 | 数量 | `rollback_index` | `flags` | 来源 |
|---|---|---|---|---|
| 设备上 `vbmeta*` 分区 | 20 | **全部 0** | 全部 0x0 | `dd` 读 20 个分区首 4 KB，AVB 头大端解析 |
| 包内 `vbmeta_*` | 12 | **全部 0** | 全部 0x0 | 从 OTA payload 绝对 op 重建 |

⇒ 结论：**AVB 不会阻止降级**；但"不阻止" ≠ "有通道"。
（附带事实：包内 vbmeta 由 `avbtool 1.4.0` 生成，设备上是 `1.3.0`）

### 2.2 设备上没有可退回的旧固件

`boot_a` 与 `boot_b` **md5 完全相同**（`c905734e3412452fbb19a59b3a3877c1`），`vendor_boot_a == vendor_boot_b == dac404c10af2e7c6a4bba4a9c27dbaa8`。
⇒ 本机**从未做过 A/B 切槽**，两个槽都是同一套 10.0.0.175。

### 2.3 三条自助回滚路径全部堵死

| 路径 | 状态 |
|---|---|
| fastboot 刷回旧镜像 | ✗ `ro.boot.flash.locked=1`（BL 锁死）；`verifiedbootstate=green`、`veritymode=enforcing` |
| 引导另一槽的旧系统 | ✗ 另一槽内容 == 当前槽，且切槽需 bootloader 命令（同上锁死） |
| 本地降级包（`*#*#2846579#*#*` 工程菜单/sd 卡升级） | ✗ 荣耀不提供 OTA 降级包；官方仅"服务中心回退到上一大版本最新正式版"，**且会清除全部数据** |

**关于升级后的槽位**（`[源码推断未验证]`）：`fw_vab_switch_slot_on_reboot=1` 表明更新会写入**非活动槽**并在重启后切过去，因此升级完成后**升级前的镜像很可能仍留在届时非活动的 B 槽**。但这**依旧不构成可用回滚**：引导槽由 bootloader 决定，无 fastboot 就无法切回；也没有官方降级包。

### 2.4 小结
> **升级后无法自助回滚。**唯一理论出口是荣耀服务中心（上一大版本最新正式版 + 清数据 + 需到店确认）。升级前请假定"单向、不可逆"。

---

## 3. 问题二：漏洞是否被修（核心）

### 3.1 方法（可复现）

1. 通过 HTTP Range 从 CDN 按需取 `update_base.zip` 中的 `payload.bin` 片段（包 3.29 GB，`payload.bin` 未压缩、STORED）；
2. 手写 `update_engine` payload 解析器（`CrAU`，大端），取 `boot` 分区的 75 个 install op；
3. 以设备现有 `boot_b` 为源，套用 `BSDF2`（BRotli BSDIFF）增量补丁 → 得到 `ota_extract/boot_new.img`（100,663,296 B）；
4. 用 `vmlinux_to_elf` 从新内核重建符号表 → `analysis/output/mey_11.0.0.109.kallsyms.txt`（**111,075** 符号，旧内核 110,992）；
5. 新旧内核做**函数级规范化对比**（丢弃全部立即数/目标地址，只留助记符+寄存器/寻址形状），消除重定位与 rodata 漂移噪声。

### 3.2 新内核身份

| 项 | 旧（设备） | 新（MagicOS 11） |
|---|---|---|
| linux_banner | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` | `6.6.118-android15-8-g554929766a0d-abogki544555896-4k` |
| 编译器 | `Android (11368308, +pgo, +bolt, +lto, …)` | 同（**clang 版本未变**） |
| 内核映像大小 | 37,128,704 B | 37,128,704 B |
| sha256 | `e8ce5dbf904ecb602b7c486ed365f081…` | `ebb5bd6e70c9a19d9fb536694201f471…` |
| 逐字节差异 | — | **29,900,651 B / 80.53%**，2,332,155 段 |

⇒ **KMI 家族不变（仍 6.6.118）**，但是一次彻底的重新构建。

### 3.3 ★ CVE-2026-43284（DirtyFrag）—— **已修**

**(a) 源码对账**：可信树 6.6.127 → 6.6.139 的 `net/ipv4/esp4.c`（`esp_input()` 内，约 917 行）与 `net/ipv6/esp6.c`（约 965 行）各有一处**恰好 +1 行**的改动：

```c
 	} else if (!skb_has_frag_list(skb)) {
 /* 改为 */
 	} else if (!skb_has_frag_list(skb) &&
 		   !skb_has_shared_frag(skb)) {
```

**(b) 行号指纹精确吻合**：`module_init()` 在文件内的行号

| 文件 | 6.6.127 树 | 设备旧内核 | **MagicOS 11** | 实测 Δ |
|---|---|---|---|---|
| `net/ipv4/esp4.c` | 1249 | **1249** | **1250** | **+1** |
| `net/ipv6/esp6.c` | 1302 | **1302** | **1303** | **+1** |

（6.6.139 树为 1253 / 1306 ＝ 该范围共 +4 行，其中只有 1 行是上述守卫；MagicOS 11 只吃下了这 1 行 ⇒ 一次**外科式单行回移**。）

**(c) 汇编实证**（不依赖行号巧合）：

```
esp_input  旧 202 条 → 新 204 条
  新增:  ldrb w9, [x8]        ← 读 skb_shared_info.flags（字节宽，正是 SKBFL_* 所在）
         tbz  w9, #0, …       ← 测 SKBFL_SHARED_FRAG(bit0)
  另有:  cbz → cbnz、tbnz → tbz 各一次（因分支落空方向反转）
esp6_input 旧 204 条 → 新 206 条（同形）
skb_splice_from_iter       —— 指令多重集完全一致（bag = 1.0000）
esp_output_head / skb_cow_data / skb_zerocopy_iter_stream —— 完全一致
```

⇒ **`esp_input()` 在 skb 带共享页（`MSG_SPLICE_PAGES` 进来的页缓存页）时强制走拷贝路径，DirtyFrag 的"把 AES-CBC 解密结果就地写进页缓存"原语失效。** `[汇编已证 ★★★★★]`

### 3.4 ★ CVE-2026-43499（rt_mutex PI）—— **已修**

`remove_waiter()`：旧 `0xffffffc081080e60`，新 `0xffffffc081081430`。

```
旧:  mrs x20, sp_el0              ← current
     add x21, x20, #0x90c        ← &current->pi_lock
     …
     str xzr, [x20, #0x938]      ← current->pi_blocked_on = NULL

新:  ldr x20, [x23, #0x50]       ← waiter->task   （0x50 = rt_mutex_waiter.task）
     cbz x20, <unlock 路径>       ← 新增空指针检查
     add x21, x20, #0x90c        ← &waiter_task->pi_lock
     …
     str xzr, [x20, #0x938]      ← waiter_task->pi_blocked_on = NULL
     …
     mov x5, x20                 ← rt_mutex_adjust_prio_chain(..., waiter_task)
```

与可信树 6.6.127 → 6.6.139 的 `kernel/locking/rtmutex.c` 补丁**逐字对应**：

```c
+ * When invoked from rt_mutex_start_proxy_lock() waiter::task != current !
+	struct task_struct *waiter_task = waiter->task;
…
-	raw_spin_lock(&current->pi_lock);
-	rt_mutex_dequeue(lock, waiter);
-	current->pi_blocked_on = NULL;
-	raw_spin_unlock(&current->pi_lock);
+	scoped_guard(raw_spinlock, &waiter_task->pi_lock) {
+		rt_mutex_dequeue(lock, waiter);
+		waiter_task->pi_blocked_on = NULL;
+	}
…
-				   next_lock, NULL, current);
+				   next_lock, NULL, waiter_task);
```

旁证：`rt_mutex_start_proxy_lock` 27 → 40 条；`remove_waiter` 155 → 153 条；而 `task_blocks_on_rt_mutex` bag=1.0000、`rt_mutex_adjust_prio_chain` bag=0.9983（仅 1 处 rodata 偏移）⇒ 改动**局部化在这两函数**。
⇒ 项目在 R9 认定的"`mrs sp_el0` + `str xzr,[x,#0x938]`、全函数 `#0x50` 零命中 ＝ 43499 漏洞变体"指纹，在 MagicOS 11 上**消失**。`[汇编已证 ★★★★★]`

> 注：`remove_waiter` 中 `mov x5, x20` 这条指令新旧**字面相同**，但 x20 的语义由 `current` 变成 `waiter_task` —— 这正是"逐字节/逐助记符对比会漏判、必须读语义"的典型例子。

### 3.5 CVE-2026-64560 —— **未修**

`release_task()`（`kernel/exit.c` 的 `tsk->sighand = NULL` 所在函数，`__exit_signal` 已内联）
：382 → 382 条指令，**仅 1 条不同**且只是 rodata 页偏移（`add x1,x1,#2688` vs `#1728`）。`do_exit` 同为 699→699 条、1 处 rodata 偏移。
⇒ 64560 的姿态与升级前一致。`[汇编已证 ★★★★☆]`
（该线在本项目本就卡在 stageB W1，不是当前可用原语。）

### 3.6 整个改动的规模

| 指标 | 数值 |
|---|---|
| 共同代码符号 | 62,552 |
| **结构完全一致** | **62,308（99.61%）** |
| 结构有差异 | 244（含数据/节标记等非函数符号与布局噪声） |
| 有差异函数的主聚集区 | MM/pte/TLB/rmap、HID、MMC/SDHCI、f2fs、dma-heap、xfrm |

**含 `module_init` 的源文件行号指纹**（`__initcall__kmod_<mod>__<id>_<line>_<fn>`，行号 = 文件内 `module_init()` 位置；990 个可比对项中 11 个变化）：

| Δline | 模块 | 文件 |
|---|---|---|
| +29 | `hid` | `drivers/hid/hid-core.c` |
| +22 | `page_alloc` | `mm/page_alloc.c` |
| +20 | `eventpoll` | `fs/eventpoll.c` |
| +17 | `f2fs` | `fs/f2fs/super.c` |
| +7 | `wacom` | `drivers/hid/wacom_sys.c` |
| +3 | `dma_heap` | `drivers/dma-buf/dma-heap.c` |
| +2 | `mmc_block` / `sdhci` | `drivers/mmc/core/block.c` / `host/sdhci.c` |
| **+1** | **`esp4` / `esp6`** | **`net/ipv4/esp4.c` / `net/ipv6/esp6.c`** ★ |
| +1 | `vmscan` | `mm/vmscan.c` |

改动的另外两条线索（**不出现**在上述表里，因为这两个文件没有 `module_init`）：
- `kernel/locking/rtmutex.c`（43499 修复，§3.4）；
- 一批**新增的厂商延迟埋点**：`android_vh_cma_alloc_lat_start/end`、`android_vh_mm_direct_reclaim_start/end`、`android_vh_dma_heap_buffer_alloc_lat_start/end`、`android_vh_mmc_*`、`android_vh_sdhci_get_cd`（新增 `__tracepoint/__traceiter/__probestub/__TPSTRTAB` 全套）—— 属功能新增，会带动 `cma_alloc`(+55)、`dma_heap_buffer_alloc`(+74) 等函数变化。

⇒ **该"11 文件清单"是下界**（只覆盖含 initcall 的文件）。可以确定的是：**改动面很小、且两个当前可用原语都被精准修掉。**

---

## 4. 升级的连带影响（即使漏洞没修也是门槛）

### 4.1 vermagic 与构建绑定 ⇒ 现成 KO 一律拒载

内核内 `.rodata` 的 `VERMAGIC_STRING` 字面量（`[汇编已证]`）：

```
旧: 6.6.118-android15-8-gf17133276a57-abogki518694926-4k SMP preempt mod_unload modversions aarch64
新: 6.6.118-android15-8-g554929766a0d-abogki544555896-4k SMP preempt mod_unload modversions aarch64
```

设备 `uname -r` 也返回带 SCM 的全串 ⇒ **UTS_RELEASE 含 git/构建号**。
⇒ 为旧 build 编译（或伪造 vermagic）的 `kernelsu-*.ko`、`dirtyfrag-*.ko` 在新内核上会被 `check_modinfo()` 以 vermagic 不符拒绝。
**好消息**：两串**等长**（各 29 字符），理论上可**原地改写** KO 的 `.modinfo` 串 —— 但这只解决"装"，不解决"怎么把 KO 装进去"（原语已被修）。

### 4.2 root 是易失态，升级即终局

`[已实测]` boot `cd7f6f4d`（uptime 551 s）下：
- `/proc/modules` 645 行，**无 `kernelsu`**；
- `/system/bin/su` → `inaccessible or not found`；
- `uname -r` = `…gf17133276a57…`，slot `_b`，`flash.locked=1`。

⇒ DirtyFrag 的 root **不跨重启存活**，每次重启都要重跑工具。**一旦升级，重跑也没有用了**（原语已修）。

---

## 5. 可选项与建议

| 选项 | 内容 | 代价 / 风险 |
|---|---|---|
| **A. 不升级（推荐，若需要 root）** | 保持 10.0.0.175。每次重启后重跑 DirtyFrag 恢复 root | 无 MagicOS 11 新功能；root 为易失态 |
| B. 先升级、再等新原语 | 升级后内核仍 6.6.118，**64560 未被修**，另有 244 个函数改动面里的未知项 | 升级后**无 root**、**无回滚通道**；64560 线还卡在 stageB |
| C. 升级前做完整备份 | 已备份 `boot_b_full.img`（100,663,296 B）、`Image-mey`、20 个 vbmeta 头、OUC 数据库、整份 OTA 可随时重下 | 低风险，应与 A 一起做 |
| D. 想两全 | 目前**无**可行方案：本机 BL 锁死，无法双系统/降级分区；官方不提供降级包 | — |

**建议动作顺序**
1. 若不急，**先不点升级**（`fw_state=0`，主动权在手上）；
2. 无论选 A 还是 B，先把已备份清单交叉存档（`analysis/output/h253` 旁证文件见 §6）；
3. 若确实需要 MagicOS 11 的功能，把这次升级按"**永久放弃当前唯一 root 通道**"来对待，而不是"试一下、不行再退"。

---

## 6. 证据文件清单（本仓）

| 文件 | 内容 |
|---|---|
| `analysis/scratch/ota_extract/boot_new.img` | 重建出的 MagicOS 11 `boot` 镜像（100,663,296 B） |
| `analysis/scratch/ota_extract/kernel_new.raw` | 新内核裸镜像（37,128,704 B） |
| `analysis/output/mey_11.0.0.109.kallsyms.txt` | 新内核符号表 **111,075** 条 |
| `analysis/scratch/Image-new.symtab.elf` | 新内核带符号 ELF |
| `analysis/scratch/ota_final_rebuild.py` | 增量 payload 套用器（BSDF2，含 extent repeated 修正） |
| `analysis/scratch/fn_cmp.py` | 函数级对比（seq + bag 双度量） |
| `analysis/scratch/fn_changed.py` / `fn_changed.txt` | 去立即数后的"真正改动函数"清单（244 项） |
| `analysis/scratch/dis_sym.py` | 按符号名反汇编裸镜像 |
| `analysis/scratch/vbhdr/*.hdr` | 设备 20 个 vbmeta 首 4 KB |
| `analysis/scratch/oucdb/hnouc.db` | OTA 计划（target 版本、URL、md5、VAB 参数） |
| `analysis/scratch/boot_b_full.img` | 升级前 `boot_b` 全量 |

---

## 7b. 2026-10-10 独立复算（回应"你怎么确定被修了"）

对 §3.3 结论做**不引用旧结果**的当场重演。三环独立闭合：

### 环一 · 源码对账（可信树，`git show HEAD:<path>`）

| 树 | HEAD | `net/ipv4/esp4.c` 的 skip_cow 判定 |
|---|---|---|
| `refs/kernel_nothing_sm8735`（sun，设备同源 6.6.127） | `00f929de3` | L914 `} else if (!skb_has_frag_list(skb)) {` ← **未修** |
| `analysis/src_refs/code-linaro-full`（6.6.139） | `e96e8c30e` | L917–918 `} else if (!skb_has_frag_list(skb) &&` / `!skb_has_shared_frag(skb)) {` ← **已修** |

### 环二 · 常量位定义（消除"我记错了 bit 位"的风险）

两棵树的 `include/linux/skbuff.h` 一致：

```
501:  SKBFL_ZEROCOPY_ENABLE = BIT(0),
508:  SKBFL_SHARED_FRAG    = BIT(1),   ★
```

⇒ 汇编里的测试位应当是 **`#1`，不是 `#0`**。

> **订正**：§3.3(c) 原文写「`tbz w9, #0` ← 测 SKBFL_SHARED_FRAG(bit0)」，**位号写错了**。
> 实测机器码测试位是 **`#1`**，与 `BIT(1)` 一致；**结论不受影响**，仅标注错误。

### 环三 · 本机汇编实读（两侧镜像均为本机落盘文件，非网络引用）

`esp6_input`（二者结论一致，`esp_input` 同形）关键块：

```
OLD 设备 10.0.0.175          │  NEW MagicOS 11.0.0.109
50 ldr x9,[x8,#8]  frag_list │  50 ldr  x9,[x8,#8]   frag_list
51 cbz x9, <skip_cow>        │  51 cbnz x9, <copy>          极性翻转
                             │  52 ldrb w9,[x8]      ★ shinfo->flags  新增
                             │  53 tbz  w9,#1, <skip_cow>   ★ 新增 = SKBFL_SHARED_FRAG
52 mov x2,sp / 53 mov x0,x19 │  54 mov x2,sp / 55 mov x0,x19
55 bl <copy>                 │  57 bl <copy>
```

- `x8 = skb->head + skb->end` = `skb_shinfo(skb)`；`[x8,#8]` = `frag_list`，`[x8]` = `flags`。
- **OLD 只看 frag_list**（`cbz` ⇒ frag_list 为空就跳过 cow，就地解密写回 skb 的页 = DirtyFrag 的原语）；
- **NEW 多了 `flags & BIT(1)` 的守卫**：带共享页就强制走 `<copy>`（先 cow 再解密），页缓存不再被就地改写。
- 两侧 `cbz` → `cbnz` 的极性翻转，正是"单条件谓词变成双条件与"的典型 codegen 表现。
- 指令计数符合预期：**+2 条**（`esp_input` 201→203，`esp6_input` 203→205），恰好就是 `ldrb` + `tbz` 这 2 条。
- 对照组：`esp_output` 98→98 条、`skb_splice_from_iter` 163→163 条（指令数完全一致）⇒ 改动没有波及发送侧和 splice 侧，是**单点的接收侧外科修补**。

### 附：同批发言值同步复核（全部吻合）

| 项 | 报告值 | 本次复算 |
|---|---|---|
| 两内核大小 | 各 37,128,704 B | ✔ 37,128,704 / 37,128,704 |
| 逐字节差异 | 29,900,651 B / 80.53% | ✔ 29,900,651 / 37,128,704 = 80.53% |
| OLD banner | `…gf17133276a57-abogki518694926-4k` | ✔ 逐字一致 |
| NEW banner | `…g554929766a0d-abogki544555896-4k` | ✔ 逐字一致 |

### 本结论的强度与边界（不夸大）

- **成立的是**：新内核在接收侧增加 `SKBFL_SHARED_FRAG` 守卫 ⇒ DirtyFrag 依赖的"就地解密改写页缓存"路径被堵。
- **不成立 / 未做的是**：**没有真机跑过 MagicOS 11 去做实机验证**（用户提出的这一点是对的）。本结论是**离线静态判决**，全部证据链来自
  ① 荣耀官方 CDN 的 OTA `update_base.zip`（HTTP Range 按需取 `payload.bin`）→ 手写 CrAU 解析 → BSDF2 增量套用到 `boot_b` → `boot_new.img`；
  ② `vmlinux_to_elf` 恢复出 **111,075** 个符号；
  ③ 与设备旧内核逐函数规范化对比（62,552 共同符号中 **99.61% 指令多重集完全一致**，仅 244 个有差异）。
  三重自洽性使得"重建镜像有误"的概率很低，但**它不等价于实机运行验证**。要补这一环，唯一办法是真升级一台并在其上实测 PoC——而那台设备会永久失去 root 且无法回滚。
- **残留未知**：244 个差异函数中的厂商私有改动未被逐一审计（只逐一看过含 `module_init` 的行号指纹变迁），因此除 CVE-2026-43284 / 43499 / 64560 这三条已逐条比对过的线之外，其余新增面不保证已穷举。

**复算脚本**：`analysis/scratch/h253_verify.py`（守卫指纹扫描）+ 内联的一次性反汇编取样脚本；产物落盘
`analysis/output/h253_reverify_esp_ctx.txt`、`analysis/output/h253_reverify_block.txt`。

---

## 7. 需带回主记忆的新铁律

1. **AVB 头部整数字段为大端**（`>IIQQ…`）；描述符偏移相对 aux block（`256 + auth_block_size`）。
2. **protobuf 中 extent 字段是 repeated**；解析必须 `extend` 而非赋值覆盖（曾因此得出"内核未变"的错误中间结论）。
3. **`__initcall__kmod_<mod>__<id>_<line>_<fn>` 的行号 = 文件内 `module_init()` 位置**，可作"该文件改了 N 行"的离线指纹；但**无 initcall 的文件（如 `rtmutex.c`）不可见 ⇒ 该清单是下界**。
4. **GKI vermagic 含 SCM 串**（`uname -r` 亦含）⇒ KO 与构建强绑定，等长可原地改写。
5. **函数级对比必须读语义**：`mov x5, x20` 这类指令字面相同而语义不同（`current` → `waiter_task`），纯字节/助记符比对会漏判；反之 `mrs sp_el0` → `ldr [x23,#0x50]` 才是可靠信号。
6. **DirtyFrag root 为易失态**：`/proc/modules` 无 `kernelsu` ⇒ 已失效；不要再用 `getenforce` 或 `/system/bin/su` 存在性判断。
