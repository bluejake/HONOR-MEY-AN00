# R8 refs/ 全量盘点 + kernel_nothing_sm8735 可信度裁决

> 目标：MEY-AN00（荣耀 500，内核 `6.6.118-android15-8`，BL锁，uid=2000）
> 模式：**纯离线**（静态分析，未上机）
> 素材：`D:/MEY-AN00-root-repro/refs/`（129 个目录）+ `dc15_repro/` + `analysis/src_refs/code-linaro-full/`

## 结论摘要

1. **`kernel_nothing_sm8735` 是真实 6.6 树，可信度通过** —— 但**不能**用「MAPLE_TREE/futex 拆分 = 6.9+」判据裁决，因为**官方 CodeLinaro qcom 6.6.139 树呈现完全相同的特征**（Android GKI 把 6.9/6.10 特性回移进 6.6）。**真正的裁决证据是与 CodeLinaro 官方树 blob 逐字节相同**。**[汇编已证]**
2. ★ **这棵树精确定界了 CVE-2026-43499 的修复边界**：`remove_waiter()` 在 6.6.127 用 `current->pi_blocked_on`（**漏洞态**），6.6.139 改为 `waiter_task->pi_blocked_on`（**已修**）。本机 6.6.118 **低于 127 ⇒ 必在漏洞侧**。（★ 已由 R9 用本机反汇编独立实证）
3. **投 `MCAST 载体`（`do_ipv6_setsockopt` 深栈拷贝），不要投 pselect**。dc15 §3.4o 已用「种125 + 开火 nice=5 ⇒ 存活」这条**独立判别实验**证明 MCAST 的 plant 真正落在槽位 +0x18，而 pselect 覆盖区间 [0x148,0x1b0] 结构上够不到。
4. **43499 在本机并未「机制性死亡」**：H47 的判死理由（`nfds≥44` 走 kmalloc ⇒ 栈不重叠）**只对 pselect 成立**。MCAST/pselect/sigreturn/sendmsg 是**不同承载机制**，H47 的禁令被误推广。
5. `honor300-amm-an00-kernel` **复核确认是空仓库**（全库仅 3 个 git 对象：1 commit + 1 tree + 1 blob，blob 就是 3 行 README，**无任何外部链接**）。
6. **真正的同厂同内核资产**是 `GhostLock-MEP-AN00-App`（与 dc15 同型号 MEP-AN00、同内核 6.6.118）+ `cve-2026-43499-honor`（荣耀私有偏移表）+ `cve-2026-43499-aak-an00`（荣耀 6.6.89，10 篇 docs）。
7. **次高投** `cve-2026-64560-a16`：明示 **6.6.118 未修复、6.6.147 才修**（★ 已由 R9 独立验证：6.6.127 与 6.6.139 两棵可信树均为裸赋值 + `timer_lock_sighand` 均 0 命中）。
8. ⚠️ `kernel_nothing_sm8735` 的 `sun` 提交前缀 = 本机平台代号（已用阳性对照排除 `sockaddr_un sun` 噪声）。

---

## R8.1 refs/ 全量清点（129 项，摘要）

**厂商图例**：Honor=荣耀/华为系 · QC=高通/SoC系 · 通用=跨厂Android · 其他=PC/IoT/TV

### ★★★ 第一梯队：同内核 / 同厂商 / 同 SoC

| 目录 | 内容 | 厂商 | 内核 | 评级 |
|---|---|---|---|---|
| **`GhostLock-MEP-AN00-App`** | ★**与 dc15 同型号 MEP-AN00** 的 43499 APK，exploit 随仓库分发 | Honor | **`6.6.118-android15-8`**（与本机**逐字同串**） | **最高** |
| **`kernel_nothing_sm8735`** | ★LineageOS **sun/SM8735** GKI 源码树 | QC | **6.6.127** | **最高（偏移仲裁器）** |
| **`opace6-cve-2026-64560`** | ★OnePlus Ace6 64560 临时 root | QC | `6.6.118-android15-8` | **最高（参数逐字对齐）** |
| **`cve-2026-64560-a16`** | ★64560 工具链 + 3 个 6.6.118 profile | QC | `6.6.118-android15-8` | **最高（同内核+明示未修）** |
| `cve-2026-43499-honor` | ★荣耀 BVL-AN16(Magic6 Pro)，**含荣耀扁平化 `rt_mutex_waiter` 完整偏移表** | Honor | 6.1.128 | 思路必读 |
| `cve-2026-43499-aak-an00` | ★荣耀 AAK-AN00 43499 全程复盘，10 篇 docs | Honor | 6.6.89 | 高（同代6.6荣耀） |
| `ghostlock-honor-aak(-probe)` | 上者的 bruteforce/leak_minimal 实测代码 | Honor | 6.6.89 | 高 |
| `ghostlock-h80gt` | ★Honor 80 GT **MCAST 载体 + KernelSU 装载**，**实机验证** | Honor | 5.10.168~236 | 高（载体参考实现） |
| `galaxy-a37-root` | ★A37 43499：**FUTEX_CMP_REQUEUE_PI + kernelsnitch 堆哈希碰撞** | 其他 | 6.12 系 | 高（推翻判死先例） |
| `ghostlock-app` | 43499 + Shizuku shell(uid=2000) 执行 | 通用 | `6.6.118/android15-8` | 高 |

### ★★ 第二梯队：同内核（6.6.118-android15-8）

| 目录 | 内容 | 评级 |
|---|---|---|
| `op13-cve-2026-64560` | OnePlus 13 64560 移植 | 高 |
| `xiaomi15-dada-cve-2026-64560` | Xiaomi 15 64560 移植（★ opace6 曾误用其常量出事） | 高 |
| `k80pro-miro-cve-2026-64560` | Redmi K80 Pro；★ 文档独立判定 direct-probe 可放弃 | 中 |
| `cve-2026-43499-for-xiaomi-17t-chagall` | ★Xiaomi 17T；**明记 6.6.118-android15-8 后失效**（★已由 R9 裁决为不可采信） | 高（负面情报已被证伪） |
| `cve-2026-43499-pmg110-root` / `cve-2026-43499-for-xiaomi-17t-chagall` 等 | 各家 43499 | 中 |
| `redmi14c-pond-cve-2026-64560` | 64560 **待填值骨架**（非可运行） | 低 |
| `cve-2026-64560-analysis` | 64560 触发 PoC（**无提权**） | 中（仅触发） |

### ★ 第三梯队：43499 生态（其他内核/厂商）

`ghostlock-x200-root/app`（x200，项目自标"最有价值参照"）· `ghostlock-selinux-disabler` / `ghost-hoock`（**只关 SELinux 单原语**，写原语校验用）· `CyberMeowfia` 系列（NebuSec 上游骨架 + 样本分析方法论）· `CVE-2026-43499-Neo11Plus-main` / `duchamp-root` / `redmi-turbo5`（dc15 fork 上游）· `ghostlock`（pselect 载体原理 + waiter 栈图）· `ghostlock-custom`（非 Android 通用 Linux 6.x）· `unplus`（★43499 **绕过 SELinux 的任意写核心逻辑**）· `openvz-cve-patch-2026`（★OpenVZ 的 43499 **补丁**，反向价值 = 根因）· `cve-2026-43499_hw-clt-al01` / `-poc-analysis`（★target.h 生成器，profile 驱动工具链）· `auto_extract_offsets`（偏移自动提取工具）· `tcp-zerocopy-sm`（TCP_ZEROCOPY 载体几何）

### ★ MCAST 载体族（★ dc15 已验证 MCAST 路线，值得集体看）

`ghostlock-h80gt`（MCAST + KernelSU，**实机验证**）· `ghostlock-kit`（iQOO Neo9S Pro **MCAST 移植补丁**）

### ★ KASLR / 泄漏族

`s26-m1q-ghostlock-selinux`（★S26 M1Q **tracefs KASLR 移植**，dc15 的 KASLR 来源）· `cve-2026-43499-m3q-azf1`（SELinux-only park）

### 载体族（栈回收几何）

`ghostlock-pfem10`（OPPO Find X5 Pro，★**8 字节写原语语义**）· `ghostlock-aresin`（MTK Dimensity 1200 **physmap overwrite**）· `ghostlock-galaxy`（需 Android shell）· `rootmyvivo-exploit` / `vivo-root-build`（★基于同 SoC PD2415 6.6.57/6.6.89 **IonStack 引擎**）

### BL 锁定框架族

`ghostlock-oneplus` / `-for-oneplus` / `-for-oneplus15t` / `-k419-adapter`（★BL 锁定 OnePlus/OPPO/realme **运行时探测**自动识别）

### ★ 明确不投

| 目录 | 原因 |
|---|---|
| `honor300-amm-an00-kernel` | **空仓库**（仅 3 行 README，3 个 git 对象）；且 5.15.180 与本机差两世代 |
| `google_kernel_GKI-6.6.118-android15.8` | 前轮判定版本自相矛盾（第三方伪装树） |
| 三星 6.12 系（`ghostlock-a17/-s26/-a36/-s24u/-s25u/-s26/-zfold4`/`rmgp-*`/`ionstack-*`） | 世代错配 |
| MTK 5.10/4.x 系（`ghostlock_mt6983v_5.10`/`ksuroot`/`iqoo-*`/`rootmyvivo`/`vivo-root-build`/`f9360*`/`ghostlock-oppo-*`） | 世代 + 架构双重错配（MTK vs 高通） |
| IoT/TV 系（`aquos-r6/r7`/`asus-i005`/`lg-*`/`hazel-cve`/`logitech-g-cloud`/`humane-aipin`/`ghostlock-nvidia-shield`/`ghostlock-sabrina`/`ghost-hoock`） | 场景完全不符 |
| armv7l（`cve-2026-43499-armv7`、`ghostlock-cve-2026-43499`、`ghostlock-oppo-watch3pro`） | 架构不符 |
| `cve-2026-43499-x86_exploit` / `-poc-scanner` | 架构不符 |

---

## R8.2 荣耀系/高通系逐个深度评估

### ① `cve-2026-43499-honor`（荣耀 BVL-AN16）— 最高信息密度

1. **解决什么**：在荣耀 6.1 上完整测绘 43499 的**所有栈回收载体**，给出**荣耀私有 `rt_mutex_waiter` 扁平化布局**。
2. **前置条件**：BVL-AN16 / 6.1.128-android14-11 / SM8650 / Android 16 / MagicOS 10 / BL锁 / enforcing。
3. **本机满足**：
   - 6.6.118 ≠ 6.1.128 ⇒ **6.1 专属的 do_futex 内联不适用**（该文自己指出 AAK-AN00 的 6.6.89 已改，`PSELECT_WAITER_WORD_SHIFT=0`）。**[汇编已证]**
   - ★ `MM_STRUCT_SZ=0x500`（kmem_cache 对象大小，**≠ BTF sizeof 0x3c0**）—— **对 6.6 同样适用且极易踩坑**
   - 荣耀扁平化 waiter 偏移**不可直接套用**（那是 6.1 荣耀私有改动）
4. **评级**：**思路可参考**（载体穷尽表 = 现成的排除清单）
5. **缺什么**：套用偏移需本机 BTF/kallsyms 复核

### ② `cve-2026-43499-aak-an00` + `ghostlock-honor-aak(-probe)`（荣耀 6.6.89）

1. **解决什么**：荣耀同代 6.6 43499 全流程复盘 + APK loader。
2. **前置条件**：AAK-AN00 / 6.6.89-android15 / MagicOS 10 / **BL 永久锁死**（`ro.oem_unlock.supported` 为空）。
3. **本机满足**：6.6.89 vs 6.6.118 **同 6.6 荣耀系、同 android15 GKI**，仅小版本差 ⇒ **前置条件基本全满足**（BL 锁状态一致）。**[源码推断未验证]**
4. **评级**：**需改造但收益高**。作者自述"进展为零、放弃"、"root 后断网、拔线重启"（`B类断网-内核IP栈瘫痪.md`）
5. **缺什么**：需本机 `target.h`（偏移）+ BTF；**dc15 已在同内核 MEP-AN00 上测出等价偏移**，可直接复用

### ③ `GhostLock-MEP-AN00-App`（★ 同型号同内核）

1. **解决什么**：MEP-AN00 的 43499 三键 APK，**exploit 随仓库分发**。
2. **前置条件**：内核 **`6.6.118-android15-8`** —— **与本机逐字同串**。
3. **本机满足**：版本串满足；MEP-AN00 ≠ MEY-AN00（同为荣耀 AN00 命名法、同 sun 平台家族）⇒ **偏移大概率逐字节相同，但必须用本机 kallsyms/BTF 复核**。**[源码推断未验证]**
4. **评级**：**需改造（换 target.h/profile）** —— 但这是**全库与本机内核最近的一条**
5. **缺什么**：`target.h` 的 48 个偏移、`p0_fingerprint.h` 的 32 行指纹表（用本机 `Image-mey` 重生成，方法见 dc15 SOP 步骤 9~11）

### ④ `ghostlock-h80gt`（荣耀 80 GT，MCAST 载体参考实现）

1. **解决什么**：AGT-AN00 实机验证的 43499，**MCAST 载体 + 线程自开火 + KernelSU 装载**。
2. **前置条件**：5.10.168~5.10.236，Android 8~9。
3. **本机满足**：5.10 vs 6.6 ⇒ 具体 opt/level/偏移**不可直用**；但**载体力学（深度区间与拼接方式）与厂商无关**。**[源码推断未验证]**
4. **评级**：**MCAST 路径的可行性证据**。dc15 §3.4o 已独立验证 MCAST 在 6.6.118 上 plant 成功。
5. **缺什么**：本机 opt/level 需重扫（`SLIDE_PLANT_OPT_A/B` 是现成开关）

### ⑤ `opace6-cve-2026-64560` / ⑥ `cve-2026-64560-a16`

见 R7 报告。关键补充：
- opace6 内核串完全一致但 **Image 哈希不同** ⇒ 地址集不可直用
- ★ `cve-2026-64560-a16` 明示 **6.6.118 未修复、6.6.147 才修** ⇒ 本机可用；工具链（纯 Go 单二进制 + `android/arm64` 产物）现成。注意该仓库自标 rmx5010「完整提权**尚未实机验证**」

---

## R8.3 ★ `kernel_nothing_sm8735` 可信度裁决（最重要）

### 判定：**可信，是真实的 6.6 GKI 树，可用作 6.6 偏移仲裁器。但第一遍裁决方法有错，必须记录这个坑。**

### 证据 1：仓库身份 —— `sun` 就是本机平台代号

- `HEAD = 00f929de3`，提交信息 **`sun: Update modules list`**，作者 `HELLBOY017`，分支 `lineage`。**[汇编已证]**
- remote：`https://github.com/HELLBOY017/kernel_nothing_sm8735.git`；`arch/arm64/boot/dts/vendor` 是符号链接 → `../../../../../sm8735-devicetrees`（外部仓库，未 clone）
- in-tree `README.md` 是 **AOSP common kernel 补丁提交指南** ⇒ 确为 **AOSP GKI common 树**

> ⚠️ **阳性对照**：全库 100+ 目录中 `sun` 命中极多，但抽样显示**绝大多数是 `struct sockaddr_un sun;` 变量名**。真正的平台代号证据是**提交前缀** + dc15 文档 `ro.board.platform=sun`。

### 证据 2：Makefile（`git show HEAD:Makefile`）

```
VERSION = 6 / PATCHLEVEL = 6 / SUBLEVEL = 127 / EXTRAVERSION =
NAME = Pinguïn Aangedreven
```

`EXTRAVERSION` 空、`NAME` 是 6.6 真实代号 ⇒ **自洽**。**[汇编已证]**

### 证据 3（决定性）：与 CodeLinaro 官方 qcom 6.6 树 **blob 逐字节相同**

项目自己已有：`analysis/src_refs/code-linaro-full`（remote `git.codelinaro.org/clo/la/kernel/qcom.git`，分支 `kernel.lnx.6.6.r17-rel`，`HEAD=e96e8c30ee`，Makefile = **6.6.139**，同为 `Pinguïn Aangedreven`）。

| 文件 | kernel_nothing_sm8735 (127) | code-linaro (139) | 结论 |
|---|---|---|---|
| `include/linux/fs.h` | `6065d6d85e18` | `6065d6d85e18` | **IDENTICAL** |
| `mm/shmem.c` | `d2d08ee11ccb` | `d2d08ee11ccb` | **IDENTICAL** |
| `kernel/futex/core.c` | `0a1745d76c25` | `0a1745d76c25` | **IDENTICAL** |
| `include/linux/maple_tree.h` | `a452dd8a1e5c` | `a452dd8a1e5c` | **IDENTICAL** |
| `kernel/locking/rtmutex.c` | `10521605e30e` | `6d4942bcec7d` | **DIFF（★ 关键）** |

两个独立来源（GitHub 个人 fork vs CodeLinaro 官方）产出**逐字节相同**的通用文件 ⇒ **绝无伪装**。**[汇编已证]**

### 证据 4：★ 我最初的判据是错的 —— 必须推翻自己

任务书给的验证方法（`shmem_get_folio` 有 / `shmem_getpage` 无 / `MAPLE_TREE` 存在 ⇒ 6.9+）在本树上**全部命中「6.9+」特征**：

| 特征 | 结果 | 我的初判 | 实际 |
|---|---|---|---|
| `mm/shmem.c` `shmem_get_folio` | **17 命中** | 6.9+ | ✗ |
| `mm/shmem.c` `shmem_getpage` | **0** | 非 6.6 | ✗ |
| `include/linux/maple_tree.h` | **EXISTS** | 6.9+ | ✗ |
| `kernel/futex/core.c` 存在、`kernel/futex.c` 不存在 | — | 6.9 拆分 | ✗ |
| `mm/kasan/quarantine.c` | EXISTS | 6.10+ | ✗ |

**但同样的特征在 CodeLinaro 官方 6.6.139 树上 100% 复现**（12/12 路径存在性完全一致，无一处 DIFF）⇒ **这些是 Android GKI 把 6.9/6.10 特性回移到 6.6 的产物，不是版本判据。**

> ★ **结论：版本特征法在 Android GKI 上不可用，唯一可靠判据是 blob 哈希比对。**
> 这同时解释了 `google_kernel_GKI-6.6.118` 为何被判伪装：应当用同一方法（与官方 6.6.139 比 blob）复验。

### 证据 5：★ **这棵树精确定位了 CVE-2026-43499 的修复边界**

127 → 139 唯一的实质差异就在 `remove_waiter()` —— **正是 43499 的根因函数**：

```c
/* 6.6.127  —— 漏洞态 */
raw_spin_lock(&current->pi_lock);
rt_mutex_dequeue(lock, waiter);
current->pi_blocked_on = NULL;          // ← 清的是 current，不是 waiter->task
raw_spin_unlock(&current->pi_lock);

/* 6.6.139  —— 已修 */
struct task_struct *waiter_task = waiter->task;
scoped_guard(raw_spinlock, &waiter_task->pi_lock) {
    rt_mutex_dequeue(lock, waiter);
    waiter_task->pi_blocked_on = NULL;   // ← 修好了
}
```

注释还写明：`When invoked from rt_mutex_start_proxy_lock() waiter::task != current !`

**推导**：本机 **6.6.118 < 6.6.127 < 6.6.139** ⇒ 必然落在漏洞侧。**[源码推断，逻辑闭合]**

> ★ **该推断已由 R9 用本机 `Image-mey` 反汇编独立实证**（`mrs x20, sp_el0` + `str xzr, [x20, #0x938]`，无 `waiter->task` load）。

**与外部情报互相印证**：`cve-2026-64560-a16` 说 64560 在 6.6.118 未修（已由 R9 验证）；`chagall` 说 43499 在 6.6.118 失效（★ 已由 R9 裁决为**不可采信**，见 `R9.5`）。

### 用途与限制

| 可仲裁 | 不可仲裁 |
|---|---|
| 6.6 通用结构体布局、`rt_mutex_waiter`/`rt_mutex_base` 字段序、`fs.h`/`shmem.c` 相关偏移 | 厂商私有部分（Honor `.strtab` 被剥离）、`vendor_dlkm` 的 456 个 `.ko`、本机 4K 页/配置差异 |

⚠️ **不要用这棵树单独判定 f77.c 的硬编码偏移**，必须三方交叉：源码树布局 + 本机 BTF + 本机 kallsyms。

---

## R8.4 dc15_repro 未消化细节

### 三份交接 md（★ 重要修正：只有 1 份是 MEP-AN00）

| 路径 | 行数 | 内容 |
|---|---|---|
| `dc15_repro/交接-临仵root-MEP-AN00.md` | **984** | ★**唯一的 MEP-AN00 主时间线**。§2 已解决 / §3 唯一卡点（3.4a→3.4o 逐轮）/ §3.5 核实事实 / §4 产物 / §5 外部参考 |
| `dc15_repro/交接文档-临仵Root复现.md` | 163 | **BVL-AN16 交付说明**（6.1.157，非 MEP）。一键 root、命中率 1/3~1/10、命中点 uptime≈168s、失败分类 |
| `dc15_repro/流程SOP-从boot分析到提权.md` | 204 | **端到端 SOP**（工具链方法学通用）：boot.img→Image→IKCONFIG→kallsyms→BTF→符号改名→target.h 重算→每 boot 一发→loader 17 步 |
| （附加）`dc15_repro/pselect_plant_无root校验_思路.md` | 173 | pselect plant 无 root 校验思路 |

⚠️ 后两份讲 **BVL-AN16（6.1.157）**，不是 MEP-AN00。

### (1) 成功判据用什么透镜？—— ★ **本项目最该继承的方法论**

**三层递进**：

1. **闸门判据（几何正确性）**：种 `tree.prio = p->prio` ⇒ 闸门 `ldr w9,[x21,#0x18]` 匹配 ⇒ `return 0` 不进链 ⇒ **存活 = 落地**
2. ★ **A/D 二元判据（链健康度，不需要 plant）** —— 最干净的一招：
   ```
   对 owner（真 PI 等待者）开火，nice 使 p->prio ≠ waiter->tree.prio ⇒ 闸门必不匹配 ⇒ 走链
     存活 ⇒ 链健康（dance 没问题）
     panic ⇒ 链被 dance 弄坏（当前状态）
   ```
3. **CFI 阶段读回**：`*(ASHMEM_MISC_FOPS) == fake_fops` —— 被明确称为"唯一"的端到端成功信号

**★ 关键自省（§3.4h）**：「`sched_pi_setprio` 当判据」被证伪 —— `pi_baseline` 正控（真实 PI 阻塞 + sched_setattr，**存活**、ret=0）跑完整条合法 `rt_mutex_adjust_prio_chain`，trace 里 `comm=pi_baseline` 的 `sched_pi_setprio` **= 0 条** ⇒ **合法 walk 也是静默的** ⇒ 从「0 条」推出「walk 死在 [11] 之前」**不成立**。该事件只能做**单向判据**（有 = 一定到达）。

⇒ **符合本项目「独立透镜」铁律**：判据依赖内核状态（存活/panic + CFI 读回），不循环自证。

### (2) 内核实机验证怎么做的？—— 做了，而且非常规范

- **一发制**：每 boot 只打一发，`run.lock` 用 `boot_id` 门控强制。理由：写原语扰动 PI 树，同 boot 第二发必崩
- **窗口期**：等 uptime 进 **95~300s** 才开打（实测命中点 ≈168s，460s/873s 从未命中）
- ★ **消融验证（3/3 存活）**：`NEO11_NO_FIRE=1` / `SLIDE_MCAST_SELF_FIRE=0` ⇒ dance + plant 拷贝 + 写原语全跑完、设备存活 ⇒ **崩的只有开火那一次**
- ★ **扫描式探针**：`NEO11_FIRE_NICE_SWEEP=1` 一次启动连打 40 发（nice −20..19），**「没崩的那个 nice 就是悬垂槽里那 32 位值」** —— 无读回原语也能读内核栈
- **读回验证**：handler 里从用户态读 sigframe 自检（`d0=…078` = 120）
- **离线工具链**（只需 boot.img）：`_tracefs_slide.py` / `_pair_tracefs.py` / `_btf_waiter.py` / `_stack_depth.py` / `_walk_disasm.py`

### (3) 失败尝试 —— **比成功更有价值的部分**

| # | 失败 | 教训 |
|---|---|---|
| 1 | **所有 plant 几何/宽度/载体实验一律 panic** | §3.4g：**「崩的不是 plant，是我们的 futex dance 留下的状态」** —— 对 owner 开火（走**完全合法**的链，不碰伪造对象）**照样 panic** |
| 2 | 去掉多余 `FUTEX_WAKE` | waiter 卡在 WAIT_REQUEUE_PI 数分钟不返回，但**最终仍 panic** ⇒ 不是（唯一）元兇 |
| 3 | **`rt_sigreturn` 载体证伪 0x1b0 深度模型** | 整段 512B 全填 120 仍 panic |
| 4 | **pselect 全窗口证伪** | res-encode 读回确认确实写入（`readback in0..3 = 78 78 78 78`），`PLANT_ALL=120` **仍 panic** ⇒ 槽不在 [0x148,0x1b0] |
| 5 | ★ **仪器静默假阴性（方法论级）** | `_sweep5/6` 的 trace **根本没生效**：exploit 的 tracefs KASLR 泄漏会**自己重设事件集**，把事先打开的 `sched_pi_setprio` 关掉。`host_trace_*.log` 里 0 条而同窗口本应 10+ 条。**修好后同窗口抓到 648/394 条 ⇒ 前几轮「0 条」推论全部作废** |
| 6 | 页侧真 bug：`fake_task.pi_waiters` 留成空树 | `rb_erase` 在**不含该节点的空树**上操作 ⇒ 必崩。已修 |
| 7 | `NEO11_PSELECT_PRIO=auto` 是错的 | 本机 `/proc/<tid>/stat` 第 18 栏 = `p->prio − 100` ⇒ 闸门值是 **120**，直接种 20 作废 |
| 8 | ★ **`route` 线程的 syscall 覆写了自己的 waiter**（§3.4h 根因） | plant 之后、开火之前，route 线程自己发 syscall（`write`+`fsync`/`close`）⇒ **内核栈每线程复用，从栈顶重新往下用** ⇒ depth 0x198 的闸门字被诊断日志覆盖。**教训：任何 plant 后的诊断都是攻击面** |
| 9 | `_mcast_shift.py` 帧算法**漏 pre-index stp** | 结论 0x2d0 **是错的** |
| 10 | `mt6985-cve-2026-43499`（68M tokens） | 「KernelSnitch 时序攻击在 MTK Dimensity 9200 上不可靠，`CONFIG_PANIC_ON_OOPS=y` 不给试错空间」 |

### (4) 它测出了我们项目缺的偏移/地址？（大量，全部同内核 6.6.118）

**⭐ 载体深度表**（离线实测 `poc/_stack_depth.py`，本机 futex waiter 深度 = **0x1b0**，`&rt_waiter @ sp+0x90` 三次独立验证）：

| 载体 | 覆盖深度区间 | 能否够到 waiter |
|---|---|---|
| `sendmsg` | 0x168…0x1d8 | 深度探针可用（word0 槽是 iovec 用户指针，**最终利用不可用**） |
| `writev` iovstack | 0x1b8…0x238 | 待测 |
| `process_vm_writev` | 0x190…0x210 | 待测 |
| `pselect` 浅栈 | 0x138…0x200（word0..4 verbatim @0x188..0x200；word5..13 走 res-encode → 0x148..0x188） | ❌ 结构上不够 |
| `rt_sigreturn` | 0x080…0x280 | ❌ 实测不够 |
| **`do_ipv6_setsockopt`（MCAST）** | **0x084…0x290**（两支合起来） | ✅ **实测成功** |

**MCAST 具体参数**：opt46 → `sp+0x40`，264B，覆盖 word0..4；opt48 → `sp+0x148`，260B，覆盖 word5..13，waiter 基准 = entry−0x1b0；**shell 域可达**（普通 setsockopt）；实测 opt46→errno 99、opt48→errno 22 = **先拷贝后校验**（这两条报错**不影响 plant**）。

**其它已测事实**：
- `rt_mutex_waiter`（MEP 非紧凑）偏移：`tree.prio 0x18 / tree.deadline 0x20 / pi_tree 0x28 / pi_tree.prio 0x40 / pi_tree.deadline 0x48 / task 0x50 / lock 0x58 / wake_state 0x60 / ww_ctx 0x68` —— walk 反汇编 / BTF / target.h **三者一致**
- 关键地址：`__arm64_sys_futex @0x119ad8`（帧 0x80，内联分派）、`futex_wait_requeue_pi @0x958e1c`（帧 0x1c0）、`__arm64_sys_pselect6 @0x244230`（帧 0x90）、`core_sys_select @0x243ee8`（帧 0x1e0）、`rt_mutex_adjust_pi @0x1081438`、`remove_waiter @0x1080e60`、`__sched_setscheduler @0x16a224`、`futex_lock_pi @0x2cb4a8`（帧 0x1a0）、`__arm64_sys_rt_sigreturn @0x49b2e4`（帧 0x290）
- 符号表段界：`_sdata=0x2160000 … _edata=0x2368a00`；`ASHMEM_MISC_FOPS = ashmem_misc+0x10`
- ★ **KASLR 泄漏（已实测，跨 8+ boot 零复位）**：`SLIDE_TRACEFS_ROOT=/sys/kernel/tracing`（shell **可读可写**）、`SLIDE_TRACEFS_EVENT_ID=109`、锚点 `worker_thread+0x17c = 0x185864`、次锚点 `rcu_gp_fqs_loop+0x144 = 0x28b38`，`task = base + 0x217e280`。原理：tracefs `sched_blocked_reason` 的 `caller` 字段在二进制 `trace_pipe_raw` 里不受 `kptr_restrict` 遮蔽。
  > ★★ **这与本项目 HANDOFF 记的「tracefs 写被 SELinux 拒」矛盾** —— dc15 说**可读可写**。**必须上机裁决这个矛盾**（R5 的 J 系列判据可加一条）
- **本机内核配置**：`KASAN=y` + `KASAN_HW_TAGS`(MTE)、`SHADOW_CALL_STACK=y`、`VMAP_STACK=y`、`PANIC_ON_OOPS=y`、`INIT_ON_ALLOC_DEFAULT_ON=y`、`RANDOMIZE_KSTACK_OFFSET=y`
  > ★★ **`RANDOMIZE_KSTACK_OFFSET` 已由 R9 从 Image 内嵌 bootconfig + `invoke_syscall` 改 SP 汇编**双重实证** = 生效**
- tracefs 对 shell 只开放 4 项 ⇒ **无法内核侧插桩**，panic 定位只能"一发一重启 + 二分"

---

## R8.5 建议的下一步攻哪个

| 优先级 | 目标 | 理由 |
|---|---|---|
| **1** | ~~定死 43499 补丁状态~~ **★ R9 已完成** | 唯一能免费消除「43499 是否还在牌桌上」这个二值不确定性的动作 —— **已完成**：`remove_waiter` 漏洞变体 + `RANDOMIZE_KSTACK_OFFSET=y` 生效 |
| **2** | **43499 MCAST 载体路线**（不是 pselect） | dc15 在**同内核同荣耀家族**上已用独立判据实测 MCAST 的 plant 落在槽位 +0x18（§3.4o），且 §3.4h 证明 dance+plant+写原语**本身无害**（3/3 消融存活）。唯一未解决 = **A/D 判据下的链健康度** |
| **3** | `GhostLock-MEP-AN00-App` target 移植 | 内核串逐字相同，是全库最近的同内核参考资产。价值是提供**一份已知可用的 `target.h` 骨架**，与 dc15 独立测出的偏移**交叉验证** |
| **4** | `cve-2026-64560-a16` | 6.6.118 未修（R9 已独立验证）；工具链现成；**不依赖任何栈几何**（避开 kstack 随机化风险），与 43499 是**正交的第二条腿** |
| **5** | `cve-2026-43499-honor` 的**载体穷尽表** | 现成的「已排除载体」清单（含 `PR_SET_MM_MAP`/pselect/kgsl/TCP_ZEROCOPY/356 个 `__arm64_sys_*`）。⚠️ 对 6.6 适用性未验证，pselect 一项要重估 |
| **6** | 裁决 dc15「tracefs shell 可读可写」与本项目「SELinux 拒」的矛盾 | 若 dc15 正确 ⇒ KASLR 泄漏路线可复用（跨 8+ boot 零复位，价值极高） |

### 建议的 MCAST 路线具体动作

1. **先复现 dc15 的 A/D 二元判据**（对 owner 开火，nice 0 vs 5）—— **不需要 plant 就能测链健康度**，这是**最高信息密度的单发实验**
2. 若 A 存活/D panic ⇒ 逐项对照 `ghostlock-h80gt/exploit/src/slide.c` 修 dance，候选差异：`pin_to_core`、`disable_rseq_for_thread()`、多余的 `FUTEX_WAKE`、requeue 前 `usleep` 时长、consumer 开火后是否立刻 `FUTEX_LOCK_PI(f_pi_target,0)+UNLOCK`
3. **必须照 §3.4h 教训**：plant 之后到开火完成，route 线程**禁止任何 syscall**（诊断全部移到开火之后或换线程写）
4. **必须照 §3.4n 教训**：判读一律用"先等 leak ok 再开事件"的 `_watch2.sh`，否则全是假阴性
5. 载体深度不够时，直接上 §3.4l 设计的 **`sendmsg`/`writev`/`process_vm_writev` 三窗口拼接**（覆盖 0x140…0x238）

### ★ 建议修正的项目内既有错误结论

H47 的「43499 机制性死亡」判据（`nfds≥44` 走 kmalloc ⇒ 栈不重叠）**只对 pselect 成立**。建议在 HANDOFF §3 把「真死路」改为「**pselect 载体死，MCAST/sigreturn/sendmsg 未评估**」，并保留「禁止再扫 nfds」的禁令（该禁令本身仍有效）。

---

## 纪律附记

- **假 0 命中已实证 2 例**：(a) `kernel/futex.c` 用 Grep 得 0，`git cat-file -e` 证实是**路径不存在**（实际是 `kernel/futex/` 目录）；(b) `include/linux/kernel.h` 的 `LINUX_VERSION_CODE` 用 Grep 与 Python 双查均 0（该文件确实无此宏，非工具故障）
- **`sun` 噪声已做阳性对照**：抽样 18 处全是 `struct sockaddr_un sun`；真平台代号证据只有提交前缀 `sun:` 与 dc15 的 `ro.board.platform=sun`
- 未连 adb、未上机、未编译；全程只读 + 静态分析
- 未读 `refs/google_kernel_GKI-6.6.118-android15.8/`

## ★★ 遗留矛盾（必须诚实标出）

| # | 矛盾 | 状态 |
|---|---|---|
| 1 | **tracefs 写权限**：dc15 说 shell **可读可写**（并用其做 KASLR 泄漏，跨 8+ boot 零复位）；本项目 HANDOFF 说 `kprobe_events` 写被 SELinux 拒 | ★ **待上机裁决**。若 dc15 正确，KASLR 泄漏路线价值极高 |
| 2 | **RANDOMIZE_KSTACK_OFFSET**：dc15 列为「要优先排除的重大风险」 | ★ **R9 已实证 = 生效**。⇒ **固定栈偏移路线（含 MCAST/sigreturn 栈几何）全部作废** |
| 3 | chagall 说 6.6.118 已修 43499 vs 源码树 127 仍漏洞态 | ★ **R9 已裁决为 chagall 不可采信**（不同 build 通道 + 逻辑不可能） |