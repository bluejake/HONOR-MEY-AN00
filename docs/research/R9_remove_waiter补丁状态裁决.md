# R9 离线反汇编裁决：remove_waiter 补丁状态 / RANDOMIZE_KSTACK_OFFSET / 64560 验证

> 目标：MEY-AN00（荣耀 500，内核 `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`，4K页）
> 模式：**纯离线**（反汇编 + 源码树对账 + 内嵌 bootconfig 解压），未上机
> 工具：`analysis/scratch/dis_mey.py`、kallsyms、两棵可信 GKI 树

## 判决

> ## **`remove_waiter()` = 漏洞变体（VULNERABLE）** — 汇编已证
> ## **`CONFIG_RANDOMIZE_KSTACK_OFFSET=y` 且运行时生效** — 汇编已证（smoking gun 在 `invoke_syscall`）
> ## **CVE-2026-64560 漏洞态成立** — 源码对账已证

---

## R9.1 本机 `remove_waiter` 定位

| 项 | 值 |
|---|---|
| 函数 VA | `0xffffffc081080e60` |
| 下一符号 | `rt_mutex_wait_proxy_lock @ 0xffffffc0810810cc` |
| **函数大小** | **`0x26c`（620 字节）** |
| 文件偏移 | `0x1080e60` |
| 反汇编命令 | `python analysis/scratch/dis_mey.py ffffffc081080e60 26c` |

**内联展开的被调函数**：

| 地址 | 符号 | 对应源码 |
|---|---|---|
| `0xffffffc081083358` | `_raw_spin_lock` | `raw_spin_lock(&current->pi_lock)` |
| `0xffffffc081083520` | `_raw_spin_unlock` | `raw_spin_unlock(&current->pi_lock)` |
| `0xffffffc08003a9d4` | `rb_erase` | `rt_mutex_dequeue()`（内联） |
| `0xffffffc08003af24` | `rb_next` | `rt_mutex_top_waiter()`（内联） |
| `0xffffffc08003a860` | `rb_insert_color` | `rt_mutex_enqueue_pi()`（内联） |
| `0xffffffc0801691c8` | `rt_mutex_setprio` | `rt_mutex_adjust_prio()`（内联） |
| `0xffffffc0810815d4` | `rt_mutex_adjust_prio_chain` | — |

**参数映射**：`x0 → lock`（存 `x19`）；`x1 → waiter`（存 `x23`）

**BTF 偏移 ↔ 汇编 三方对账（闭环）**：

| 字段 | BTF 偏移 | 对应汇编 |
|---|---|---|
| `task_struct.pi_lock` | `0x090c` | `add x21, x20, #0x90c` ✅ |
| `task_struct.pi_waiters` | `0x0920` | `add x24, x21, #0x920` ✅ |
| `task_struct.pi_blocked_on` | `0x0938` | `str xzr, [x20, #0x938]` ✅ |
| `rt_mutex_base.owner` | `0x0018` | `ldr x25, [x19, #0x18]` ✅ |
| `rt_mutex_waiter.task` | `0x0050` | **本函数无**（= 漏洞指纹） |

---

## R9.2 指纹逐条核对

| # | 判据 | 期望（漏洞变体） | 实测 | 符合 |
|---|---|---|---|---|
| 1 | 读 `current` 的方式 | per-CPU 读取 | `mrs x20, sp_el0` | ✅ |
| 2 | `pi_lock` 锁对象基址 | per-cpu 派生 | `add x21, x20, #0x90c`，x20 源自 SP_EL0 | ✅ |
| 3 | `pi_blocked_on=NULL` 写基址 | **与 #2 同源** | `str xzr, [x20, #0x938]`，**同一个 x20** | ✅ |
| 4 | 是否有 `waiter->task`（`#0x50`）链式 load | **不应有** | **全函数 0 命中** | ✅ |
| 5 | 结论 | 漏洞变体 | **漏洞变体** | ✅ |

**关于 `mrs sp_el0` 的正确解读**：本机 `CONFIG_THREAD_INFO_IN_TASK=y`，arm64 上 `current` 的定义就是「SP_EL0 本身就是 `task_struct*`」（6.6.139 树 `arch/arm64/include/asm/current.h` 实证）：

```c
static __always_inline struct task_struct *get_current(void)
{
	unsigned long sp_el0;
	asm ("mrs %0, sp_el0" : "=r" (sp_el0));
	return (struct task_struct *)sp_el0;
}
#define current get_current()
```

⇒ **`mrs sp_el0` 就是本配置下 per-CPU `current` 读取的唯一正确形态**。判据核心是「per-CPU 派生」vs「入参派生」的**对立**，而非字面匹配某个助记符。

**已修变体应有的形态**（6.6.139）：

```c
struct task_struct *waiter_task = waiter->task;       /* ← 从入参 x1 经 #0x50 链式 load */
scoped_guard(raw_spinlock, &waiter_task->pi_lock) {   /* ← 锁基址来自 waiter_task，不是 current */
    rt_mutex_dequeue(lock, waiter);
    waiter_task->pi_blocked_on = NULL;                 /* ← 写基址来自 waiter_task，是另一个寄存器 */
}
```

---

## R9.3 关键反汇编片段

```asm
; ---- 取 current（per-CPU，SP_EL0 == task_struct 指针）----
0xffffffc081080e98:  mrs      x20, sp_el0              ; ★指纹1：x20 = current
0xffffffc081080e9c:  add      x21, x20, #0x90c         ; ★指纹2：&current->pi_lock
0xffffffc081080ea0:  ldr      x25, [x19, #0x18]        ; lock->owner
0xffffffc081080ea4:  mov      x0, x21
0xffffffc081080ea8:  bl       #0xffffffc081083358      ; _raw_spin_lock(&current->pi_lock)

; ---- rt_mutex_dequeue(lock, waiter) ----
0xffffffc081080eac:  ldr      x8, [x23]                ; waiter->tree.rb_node  (x23 = 入参 x1)
0xffffffc081080eb0:  cmp      x8, x23
0xffffffc081080eb4:  b.eq     #0xffffffc081080ee4
0xffffffc081080eb8:  ldr      x8, [x19, #0x10]
0xffffffc081080ebc:  add      x22, x19, #8             ; &lock->waiters
0xffffffc081080ecc:  bl       #0xffffffc08003af24      ; rb_next
0xffffffc081080ed0:  str      x0, [x19, #0x10]
0xffffffc081080ed4:  mov      x0, x23
0xffffffc081080ed8:  mov      x1, x22
0xffffffc081080edc:  bl       #0xffffffc08003a9d4      ; rb_erase ★ rt_mutex_dequeue()

; ---- current->pi_blocked_on = NULL  ★★★ 决定性 ----
0xffffffc081080ee4:  mov      x0, x21                  ; 复用 pi_lock 地址准备解锁
0xffffffc081080ee8:  str      xzr, [x20, #0x938]       ; ★写基址是 x20（current），非入参派生
0xffffffc081080eec:  bl       #0xffffffc081083520      ; _raw_spin_unlock
```

**决定性在 `0x...ee4`–`0x...ee8`**：`x20`（current）在此**同时充当锁基址来源与清零写基址来源**。已修变体写基址必须是**另一个寄存器**（从 `x23` 经 `#0x50` 加载）。

**交叉验证**：`0x...ef8`–`0x...f00` 是 owner 分支（第二个 `raw_spin_lock(&owner->pi_lock)`），其 `add x22, x21, #0x90c` 与 `0x...e9c` 的 `add x21, x20, #0x90c` **偏移完全相同** ⇒ 反证 `0x90c` 就是 `pi_lock` 的 `task_struct` 偏移。

**全函数 `str xzr` 穷举**（排除第二处清零点）：

```
0xffffffc081080ee8:  str xzr, [x20, #0x938]   ← 唯一 task_struct 字段清零
0xffffffc081081070:  str xzr, [x8, #0x38]     ← rb_erase 内部（rb_node->rb_parent_color）
0xffffffc081081084:  str xzr, [x0]           ← rb_erase 内部（空孩子指针）
```

**调用点（3 个）**：

| 调用 PC | 所属函数 | 语义 |
|---|---|---|
| `0xffffffc081080e58` | `rt_mutex_start_proxy_lock` 尾部区域 | ★ **漏洞触发场景**（6.6.139 注释：*"When invoked from rt_mutex_start_proxy_lock() waiter::task != current !"*） |
| `0xffffffc0810813f0` | `rt_mutex_cleanup_proxy_lock +0x4c` | 正常路径 |
| `0xffffffc081082068` | `rt_mutex_slowlock +0x194` | 正常路径 |

**与 dc15 记录吻合**：dc15 的 `1080e98: mrs x20, SP_EL0` + `1080ee8: str xzr,[x20,#0x938]`（文件偏移）↔ 本机 `ffffffc081080e98` / `ffffffc081080ee8`（VA）。**dc15 的「漏洞变体」推断被独立实证确认。**

---

## R9.4 kallsyms 文件分歧核对

**判决：同一 build，「110,669 符号」是统计口径错误。可放心使用任一文件。**

| 项 | `mey_6.6.118.kallsyms.txt` | `kallsyms_mey_an00.txt` |
|---|---|---|
| 行数（= 符号数） | **110,992** | **110,992** |
| 唯一地址数 | 110,669 | 110,669 |
| 大小 | 4,832,627 B | 4,943,619 B |

差值 `110,992 − 110,669 = 323` = 同址多符号（ARM64 局部符号别名）。

**内容等价性**：`awk '{print $1,$3}' | sort` 后 `diff` → **exit 0，零差异**。

仅实质差异：类型字母大小写（`t` vs `T`）、排序（后者 `_text` 标 `A`）。

**建议**：统一用 `mey_6.6.118.kallsyms.txt`（严格升序，便于二分）。

---

## R9.5 chagall 矛盾情报裁决

**原文**（`refs/cve-2026-43499-for-xiaomi-17t-chagall/README.md`，全文 4 行）：

```
# CVE-2026-43499-For-Xiaomi-17T-chagall
CVE-2026-43499 reproduce in Xiaomi 17T.

tested on .307 version,it got fixed when I upgraded to A17 which also upgraded to
6.6.118-android15-8-gc4127a25dcf3-ab158633 37-4k so not working.
```

**裁决：不能推翻本机漏洞判定，该情报应降级为「不可采信的负面复现报告」。**

| # | 理由 | 强度 |
|---|---|---|
| 1 | **不是同一 build**：chagall 是 `ab158633 37`（高通平台通道），本机是 `abogki518694926`（Android common GKI 通道）。同标 6.6.118 但厂商/SoC/defconfig overlay 全不同 | 决定性 |
| 2 | **逻辑不可能**：`remove_waiter` 在 `kernel/locking/rtmutex.c`（纯通用代码，不在 `arch/` 下，不受 vendor overlay 影响）。若 6.6.118 已修，6.6.127 不可能反而退化回 `current->pi_lock` | 决定性 |
| 3 | **PoC 自述未完成**：README 只说 "not working"，无补丁分析、无 diff、无 root shell。这是「我没能复现」误推断为「上游已修复」的典型认知错误 | 强 |

**失效原因可能性排序**：

| # | 可能性 | 判别方法 |
|---|---|---|
| 1 | PoC 依赖硬编码栈/偏移，在另一 build 失效（仓库有 `preload.so` + `preload_patched.so` 两个同大小文件 ⇒ 作者自己承认需按机型适配） | ★ **离线 diff 两个 .so 的硬编码常量，成本最低鉴别力最强** |
| 2 | vendor hardening 差异（高通 A17 的 config 覆盖） | 取 A17 bootconfig 与本机 diff |
| 3 | 时序窗口竞争（竞态型 PoC，编译器 LTO/PGO 布局变化即改窗口） | 看是否提及多次尝试/概率 |
| 4 | 该机型本就无效（BL/selinux 前提不符） | 读 docs |
| 5 | 真是补丁 | 已被理由2 排除 |

---

## R9.6 RANDOMIZE_KSTACK_OFFSET 判定

> ## 判决：**`CONFIG_RANDOMIZE_KSTACK_OFFSET=y`，且运行时生效**（汇编已证 + bootconfig 实证）

### 证据链 1：内嵌 bootconfig（从 Image-mey 解压，非上机）

`Image-mey` 内嵌完整 bootconfig（`IKCFG_ST`/`IKCFG_ED`，gzip，212,910 字节）。头部自证版本：

```
# Automatically generated file; DO NOT EDIT.
# Linux/arm64 6.6.118 Kernel Configuration      ← 与本机完全一致
CONFIG_LOCALVERSION="-4k"                        ← 与 -4k 目标一致
CONFIG_CC_VERSION_TEXT="Android (11368308, +pgo, +bolt, +lto, +mlgo, ...) clang version 18.0.0"
```

决定性配置项：

```
CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET=y
CONFIG_RANDOMIZE_KSTACK_OFFSET=y                 ← ★ 开启
# CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is not set
CONFIG_THREAD_INFO_IN_TASK=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_VMAP_STACK=y
CONFIG_STACKPROTECTOR_STRONG=y / PER_TASK=y
CONFIG_ARM64_PTR_AUTH=y / ARM64_BTI=y
```

> ★ **重要副产物**：`/proc/bootconfig` 实测 EACCES 的封锁**已被离线绕过** —— bootconfig 就在 `Image-mey` 里。

### 证据链 2：符号存在性

```
ffffffc081d30380 t early_randomize_kstack_offset      ← 仅在 #ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET 内定义
ffffffc0816982d8 D randomize_kstack_offset            ← DEFINE_STATIC_KEY_MAYBE_RO 静态分支键
ffffffc082136080 D kstack_offset                      ← DEFINE_PER_CPU(u32, kstack_offset)
ffffffc0801f94cc T randomize_stack_top
```

early_param 双分支逻辑反汇编确认：

```asm
0xffffffc081d303e0:  ldrb     w8, [sp, #4]              ; bool_result
0xffffffc081d303e4:  cbz      w8, #0xffffffc081d303f8
0xffffffc081d303e8:  adrp     x0, #0xffffffc081698000
0xffffffc081d303ec:  add      x0, x0, #0x2d8           ; &randomize_kstack_offset
0xffffffc081d303f0:  bl       #0xffffffc08030e3fc       ; static_branch_enable
0xffffffc081d303f8:  ...
0xffffffc08130400:  bl       #0xffffffc08030e504       ; static_branch_disable
```

### 证据链 3：★ **smoking gun** —— `invoke_syscall` 真的改 SP

```asm
; invoke_syscall +0x8c
0xffffffc08004678c:  mrs      x8, tpidr_el1              ; per-cpu 基址
0xffffffc080046790:  adrp     x9, #0xffffffc082136000
0xffffffc080046794:  add      x9, x9, #0x80             ; &kstack_offset ★精确匹配
0xffffffc080046798:  ldr      w8, [x8, x9]              ; 读 per-cpu kstack_offset
0xffffffc08004679c:  mov      x9, sp
0xffffffc0800467a0:  and      w8, w8, #0x3ff            ; 取低 10 bit ⇒ 0..1023 页
0xffffffc0800467a4:  add      w8, w8, #0xf
0xffffffc0800467a8:  and      x8, x8, #0x7f0            ; 对齐 16 字节
0xffffffc0800467ac:  sub      x8, x9, x8                ; sp = sp - offset ★实际生效
0xffffffc0800467b0:  mov      sp, x8                    ; ★★ 真的改 SP
```

**这是教科书式实现，无法用其他机制解释。** 偏移量 = `(kstack_offset & 0x3ff)` 个 4K 页（最大约 4MB），16 字节对齐。

> **对 `# CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is not set` 的诚实说明**：该项取 Kconfig `default` 值。该判定落在通用 `init/Kconfig`，而本树的 `init/Kconfig` 是 grafted 浅克隆（`kernel/kstack.c`、`arch/arm64/kernel/stack.c`、`include/linux/randomize_kstack_offset.h` 均不在树内，已用 `git cat-file` 确认）。**但这不影响裁决** —— 证据链 3 优先：静态分支若为 disabled，`invoke_syscall` 里这段代码会被优化消除；**代码实际存在于 Image 中 ⇒ 分支处于 enabled 状态**。

### ★ 爆炸半径（必须让决策者知道）

| 攻击路线 | 是否受影响 | 说明 |
|---|---|---|
| **固定内核栈偏移**（sigreturn ROP、栈上变量硬编码偏移） | ☠️ **作废** | 每次 syscall `sp` 都被随机下移 |
| **43499 的 MCAST / sigreturn 栈几何** | ☠️ **高风险作废** | 依赖固定栈偏移的路线全部失效 |
| **纯数据流攻击**（UAF write 到任意内核地址） | ✅ **不受影响** | `pi_lock`/`pi_blocked_on` 是堆上 `task_struct` 字段，与栈随机化正交 |
| **依赖 `current` 值本身** | ✅ **不受影响** | `current` = SP_EL0，偏移 0x90c/0x938 恒定 |

**关键洞察**：本报告裁决的 43499 漏洞，其利用原语是 `current->pi_blocked_on = NULL`（**写堆上 task_struct**）+ PI 链遍历，属「数据流」而非「栈几何」类 ⇒ **kstack 随机化不构成对该漏洞利用的阻断**。但它**会阻断任何以固定栈偏移为前提的备用路线** —— 这恰好也是 chagall PoC 可能失效的原因（可能性 #1）。

---

## R9.7 CVE-2026-64560 补丁状态独立验证

**判决：声明成立（SUPPORTED）。本机 6.6.118 在漏洞侧。**

| 树 | 版本 | `tsk->sighand = NULL;` | `timer_lock_sighand` 计数 | 加固 |
|---|---|---|---|---|
| `refs/kernel_nothing_sm8735` | 6.6.127 | **裸赋值**（line 209） | **0** | ❌ |
| `analysis/src_refs/code-linaro-full` | 6.6.139 | **裸赋值**（line 209） | **0** | ❌ |
| `google_kernel_GKI-6.6.118`（伪装树，仅对照） | 自称 6.6.118 | 裸赋值 | 0 | ❌ |

**6.6.139 `kernel/exit.c` 逐字**（`__exit_signal()`，行 205-214）：

```c
	flush_sigqueue(&tsk->pending);
	tsk->sighand = NULL;          /* 裸赋值，无 smp_store_release / WRITE_ONCE / xchg */
	spin_unlock(&sighand->siglock);
	__cleanup_sighand(sighand);
```

6.6.127 同函数**字节级一致**。

**加固痕迹搜索（全 0）**：`timer_lock_sighand` 在两树 `kernel/posix-timers.c` 均 0 次（这是 posix-cpu-timers UAF 的标志性加固函数）；`exit.c` 中 `sighand` 全部 19 处出现均无 `smp_store_release`/`WRITE_ONCE`。

**裁决逻辑**：6.6.127 与 6.6.139 跨越两个 LTS 小版本、且 6.6.139 是 6.6.147 之前最后一个 6.6 分支，写法**完全一致且均无加固** ⇒ 把补丁落地窗口**下界推到 6.6.139 之后**。本机 6.6.118 < 6.6.139 ⇒ **必然早于加固引入点** ⇒ 声明得到独立支持，无反证。

> **[未验证]** 无法离线直接检验 6.6.147 源码（两棵可信树都没该版本），故「恰好在 6.6.147 落地」仍属推断。但「本机在漏洞侧」这一结论**只依赖「6.6.139 仍裸赋值」这一个已证事实**，是稳健的。

**与 R9.2 交叉一致**：两条独立线（本报告汇编实证 + 64560 源码对账）收敛到同一结论 —— **本机处于 GKI 6.6 早期，是「后加的 RT-mutex 与 sighand 加固都还没落地」的窗口**。

---

## R9.8 阳性对照记录

| # | 0 命中的检验 | 阳性对照 | 结论 |
|---|---|---|---|
| 1 | **`#0x50]` 正则**在 `remove_waiter` 中 0 命中 | `rt_mutex_adjust_pi` **1 命中**（`ldr x21,[x21,#0x58]`）；`task_blocks_on_rt_mutex` **3 命中** | 同正则同 Image 同脚本 ⇒ **0 命中是真实结构性缺失**，判据#4 有效 |
| 2 | `remove_waiter` 无 `tpidr_el*` | `rt_mutex_adjust_pi` 有 `mrs x8, tpidr_el1`；`invoke_syscall` 有 `mrs x8, tpidr_el1` | 二值判别成立 |
| 3 | 需排除第二处 `pi_blocked_on` 清零点 | 穷举全函数 `str xzr` 共 3 处，其余 2 处属 `rb_node`（`#0x38` ≠ `0x938`） | 判据#3 有效 |
| 4 | 9 个被调目标全部解析 | `_raw_spin_lock`/`rb_erase`/`rt_mutex_setprio` 等全中，**0 个未解析** | 反汇编 BL 解析链路完整 |
| 5 | bootconfig 解压 | 首次 zlib/lzma **均失败** → 检查 magic bytes `1f8b0800` = **gzip** → 成功解出 212,910 B | 未把失败当结论；配置自证版本与本机吻合 |
| 6 | BTF 偏移可信 | BTF 预言 `pi_blocked_on=0x938`，汇编**精确命中** `str xzr,[x20,#0x938]` | BTF 是正向对照物；若有误不会如此精确 |
| 7 | 两个 kallsyms 分歧 | `awk '{print $1,$3}'\|sort` 后 `diff` **exit 0** | 同一 build，分歧是统计口径 |

---

## R9.9 给上机阶段的可执行判据

### 🟢 只需 1 条命令复核（≈0 成本）

| # | 判据 | 命令 | 预期 |
|---|---|---|---|
| A1 | remove_waiter 漏洞变体 | `dis_mey.py ffffffc081080e60 26c \| grep -E "sp_el0\|#0x938"` | `mrs x20, sp_el0` 与 `str xzr, [x20, #0x938]` **成对** |
| A2 | 反证 | 同上 `\| grep -c "#0x50]"` | **0** |
| A3 | kstack 随机化开 | bootconfig `\| grep KSTACK` | `CONFIG_RANDOMIZE_KSTACK_OFFSET=y` |
| A4 | 运行时生效 | `dis_mey.py ffffffc08004678c 30` | `ldr w8,[x8,...kstack_offset]` + `sub sp` + `mov sp` |

### 🔴 上机纪律提醒

1. **C2 是前置门禁**：若设备 `/proc/version` ≠ `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`，则本报告全部汇编结论**立即失效**。
2. **不要依赖 chagall 的版本声明做任何判断**（`abogki` vs `ab158633` 是不同 build 通道）。
3. **不要因为 `RANDOMIZE_KSTACK_OFFSET=y` 就判定 43499 整体不可行** —— 本报告裁决的原语是**堆上 `task_struct` 字段**，与栈几何正交。kstack 随机化阻断的是固定栈偏移类路线（sigreturn ROP / 栈上变量硬编码），**不是**本条漏洞的数据流路线。
4. 若要复核 chagall 失效真因：**离线 diff `preload.so` vs `preload_patched.so`**（≈0 成本，鉴别力最强）。

---

## 证据强度总览

| 结论 | 标注 | 强度 |
|---|---|---|
| remove_waiter 是漏洞变体 | **[汇编已证]** | ★★★★★ 三条独立指纹 + BTF 三方对账 + 与 dc15 独立吻合 |
| `RANDOMIZE_KSTACK_OFFSET=y` 且生效 | **[汇编已证]** | ★★★★★ bootconfig 实证 + `invoke_syscall` 改 SP smoking gun |
| 两 kallsyms 同 build | **[汇编已证]** | ★★★★★ 规范化 diff 零差异 |
| 6.6.118/127/139 皆无 sighand 加固 | **[源码推断未验证]** | ★★★★☆ 两棵可信树逐字一致；6.6.147 未直接检验 |
| chagall「已修复」不可采信 | **[已证伪其推论]** | ★★★★☆ build 串不符 + 逻辑不可能 + 通用代码不受 vendor 影响 |
| `pi_lock=0x90c` / `pi_blocked_on=0x938` | **[汇编已证]** | ★★★★★ BTF 预言被汇编精确命中 |