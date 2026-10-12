# H140 · 两个 CVE 的设备侧实证 + 攻击面重开

> 设备：MEY-AN00 ｜ MagicOS 10.0.0.175 ｜ A16 ｜ SM8735 ｜ 内核 `6.6.118-android15-8`（4K 页）
> 源码树：`kernel_src/Code_Opensource/kernel`（**6.6.56**，与设备差 62 版本）
> 镜像：`analysis/scratch/Image-mey`（ARM64 raw Image，`text_offset=0`，`_text=0xffffffc080000000` 映射到文件偏移 **0**）
> 符号：`analysis/output/kallsyms_mey_an00.txt`（110,992 行）
> 工具：`analysis/scratch/dis_mey.py`（capstone 5.0.7 反汇编器）

---

## 零、一句话结论

> **两个 CVE 均真实存在，且均已在【设备镜像层面】逐条实证为「未修复」——不是靠源码树版本推断，而是直接反汇编设备内核的关键指令点。**
>
> - **CVE-2026-43499（GhostLock，rtmutex UAF）**：`remove_waiter()` 用 `sp_el0`（=current）而非 `waiter->task` ⇒ **未修复**。且其 dequeue 调用点 `0xffffffc08003a9d4` **正是 MEY-AN00 本机 `rb_erase`** —— 与 L1/L2 存档原语线**同源合流**。
> - **CVE-2026-64560（posix-cpu-timers UAF）**：修复 5 点中可静态验证的 3 点全部缺失 ⇒ **未修复**。
>
> **⇒ 两条线重开，且第一条（rtmutex）直接复用已存档的 L2 攻击几何。**

---

## 一、任务背景与用户指令

用户最新指令：`继续深挖sigreturn：CVE-2026-43499、CVE-2026-64560`

**先说清一个事实**：这两个 CVE **都与 sigreturn 无关**。

| CVE | 子系统 | 与 sigreturn 关系 |
|---|---|---|
| CVE-2026-43499 | `kernel/locking/rtmutex.c`（futex PI 依赖） | **无关**；对应本项目 **L2 存档原语线** |
| CVE-2026-64560 | `kernel/time/posix-cpu-timers.c` | **无关**；独立新面 |

我按「用户想让我走的其实是这两条线」执行（前几轮 L1/L2 因用户指令冻结，现由 CVE 编号指名解冻）。

---

## 二、CVE 情报（WebSearch 核实）

### CVE-2026-43499（"GhostLock"）

| 项 | 值 |
|---|---|
| 子系统 | `kernel/locking/rtmutex.c` → `remove_waiter()` |
| 类型 | CWE-416 UAF ｜ CVSS 3.1 **7.8 HIGH**（`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`）|
| 引入 | 2.6.39（2011）⇒ 潜伏 ~15 年 |
| 受影响 | 2.6.39–6.1.174｜**6.2–6.6.139**｜6.7–6.12.85｜6.13–6.18.26｜6.19–7.0.3 |
| 设备 | **6.6.118 < 6.6.139 ⇒ 在区间内** |
| 修复 commit | `d8cce4773c2b23d819baf5abedc62f7b430e8745` 等 6 个 stable |
| 公开 PoC | 有（KernelCTF，奖金 92,337 美元，成功率 97%，5 秒提权） |

**机制**：`remove_waiter()` 既用于慢锁路径（`waiter->task == current`），也用于 `rt_mutex_start_proxy_lock()` 的**代理锁回滚**（`futex_requeue()` 调用）。后者 `waiter->task` **不是 `current`**，但函数体对 **`current`** 做 dequeue/清 `pi_blocked_on` ⇒ 三个后果：
1. rbtree dequeue 时未持 `waiter->task->pi_lock`
2. **waiter task 的 `pi_blocked_on` 未清 ⇒ 悬垂指针（UAF）**
3. `rt_mutex_adjust_prio_chain()` 操作错误的 top-priority waiter

### CVE-2026-64560（posix-cpu-timers UAF）

| 项 | 值 |
|---|---|
| 子系统 | `kernel/time/posix-cpu-timers.c` + `kernel/exit.c` + `kernel/signal.c` |
| 类型 | CWE-416 UAF + CWE-364 信号处理竞争 ｜ CVSS 3.1 **7.8 HIGH** ／ CVSS4 8.5 |
| 引入 | 5.7（commit `55e8c8eb2c7b6bf30e99423ccfe7ca032f498f59`）|
| 受影响 | < **6.6.147** ｜ < 6.12.100 ｜ < 6.18.41 ｜ < 5.15.213 ｜ < 5.10.262 ｜ < 7.1.5 |
| 设备 | **6.6.118 < 6.6.147 ⇒ 在区间内** |
| 修复 commit | `ad1cafa1bdaa71da85d71cac053838bbe97852b6`（7.1.5）｜`920f893f735e92ba3a1cd9256899a186b161928d`（7.2-rc3）等 8 个 |

**机制（上游原文竞争图）**：
```
sys_timer_delete()                    exec()
posix_cpu_timer_del()
  p = pid_task(pid, pid_type);   // 观察到【旧 leader】
                                      de_thread()
                                        switch_leader();
                                        release_task(old_leader)
                                          __exit_signal(old_leader)
                                            posix_cpu_timers*_exit();
                                            unhash_task(old_leader);
                                            old_leader->sighand = NULL;   // ★ 普通 str
  sighand = lock_task_sighand(p)
    sh = lock(p, sighand)      // p 的 sighand
    (p->sighand == NULL)
    return NULL;               // ★ 直接返回，无重试
  if (!sighand) return 0;      // ★ 提前返回，不 free_posix_timer()
```
**危害成立条件**：被删 timer **已 armed 且 enqueued 在 `p->signal`**，因为 exec() 时 TGID-targeted timer 会被继承 ⇒ `sys_timer_delete()` 释放了 timer 对象，而 `run_posix_cpu_timers()` 或其他 timerqueue add/delete 会访问**已释放对象的 timerqueue node** ⇒ UAF。

**上游修复 5 点**：
1. `__exit_signal()` 的 store → `smp_store_release()`
2. `lock_task_sighand()` 的 `!sighand` 路径加 `smp_acquire__after_ctrl_dep()`
3. 新建 helper：查 task + 锁 sighand，`sighand==NULL` 时**重试 task lookup**，仅当 lookup 失败才放弃
4. 在 **3 个受影响函数**（`posix_cpu_timer_del` / `posix_cpu_timer_set` / `posix_cpu_timer_rearm`）中使用该 helper
5. task lookup 失败时检查 timer 是否仍 enqueued（`timer_queued()`）+ `smp_rmb()` 配对 `__exit_signal()` 的 `smp_wmb()`

---

## 三、设备侧实证（★ 本轮核心，反汇编实读）

### 3.1 工具链建立（踩坑记录）

| 坑 | 现象 | 修复 |
|---|---|---|
| ① `llvm-objdump.exe` 不认裸二进制 | `--triple=aarch64` 无效，识别为 `coff-<unknown arch>`，无输出 | 改用 **Python + capstone 5.0.7**（本机已有） |
| ② 文件偏移算错 | 假设 `_text` 在文件 0x80000 ⇒ 全部 `udf #0` | 读 Image 头 `text_offset` @0x8 = **0** ⇒ `_text` 在**文件偏移 0** |
| ③ `--adjust-vma=0x...` | `expected a non-negative integer` | capstone 直接传 int vaddr，无需此参数 |

**★ 新工具**：`analysis/scratch/dis_mey.py <vaddr_hex> <len_hex>`
```python
TEXT = 0xffffffc080000000
FOFF = 0x0      # Image header text_offset == 0
skip = va - TEXT + FOFF
```

### 3.2 CVE-2026-43499：`remove_waiter()` 未修复 ✅

设备 `remove_waiter` @ `0xffffffc081080e60`：

```
+0x98  mrs  x20, sp_el0              ← ★ current（不是 waiter->task）
+0x9c  add  x21, x20, #0x90c         ← &current->pi_lock
+0xa0  ldr  x25, [x19, #0x18]        ← rt_mutex_owner(lock)
+0xa8  bl   0x...081083358           ← _raw_spin_lock(&current->pi_lock)
+0xac  ldr  x8, [x23]                ┐
+0xb0  cmp  x8, x23                  │ rt_mutex_dequeue(lock, waiter)
+0xb4  b.eq +0x...80ee4              │
+0xb8  ldr  x8, [x19, #0x10]         │
+0xc8  mov  x0, x23                  │
+0xcc  bl   0x...08003af24           │ ← rb_next
+0xdc  bl   0x...08003a9d4           │ ← ★★★ rb_erase（本机 L1 原语地址！）
+0xe0  str  x23, [x23]               ┘
+0xe8  str  xzr, [x20, #0x938]       ← ★ current->pi_blocked_on = NULL（写 current！）
+0xec  bl   0x...081083520           ← _raw_spin_unlock
```

**判定**：
- 写 `current->pi_blocked_on`（偏移 **0x938**），**用 `current`（`sp_el0`）而非 `waiter->task`** ⇒ **正是 CVE 描述的漏洞形态**
- **`rb_erase` 调用点 = `0xffffffc08003a9d4`** ⇒ 与 memory 记录的 MEY-AN00 本机 `rb_erase` **逐字节一致** ⇒ **L1/L2 存档几何可直接复用**

**★ 触发入口**：`rt_mutex_start_proxy_lock` @ `0xffffffc081080df4`：
```
+0x24  bl   0x...081080570           ← try_to_take_rt_mutex
+0x2c  cbnz w0, +0x...80e50
+0x58  bl   0x...081080e60           ← ★ remove_waiter（失败回滚路径）
```
⇒ `futex_requeue()` → `rt_mutex_start_proxy_lock()` 失败时**必然**走 `remove_waiter()`，而此路径 `waiter->task` = 被 requeue 的目标任务（≠ current）⇒ **漏洞触发点确认**。

### 3.3 CVE-2026-64560：修复 3 点全缺失 ✅

#### 修复点① `__exit_signal()` store 类型 —— 未修复

`__exit_signal` 内联进 `release_task` @ `0xffffffc08019b7cc`。扫描 `+0x880` store：

```
0xffffffc08019baac:  str  xzr, [x19, #0x880]     ← ★ 普通 str，不是 stlr
```

**⇒ 是 `str` 而非 `smp_store_release()`（`stlr`）⇒ 修复点① 缺失。**

上下文（`+0x19baa0`）：
```
+0xbaa0  add  x0, x19, #0x8a0
+0xbaa4  bl   0x...080275700      ← posix_cpu_timers_exit[_group]
+0xbaa8  mov  x0, x22
+0xbaac  str  xzr, [x19, #0x880]  ← ★ tsk->sighand = NULL（普通 str）
+0xbab0  bl   0x...081083520      ← _raw_spin_unlock
```
⇒ 顺序与上游竞争图一致：先 `posix_cpu_timers*_exit()`，再 `sighand = NULL`。

#### 修复点② `__lock_task_sighand()` acquire —— 未修复

设备 `__lock_task_sighand` @ `0xffffffc0800b9488`：

```
+0xa4  bl   0x...080028764        ← rcu_read_lock
+0xa8  ldr  x21, [x20, #0x880]    ← sighand = tsk->sighand（偏移 0x880）
+0xac  cbz  x21, +0x...80b94e8    ← if (sighand == NULL) break
+0xb4  bl   0x...0810833c4        ← spin_lock_irqsave(&sighand->siglock)
+0xbc  ldr  x8, [x20, #0x880]     ┐
+0xc0  cmp  x21, x8               │ 复用校验
+0xc4  b.ne +0x...80b94f0         ┘
...
+0x4e8  mov  x22, xzr             ← ★ ret = NULL（无 smp_acquire__after_ctrl_dep）
+0x4fc  ldr  x21, [x20, #0x880]   ┐ 重试循环（仅在复用失败时）
+0x500  mov  x22, xzr             │
+0x504  cbnz x21, +0x...80b94b0   ┘
```

**⇒ `!sighand` 路径直接 `ret = NULL` 返回，无 `smp_acquire__after_ctrl_dep()`（`dmb ishld`），无「重试 task lookup」helper ⇒ 修复点②③④ 全缺失。**

#### 修复点④ 三个受影响函数 —— 未修复

| 函数 | 地址 | `lock_task_sighand` 调用 | NULL 分支 |
|---|---|---|---|
| `posix_cpu_timer_del` | `0xffffffc080880088` | `+0xdc bl 0x...0800b9488` | `+0xe0 cbz x0, →+0x...80a168` |
| `posix_cpu_timer_set` | `0xffffffc08087fdb4` | 同址调用 | 同型 NULL 直返 |
| `posix_cpu_timer_rearm` | `0xffffffc0808802c4` | `+0x18 bl 0x...0800b9488` | `+0x1c cbz x0, →+0x...80a35c` |

`posix_cpu_timer_del` 的 NULL 分支体内（`+0x1b0`）：
```
+0x1b0  ldr  x8, [x19, #0x98]     ┐ ctmr->head
+0x1b4  cbz  x8, +0x...80a1c0     │
+0x1b8  brk  #0x800               │ ★ WARN_ON_ONCE（就是修复点⑤的 WARN）
+0x1c0  ldr  x8, [x21]            │ ctmr->node.next
+0x1c4  cmp  x8, x21              │ (timerqueue_node_queued)
+0x1c8  b.eq +0x...80a174         │
+0x1cc  b    +0x...80a1b8         ┘
```
⇒ **只有 `WARN_ON_ONCE`，没有修复后的重试 helper** ⇒ 与源码 6.6.56 完全一致。

---

## 四、源码树交叉验证

| CVE | 源码 6.6.56 位置 | 状态 | 与设备一致？ |
|---|---|---|---|
| 43499 | `kernel/locking/rtmutex.c:1533-1535` `raw_spin_lock(&current->pi_lock); rt_mutex_dequeue(lock,waiter); current->pi_blocked_on=NULL;` | 用 `current` | ✅ 一致（设备同样用 current） |
| 43499 | `rtmutex.c:1707` `remove_waiter(lock,waiter)`（`__rt_mutex_slowlock` deadlock 分支） | — | ✅ |
| 64560 | `posix-cpu-timers.c:488-502` `sighand=lock_task_sighand(p,&flags); if(unlikely(sighand==NULL)){WARN_ON_ONCE(...)}` | 无重试 | ✅ 一致 |
| 64560 | `include/linux/sched/signal.h:763-771` `lock_task_sighand()` inline | 直接返回 | ✅ |
| 64560 | `kernel/signal.c:1456-1486` `__lock_task_sighand()` | `sighand==NULL → break → return NULL` | ✅ 一致 |
| 64560 | `kernel/exit.c:145` `__exit_signal()` | 读 store 类型（见下） | 设备为 `str` |

**★ delta 判定**：源码 6.6.56 vs 设备 6.6.118（62 版本差）。但**三处关键指令点均在设备镜像上直接反汇编核对**，非版本推断 ⇒ **delta 已消解，结论为「已实测」级。**

---

## 五、判死/重开矩阵更新

| 面 | 前状态 | 现状态 |
|---|---|---|
| F. SROP/信号域 | ❌ 判死（七维度全闭合） | ❌ 不变 |
| G. 非 pstate 控制流落点 | ❌ 判死（H115+H138 双向闭合） | ❌ 不变 |
| A. 厂商 cdev ioctl | ❌ 判死（H121–H127） | ❌ 不变 |
| B. binder / binderfs | ❌ 判死（H128–H137） | ❌ 不变 |
| **E-L1. `rb_erase` 原语** | ⚠️ 冻结 | **★ 重开（CVE-2026-43499 的 dequeue 即它）** |
| **E-L2. `rt_mutex` 载波几何** | ⚠️ 冻结 | **★ 重开（CVE-2026-43499 本体）** |
| **H. posix-cpu-timers** | — | **★ 新面（CVE-2026-64560）** |
| D. `dma_heap/system` | ⚠️ 未测 | ⚠️ 未测（降优先级） |

---

## 六、下一步（候选）

### 路线 A（CVE-2026-43499 / rtmutex）—— 优先级最高

**理由**：①已存档 L1/L2 几何可直接复用 ②`rb_erase` 地址已确认为本机 `0xffffffc08003a9d4` ③公开 PoC 存在（成功率 97%）

需先解决的前置：
1. **shell 域可达性**：`futex(FUTEX_LOCK_PI / FUTEX_CMP_REQUEUE_PI)` 系统调用是否被 SELinux 拦（查 `u:r:shell:s0` 的 `allow` 规则）
2. 确认 `rt_mutex_start_proxy_lock` 回滚路径确实由 futex requeue 触发（需复读 `kernel/futex/requeue.c`）
3. 复用 H106 载波几何：帧 `0x290`；FPSIMD `0x200B` 拷贝目的地 = `SP0−0x280`；`SIGRETURN_WAITER_VREG_OFF=0xD0`(qword 26)
4. 单发单 boot 探针设计

### 路线 B（CVE-2026-64560 / posix-cpu-timers）

需构造 `non-leader exec()` + `timer_delete` 竞争。难度可能高于 A（需要精确时序），但可作为 A 的备选。

### 立即动作（下一步执行）

1. 反汇编 `futex_requeue` @ `0xffffffc0802c9f50` 与 `futex_lock_pi` @ `0xffffffc0802cb4a8`，确认 `rt_mutex_start_proxy_lock` 调用点
2. 检查 shell 域对 futex PI 的 SELinux 可达性
3. 复核 H106 载波几何存档（MEY-TECH §8–§11）

---

## 七、产物

| 文件 | 内容 |
|---|---|
| `analysis/scratch/dis_mey.py` | ★ 设备镜像反汇编器（capstone） |
| `analysis/output/h140_cve_device_verify.md` | 本报告 |

**未变更**：`boot_id = 2888f136-4ff1-487b-8d4c-58e02e1897e0`（本轮纯静态，无真机动作）

---

## 八、附录：H140 真机轮（futex 可达性实测）

### 8.1 真机结果（`tools/h140_futex_reach.c`，md5 `22f8b926728aca5386b4b61723dbbc71`）

```
=== h140_futex_reach uid=2000 ===
T1 FUTEX_WAKE          rc=0 errno=0(ok)
T2 FUTEX_LOCK_PI       rc=0 errno=0(ok)          ← PI 锁可达
T3 FUTEX_UNLOCK_PI     rc=0 errno=0(ok)
T4 FUTEX_LOCK_PI(dst)  rc=0 errno=0(ok)          ← dst 已持有
T5 CMP_REQUEUE_PI      rc=1 errno=0(ok)          ← ★ requeue 成功 1 个 waiter
--- verdict ---
boot_id BEFORE = 2888f136-4ff1-487b-8d4c-58e02e1897e0
boot_id AFTER  = 2888f136-4ff1-487b-8d4c-58e02e1897e0   （未变，无 panic）
```

**判定**：
- `T2==0` ⇒ **`FUTEX_LOCK_PI` 可达**（SELinux `u:r:shell:s0` **不拦** futex PI）
- `T5==1` ⇒ **`rt_mutex_start_proxy_lock()` 已被真实调用**（`futex_requeue` line 627 调用即在本轮发生）
- 但 `T5` 走的是 **`try_to_take_rt_mutex()→return 1`** 成功路径（`requeue.c:631`），**未走 `remove_waiter` 回滚分支**

### 8.2 完整触发链（设备镜像 + 源码双证）

```
用户态: futex(src, FUTEX_CMP_REQUEUE_PI, 1, val, dst, 0)   [T5 已实测可达]
  → do_futex @ 0xffffffc0801edfc0
    → futex_requeue @ 0xffffffc0802c9f50
      (0xffffffc0802ca35c) → rt_mutex_start_proxy_lock @ 0xffffffc081080df4
        → __rt_mutex_start_proxy_lock @ 0xffffffc081080570
          → try_to_take_rt_mutex @ 0xffffffc0810805e4   [T5 走这条，return 1]
          → task_blocks_on_rt_mutex @ 0xffffffc0810809c0   [★ 需走这条并失败]
        → remove_waiter @ 0xffffffc081080e60    [★ ret != 0 时才调用]
          → rb_erase @ 0xffffffc08003a9d4        [★ 本机 L1 原语地址]
          → str xzr, [current(sp_el0), #0x938]   [★ BUG: 写 current 而非 waiter->task]
```

源码行对照：
| 位置 | 源码 |
|---|---|
| `rtmutex_api.c:344-357` | `rt_mutex_start_proxy_lock()`；`if (unlikely(ret)) remove_waiter(lock,waiter);` |
| `rtmutex_api.c:297-323` | `__rt_mutex_start_proxy_lock()`；`ret = task_blocks_on_rt_mutex(..., RT_MUTEX_FULL_CHAINWALK)` |
| `rtmutex.c:1524-1536` | `remove_waiter()` 写 **`current`** 的 `pi_lock`/`pi_blocked_on` |
| `requeue.c:627-663` | 调用点；`ret<0`（非 0/1）时进入 `else` 分支 `this->pi_state=NULL; put_pi_state()` |
| `requeue.c:655-662` | 回滚后 `break`，返回 `ret`（负值）给用户态 |

### 8.3 触发缺口（下一步要解的）

**要走进 `remove_waiter`，必须让 `task_blocks_on_rt_mutex` 返回非零。** 该函数在以下情况返回非零：
- **`-EDEADLK`（`RT_MUTEX_FULL_CHAINWALK` 检测到 PI 链死锁）**

`futex` 强制 `RT_MUTEX_FULL_CHAINWALK`（`rtmutex_api.c:310`），所以**只要构造出 PI 死锁环，就会进入回滚路径**。

**构造思路（待验证）**：
1. 主线程：持 `lockA`（PI futex）
2. 线程 W：`FUTEX_LOCK_PI(lockA)` 阻塞 ⇒ `lockA` 的 waiter = W
3. 线程 X：`FUTEX_LOCK_PI(lockB)` 阻塞，且 **X 已持有 lockA 之外的某个锁**… 

若能在 chainwalk 中让 `task`（= requeue 的 waiter W）的 PI 链触达 `current`（requester），即形成环 ⇒ `-EDEADLK`。

### 8.4 下一步动作

1. 设计三线程 PI 死锁环（`lockA/lockB/lockC`），使 `FUTEX_CMP_REQUEUE_PI` 的 `rt_mutex_start_proxy_lock` 返回 `-EDEADLK`
2. 命中后立即观测：`remove_waiter` 是否写错对象 —— 由于 UAF 需要后续触发才能显形，**需要设计一个「独立透镜」判定 `pi_blocked_on` 悬垂**
3. 一次一个 boot，单发

---

## 九、H140 真机轮②：确定性触发 + 归因闭环（★ 本轮核心成果）

### 9.1 触发原理（源码 + 设备汇编双证）

**根因定位到源码 1 行**（`kernel/locking/rtmutex.c:1213`）：

```c
static int task_blocks_on_rt_mutex(lock, waiter, task, ww_ctx, chwalk)
{
    struct task_struct *owner = rt_mutex_owner(lock);
    ...
    if (owner == task && !(build_ww_mutex() && ww_ctx))
        return -EDEADLK;            // ★★★ 命中点
```

配合 `rtmutex_api.c:344-357`：
```c
int rt_mutex_start_proxy_lock(struct rt_mutex_base *lock, waiter, task)
{
    raw_spin_lock_irq(&lock->wait_lock);
    ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
    if (unlikely(ret))
        remove_waiter(lock, waiter);     // ★★★ BUG 点：waiter->task ≠ current
    raw_spin_unlock_irq(&lock->wait_lock);
    return ret;
}
```

**构造（确定性，零竞态）**：
| 步骤 | 动作 | 内核效果 |
|---|---|---|
| 1 | 线程 W：`FUTEX_LOCK_PI(dst)` 成功 | W = dst 的 rtmutex owner |
| 2 | 线程 W：`FUTEX_WAIT_REQUEUE_PI(src, dst)` | W 挂到 src 的 futex_q，`rt_waiter` 指向 dst 的 pi_mutex |
| 3 | 主线程：`FUTEX_CMP_REQUEUE_PI(src→dst)` | `futex_requeue` → `rt_mutex_start_proxy_lock(dst_pi_mutex, W.rt_waiter, W)` |
| 4 | — | `owner(dst_pi_mutex)` = **W** == `task` = **W** ⇒ **`-EDEADLK`** |
| 5 | — | ⇒ **`remove_waiter(dst_pi_mutex, W.rt_waiter)` 执行** ❌ |

**`remove_waiter()` 的错误**：写 **`current`**（= 主线程，requester）的 `pi_lock`/`pi_blocked_on`，而**应写 `waiter->task`（= W）**。⇒ W 的 `pi_blocked_on` 保持悬垂。

### 9.2 真机结果（`tools/h140b_deadlock.c`，md5 `78e6c6bf45819512641b31273d76a6b8`）

```
=== h140b_deadlock uid=2000 ===
[M] LOCK_PI(src)   rc=0 errno=0
[W] LOCK_PI(dst)        rc=0 errno=0(ok)
[M] W holds dst (phase=1)
[M] CMP_REQUEUE_PI src->dst  rc=-1 errno=35(Resource deadlock would occur)   ← ★★★ EDEADLK
[M]   ==> rc==-35(-EDEADLK) means remove_waiter() WAS called
[M] W wait_rc=-777 phase=1
[M] UNLOCK_PI(dst) rc=-1 errno=1(Operation not permitted)                    ← ★ PI 状态已扰动
boot_id BEFORE/AFTER = 2888f136-4ff1-487b-8d4c-58e02e1897e0（未变，无 panic）
```

### 9.3 差分归因（`tools/h140c_diff.c`，md5 `0935b377ed1f0330296809b6d85e8f11`）

**唯一变量：W 是否持有 dst。**

| 组 | W 持 dst | `CMP_REQUEUE_PI` | 路径 | 结论 |
|---|---|---|---|---|
| **D0 对照** | ❌ | `rc=1`（成功） | `try_to_take_rt_mutex→1`（`requeue.c:631`） | **不进回滚** |
| **D1 实验** | ✅ | `rc=-1 errno=35 EDEADLK` | `task_blocks_on_rt_mutex→-EDEADLK` ⇒ **`remove_waiter()`** | **★ 进回滚** |

真机输出：
```
--- D0 CONTROL  (W does NOT hold dst) (W holds dst = 0) ---
   [M] CMP_REQUEUE_PI rc=1 errno=0(ok)
   [M] ==> success : normal path (no rollback)
   [W] WAIT_REQUEUE_PI rc=0 errno=0(ok)
   [M] W rc=0 phase=2
--- D1 TREATMENT(W holds dst) (W holds dst = 1) ---
   [W] LOCK_PI(dst) rc=0 errno=0
   [M] CMP_REQUEUE_PI rc=-1 errno=35(Resource deadlock would occur)
   [M] ==> -EDEADLK : remove_waiter() rollback path TAKEN
   [M] W rc=-777 phase=1
```

**归因成立**：唯一变量完美解释结果差异 ⇒ `-EDEADLK` 确由 `owner == task` 引发 ⇒ `remove_waiter()` 确已被执行。

### 9.4 置信度评定

| 结论 | 置信度 |
|---|---|
| CVE-2026-43499 在设备上**未修复**（`remove_waiter` 用 `sp_el0`/current） | **已实测**（设备镜像反汇编） |
| `futex(FUTEX_LOCK_PI / CMP_REQUEUE_PI)` 在 shell 域**可达** | **已实测**（真机 T2/T5） |
| `rt_mutex_start_proxy_lock` → `remove_waiter` 回滚路径**可确定性触发** | **已实测**（真机 EDEADLK） |
| EDEADLK 归因于 `owner == task` | **已实测**（差分 D0/D1） |
| UAF 已实际发生（悬垂 `pi_blocked_on`） | **汇编已证未实测**（未构造后续访问观测） |
| 可提权到 root | **未验证** |

### 9.5 下一步

1. **独立透镜**：requeue 后主动 wake W，让 W 继续 PI 操作 ⇒ 观测悬垂 `pi_blocked_on` 是否被消费
2. 复用 H106 载波几何做写原语（`rb_erase` @ `0xffffffc08003a9d4` 已确认）
3. 备选路线：CVE-2026-64560（posix-cpu-timers，同样未修复）

---

## 十、H140 真机轮③：内核状态破坏的独立透镜实证（★ 证据链闭环）

### 10.1 透镜设计

**问题**：EDEADLK 返回只证明「进了回滚分支」，**不证明内核状态真被破坏**。需要独立透镜。

**透镜原理**（纯用户态可观测）：
- `remove_waiter()` 的 bug 是「dequeue 了 waiter，但清的是 `current->pi_blocked_on` 而非 `waiter->task->pi_blocked_on`」
- ⇒ `src` rtmutex 的 rb-tree 节点被 `rb_erase` 移除，但 **W 的 futex_q/pi_state 残留**
- ⇒ 事后对 **同一个 src** 做 `FUTEX_LOCK_PI` 时，内核从用户态值反查 `pi_state`，
  `pi.c:294 if (pid != task_pid_vnr(pi_state->owner)) goto out_einval;`
  ⇒ owner 记录与用户态值不匹配 ⇒ **返回 -EINVAL**

### 10.2 真机结果（`tools/h140e_ctrl.c`，md5 `17971166433f76b1bda6cc2c0e34da09`）

```
=== h140e_ctrl uid=2000 ===
--- C0 BASELINE (no requeue) ---
   [C0] post LOCK_PI(src) rc=0 errno=0(ok)
--- C1 CONTROL  (requeue, W no dst) ---
   requeue rc=1 errno=0(ok)
   [C1 CONTROL  (requeue, W no dst)] post LOCK_PI(src) rc=0 errno=0(ok)
--- C2 TREATMENT(requeue, W dst) ---
   requeue rc=-1 errno=35(Resource deadlock would occur)
   [C2 TREATMENT(requeue, W dst)] post LOCK_PI(src) rc=-1 errno=22(Invalid argument)
boot_id BEFORE/AFTER = 2888f136-4ff1-487b-8d4c-58e02e1897e0（未变）
```

### 10.3 结论

| 组 | 场景 | requeue | 事后 `LOCK_PI(src)` | 判定 |
|---|---|---|---|---|
| C0 | 不跑 requeue | — | `rc=0` | 基线正常 |
| C1 | requeue 成功 | `rc=1` | **`rc=0`** | 正常路径**不**破坏状态 |
| C2 | requeue EDEADLK | `rc=-1` | **`rc=-1 EINVAL`** | **★ bug 路径破坏状态** |

**三组唯一差别 = 是否走进 `remove_waiter()`** ⇒ **EINVAL 与 bug 路径因果绑定**。

**⇒ 内核 PI 状态被破坏，已由独立透镜（另一 syscall 的返回码变化）实证，非循环自证。**

### 10.4 附带发现：W 永久阻塞

```
[M] FUTEX_WAKE(src) rc=-1        ← 普通 WAKE 无法唤醒挂在 PI 队列的 W
[M] W final: r2=-777 r3=-777 phase=1   ← W 永久阻塞
```

**机制**（源码 `requeue.c:139-141`）：deadlock 分支 `futex_requeue_pi_complete(q, ret<0)` 把 `requeue_state` 置 `Q_REQUEUE_PI_NONE`，且 `break` 后 `wake_up_q(&wake_q)` 的队列里**没有 W**（W 的 futex_q 从未 `futex_wake_mark`）。而 `remove_waiter` 又清了错的对象的 `pi_blocked_on` ⇒ **W 无法被任何路径唤醒** ⇒ 永久 D 状态。

**这本身是第二个独立副作用**（DoS 面），且**与 bug 同源**。

### 10.5 ★★ CVE-2026-43499 完整证据链（全部已实测）

| # | 环节 | 判据 | 状态 |
|---|---|---|---|
| 1 | 设备**未修复** | 镜像反汇编 `remove_waiter` 用 `sp_el0`（current），非 `waiter->task` | ✅ 已实测 |
| 2 | shell 域**可达** | `FUTEX_LOCK_PI`/`CMP_REQUEUE_PI` rc=0 | ✅ 已实测 |
| 3 | 触发链**存在** | `do_futex`→`futex_requeue`→`rt_mutex_start_proxy_lock`→`remove_waiter` 全符号在设备 | ✅ 汇编已证 |
| 4 | **确定性触发** | EDEADLK（零竞态，无需 race） | ✅ 已实测 |
| 5 | **归因闭环** | 差分 D0(rc=1) vs D1(rc=-35)，唯一变量=W持dst | ✅ 已实测 |
| 6 | **状态破坏实证** | C0/C1 `LOCK_PI(src)`=0 vs C2=-EINVAL | ✅ 已实测 |
| 7 | 附带 DoS | W 永久阻塞（无法唤醒） | ✅ 已实测 |
| 8 | 转化为写原语 | 尚需构造（`rb_erase` @ `0xffffffc08003a9d4`） | ⏳ 待做 |
| 9 | 提权到 root | 尚需构造 | ⏳ 待做 |

### 10.6 与 L1/L2 存档原语的合流

| 项 | 值 | 状态 |
|---|---|---|
| `rb_erase`（设备） | `0xffffffc08003a9d4` | 与 memory 记录一致 |
| `remove_waiter` 内 `rb_erase` 调用点 | `0xffffffc08003a9d4`（`+0xdc bl`） | **★ 同址，合流确认** |
| `current->pi_blocked_on` 偏移 | `0x938`（写 `sp_el0+0x938`） | 本机实测 |
| `current->pi_lock` 偏移 | `0x90c` | 本机实测 |
| H106 载波几何（帧 0x290 等） | 见 MEY-TECH §8–§11 | 可复用 |

**⇒ CVE-2026-43499 的攻击面 = 冻结中的 L1/L2 存档原语线，现由 CVE 编号正式解冻。**

---

## 十一、H141 修正：D1 是「伪环」，真实触发需三 futex 环

### 11.1 ★ 上一轮的错在哪（重要更正）

`h140c`/`h140e` 用的 D1 构造（**W 自己持有 dst**）命中的是 `rtmutex.c:1213` 的**早退分支**：

```c
if (owner == task && !(build_ww_mutex() && ww_ctx))
    return -EDEADLK;        // ★ 此处 return，尚未执行下面两行
...
rt_mutex_enqueue(lock, waiter);      // line 1226 —— 未执行
task->pi_blocked_on = waiter;        // line 1228 —— 未执行
```

⇒ **waiter 从未入队（`RB_EMPTY_NODE` 为真）、`pi_blocked_on` 从未被设置**。

于是 `remove_waiter()` 内：
```c
rt_mutex_dequeue(lock, waiter) {
    if (RB_EMPTY_NODE(&waiter->tree.entry))
        return;                       // ★ 守卫命中，rb_erase 根本不执行
    ...
}
current->pi_blocked_on = NULL;        // 写 current（本为 NULL），无害
```

**⇒ D1 是「走了 remove_waiter 函数体，但两条关键操作都空转」的伪环。**
它证明的只是「`remove_waiter` 可被调用」，**不能**推出「悬垂指针已产生」——上一轮报告 §10.5 第 6 行的「状态破坏实证」应降级为「函数被调用实证」。

### 11.2 真实触发形态（公开材料 + 源码双证）

Nebula Security 披露原文（`nebusec.ai/buglist/CVE-2026-43499`）：

> Reaching the rollback needs a **PI dependency cycle across three futex words and three threads** (`waiter -> f_pi_target -> owner -> f_pi_chain -> waiter`), which closes on its own once staged. After that there is no time pressure: a follow-up **`sched_setattr()`** walks the chain through the task whenever it likes, and dereferences the dangling pointer.

**关键差异：**

| 项 | 我的 D1（伪环） | 真实触发（三环） |
|---|---|---|
| `-EDEADLK` 来源 | `rtmutex.c:1213` 早退 | **`rt_mutex_adjust_prio_chain` 返回**（line 1283-1288） |
| waiter 是否入队 | ❌ 从未 | ✅ line 1226 已入队 |
| `task->pi_blocked_on` | ❌ 从未设置 | ✅ line 1228 已设置 |
| `rb_erase` 是否执行 | ❌ 守卫拦截 | ✅ **真执行** |
| 悬垂指针 | 无 | ✅ **W 返回后 `pi_blocked_on` → 已释放栈帧** |

### 11.3 `pi_blocked_on` 的消费点（源码定位）

`pi_blocked_on` 全树仅 17 处引用。**UAF 读**发生在：

| 位置 | 代码 | 语义 |
|---|---|---|
| `rtmutex.c:587` | `return p->pi_blocked_on ? p->pi_blocked_on->lock : NULL;` | `task_blocked_on_lock()` ⇒ **解引用 UAF** |
| `rtmutex.c:722` | `waiter = task->pi_blocked_on;` | `rt_mutex_adjust_prio_chain` 主循环 ⇒ **UAF 读** |
| `rtmutex.c:752` | `if (next_lock != waiter->lock)` | 解引用 waiter->lock ⇒ **UAF 读** |
| `rtmutex_api.c:466` | `waiter = task->pi_blocked_on;` | `rt_mutex_cleanup_proxy_lock` |
| `rtmutex_api.c:493` | `DEBUG_LOCKS_WARN_ON(task->pi_blocked_on);` | 仅 debug |

**入口**：`rtmutex.c:1022` / `896` / `1263` / `1555` 四处 `task_blocked_on_lock()`。

**触发消费的用户态入口**（公开材料）：**`sched_setattr()`**（`sched/core.c:8260`）
⇒ `__sched_setscheduler` ⇒ PI 传播 ⇒ `rt_mutex_adjust_prio_chain` ⇒ `task_blocked_on_lock(W)` ⇒ **UAF 读**。

### 11.4 下一步（路线修正）

1. **构造真三 futex 环**：`waiter -> f_pi_target -> owner -> f_pi_chain -> waiter`
2. 确认 `-EDEADLK` 由 `rt_mutex_adjust_prio_chain` 返回（而非 line 1213 早退）—— 判据：**W 返回用户态**（而非永久阻塞）
3. **消费**：`sched_setattr(W, ...)` 触发链遍历 ⇒ 观测 UAF 读（SIGSEGV/panic/boot_id 变化）
4. 确认 shell 域 `sched_setattr` 可达性（同进程线程 vs 跨进程）

### 11.5 公开利用链（供参考，非本机验证）

```
① preload 探测       → 泄露 kernel slide + physmap base（prefetch 侧信道）
② GhostLock          → W 的 pi_blocked_on 悬垂指向已释放栈帧
③ 栈 UAF 重占        → 用 PR_SET_MM_MAP 的 user_auxv 缓冲重占该栈区，伪造 rt_mutex_waiter
④ 一次约束写         → rtmutex rb-tree erase 把 CEA 指针写进 inet6_protos[IPPROTO_UDP]
⑤ 控制流劫持         → loopback IPv6 UDP 包经被覆盖的 handler 分派 → CEA 中的 ROP
⑥ DirtyMode          → 单次写翻转 core_pattern 的 mode bits ⇒ 用户态取 root
```
公开 PoC：`github.com/Linuxoid-cn/CVE-2026-43499-Poc-Analysis`（Android arm64，LD_PRELOAD 形态）
