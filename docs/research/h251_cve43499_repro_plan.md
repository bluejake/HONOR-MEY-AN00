# H251 · CVE-2026-43499 复现方案（KernelSU 在场版）

> 日期：2026-10-06 · 设备：MEY-AN00（`A22C026319001339`）· 内核 `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`
> 用户决策：**保留 KernelSU** · **先打 43499** · **先出方案再执行**
> 本轮 boot 消耗：**0**（纯离线 + 反汇编 + 日志核实）

---

## ★★ 一句话结论

**参考实现（`refs/cve-2026-43499-honor`）依赖 pselect 固定栈偏移做「路由」，而本机 `RANDOMIZE_KSTACK_OFFSET=y` 运行时生效 ⇒ 该机制在本机不可直接用。**
**但漏洞触发点（`rt_mutex_start_proxy_lock` 失败分支）已被本轮反汇编精确定位，且不经 EDEADLK ⇒ 可绕开 `h105` 报告的硬化点。**
**⇒ 复现路径 = 「触发可达（阶段1）→ 链健康度（阶段2）」，而「任意写」需要绕开栈随机化的新机制。**

---

## 0. 先纠正一个前提（最重要）

### 0.1 设备上的 root 来源 = KernelSU，不是本项目 CVE

| 证据 | 内容 |
|---|---|
| `dmesg_uid0_boot95f49e33.txt` | `[15206:sh]KernelSU: newfstatat su->ksud!` / `faccessat su->ksud!` |
| 同上 | `[15208:sh]KernelSU: sys_execve su found` → `ksu fd installed: 3 for pid 15208` |
| 同上 | `[13255:ksud]KernelSU: tp_marker: unmark process` × 数十条 |
| `grep '43499\|64560\|rt_mutex\|pi_blocked' dmesg` | **0 命中** ⇒ 无本项目 CVE 链痕迹 |

⇒ **`su` 之所以能用，是 KernelSU 给的，与本项目研究的 CVE 链完全无关。**

### 0.2 这对「复现 43499」的影响（必须写清，否则结论无效）

| 验证环节 | KernelSU 是否污染 | 可行性 |
|---|---|---|
| ① 读镜像 / 反汇编 / 符号对账 | ❌ 不污染 | ✅ 完全可行（纯离线） |
| ② **A/D 二元判据**（测 PI 链健康度） | ❌ 几乎不污染 | ✅ 可行 —— 判据是「**存活 vs panic**」，**不是 uid0**，故 KernelSU 无法冒充 |
| ③ 载体穷尽（waiter 能否落到目标槽位） | ❌ 不污染 | ✅ 可行 |
| ④ **写原语落地**（魔数写入 TARGET 并独立回读） | ❌ 不污染 | ✅ 可行 —— 判据是「**目标地址变成魔数**」，与 uid0 无关 |
| ⑤ **真提权到 uid0** | ✅ **严重污染** | ❌ **不可行** —— KernelSU 也在 cred/execve 路径上 |

★★ **结论：43499 的验证工作可以做到 ④ 为止，全部在 KernelSU 在场时安全进行且结论有效。只有 ⑤ 需要干净内核。**
这正好落在用户的授权范围内（保留 KernelSU + 先出方案）。

---

## 1. 漏洞机制（本轮新反汇编取证）

### 1.1 ★ 漏洞触发点确认（本轮新证）

```
rt_mutex_start_proxy_lock @0xffffffc081080df4:      ← kallsyms: T
  0xffffffc081080e14:  bl   #0xffffffc081083444
  0xffffffc081080e24:  bl   #0xffffffc081080570    ← 内部实现，返回 w0
  0xffffffc081080e28:  mov  w21, w0
  0xffffffc081080e2c:  cbnz w0, #0xffffffc081080e50 ← w0 != 0 ⇒ 失败分支
  ...
  0xffffffc081080e50:  mov  x0, x19               ← lock
  0xffffffc081080e54:  mov  x1, x20               ← waiter
  0xffffffc081080e58:  bl   #0xffffffc081080e60   ← ★★ remove_waiter(lock, waiter)
```

★★ **这就是漏洞场景的完整落点**：`rt_mutex_start_proxy_lock` **失败**时调 `remove_waiter(lock, waiter)`，而此时 `waiter` 属于**另一个线程**（代理锁语义：waiter 是给 owner 用的，不是给 current 用的）。

### 1.2 漏洞本质

```
remove_waiter @0xffffffc081080e60（size 0x26c，kallsyms: t）
  0xffffffc081080e98:  mrs  x20, sp_el0            ← x20 = current  ★ 不是 waiter->task!
  0xffffffc081080e9c:  add  x21, x20, #0x90c       ← &current->pi_lock
  0xffffffc081080ea8:  bl   _raw_spin_lock
  0xffffffc081080edc:  bl   rb_erase               ← ★ rt_mutex_dequeue 内联
  0xffffffc081080ee8:  str  xzr, [x20, #0x938]     ← ★★ current->pi_blocked_on = NULL
  0xffffffc081080eec:  bl   _raw_spin_unlock
```

**上游修复**（commit `3bfdc63936dd`，标题即答案）：
> *"rtmutex: Use waiter::task instead of current in remove_waiter()"*

| | 漏洞版（本机） | 已修版 |
|---|---|---|
| 取 task | `mrs x20, sp_el0` = `current` | `ldr xN, [waiter, #0x50]` = `waiter->task` |
| 清零基址 | `x20`（与锁基址**同源**） | 另一个寄存器（从入参 `x1` 派生） |
| 全函数 `#0x50` 命中 | **0**（阳性对照：`rt_mutex_adjust_pi` 1、`task_blocks_on_rt_mutex` 3） | — |

**后果**：代理场景下 `waiter->task->pi_blocked_on` **未被清零**，仍指向该 waiter。若该 waiter 所在内存被释放/重用 ⇒ **`pi_blocked_on` 成为悬垂指针**（UAF）。

### 1.3 ★ 清零值 = `waiter->task->pi_blocked_on`（利用入口）

- `waiter->task` 是**目标线程的 task_struct**
- `pi_blocked_on` 偏移 **`0x938`**（BTF ↔ 汇编三方对账：`str xzr,[x20,#0x938]`）
- ⇒ 本漏洞的**原语是「把某个 task_struct 的 `+0x938` 清零」**，而**清零基址写的是 current 而非 waiter->task**

⇒ 利用方向：**让 `current` 指向一块我可控/可预测的内存**，则 `[current + 0x938] = 0` 就变成**任意地址清零**（写 0）。

---

## 2. 三道关卡的真实状态（h105 vs R9 的裁决）

`h105`（10-05 10:29）与 `R9`（10-06 17:00）在**消费器**问题上给出矛盾方向。**本节裁决以 R9 为准**（R9 更晚、且建立在 kstack 随机化实证之上）。

| # | 关卡 | h105 判定 | ★ R9 裁决 | 依据 |
|---|---|---|---|---|
| ① | 漏洞存在性 | ✅ 存在 | ✅ **维持**（更强化：`remove_waiter` 漏洞变体汇编已证） | `remove_waiter` 全函数 0 条 `#0x50` |
| ② | UAF 触发 | ❌ `rt_mutex_slowlock` 有 `brk #0x800` 硬化 | ⚠️ **换路径**：改从 `rt_mutex_start_proxy_lock` 失败分支进（§1.1 新证，**不经 EDEADLK**） | 本轮反汇编 |
| ③ | 栈回收（pselect 覆盖） | ❌ 几何错位，`waiter->lock` 落归零区 | ☠️ **进一步判死**：`CONFIG_RANDOMIZE_KSTACK_OFFSET=y` **运行时生效** ⇒ **一切固定栈偏移作废** | `invoke_syscall@+0x8c` smoking gun |
| ④ | 写目标基址 | ⚠️ `selinux_state` 被证伪 | ⚠️ **需重定位**；且本原语是**写 0**，不是写任意值 | — |

★★ **R9 的关键转折**：kstack 随机化把「栈几何」路线全灭，但 43499 的原语是 **`current->pi_blocked_on = 0`，属「纯数据流」类** ⇒ **不受随机化影响**。⇒ 路线从「栈覆盖」转向「**数据流写 0**」。

---

## 3. ★ 复现方案（三段，按风险递增）

### 3.1 阶段 1：漏洞触发确认（零风险，纯观测）

**目标**：证明 `rt_mutex_start_proxy_lock` 失败分支可被用户态到达（这是漏洞的必要条件）。

**方法**：`FUTEX_LOCK_PI` + `FUTEX_CMP_REQUEUE_PI` 组合，构造「代理锁启动失败」。触发条件是：
- 目标 futex 的 owner 状态与期望不符（`uaddr2` 指向的锁 owner 已被改）
- 或 waiter 与 owner 形成自锁（`waiter->task == owner->task`）

**关键 syscall**：
```
syscall(SYS_futex, uaddr2, FUTEX_CMP_REQUEUE_PI, 1, 0, uaddr1, val3)
```
其中 `val3` 与 `*uaddr1` 不匹配 ⇒ `rt_mutex_start_proxy_lock` 返回失败 ⇒ 进 `remove_waiter`。

**判据（必须同 boot 内回读，禁止跨重启）**：
1. **独立透镜**：读 `boot_id`（`sysctl_bootid`）；`uptime`；`history.log` 无新增条目
2. **存活** = 触发成功但未崩 ⇒ 证明失败分支可达且 `remove_waiver` 被调用
3. **反证** = panic 且 `history.log` 新增 `page_request`/`null_pointer` ⇒ 定位到崩溃点判断走的是哪一支

**风险**：低。panic 由 `PANIC_ON_OOPS=1` 强制，但**一 boot 一发**纪律下可接受。

---

### 3.0 ★ 触发条件已精确化（本轮反汇编新证，置于 3.1 之前）

完整调用链（全部 kallsyms 实名核对）：

```
rt_mutex_start_proxy_lock @0xffffffc081080df4           [kallsyms: T]
  └─ __rt_mutex_start_proxy_lock @0xffffffc081080570    [T]
       ├─ try_to_take_rt_mutex @0xffffffc0810805e4      [t]
       │    0xffffffc081080598: bl   try_to_take_rt_mutex
       │    0xffffffc08108059c: cbnz w0, +0x30         ← 非0 ⇒ 返回1（拿到锁=成功）
       └─ task_blocks_on_rt_mutex @0xffffffc0810809c0   [t]   w3=1 (FULL_CHAINWALK)
            0xffffffc0810805b0: bl   task_blocks_on_rt_mutex
            0xffffffc0810805b4: cbnz w0, +0x20         ← 非0 ⇒ 返回1（失败）
  ★ 0xffffffc081080e2c: cbnz w0, #0xffffffc081080e50   ← 失败 ⇒ 进 remove_waiter
  ★ 0xffffffc081080e58: bl   remove_waiter @0xffffffc081080e60
```

⇒ **唯一触发条件 = `task_blocks_on_rt_mutex(lock, waiter, task, 1)` 返回非 0。**

**返回非 0 的路径**：

| 返回点 | 条件 | 可达性 |
|---|---|---|
| `0xffffffc081080d90: mov x1, xzr` → `0xffffffc081080af0` | `owner == task` **自锁** | ★ 用户态可构造，**确定性** |
| `0xffffffc081080b28: mov w0, w20` → `ret` | 主返回，`w20` = 链走结果 | 取决于参数 |

★★ **关键区分（决定能否构成 UAF）**：

| 场景 | `current` | `waiter->task` | 清零对象 | 是否 UAF |
|---|---|---|---|---|
| **自锁**（T 持锁，T 自己 requeue） | T | T | T 的 `pi_blocked_on` | ❌ **不是**（同一对象，清对了） |
| **跨线程代理**（A 持锁，waiter 属 B） | A | B | **A** 的 `pi_blocked_on` | ✅ **是**（B 悬垂） |

⇒ **必须走「跨线程代理」**：`FUTEX_CMP_REQUEUE_PI` 由持锁线程 A 调用，而被 requeue 的 waiter 属于线程 B ⇒ `current=A ≠ waiter->task=B` ⇒ **B 的 `pi_blocked_on` 未清 ⇒ B 悬垂 ⇒ UAF**。

**构造要点（离线可验证部分）**：
- `syscall(SYS_futex, uaddr2, FUTEX_CMP_REQUEUE_PI, 1, 0, uaddr1, val3)`
- `uaddr1` = 被 requeue 的 futex（B 在其上等待）；`uaddr2` = 目标 PI 锁（A 持有）
- 需让 `task_blocks_on_rt_mutex` 返回非 0 ⇒ 走 `owner == task` 支或链走失败支

---

### 3.2 阶段 2：★ A/D 二元判据 —— 测 PI 链健康度（本轮最推荐）

**来源**：`R0` §「dc15 未消化细节」第 1 条，**本项目最该继承的方法论**。

**原理**：
- 对 owner 开火（`sched_setattr` 改 nice），使 `p->prio ≠ waiter->tree.prio`
- ⇒ PI 链的闸门**必不匹配** ⇒ 走链
- **存活 ⇒ 链健康；panic ⇒ 链被 dance 弄坏**
- ★ **不需要 plant 就能测链健康度**

**价值**：
- 直接决定后续「数据流写」路线是否可行
- 单发实验 = **最高信息密度**
- 判据是「存活 / panic」，**与 uid0 无关 ⇒ KernelSU 无法污染**

**判据**：
| 结果 | 含义 |
|---|---|
| 存活 | PI 链健康 ⇒ 可继续阶段 3 |
| panic | 链已坏 ⇒ 先修链，别再往下走 |

**风险**：中低（可能 panic）。

---

### 3.3 阶段 3：写原语落地验证（到「魔数写入」为止，不碰 cred）

**目标**：证明 `[current + 0x938] = 0` 这个写原语**真的落地**。

**方法**：
1. 选一个**已知地址、可独立回读、且写 0 无副作用**的 TARGET
2. 让 `current`（即触发线程的 task_struct）的 `+0x938` 落在 TARGET ⇒ 实为「让 TARGET 被写 0」
3. **独立通道回读** TARGET，确认变成 0

#### ★ 3.3.1 TARGET 选址预研（本轮完成，零设备）

| 候选 | 地址 | 类型 | 可回读通道 | 写 0 副作用 | 评级 |
|---|---|---|---|---|---|
| **`sysctl_bootid`** | `0xffffffc0823db420` | `b` | ★ **10-04 链已实战验证**（`STAGEB_STAGE0_CHANNEL ... text=90b0292a`）；`cat /proc/sys/kernel/random/boot_id` | 仅改 boot_id 字符串 ⇒ **可接受** | ★★★ **首选** |
| `modules_disabled` | `0xffffffc08239b970` | `B` | `cat /proc/sys/kernel/modules_disabled` | ⚠️ **不可逆**（置 0 后不能再禁模块，但**本机禁不了模块**故影响小） | ★★ 备选 |
| `kptr_restrict` | `0xffffffc08217bcf8` | `D` | `cat /proc/sys/kernel/kptr_restrict` | ⚠️ 写 0 会**放宽** kptr 限制 ⇒ 有副作用但**对我们有利** | ★★ 备选 |
| `selinux_state` | `0xffffffc0823ba418` | `B` | `getenforce` | ❌ **真提权**，阶段 4 才可碰 | ⏸ 阶段 4 |

★ **首选 `sysctl_bootid`** 的三条理由：
1. **已有实战先例**（10-04 链用它做写验证独立透镜，实证可行）
2. **回读通道完全独立**（另一个进程 `cat /proc/sys/kernel/random/boot_id`，不依赖任何我们自己的内核内存）
3. **写 0 的后果可控**（只影响 boot_id 显示，不影响系统行为；且 boot_id 本来就是随机的）

**几何要求**（离线算术，零设备）：

```
原语写地址 = current + 0x938
要写 sysctl_bootid(0xffffffc0823db420) ⇒ 需 current = 0xffffffc0823daae8
```

⚠️ **`0xffffffc0823daae8` 是 `.bss` 内的地址（非真实 task_struct）** ⇒ 本方案需要**先在 `.bss` 内构造/定位一个"伪 current"**，或改用其它机制让 `current` 可控。

★★ **这是阶段 3 的核心技术难点，也是本轮暴露出的最大未知**：
- 若 `current` 恒为真实 task_struct ⇒ 写的是真 `task_struct+0x938` ⇒ **只能改自己/别人的 `pi_blocked_on`**，无法任意地址写
- ⇒ **必须找到让 `current` 可控的路径**（如 `sp_el0` 劫持、或 UAF 后被重用的 task_struct）

⇒ **建议在阶段 1/2 之后再决定阶段 3 的具体形态**，因为阶段 2 的 A/D 判据会告诉我们「链是否健康」，而「current 可控性」可能需要**另一条独立漏洞或原语**配合。

**判据（h105 §6 模板，沿用）**：
1. **写原语生效（独立透镜）**：TARGET 变成预期值（此处是 0）
2. **不崩**：`boot_id` 不变 + uptime 未归零 + `history.log` 无新增
3. **反证**：panic 且定位到 `raw_spin_lock(&lock->wait_lock)` ⇒ 消费器走错

⚠️ **本阶段不写 cred、不碰 `selinux_state`** ⇒ 不会与 KernelSU 冲突，也不会提权（提权是阶段 4）。

**风险**：中（可能 panic，但可通过 TARGET 选择控制副作用）。

---

### 3.4 阶段 4（★ 需摘 KernelSU）—— 真提权

**必须摘掉 KernelSU 才能进行**，理由见 §0.2。

**目标**：`uid == 0` + `getenforce != Enforcing` + 一次受保护写。

**候选写目标**：
| 目标 | 说明 | 代价 |
|---|---|---|
| `task_struct.cred` / `real_cred` | 指向 `init_cred` | **需两次写 = 两个 boot** |
| `selinux_state` | 置 false ⇒ Permissive | 需重定位（H99 已证伪 `0x23ba418`） |
| `modprobe_path` | 10-04 链已证明**能改写**（`MP_SET_OK`），但触发端 `errno=10` | 触发问题未解 |

⚠️ **本原语是「写 0」**，所以：
- 写 `cred` 字段：不能直接写「`&init_cred`」这个非零值 ⇒ **需配合其它原语或用 0 值达成目标**（如把 `cred->uid` 写 0 —— 但 `kuid_t` 是 32 位，写 8 字节 0 会同时清掉相邻字段，**需精确核对布局**）
- ★ **这是阶段 3 之后必须重新设计的一环**

---

## 4. 执行顺序与授权边界

| 阶段 | 风险 | 是否需摘 KernelSU | 授权状态 |
|---|---|---|---|
| 1. 触发确认 | 低 | ❌ 不需要 | ✅ 已在授权内 |
| 2. A/D 判据 | 中低 | ❌ 不需要 | ✅ 已在授权内 |
| 3. 写原语落地 | 中 | ❌ 不需要 | ✅ 已在授权内 |
| 4. 真提权 | 中高 | ✅ **需要** | ⏸ **待你单独授权** |

**每阶段纪律**：
- 一 boot 一发
- 独立透镜（`boot_id` + `history.log`）
- 上机前验二进制（md5 + 关键字符串）
- 0 命中必做阳性对照

---

## 5. 需要在阶段 3 之前离线完成的事（零风险，可立即做）

| # | 事项 | 产出 |
|---|---|---|
| 1 | **TARGET 选址**：找一块「写 0 无副作用 + 可独立回读」的内核内存 | 候选列表 |
| 2 | **`current + 0x938` 可达性**：确认能否让触发线程的 task_struct 落在预期位置 | 几何分析 |
| 3 | **载体穷尽**：`D − B = 0x1B0` 且 ≥0x60 可控的对齐候选（h105 §7 第 4 条遗留） | 全量 `__arm64_sys_*` 帧扫描 |
| 4 | **`rt_mutex_start_proxy_lock` 失败条件**精确化：反汇编 `0xffffffc081080570` 的返回判据 | 触发参数表 |
| 5 | **`cred` 布局核对**：写 0 对 `kuid_t uid` 的影响（是否波及 `gid`/`suid`） | 布局表 |

★ 以上 5 项**全部离线可做，0 boot 消耗**。建议先做完再上机。

---

## 8. ★★★ 参考实现机制对照（本轮新读，决定方案形态）

来源：`refs/cve-2026-43499-honor/exploit/exploit/src/`（Honor BVL-AN16 / 6.1.128 移植版，23/26 符号直接命中）

### 8.1 真实利用拓扑（`main.c`，与我的初版推测不同）

```c
waiter_thread:
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, ...)                        ← 先持 chain 锁
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
           &f_pi_target, 0)                                        ← ★ WAIT_REQUEUE_PI
  do_pselect_fake_lock_route()                                     ← ★★ 用 pselect 做 fake lock 路由
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, ...)

owner_thread:
  futex_op(&f_pi_target, FUTEX_LOCK_PI, ...)                       ← 持 target 锁
  futex_op(&f_pi_chain,  FUTEX_LOCK_PI, ...)                       ← ★ 再抢 chain ⇒ 形成 PI 环
```

★ **关键**：`FUTEX_WAIT_REQUEUE_PI` + `FUTEX_LOCK_PI` 双向持有 ⇒ **构造 PI 链环** ⇒ 使 `rt_mutex_start_proxy_lock` / 链走失败 ⇒ **进 `remove_waiter`**（与 §3.0 的触发点吻合 ✅）。

### 8.2 ★★★ 路由机制 = pselect fd_set 位图写内核栈（**这是本机不可用的核心**）

```c
// fops.c:73-86
void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  fdset_put_word(in, 0, fake_w0);
  fdset_put_word(ex, 0, text_addr(INIT_TASK));   ← ★ 直接写字面内核地址
  fdset_put_word(ex, 1, fake_lock);
  fdset_put_word(ex, 2, 3);
}
// fops.c:46-48  —— 就是把 64 位值直接写进 fd_set 位图
void fdset_put_word(fd_set *set, int word, uint64_t value) {
  ((unsigned long *)set)[word] = (unsigned long)value;
}
```

**机制**：`pselect6` 的 `in/out/ex` 三个 fd_set 由 `copy_from_user` 拷到 `core_sys_select` 的**栈上 `stack_fds` 数组**。而 `futex_wait_requeue_pi` 的 `waiter` 恰好落在同一内核栈的固定相对位置（`h105` 实测 **`waiter = stack_fds + 0x50`**，即 `PSELECT_WORD_SHIFT = 10`）。

⇒ **`fdset_put_word(ex, 0, ...)` = 写 `waiter+0x00`** ⇒ 精确伪造 `waiter` 的三个关键字段。

### 8.3 ★★ 对本机（MEY-AN00）的决定性影响

| 项 | 参考实现（BVL-AN16，6.1.128） | 本机（MEY-AN00，6.6.118） |
|---|---|---|
| `RANDOMIZE_KSTACK_OFFSET_DEFAULT` | 未设 ⇒ **栈偏移固定** | 未设，但 **R9 实测 `CONFIG_RANDOMIZE_KSTACK_OFFSET=y` 运行时生效** |
| `invoke_syscall` 改 SP | 无（或未生效） | ★ `ldr w8,[x8,&kstack_offset]` → `sub sp,x8` → `mov sp,x8` |
| pselect 路由可行性 | ✅ 可用（固定偏移 `+0x50`） | ☠️ **作废**（每次 syscall SP 随机偏移 0..1023 页，16B 对齐） |
| 参考实现中有无应对代码 | — | **`grep -iE 'kstack\|RANDOMIZE_KSTACK\|sp_el0'` → 0 命中** ⇒ 作者未处理 |

★★★ **结论**：
1. 参考实现的**路由**（`do_pselect_fake_lock_route`）是它整个链条的**基石**——没有它就无法把伪造 waiter 精确投放到内核栈
2. 本机 kstack 随机化 ⇒ **这块基石作废** ⇒ **参考实现不能直接移植**
3. 但参考实现的**触发拓扑**（§8.1 的双向 PI 环）**与路由无关，仍然可用** ⇒ **阶段 1 可以直接借鉴**

### 8.4 参考实现的利用终点（供阶段 4 参考）

| 目标 | 符号/偏移 | 说明 |
|---|---|---|
| `commit_creds` | `0xffffffc008133538`（BVL-AN16） | 标准提权函数 |
| `prepare_kernel_cred` | `0xffffffc008dc9694` | 同上 |
| `init_cred` | `0xffffffc00a1f3f48` | 目标 cred |
| **`SELINUX_ENFORCING`** | `selinux_state + 0x00` | ★ **重构**：不再是独立全局变量，而是 `struct selinux_state` 的 `enforcing` 字段（偏移 0） |
| `task_struct.pi_blocked_on` | **`0x958`**（BVL 6.1）/ 本机 **`0x938`** | ⚠️ 不同机器不同值 |
| `task_struct.cred` | `0x840`（BVL 6.1）/ 本机待核 | — |

★ **本机 `selinux_state @0xffffffc0823ba418`**（`B` 类型），与参考实现的「偏移 0 = enforcing」结构一致 ⇒ **阶段 4 写 `selinux_state+0` 置 0 ⇒ Permissive** 这条路可参考。

⚠️ 但本原语是**写 0**，而 `enforcing=false` 恰好**就是 0** ⇒ ★★ **本原语与「置 Permissive」完美匹配**！（比写 `cred` 更契合）

---

## 9. 修订后的路线判断

| 环节 | 原判断 | ★ 修订后 |
|---|---|---|
| 触发拓扑 | 待设计 | ★ **直接借鉴参考实现 §8.1 的双向 PI 环**（不经 EDEADLK，绕开硬化） |
| 路由（伪造 waiter 投放） | 未明确 | ☠️ **参考实现的 pselect 法作废**；需**新机制**绕开 kstack 随机化 |
| 利用终点 | `cred` 或 `modprobe_path` | ★ **`selinux_state+0 = 0`（置 Permissive）最契合「写 0」原语** |
| 阶段 1/2 可行性 | — | ✅ **不受 kstack 影响**（触发与链健康度都与栈偏移无关） |

⇒ **建议的执行顺序不变（阶段 1 → 2 → 3），但阶段 3 的设计必须重做**：
- 放弃 pselect 路由
- 寻找「不依赖固定栈偏移」的 waiter 投放/伪造机制
- 候选方向：`h105` §7 第 4 条的**载体穷尽扫描**（`D − B = 0x1B0` 且 ≥0x60 可控的对齐候选）——**注意：这本质上仍在赌栈偏移，需重新评估**

---

## 10. 产物

| 路径 | 内容 |
|---|---|
| `analysis/output/h251_cve43499_repro_plan.md` | 本方案（含参考实现机制对照） |

**未修改任何既有文件**（本轮为方案设计，零设备操作、零 boot 消耗）。
