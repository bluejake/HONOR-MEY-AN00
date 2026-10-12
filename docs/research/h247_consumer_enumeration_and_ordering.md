# H247 · 消费器全枚举（离线）+ 顺序矛盾（收口）

> 真机：H247 一发 → panic（`20261006105103`）。设备已恢复（`4d335742-…`）。
> 本会话真机开火累计 **13 发**（8 panic + 5 零 panic）。

---

## §1 ★★★ 消费器全枚举（本会话最重要的离线成果）

**判据**：真正的 `pi_blocked_on` 消费者必须**同时**访问 `pi_lock(+0x90c)` 与 `pi_blocked_on(+0x938)`
（单看 `#0x938` 会被大量无关偏移污染 —— 实测有 26 处 `udf #0x938`、大量 `add`/`movk` 噪声）。

**结果（全树仅 9 个函数同时命中，其中 6 个是误命中）**：

| 函数 | 自身 frame | 是否真正消费 `pi_blocked_on` | 判定 |
|---|---|---|---|
| `remove_waiter` | **0x50** | ✅ 读 `[x24,#0x58]`（top_waiter->lock） | **不覆盖 waiter 槽**，但需 `-EDEADLK` 触发 |
| `rt_mutex_adjust_pi` | **0x50** | ✅ `0x8146c: ldr x21,[x19,#0x938]` | **不覆盖 waiter 槽** ⇒ ★ 理论首选 |
| `rt_mutex_adjust_prio_chain` | **0x80** | ✅ `0x81648: ldr x25,[x19,#0x938]` | ❌ **覆盖** waiter 槽 `[0x1F0,0x270)` |
| `task_blocks_on_rt_mutex` | 0x60 | ✅ 写点 | 非消费器（生产者） |
| `try_to_take_rt_mutex` | 0x50 | ✅ 写点 | 非消费器 |
| `copy_process` | 0x150 | 写点（fork/clone） | 非消费器 |
| `__netif_set_xps_queue` / `netdev_txq_to_tc` / `linux_banner` | — | ❌ 同偏移巧合 | 排除 |

⇒ ★★★ **`pi_blocked_on` 的真实消费者只有 3 个**：
`remove_waiter`(0x50) · `rt_mutex_adjust_pi`(0x50) · `rt_mutex_adjust_prio_chain`(0x80)。

### 1.1 关键：`rt_mutex_adjust_prio_chain` 是**内联**调用

`rt_mutex_adjust_pi` 并不 `bl` 它，而是**内联展开**（`__sched_setscheduler` 里也一样）。
⇒ 链执行时的实际栈深度 = `0x80(el0_svc) + 0x80(sched_setattr) + 0xa0(sched_setscheduler) + 0x50(adjust_pi)`
= **0x1F0**，链的 `sub sp,#0x80` 覆盖 `[0x1F0, 0x270)` —— **正好盖住 waiter 槽 `[0x1F0,0x260)`**。

⇒ 但 `rt_mutex_adjust_pi` 在 `0x8146c` 读 `pi_blocked_on` 时，**它自己的 frame 尚未建立**
（`0x8146c` 在 `sub sp,#0x50` **之前**？不 —— 序言在 `0x8143c`，读在 `0x8146c`，**已建立**）
⇒ 实际深度 0x1F0，`adjust_pi` frame `[0x1A0,0x1F0)` **不覆盖** waiter 槽 ⇒ **读了就能拿到画布** ✔

---

## §2 ❌ 顺序矛盾（H246/H247 两发实证）

| 实验 | 顺序 | 结果 |
|---|---|---|
| H246 | **fire 先，requeue 后** | `CMP_REQUEUE_PI rc=0`（**成功**）⇒ `remove_waiter` **不被调用** ⇒ 不写 |
| H247 | **requeue 先（拿到 EDEADLK），fire 后** | **panic**（`page_request`） |

⇒ ★★★ **两条顺序都不可用**，原因分别是：

- **fire 在前**：画布内容改变了 requeue 的成败（`rc` 由 EDEADLK 变 0）
  ⇒ `__rt_mutex_start_proxy_lock` 成功 ⇒ `remove_waiter` 不被调用。
- **requeue 在前**：第一发 `CMP_REQUEUE_PI` 已消耗掉 W 的 waiter
  ⇒ 随后 fire 的信号在 W 的内核上下文里与 `remove_waiter` 的收尾**竞争**
  ⇒ 读到半更新状态 ⇒ `page_request`。

### ★★ 结论（H248 复核后定论）

| 顺序 | 结果 | 机制 |
|---|---|---|
| fire **先**，requeue 后 | `rc=0`（成功）⇒ 无 `remove_waiter` | 画布内容改变了 requeue 成败 |
| requeue **先**（EDEADLK），**延迟** fire | **panic** `20261006105103` | 与收尾竞争 |
| requeue **先**（EDEADLK），fire **紧跟不 sleep** | **panic** `20261006105243` | **同签名** ⇒ 与延迟无关 |

⇒ ★★★ **`fire-after-EDEADLK` 是结构性失败点**（两次不同延迟、同签名 panic）：
在 `remove_waiter` 已改动 W 的 futex 状态之后，
**定向信号落帧 + pc 劫持** 会踩到不一致状态 ⇒ `page_request`。

⇒ ★★ **本装置下「画布就位」与「`remove_waiter` 被调用」无法在同一线程/同一栈槽上共存。**

### ★ 参考实现能共存的原因（推断）

dc15 的 `remove_waiter` 在 EDEADLK 滚动中把**真实** waiter 从 `pi_tree` 摘掉后，
`pi_blocked_on` 变为悬垂，但 **W 仍被 futex 持有**（其 waiter 仍在 `lock->waiters` 里）；
随后 fire 的**信号落在 W 的 syscall 上下文**时，`remove_waiter` **已经返回**（不在栈上活跃），
故无竞争。我这两发之所以崩，最可能是 **W 在 ① 之后已被唤醒/状态已变**，
导致 fire 的落帧与内核的唤醒路径交错。

⇒ **需要的是**：让 W 在 ① 之后**仍稳定阻塞**（如 `to = NULL` 且不被 ① 唤醒），
再 fire、再 `sched_setattr`。
⚠️ 但 ① 的 `-EDEADLK` 本身可能就唤醒了 W（`requeue` 失败路径会 `futex_wake`）——
这需要从 `futex_requeue` 的失败分支**逐条读出是否唤醒 W**，属下一轮离线工作。


---

## §3 收口：本会话完整账目

### 3.1 已验证为真（本机证据）

1. 技能安装 + 加载 ✅
2. sigreturn fpsimd 帧被内核采信（magic/size `0x210`）✅ 真机
3. **SP0 可读**（`/proc/<pid>/task/<tid>/syscall` 的 `sp`）且同线程 6/6 恒定 ✅ 真机
4. **画布 512B 真的进内核栈**（`restore_fpsimd_context`）—— **推翻 H195** ✅ 反汇编+真机
5. 步 C：EDEADLK 回滚拓扑可触发且不崩 ✅ 真机
6. **消费器 frame 不得与 waiter 槽重叠**（7 发 panic 的真死结）✅ 反汇编+真机
7. 写原语几何（第二次 `rb_erase` / `pi_tree` 三字段）✅ dc15 参考 + 本机汇编
8. 上游 `waiter` 实参 = `futex_q.rt_waiter` = 画布槽 ✅ `futex_requeue` 汇编
9. **消费器全枚举**（`pi_blocked_on` 真实消费者只有 3 个）✅ 本报告 §1
10. **顺序互斥约束** ✅ H246/H247 两发实证

### 3.2 未达成

**写原语未在真机落地。** 缺口 = §2 的**时序拼装**（需把 H246/H247 各取一半）。

### 3.3 真机开火账

| 类别 | 发数 |
|---|---|
| panic | **8**（全 `page_request`） |
| 零 panic | **5** |
| 设备 | 全程自动恢复，最终健康 |

---

## §4 铁律增补

| # | 铁律 |
|---|---|
| **㊸** | ★★★ **消费器全枚举**：`pi_blocked_on` 真实消费者仅 `remove_waiter`(0x50) / `rt_mutex_adjust_pi`(0x50) / `rt_mutex_adjust_prio_chain`(0x80)。**判据 = 同时访问 `0x90c` 与 `0x938`**（单看 `0x938` 有大量噪声） |
| **㊹** | ★★★ **「画布就位」与「`remove_waiter` 被调用」时序互斥**：fire 在前 ⇒ requeue 变 rc=0（不调用）；requeue 在前 + 延迟 fire ⇒ 与收尾竞争 ⇒ panic。**正解 = ② 后【紧跟】③、不额外 sleep** |
| **㊺** | `rt_mutex_adjust_prio_chain` 是**内联**的（无独立 `bl` 调用点）；其 `sub sp,#0x80` 覆盖 waiter 槽，但**读 `pi_blocked_on` 发生在更浅处** ⇒ 链路可达 ≠ 安全 |
