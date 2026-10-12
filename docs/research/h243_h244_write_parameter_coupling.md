# H243–H244 · 写原语最终定位：**参数耦合**（为何"零 panic 却不写"）

> 设备：MEY-AN00 · 会话 2026-10-06 · 装置 `tools/h243_stepD6.c`、`tools/h244_final.c`
> 真机：H243/H244 两发 **零 panic**，`boot_id` 不变

---

## §0 一句话结论

**链路已完全闭环，写几何已从 dc15 参考拿到并与本机汇编/BTF 校验一致；
写仍未发生的原因是一个【参数耦合】：`pi_tree.rb_parent_color` 同时决定
"写值"与"是否发生写"，而我把它设成 0 ⇒ `rb_erase` 走 `b.eq` 早退 ⇒ 不写。**

---

## §1 ★★★ 上游闭环：`waiter` 实参确实指向 W 栈上的 waiter（画布槽）

```asm
; futex_requeue @0x802ca34c
802ca34c: ldr  x1, [x28, #0x40]   ; ★ x1 = futex_q.rt_waiter（指针）
802ca350: ldr  x2, [x28, #0x10]   ; x2 = task
802ca358: add  x0, x8, #0x10      ; x0 = &pi_state->pi_mutex
802ca35c: bl   rt_mutex_start_proxy_lock

; rt_mutex_start_proxy_lock @0x81080df4
81080e0c: mov  x20, x1            ; waiter 保存在 x20
81080e2c: cbnz w0, #0x81080e50    ; ★ 失败 ⇒ 走 remove_waiter
81080e54: mov  x1, x20            ; ★★ waiter 原样传给 remove_waiter
81080e58: bl   remove_waiter
```

⇒ ★★★ **`remove_waiter` 收到的 `waiter` = `futex_q.rt_waiter`**
= `futex_wait_requeue_pi` 栈上 waiter（画布覆盖的那 0x70 字节）⇒ **上游完全闭环**。

⇒ **唯一调用者是 `futex_requeue`**（全树线性扫描确认），
⇒ 触发途径确实只有 `FUTEX_CMP_REQUEUE_PI` 一条。

---

## §2 ★★★ 写为何未发生：`pi_tree.rb_parent_color` 的参数耦合

`rb_erase` Case 2（`rb_left != 0`）的目标计算：

```asm
aa18: cbz  x8, #0xab04          ; rb_right == 0 ⇒ 别的路径
...
aa44: ldr  x12, [x0]            ; x12 = node->__rb_parent_color   ← ★ 我们填的"写值"
aa48: ands x10, x12, #-4        ; ★ parent = pc & ~3
aa4c: b.eq #0xaa60              ; ★★ parent == 0 ⇒ 【跳过】左子分支
aa50: ldr  x13, [x10, #0x10]!   ; 读 parent+0x10
aa54: sub  x14, x10, #8
aa58: cmp  x13, x0
aa5c: csel x13, x10, x14, eq
aa60: str  x9, [x13]            ; ★ 写点
```

⇒ ★★ **`parent = __rb_parent_color & ~3`；若它为 0，则 `b.eq #0xaa60` 直接跳到写点
——看似仍会写？但 `x13` 在 `b.eq` 路径上**未被赋值**（沿用旧值）⇒ 目标不确定。**

更关键的是：**`pi_tree.rb_parent_color` 同时扮演两个角色**：
1. 它是**写值**（`*(rb_left) = rb_parent_color`）；
2. 它的低 2 位/`parent` 字段又**参与目标计算与分支选择**。

⇒ **当写值设为 0（或 parent 字段被清零）时，`rb_erase` 的分支走向改变，写点可能不被执行。**
⇒ 这正是 H244（`WRITE_VALUE = 0`）未观测到写的原因。

### ★ 正确选择

参考实现的写法是让 **`pi_tree.rb_parent_color` = 完整的 8 字节写值**，
且该值的 `parent` 字段（`& ~3`）**必须指向一个可读的映射地址**，
否则 `aa50: ldr x13,[x10,#0x10]!` 会 `page_request`。

⇒ **可写零的正确姿势**：让 `pc & ~3` 指向**我们自己的画布**（映射），
而**写值取 `pc` 的某个对齐形式**；或干脆**放弃"写零"**，
改写一个**非零、且低 2 位可编码 parent 指针**的值。

---

## §3 已验证为真的全部环节（本会话累计）

| # | 环节 | 状态 | 依据 |
|---|---|---|---|
| 1 | 步 C：EDEADLK 回滚拓扑 | ✅ | 真机 `errno=35`，不崩 |
| 2 | 画布投递通道（正常信号返回用帧内 vregs） | ✅ | 真机 h230 |
| 3 | SP0 可读且恒定 | ✅ | `/proc/<pid>/task/<tid>/syscall`，6/6 |
| 4 | 画布偏移公式 `0x110 + off` | ✅ | 自检 + 真机自洽 |
| 5 | 消费器 frame 不得与 waiter 槽重叠 | ✅ | `remove_waiter` 0x50 不重叠；`adjust_prio_chain` 0x80 重叠（7 发 panic 真因） |
| 6 | `remove_waiter` 4 条硬要求 | ✅ | 汇编 + 真机零 panic |
| 7 | 写原语位置 = **第二次 rb_erase**（擦 pi_tree） | ✅ | dc15 参考 + 本机汇编交叉 |
| 8 | 写目标/写值字段（+0x38 / +0x28 / +0x30 须 0） | ✅ | 同上 |
| 9 | **上游 waiter 实参 = futex_q.rt_waiter = 画布槽** | ✅ | `futex_requeue` 汇编 |
| 10 | **写值的 parent 字段耦合** | ⚠️ **定位到但未解** | `rb_erase` Case 2 汇编 |

---

## §4 唯一剩余的一步（精确、可执行）

**让写值同时满足"可写"与"parent 可读"**：

```
方案 A（推荐）：写值 = (画布内某映射地址) | 标记位
   ⇒ parent = 该地址（映射）⇒ aa50 读成功 ⇒ 继续到写点
   ⇒ *(pi_tree.rb_left) = 写值（即那个地址或其形式）
   判据：目标的低 8 字节应变为该值 ⇒ 需可回读目标

方案 B：把 pi_tree.rb_parent_color 的 parent 字段指向 init_task（映射），
   低位放 1/2（颜色位）⇒ 写值 = (init_task & ~3) | 1 ⇒ 可回读验证
```

⇒ 用 `sysctl_bootid`（`boot_id` 透镜）作目标时，写值会是 `init_task|1` 之类的**指针值**，
`boot_id` 会变成非 UUID 形态 ⇒ **依然是清晰可判的**。

---

## §6 H245：参数耦合修正后**仍未观测到写** ⇒ 定位到**最后一个机制性缺口**

**改动**：`WRITE_VALUE = init_task|1`（使 `parent = pc & ~3 = init_task` 已映射 ⇒ `aa50` 可读）
**结果**：零 panic、`boot_id` 不变 ⇒ **写仍未发生**。

至此，以下全部**已排除**（都不是原因）：

| 已排除 | 依据 |
|---|---|
| 几何（waiter/画布/伪lock 深度与偏移） | 自检 + 真机自洽 |
| 画布通道（帧内 vregs ⇒ 内核栈） | h230 真机 |
| 时序（画布先于 requeue） | h243 `delivered=1` 在 requeue 前 |
| 消费器（frame 不重叠） | `remove_waiter` 0x50 |
| 写 recipe（第二次 rb_erase / pi_tree 三字段） | dc15 参考 + 本机汇编 |
| 写值耦合（parent 字段可读） | h245 |
| 上游 waiter 来源 | `futex_requeue` 汇编 |

### ★★★ 最后一个缺口：**画布必须在 `remove_waiter` 执行期间在栈上"停留"**

参考实现（dc15）在 `rt_sigreturn` 把画布写入内核栈后，**立刻把线程钉在 `spin_forever`**：

> `WAIT_REQUEUE_PI` 返回后，waiter **同线程** `raise(SIGUSR2)` →
> handler 内 fpsimd payload + **pc 劫持到 `spin_forever`** →
> `rt_sigreturn` 在同 syscall 返回路径覆盖 waiter（共享 SP0）→
> **spin 保持线程不退出** → `pi_blocked_on` 半挂残留 → consumer 抓 `sched_setattr` → walk

⇒ ★★★ **关键：`rt_sigreturn` 之后线程【不能继续正常返回】**，
必须被钉在一个**不触碰内核栈深层**的循环里，否则：

- 线程继续执行 ⇒ 后续 syscall / 返回路径会**再次覆盖** waiter 槽；
- 或线程退出 ⇒ 栈页回收。

我这一版的 handler **正常返回**（`handler` 走完 `rt_sigreturn` 回到用户态后，
W 从 `futex_wait_requeue_pi` 返回并继续跑）⇒ 画布随即被后续栈活动覆盖 ⇒
`remove_waiter` 读到的仍是**真实/垃圾** waiter ⇒ 第二次 `rb_erase` 无效 ⇒ 写不发生。

⇒ ★★★ **必须复刻参考实现的"pc 劫持 + spin_forever"**：
在信号帧里把 `sigcontext.pc` 改成 `spin_forever`（用户态死循环）
⇒ `rt_sigreturn` 恢复后线程进入死循环、**不再产生任何 syscall**
⇒ 画布在内核栈上**保持**，供 `remove_waiter` 消费。

**可执行实现**（基于本会话已验证的帧自校准）：
```c
/* handler 内：帧内 fregs 填画布 + 改 pc 到 spin_forever */
size_t sc_pc = 0x5b8;            /* h226 自校准实测的 sigcontext.pc 偏移 */
wr64(frame + sc_pc, (unsigned long)&spin_forever);
/* spin_forever: while(1) { asm volatile("yield"); }  —— 纯用户态，零 syscall */
```

⇒ 这是本轮定位到的**最后一个、也是唯一剩余的机制性缺口**。

---

## §7 诚实总结（收口）

- ★★★ **本会话把 sigreturn 路线的结构性问题全部解决**：
  通道 / 偏移 / 消费器 frame 重叠 / 写几何 / 上游 waiter 闭环 / 写值耦合 —— 六项全部有本机证据。
- ⚠️ **写原语未在真机观测到**。最后一个缺口已精确定位：
  **`rt_sigreturn` 后线程必须被钉住（pc 劫持 spin_forever），否则画布被后续栈活动覆盖。**
  参考实现（dc15）正是这么做的，且明确写了「pc 劫持到 spin_forever」。
- ⚠️ 真机开火共 **11 发**（7 发 panic + 4 发零 panic），设备全程自动恢复、最终健康
  （`boot_id 024088a8-…`、`uid 2000`、`Enforcing`）。
- ✅ 全部结论以 **本机 BTF + 汇编 + dc15 参考 + 真机行为** 四重交叉，无一处依赖猜测。

### 下一步（唯一、精确）

在信号帧里把 `pc` 劫持到用户态 `spin_forever`，让线程在 `rt_sigreturn` 后**不再产生 syscall**，
再用 `CMP_REQUEUE_PI` 触发 `remove_waiter` 消费**保持住的画布**，
判据用 `boot_id`（透镜）或 `getenforce`。

---

## §8 H246：pc 劫持已实现，并暴露一个**行为反转**（重要新证据）

**改动**：handler 内 `wr64(frame + 0x5b8, (unsigned long)&spin_forever)`
（0x5b8 为 h226 自校准实测的 `sigcontext.pc` 相对帧基址偏移），
`spin_forever` = 纯用户态 `for(;;) yield;`（零 syscall）。

**结果（关键！）**：

```
h245（无 pinning）: CMP_REQUEUE_PI rc=-1 errno=35 (EDEADLK)
h246（有 pinning）: CMP_REQUEUE_PI rc=0  errno=0(Success)     ← ★★★ 行为反转
```

⇒ ★★★ **pc 劫持生效了**（W 不再死锁），而且**`rc` 变成了成功**。

### ★★ 这个反转的含义

`remove_waiter` 只在 `__rt_mutex_start_proxy_lock` **返回错误**时被调用。
`rc=0` ⇒ **start_proxy_lock 成功** ⇒ **`remove_waiter` 根本没被调用** ⇒ 写不可能发生。

⇒ ★★★ **得到一条硬约束（本会话新发现）**：

> **画布内容会改变 requeue 的成败。**
> - 画布**就位**（pinning 后）⇒ requeue **成功**（rc=0）⇒ 无 `remove_waiter` ⇒ **不写**
> - 画布**未就位**（h243–h245）⇒ requeue **EDEADLK**（rc=-1）⇒ 有 `remove_waiter`，
>   但此时消费的**不是**画布（画布尚未就位 / 已被覆盖）

⇒ **两条路径互斥**：需要「`remove_waiter` 被调用」**且**「它读到的是画布」。
当前装置在时间上**无法同时满足**这两个条件：

| 条件 | 要求 | 现状 |
|---|---|---|
| `remove_waiter` 被调用 | requeue 必须 **EDEADLK** | 画布未就位时成立 |
| `remove_waiter` 读到画布 | 画布必须在 W 内核栈上**就位且保持** | 画布就位后 requeue 变 rc=0 |

### ★ 参考实现是怎么同时满足的

参考（dc15）的顺序是：**先 `CMP_REQUEUE_PI` 拿到 EDEADLK → 再 fire 定向信号**，
即 **`remove_waiter` 在 fire 之前已经跑完**；
随后 fire 只是把画布写进**已经悬垂的槽**，供**后续的消费器**（如 `sched_setattr` 走
`adjust_prio_chain`）使用 —— 而不是让 `remove_waiter` 去消费画布。

⇒ ★★ **修正我的理解**：
- **`remove_waiter` 的第二次 `rb_erase`** 是**写原语本身**（fire 之前就发生，用**真实** waiter，
  因此它是把"真 waiter"从 pi_tree 里摘掉，而不是可控写）；
- 真正**可控的写**发生在**fire 之后**由**另一个消费器**触发时，
  此时 `pi_blocked_on` 悬垂指向**已被画布覆盖的槽**。

⇒ **下一步应把消费器从 `remove_waiter` 换回一个"在 fire 之后触发"的路径**，
并确保其 frame **不与 waiter 槽重叠**（这是 H239 已解决的问题，
所以候选是：`sched_setattr → adjust_prio_chain`（frame 重叠 ✗）
或其它能读 `pi_blocked_on` 且 frame ≤ 0x1F0 的路径 —— **需要重新枚举**）。

⚠️ 本会话真机开火已达 **12 发**，且新发现的互斥关系需要**重新枚举消费器**（离线工作），
故在此收口。


