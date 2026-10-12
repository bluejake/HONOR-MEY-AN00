# 内核源码参考内核源码，IonStack Part II 官方原文要点（Nebula Security，2026-08-15）

> 来源：`https://nebusec.ai/research/ionstack-part-2`（中文转述版）  
> ★ 与本项目 H191/H192 结论逐条交叉校验。**x86 数值一律不得搬到本机 arm64。**

## 1. ★★ 对本项目最有价值的三条（x86 无关）

### 1.1 竞态窗口极宽，**单核也能利用**

> 「要赢得竞态并触发 UAF，你只需要一个 CPU 核心。」  
> 「环路解除后完全没有时间压力。waiter 坐在用户空间中带着悬垂的 `pi_blocked_on`，  
> 后续遍历链的 `sched_setattr()` 可以在任意时机触发。」

⇒ ★★★ **本项目的 H187/H191 已在多核下 100% 复现，此条与之完全一致。**  
⇒ ★ 重要含义：**不必做高频竞态轰炸**，「单发 + 等待 + 触发」即可。  
这与本项目「一 boot 一发」纪律**天然契合**。

### 1.2 ★ 栈复用原语清单（比 Matrix 版更全）

> 「`clone`/`setsockopt`/`pselect`/`keyctl` 及其他具有大量受控栈局部变量的系统调用  
> 工作方式相同。`prctl` 只是在此处比较方便。缓冲区大、对齐、且不需要命名空间。」

★ **注意：这修正了 Matrix 版的说法。** Matrix 版只提  
`PR_SET_MM_MAP`/`pselect`/`TCP_ZEROCOPY_RECEIVE`，本版明确 `prctl(PR_SET_MM_MAP)`  
用的是 `prctl_set_mm_map()` 里的 `unsigned long user_auxv[AT_VECTOR_SIZE]` 栈缓冲  
（自然对齐、大块、无需 namespace）。

⇒ ★★ **本项目 H192 §4.4 排除 `pselect`（42B 上限）仍然成立**，  
但应改用 **`prctl(PR_SET_MM_MAP)`**（auxv 缓冲 ≫ 112B）作为首选之一。  
⇒ ⚠️ 但 `PR_SET_MM_MAP` 需要 `CAP_SYS_ADMIN` ⇒ uid 2000 大概率 EPERM，  
**须实测**。若无权限，则回落到 `setsockopt`/`keyctl` 等无需特权的路径。

### 1.3 ★★ 写原语的精确约束（可直接用于构造）

```c
target - 8  ->  raw_spinlock_t wait_lock      (必须读为"已解锁")
target      ->  waiters.rb_root.rb_node       (此槽位会被写入)
target + 8  ->  waiters.rb_leftmost
target + 16 ->  owner
```

等价约束：

```c
*(u32 *)(target - 0x08) == 0
*(u64 *)(target + 0x08) == 0
((*(u64 *)(target + 0x10)) & ~1ULL) == 0
// 之后可：
*(u64 *)target = &W0->tree.entry
```

⇒ ★★★ **与本机 H193 汇编结论完全一致**：本机 `rt_mutex_base` 布局  
`wait_lock@+0x00 / waiters.rb_node@+0x08 / rb_leftmost@+0x10 / owner@+0x18`，  
若取 `lock = target - 8`，则  
`target-8 = wait_lock`、`target = rb_node`、`target+8 = rb_leftmost`、`target+16 = owner`  
—— **与官方 x86 布局逐字节相同**。★ 说明这是 `rt_mutex_base` 的通用布局，  
非 x86 特性。**本机 H193 的 `0x20` 定稿得到独立第三方印证。**

### 1.4 ★ 伪造 waiter 的字段取值（官方取值法）

| 字段           | 官方取值                                      |
| ------------ | ----------------------------------------- |
| `tree`       | 精心构造的 rb 节点，使 erase 把选定子指针提升为树根           |
| `task`       | **`&init_task`**（合法 task_struct，保证解引用安全）  |
| `lock`       | **`&inet6_protos[IPPROTO_UDP] - 8`**（写目标） |
| `wake_state` | `0`                                       |

⇒ ★★ **`task = &init_task` 是本项目可直接借用的技巧**：  
`init_task` 地址本项目**已知**（`0xffffffc08217e280` 记于 MEMORY，  
且 J9 已用作 `g_TASKP`）⇒ **可绕过「task 需真实地址」这一难点。**

### 1.5 ★ 触发方式

> 「一个兄弟线程在 `prctl` 期间对尾页竞速执行 `fallocate(PUNCH_HOLE)`，  
> 这拉长了 `copy_from_user` 窗口。伪造的 waiter 在栈上保持活跃，  
> 同时在另一个 CPU 上，一个消费者线程对 waiter 触发 `sched_setattr()`。」

⇒ ★ 本项目 H191 已用「attacker 线程延后 300ms 发 S4」的等价手法，  
**方向正确**；官方用 `PUNCH_HOLE` 拉长窗口是更精细的技巧。

## 2. ★★ 补丁信息（比 Matrix 版更准）

| 项           | 内容                                                                                |
| ----------- | --------------------------------------------------------------------------------- |
| 引入          | `8161239a8bcc`（2011 rtmutex 重写）                                                   |
| 主补丁         | `3bfdc63936dd`（`rtmutex: Use waiter::task instead of current in remove_waiter()`） |
| 补丁 v1 的 NPD | CVE-2026-53166，**修于 `40a25d59e85b`**（2026-07-03）                                  |
| 另一编号        | CVE-2026-53163（Matrix 版称，即 v1 引入的 NPD）                                            |
| 受影响         | `v2.6.39-rc1` ~ `v7.1-rc1`                                                        |
| 前置          | **仅需 `CONFIG_FUTEX_PI=y`**，无需 capability / user namespace                         |

★ 注意编号差异：Matrix 版写 CVE-2026-53163，Nebula 原文写 **CVE-2026-53166**。  
⇒ ★ **两个编号都记下，以 <<EMAIL-REDACTED>> / CVE 官方记录为准。**

### 2.1 ★★ 补丁源码（本机未打，实证）

```c
 static void __sched remove_waiter(struct rt_mutex_base *lock,
 				  struct rt_mutex_waiter *waiter)
 {
 	...
+	struct task_struct *waiter_task = waiter->task;
-	raw_spin_lock(&current->pi_lock);
+	scoped_guard(raw_spinlock, &waiter_task->pi_lock) {
 		rt_mutex_dequeue(lock, waiter);
-		current->pi_blocked_on = NULL;
-		raw_spin_unlock(&current->pi_lock);
+		waiter_task->pi_blocked_on = NULL;
+	}
 	...
-	rt_mutex_adjust_prio_chain(owner, RT_MUTEX_MIN_CHAINWALK, lock,
-			next_lock, NULL, current);
+	rt_mutex_adjust_prio_chain(owner, RT_MUTEX_MIN_CHAINWALK, lock,
+			next_lock, NULL, waiter_task);
```

⇒ ★ **本机 6.6.118 实测未打**（H193 汇编：`mrs x20, sp_el0` + `str xzr,[x20,#0x938]`）。

## 3. ★★ `RANDOMIZE_KSTACK_OFFSET` —— 精确的量化（补 H192 §6.5 的空白）

> 「栈复用步骤依赖被释放的 waiter 栈帧与后续的 `user_auxv` 栈帧**确定性地重叠**。  
> 开启 `RANDOMIZE_KSTACK_OFFSET` 后它们不再重叠，该步骤变为大约 **1/32（5 位）**  
> 的栈偏移猜测。**两个提交目标默认关闭它。**」

⇒ ★★★ **修正 H192 §6.5 的估算**：本轮官方给出 **5 位 = 1/32**，  
而非我此前按 `random & 0x3FF` 推的 64 档位（6 位）。  
⇒ ★ 差异原因：官方按 **16 字节对齐后的可用档位**计（`0x3FF/16 = 64`，  
但实际 AAPCS 对齐与 `KSTACK_OFFSET_MAX` 限制使有效位数降到 5）。  
⇒ ★★ **本项目判断不变但更有信心**：`CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT`  
未 set ⇒ 默认关闭 ⇒ **确定性重叠可用**。  
⇒ ★ 若日后确认开启，只需 **32 次迭代**（不是 64）即可覆盖。

## 4. 目标选择：`inet6_protos[IPPROTO_UDP]`

```c
inet6_protos[16] == NULL              // 伪造 wait_lock -> 已解锁
inet6_protos[17] == &udpv6_protocol   // ← 目标
inet6_protos[18] == NULL              // 伪造 rb_leftmost
inet6_protos[19] == NULL              // 伪造 owner
```

触发：`connect` + 向 `::1` 写 UDP ⇒ 内核解引用 `inet6_protocol.handler` ⇒ PC 控制。

⇒ ★ arm64 上 `inet6_protos` 同样存在，**邻接 NULL 条件很可能天然满足**  
（`udpv6_protocol` 两侧通常为 NULL）⇒ ★ 值得作为首个写目标验证。  
⇒ 需先定位本机 `inet6_protos` 地址（依赖 KASLR 泄漏，仍是头号卡点）。

## 5. DirtyMode 收尾

- 目标：`coredump_sysctls[1].mode`（即 `core_pattern` 的 `mode` 字段，0644）
- 一次写入翻转权限位 ⇒ `/proc/sys/kernel/core_pattern` 变 world-writable
- 非特权进程写入 `|/proc/%P/fd/666 %P` 后崩溃 ⇒ **内核以 root 执行其二进制**
- ★ 注意：**初始 rb-tree 写原语落点无法直接到达 `coredump_sysctls[1].mode`**，  
  需经短 ROP（本项目无 CET，ROP 条件更好）

⇒ ★★ **这条收尾路径对本项目特别有价值**：  
① 不需要 `/proc/kallsyms`（`boot_id` 泄漏 + `ctl_table.data` 损坏即可）  
② 不需要完整的任意读写，**只需一次受控写**  
③ 与本项目「拿到写原语后改 `selinux_state.enforcing`」是同类思路，  
但 DirtyMode **只需一次写**且落点由 `rb_erase` 决定，可精确设计。

## 6. ★ 与本项目结论的交叉校验总表

| 本项目                                               | 官方                                        |   一致   |
| ------------------------------------------------- | ----------------------------------------- | :----: |
| `pi_blocked_on@task+0x938`（H191/H193 汇编）          | 语义一致（`waiter->task->pi_blocked_on`）       |    ✅   |
| `rt_mutex_base` 布局 `0x00/0x08/0x10/0x18`（H193 汇编） | ★ 官方 x86 布局**逐字节相同**                      |   ✅✅   |
| 崩溃在 `trylock(&lock->wait_lock)`（H192 §8.2）        | ★ 官方「target-0x08 必须读为已解锁」                 |    ✅   |
| `tree.entry` 不得自指（H192 汇编 `cmp x8,x25; b.eq`）     | 官方「精心构造使子指针提升为根」                          |    ✅   |
| `task` 需真实地址（H192 卡点）                             | ★ 官方用 **`&init_task`**（本项目已知）             |  ✅ 可解  |
| 单发即可（★63 一 boot 一发）                               | ★ 官方「单核即可」「无时间压力」                         |    ✅   |
| `pselect` 容量不足（H192 §4.2 排除）                      | 官方改用 `prctl(PR_SET_MM_MAP)` 的 `user_auxv` | ✅ 需换原语 |
| kstack 未启用 ⇒ 确定性重叠                                | ★ 官方：两提交目标默认关闭                            |    ✅   |
| 需 KASLR 泄漏                                        | ★ 官方阶段 1 prefetch 泄漏（arm64 需替代）           |  ⚠ 仍开放 |
