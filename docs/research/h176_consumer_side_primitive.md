# H176 — 消费侧写原语落点判定：★推翻 H175 的 `remove_waiter` 落点★

> 结论一句话：**`rb_erase` 的可控写确实成立，但 H175 选的落点 `remove_waiter`（requeue 期间）拿不到「我方控制的 waiter 内存」；
> 真正的落点是消费侧 `rt_mutex_adjust_pi` → `rt_mutex_adjust_prio_chain` 的 `[7] rt_mutex_dequeue`，
> 而它的可控性来自 `waiter->lock`（UAF 读，我方完全控制）而不是 waiter 本身。**
>
> 本轮全程未开火，`boot_id abc61a92-7b66-4ccf-b8fe-26f70918cb30` 仍未消耗。

---

## 0. 置信度声明

| 结论 | 置信度 | 依据 |
|---|---|---|
| `rb_erase` 存在「8 字节任意值 → 任意地址」写 | **汇编已证未实测** | 本机源码 `rbtree_augmented.h:224-323` + `rbtree.h:194-205`；H172 已反汇编 `0xffffffc08003a9d4` |
| `remove_waiter` 落点**不可用**（waiter 在内核堆） | **源码推断已验证**（本轮新读） | `kernel/futex/requeue.c:790,797` + `futex.h:103` |
| 消费侧 `[7]` 是唯一可控落点 | **源码推断未实测** | `rtmutex.c:920` + `rtmutex_api.c:458-479` |
| 消费侧 `[5] trylock` 是**第二、更好**的写原语 | **源码推断未实测** | `rtmutex.c:830` |
| 画布仍可覆盖栈上 waiter（几何未变） | **汇编已证**（沿用 H172/H175） | H175 三重验证 |

---

## 1. ★★ 本轮头号发现：`remove_waiter` 落点为什么是错的 ★★

H175（及 H172）把写原语落点定在 `remove_waiter@0xffffffc081080e60`，前提是「`rb_erase` 的 `node` 参数 = 被 requeue 线程栈上的 `rt_waiter`」。
**这个前提在 6.6.118 上不成立。** 本轮读到决定性三行：

`kernel/futex/requeue.c:786-797`（`futex_wait_requeue_pi`，被阻塞线程 W 自己执行）：
```c
/*
 * The waiter is allocated on our stack, manipulated by the requeue
 * code while we sleep on uaddr.
 */
rt_mutex_init_waiter(&rt_waiter);        // :790  ← W 自己栈上的局部变量

...
q.rt_waiter = &rt_waiter;                // :797  ← 存进 futex_q
```

`kernel/futex/futex.h:103`：
```c
struct rt_mutex_waiter *rt_waiter;      // :103  ← futex_q 里只是一个【指针】
```

`kernel/futex/requeue.c:627-629`（requeue 线程 R 执行）：
```c
ret = rt_mutex_start_proxy_lock(&pi_state->pi_mutex,
                                this->rt_waiter,   // ← 从 futex_q 取出的指针
                                this->task);
```

### 1.1 两种情形必须分开

| 情形 | `this->rt_waiter` 指向 | 画布能否覆盖 |
|---|---|---|
| **`futex_wait_requeue_pi`（W 自己进 futex）** | **W 栈上局部变量**（`requeue.c:790`） | **能**（画布就在 W 栈上） |
| **`futex_requeue_pi`（W 被 R 挂上去）** | **R 自己栈上的局部变量** | **不能**（R 的栈 ≠ W 的栈，画布够不着） |

而 `futex_requeue` 主循环（`requeue.c:568-664`）遍历的是 `hb1->chain` 上的 **`futex_q`**，这些 `futex_q` 是
`futex_wait_requeue_pi`（W 视角）挂上去的 ⇒ **`this->rt_waiter` 指向 W 栈**。

> ★★★ **修正**：落点并非「一定不可用」，而是「**只在 `futex_wait_requeue_pi` 路径下可用**」。
> H175 的拓扑里 W 正是用 `WAIT_REQUEUE_PI(f_src, f_target)` 进 futex 的（`h175_staged.c` 的 `thread_W`），
> 所以几何成立。**但 H175 选 `remove_waiter` 仍是错的**——理由见 §2。

★ 补充：`struct futex_q` 带 `__randomize_layout`（`futex.h:112`），字段偏移随机化。
这**不影响**本结论（我们不解析 `futex_q` 布局，只跟随指针），但意味着任何「按偏移读 `futex_q`」的方案都不可行。

---

## 2. ★★★ 真正的错误：`remove_waiter` 里 `waiter->lock` 是**真实锁**，画布改不了 ★★★

这是本轮最关键的一步。`remove_waiter`（`rtmutex.c:1524-1545`）：

```c
static void __sched remove_waiter(struct rt_mutex_base *lock,
                                  struct rt_mutex_waiter *waiter)
{
	bool is_top_waiter = (waiter == rt_mutex_top_waiter(lock));
	struct task_struct *owner = rt_mutex_owner(lock);
	...
	raw_spin_lock(&current->pi_lock);
	rt_mutex_dequeue(lock, waiter);        // ★ waiter 是我方画布，lock 不是
```

`remove_waiter` 由 `rt_mutex_start_proxy_lock` 调用（`rtmutex_api.c:344-357`）：
```c
raw_spin_lock_irq(&lock->wait_lock);
ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
if (unlikely(ret))
	remove_waiter(lock, waiter);          // :353
raw_spin_unlock_irq(&lock->wait_lock);
```
调用方 `requeue.c:627` 传的 `lock = &pi_state->pi_mutex` ⇒ **真实内核对象，不可控**。

于是 `rt_mutex_dequeue(lock, waiter)`（`rtmutex.c:471-479`）：
```c
static __always_inline void
rt_mutex_dequeue(struct rt_mutex_base *lock, struct rt_mutex_waiter *waiter)
{
	lockdep_assert_held(&lock->wait_lock);
	if (RB_EMPTY_NODE(&waiter->tree.entry))
		return;                              // ★ 闸门，见 §4
	rb_erase_cached(&waiter->tree.entry, &lock->waiters);
	RB_CLEAR_NODE(&waiter->tree.entry);
}
```
`rb_erase_cached(&waiter->tree.entry, &lock->waiters)`：`root = &lock->waiters.rb_root` 是**真实树根**。

★ **`remove_waiter` 路径的致命问题**：它要求 `ret < 0`，即 `__rt_mutex_start_proxy_lock` 必须返回 `-EDEADLK`。
而 `remove_waiter` 一旦执行，`rt_mutex_dequeue` 会真的去动 `pi_state->pi_mutex` 的**真实** `waiters` 树
⇒ 我们伪造的 `node` 被塞进真实树做 erase ⇒ **`parent_color` 里的 parent 指针会被 `__rb_change_child`
用来写真实树节点**，副作用扩散到 `pi_state` 邻域，且 `fixup_rt_mutex_waiters` 之后还会二次动这棵树。
H175 的 R1「写 `lock->waiters.rb_node` 崩溃」就是这个问题的表征，规避它需要知道 `lock` 的真实布局 ⇒ **不可能**。

⇒ **裁决：`remove_waiter` 落点作废。**

---

## 3. ★★★ 新落点：消费侧 `rt_mutex_adjust_pi` 的 `[7]` ★★★

### 3.1 消费侧入口（`rtmutex_api.c:458-479`，本轮完整读出）

```c
void __sched rt_mutex_adjust_pi(struct task_struct *task)
{
	struct rt_mutex_waiter *waiter;
	struct rt_mutex_base *next_lock;
	unsigned long flags;

	raw_spin_lock_irqsave(&task->pi_lock, flags);

	waiter = task->pi_blocked_on;                        // :466  UAF 读
	if (!waiter || rt_waiter_node_equal(&waiter->tree, task_to_waiter_node(task))) {
		raw_spin_unlock_irqrestore(&task->pi_lock, flags);
		return;                                          // :469  早退闸门 #1
	}
	next_lock = waiter->lock;                            // :471  ★ UAF 读，我方控制
	raw_spin_unlock_irqrestore(&task->pi_lock, flags);

	get_task_struct(task);
	rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,
				   next_lock, NULL, task);       // :477
}
```

调用点：`kernel/sched/core.c:8012-8015`（`__setscheduler_params`）
```c
	if (pi) {
		if (cpuset_locked)
			cpuset_unlock();
		rt_mutex_adjust_pi(p);
	}
```
⇒ **`sched_setattr(..., pi=true)` 即触发**，与 H142 §11.5 的公开利用链一致。

★ 注意 `:469` 早退闸门：`rt_waiter_node_equal(&waiter->tree, task_to_waiter_node(task))` 比的是
`waiter->tree.prio` vs `__waiter_prio(task)=task->prio`（`rtmutex.c:327-336, 391-407`）。
画布把 `tree.prio`（waiter `+0x18` = 画布 `+0x88` = `v8.d[1]`）清零 ⇒ `0 != task->prio`（task prio ≥ 100）⇒ 不早退。
★ **H175 的 `setpriority(nice=1)` 破闸门这一步可以省掉**（但保留无害，因为 nice 会改 `task->prio`，
我们只在「相等」时才早退，清零已保证不等）。

### 3.2 链走控制流逐段（本轮完整读出 `rtmutex.c:663-1059`）

进入时：`chwalk = RT_MUTEX_MIN_CHAINWALK`，`orig_lock = NULL`，`orig_waiter = NULL`，`top_task = task`。

关键：`detect_deadlock = rt_mutex_cond_detect_deadlock(NULL, MIN_CHAINWALK)`（`:677`）
```c
static __always_inline bool
rt_mutex_cond_detect_deadlock(struct rt_mutex_waiter *waiter, enum rtmutex_chainwalk chwalk)
{
	if (IS_ENABLED(CONFIG_DEBUG_RT_MUTEXES))     // 本机 = n（已核 mey_config.txt）
		return waiter != NULL;
	return chwalk == RT_MUTEX_FULL_CHAINWALK;    // MIN != FULL ⇒ false
}
```
⇒ **`detect_deadlock = false`**（本机 config 已核：`# CONFIG_DEBUG_RT_MUTEXES is not set`）。

`again:` → `retry:` 逐段：

| 段 | 位置 | 条件 | 本次（画布）走向 |
|---|---|---|---|
| `[1]` | `:717` | `raw_spin_lock_irq(&task->pi_lock)` | 正常（task 是真实 task） |
| `[2]` | `:722` | `waiter = task->pi_blocked_on` | **UAF 读 → 我方画布** |
| `[3]` | `:733` | `if (!waiter) goto out` | waiter 非 0（画布地址）⇒ 过 |
| | `:740` | `if (orig_waiter && !rt_mutex_owner(orig_lock))` | orig_waiter=NULL ⇒ 跳过 |
| | `:752` | `if (next_lock != waiter->lock) goto out_unlock_pi` | ★ 见 §3.3 |
| | `:777` | `IS_ENABLED(CONFIG_PREEMPT_RT) && waiter->ww_ctx && detect_deadlock` | PREEMPT_RT 未开 ⇒ 短路，**不解引用 `waiter->ww_ctx`** |
| | `:785` | `if (top_waiter)` | `top_waiter = orig_waiter = NULL` ⇒ **整块跳过** |
| | `:809` | `rt_waiter_node_equal(&waiter->tree, task_to_waiter_node(task))` | prio 不等 ⇒ 过（若相等则 `requeue=false`，见下） |
| `[4]` | `:820` | `lock = waiter->lock` | ★★ **UAF 读，我方完全控制** |
| `[5]` | `:830` | `raw_spin_trylock(&lock->wait_lock)` | ★★ **写原语 #1，见 §5** |
| `[6]` | `:845` | `lock == orig_lock \|\| rt_mutex_owner(lock) == top_task` | orig_lock=NULL ⇒ 只判 owner |
| | `:870` | `if (!requeue)` | 见 §3.4 |
| `[7]` | `:920` | `rt_mutex_dequeue(lock, waiter)` | ★★★ **写原语 #2，见 §6** |

### 3.3 `[3]` 的 `next_lock != waiter->lock` —— 这是个「自锁」检查

`:752`：
```c
	if (next_lock != waiter->lock)
		goto out_unlock_pi;
```
`next_lock` 是 `rt_mutex_adjust_pi:471` 读出并传进来的，同一次链走里 `waiter` 是**同一个悬垂指针**。
两次读的是**同一块画布内存** ⇒ 只要我们在 `[2]`→`:752` 之间不改变画布，就恒等 ⇒ **恒不过早退**。

★ 但注意：如果 `[5]` trylock 失败走 `goto retry`（`:833`），会重走 `[2]`，此时 `next_lock` 仍是第一次的值。
若我们在 retry 之间改画布里的 `lock` 字段，就会触发这个早退。**第一发不要在 retry 间隙改画布。**

### 3.4 `requeue` 标志：为什么消费侧必然走 `[7]`

`requeue` 初值 `true`（`:675`），只有两处置 `false`：
- `:798`（在 `if (top_waiter)` 块内）—— 消费侧 `top_waiter = NULL`，**整块跳过** ⇒ 不触发
- `:813`（`rt_waiter_node_equal` 相等时）—— 我们让 prio 不等 ⇒ 不触发

⇒ **`requeue` 恒为 `true` ⇒ 一定走到 `[7] rt_mutex_dequeue`。**
★★ 这是消费侧相对 `remove_waiter` 的**决定性优势**：`remove_waiter` 只在 `-EDEADLK` 时被调用（要求三环拓扑），
消费侧**不需要任何死锁拓扑**，单线程 + 悬垂 waiter 即可。

---

## 4. `RB_EMPTY_NODE` 闸门（`rbtree.h:33-36`）—— H175 的「单发门」需重新表述

```c
#define RB_EMPTY_NODE(node)  ((node)->__rb_parent_color == (unsigned long)(node))
#define RB_CLEAR_NODE(node)  ((node)->__rb_parent_color = (unsigned long)(node))
```

`rt_mutex_dequeue` 第一件事就是它。画布下：
```
waiter->tree.__rb_parent_color = V   （画布 v7.d[0]，我方设）
&waiter->tree.entry               = SP0-0x210（画布 +0x70 处的地址）
```
⇒ **若 `V == (unsigned long)&waiter->tree.entry`，则 `RB_EMPTY_NODE` 成立 → `rt_mutex_dequeue` 直接 return，不执行 `rb_erase`。**

★ 这正是 H175 记忆里「rb_node 陷阱」的机制。**判据表述应改为**：
> `V ≠ (unsigned long)&waiter->tree.entry` ⇒ 进入 `rb_erase`。
>
> 而 `&waiter->tree.entry` 是**画布自己的内核栈地址**，我们不知道（栈地址随机化 + 我们只能填 vreg 常量）。
> ⇒ **约束简化：`V` 取一个与任何栈地址都不可能相等的内核值**（例如直接用目标写值 `init_cred` 或 `task+0x818`），
> 实际碰撞概率为 0。**不需要「单发门」这种读栈的操作。**

★★ **这条推翻了 H175 的「单发门」设计**（记忆 §1「`lock->waiters.rb_leftmost != waiter` ⇒ 命中干净出口 A」）：
那个门是为了绕开 `remove_waiter` 的真实 `lock`；消费侧的 `lock` 是我们自己给的假地址，**门不存在**。

---

## 5. ★ 写原语 #1：`[5] raw_spin_trylock(&lock->wait_lock)`（`rtmutex.c:830`）

```c
	lock = waiter->lock;                              // :820  ★ 我方控制
	...
	if (!raw_spin_trylock(&lock->wait_lock)) {        // :830
		raw_spin_unlock_irq(&task->pi_lock);
		cpu_relax();
		goto retry;
	}
```

`struct rt_mutex_base`（本机源码 `rtmutex_types.h`）：
```c
struct rt_mutex_base {
	raw_spinlock_t		wait_lock;      // +0x00
	struct rb_root_cached   waiters;        // +0x08（rb_root +0x08, rb_leftmost +0x10）
	struct task_struct	*owner;          // +0x18
};
```
★ 注意 `owner` 在 **`+0x18`**，不是 `+0x10`。`waiters` 是 `rb_root_cached`（**两个指针**，共 16 字节），
所以 `waiters.rb_node` 在 `lock+0x08`、`waiters.rb_leftmost` 在 `lock+0x10`、`owner` 在 `lock+0x18`。

**写原语 #1 的语义**：`raw_spin_trylock` 是原子 test-and-set，**成功即把 `*(u64*)(lock+0x00)` 从 0 写成 1**。
- 写地址 = `lock + 0x00`，`lock` 我方任意 ⇒ **任意地址的 8 字节写，值固定为 1**
- 前置：`*(u64*)lock == 0`（否则 trylock 失败 → `goto retry`）
- ★ 这是**最干净的探针**：只写 1 个已知值，且必然发生一次（成功时），失败时可观测（retry 次数）

**★ 关键：`lock` 完全由我方给定 ⇒ 不需要知道任何内核真实地址。**
但 `lock` 必须指向**可写的内核内存**。候选见 §7。

---

## 6. ★★★ 写原语 #2：`[7] rb_erase`（`rtmutex.c:920` → `rbtree_augmented.h:224`）

### 6.1 本机源码逐行（本轮实读，H175 只引了汇编）

```c
	/* [7] Requeue the waiter in the lock waiter tree. */
	rt_mutex_dequeue(lock, waiter);          // :920
	waiter_update_prio(waiter, task);        // :933
	rt_mutex_enqueue(lock, waiter);          // :935
```

`rb_erase_cached(&waiter->tree.entry, &lock->waiters)`（`rbtree.h:116-127`）：
```c
static inline struct rb_node *
rb_erase_cached(struct rb_node *node, struct rb_root_cached *root)
{
	struct rb_node *leftmost = NULL;
	if (root->rb_leftmost == node)                    // ★ 读 lock+0x10
		leftmost = root->rb_leftmost = rb_next(node);
	rb_erase(node, &root->rb_node);                  // ★ root = lock+0x08
	return leftmost;
}
```
⇒ **`root = &lock->waiters.rb_node = lock + 0x08`**，而 `lock` 是我方给的 ⇒ root 也我方控制。

`__rb_erase_augmented`（`rbtree_augmented.h:224-323`）Case 1（`node->rb_left == 0`，即 `tmp == NULL`）：
```c
	struct rb_node *child = node->rb_right;      // :227  waiter+0x08
	struct rb_node *tmp = node->rb_left;         // :228  waiter+0x10
	if (!tmp) {                                  // :232  ★ rb_left == 0
		pc = node->__rb_parent_color;        // :240  waiter+0x00 = V
		parent = __rb_parent(pc);            // :241  parent = V & ~3
		__rb_change_child(node, child, parent, root);   // :242
		if (child) {
			child->__rb_parent_color = pc;  // :244  ★ 第 2 次写
			rebalance = NULL;                // :245
		} else
			rebalance = __rb_is_black(pc) ? parent : NULL;
		tmp = parent;
	}
```

`__rb_change_child`（`rbtree_augmented.h:194-205`）：
```c
static inline void
__rb_change_child(struct rb_node *old, struct rb_node *new,
		  struct rb_node *parent, struct rb_root *root)
{
	if (parent) {
		if (parent->rb_left == old)
			WRITE_ONCE(parent->rb_left, new);     // 写 parent+0x10
		else
			WRITE_ONCE(parent->rb_right, new);    // 写 parent+0x08
	} else
		WRITE_ONCE(root->rb_node, new);            // 写 root+0x00 = lock+0x08
}
```

### 6.2 写原语的两条路径（★ H175 的 Path A/B 表述需修正★）

| 路径 | 条件 | 机制 | 写址 | 写值 | 额外动作 |
|---|---|---|---|---|---|
| **Case1-a** | `rb_left == 0`, `rb_right != 0` | `:244` `child->__rb_parent_color = pc` | **`child` = 我方设的 `rb_right`** | **`V` = 我方设的 `parent_color`** | `rebalance=NULL` ⇒ **不做 `____rb_erase_color`，干净退出** |
| **Case1-b** | `rb_left == 0`, `rb_right == 0` | `:242` `__rb_change_child(node, NULL, V&~3, root)` | `V&~3 == 0` ⇒ `lock+0x08`；否则 `V&~3 +0x10/+0x08` | `0`（child=NULL） | `rebalance = parent`（若 V 是黑）⇒ **可能进 `____rb_erase_color`** |

★ **H175 的「Path A：rb_left==0 && rb_right!=0」与「Path B：rb_left!=0 && rb_right==0」表述有误**：
`__rb_erase_augmented` 的 Case 1 分支条件是 **`!tmp` 即 `rb_left == 0`**，Case 2 是 `tmp != 0 && !child`。
即：
- **rb_left == 0** ⇒ Case 1：`child = rb_right`。若 `rb_right != 0` ⇒ 走 `:244`，**写 `*(rb_right) = V`**。
- **rb_left != 0 && rb_right == 0** ⇒ Case 2（`:249-255`）：`tmp->__rb_parent_color = pc` ⇒ **写 `*(rb_left) = V`**，然后 `rebalance = NULL`（`:254`）⇒ **干净退出**。

★★ **两条路都干净（都 `rebalance = NULL`）**，只要 **`child`/`tmp` 与 `parent` 的组合让 `rebalance` 为 NULL**：
- `rb_left != 0 && rb_right == 0` ⇒ `:254` 强制 `rebalance = NULL` ⇒ **绝对干净**，不调 `____rb_erase_color`
- `rb_left == 0 && rb_right != 0` ⇒ `:245` `rebalance = NULL` ⇒ **绝对干净**

★★ **结论：H175 的几何（`rb_left = 0`, `rb_right = T`, `parent_color = V`）走的正是 Case 1 + `:244`，
写 `*(T) = V`，且 `rebalance = NULL` 完全不碰 rebalance。H175 的 Path 判定是对的，只是命名反了（叫 A/B 但实际是 Case1/Case2）。**

### 6.3 消费侧的副作用清单（★ 这是比 `remove_waiter` 干净的根本原因★）

| 副作用 | `remove_waiter` 路径 | **消费侧 `[7]` 路径** |
|---|---|---|
| `root`（`rb_root*`） | **真实树**（`pi_state->pi_mutex.waiters`） | **我方给的 `lock+0x08`** |
| `rb_erase_cached` 读 `root->rb_leftmost` | 真实内存 | 我方内存 |
| `:244` 写 `*(rb_right)` | **任意地址 T 我方控制** | **任意地址 T 我方控制**（同） |
| `RB_CLEAR_NODE` 写 `parent_color = &node` | 写真实树 | 写画布 |
| `waiter_update_prio`（`:933`） | `waiter->tree.prio = __waiter_prio(task)`；`task->dl.deadline` | 同（写画布） |
| `rt_mutex_enqueue`（`:935`） | **`rb_add_cached` 插入真实树** ⇒ 后续 unlock 崩溃 | **插入我方树** ⇒ 若 root 为 0 则单节点插入（见下） |
| 后续 | `fixup_rt_mutex_waiters`（`rtmutex_api.c:439`）二次动树 | **无**，`[9]` 直接返回 |

★★ **干净出口的完整链条（消费侧）**：
```c
	rt_mutex_dequeue(lock, waiter);     // :920  ★ 写原语在此
	waiter_update_prio(waiter, task);   // :933  只写画布
	rt_mutex_enqueue(lock, waiter);     // :935  ★ root=lock+0.08 若为 0 ⇒
	                                     //        rb_add_cached 走 while 不进,
	                                     //        rb_link_node(node,NULL,&root->rb_node)
	                                     //        → root->rb_node = node
	                                     //        rb_insert_color: parent=NULL ⇒ break（:95-99）
	raw_spin_unlock(&task->pi_lock);    // :944
	put_task_struct(task);              // :945
	if (!rt_mutex_owner(lock)) {        // :954  ★ 若 lock+0x18 == 0 ⇒
		top_waiter = rt_mutex_top_waiter(lock);        // :960  读 lock+0x10
		if (prerequeue_top_waiter != top_waiter)      // :961  两者都读 lock+0x10 ⇒ 相等
			wake_up_state(...);                       //      ★ 不执行
		raw_spin_unlock_irq(&lock->wait_lock);         // :963  把 #1 写的 1 还原为 0
		return 0;                                       // :964  ★ 干净返回 0
	}
```

★★★ **三个「我方给 lock」带来的红利**：
1. **`lock+0x08 == 0`** ⇒ `rb_add_cached` 的 `while (*link)` 一次都不进 ⇒ 单节点插入，`__rb_insert` 在 `parent == NULL` 处 `break`（`rbtree.c:93-99`）⇒ **不做任何重平衡**
2. **`lock+0x18 == 0`** ⇒ `[9]` 命中 ⇒ `raw_spin_unlock_irq(&lock->wait_lock)` **把 trylock 写的 1 擦回 0** ⇒ 写原语 #1 净效果为零，**不留痕迹**
3. **`prerequeue_top_waiter`（`:917` 读 `lock+0x10`）与 `top_waiter`（`:960` 读 `lock+0x10`）是同一地址** ⇒ `:961` 恒等 ⇒ **不执行 `wake_up_state`**

⇒ **消费侧路径可以做到「写原语 #2 落地 + 不 panic + 内核状态基本不变」。这是 `remove_waiter` 做不到的。**

★ 唯一残留：`[9]` 分支里 `raw_spin_unlock_irq(&lock->wait_lock)` 会写 `lock+0x00`。若我们把 `lock` 指向**真实的**
可写内核地址，这会破坏真实 spinlock；所以 `lock` 必须指向**一块安全的、我们独占的可写内核内存**。

---

## 7. `lock` 的选点：必须是「可写 + 独占 + wait_lock 初值为 0」

| 约束 | 来源 |
|---|---|
| `lock+0x00` 可写，初值 0 | `[5]` trylock 成功；`[9]` unlock 写回 0 |
| `lock+0x08 == 0`（root 空） | §6.3 红利 1 |
| `lock+0x10` 任意但两次读同值 | §6.3 红利 3 |
| `lock+0x18 == 0`（无 owner） | §6.3 红利 2 ⇒ `[9]` 命中 |
| `lock+0x00` 独占（trylock/unlock 之间不被抢） | `[5]`→`[9]` 期间持锁 |

★ **不能选 `pi_state->pi_mutex`**（真实、有 owner、有 waiters）。
★ **候选：`task_struct` 内某个当前进程独占的、值为 0 的 8 字节字段**，例如
`task->ptracer_cred`（`+0x810`，BTF 已证，通常为 NULL）、`task->real_cred` 之外的空隙等。
⇒ **`task + 0x810`（`ptracer_cred`）是首选候选**：一个进程独享、初值 NULL（0）、8 字节对齐。
trylock 写 1 → `[6]` owner 读 `+0x18`（落在 `task+0x828`，需为 0）→ `[7]` root 读 `+0x08`（`task+0x818`，需为 0）……
★ **但 `task+0x818 = real_cred`、`+0x820 = cred` 非 0** ⇒ `lock = task+0x810` 会让 `lock+0x08 = task+0x818 = real_cred ≠ 0`
⇒ `rb_add_cached` 会进入 while 循环遍历 `real_cred` 指向的树 ⇒ **必崩**。

⇒ **必须找一块全 0 的 8 字节对齐区**。这需要扫描 BTF 里的候选字段，**列为下一步**（见 §9）。

---

## 8. 写原语 #2 的最终写入语义（★ 这一发怎么打★）

设定画布（`waiter` 偏移 → 画布偏移 → vreg 槽沿用 H175 机器重算表）：
```
waiter+0x00  __rb_parent_color = V   画布+0x70  v7.d[0]   ★ 写值
waiter+0x08  rb_right          = T   画布+0x78  v7.d[1]   ★ 写地址（Case 1, :244）
waiter+0x10  rb_left           = 0   画布+0x80  v8.d[0]   ★ 必须 0（进 Case 1）
waiter+0x18  tree.prio         = 0   画布+0x88  v8.d[1]   ★ 与 task->prio 不等即可
waiter+0x50  task              = ?   画布+0xc0  v12.d[0]
waiter+0x58  lock              = L   画布+0xc8  v12.d[1]   ★ 假锁地址
```

★ **结构巧合（比 H175 更优）**：`V`（写值）与 `T`（写地址）**同处 `v7` 的两个 lane**：
`fmov d7, %[VT]` 一次 8 字节加载即可同时设置 `v7.d[0]=V`、`v7.d[1]=T`（若编译器把 16 字节常量塞进一个 d 寄存器对）。
需写成 `ldr q7, %[VT16]` 或 `fmov x7, %[VT]`（x 寄存器视图写 v7 的低 64 位）—— **H175 的 `fmov d7/d8` 写法需要改成 `fmov x7` 形式**才能一次填满 v7 两 lane。

执行序列（第一发，**只验通道 + 不崩**，零内核语义写）：
| 步 | 动作 | 判据 |
|---|---|---|
| S1 | W 持 `f_chain`，等 `g_go` | — |
| S2 | `WAIT_REQUEUE_PI(f_src, f_target)` 带 abs_time → 超时返回，栈上留 `rt_waiter` | 返回 `ETIMEDOUT` |
| S3 | `tgkill` 投递画布（v7={V,T}, v8.d[0]=0, v8.d[1]=0, v12={task,L}） | `sig_hits` 计数 |
| S4 | `sched_setattr(self, SCHED_FIFO/RR, pi=true)` | **返回码 0**（`[9]` `return 0`） |
| ★ 判据 | S4 返回 0 且不 panic ⇒ 写原语 #1+#2 都执行了 | 独立透镜：syscall 返回码 |

★ **V/T 的第一发取值（`verify` 模式）**：
- `T` = 一个**无害可写地址**（暂定某 `.bss` 空隙，待 §9 选定）
- `V` = `0xdeadbeef` 之类哑值（写进去无害，且 `V != &node` 保证过 `RB_EMPTY_NODE`）
- `L` = 全 0 的 8 字节对齐内核地址（待 §9 选定）

---

## 9. 未决项（下一轮必须闭合，按优先级）

| # | 事项 | 为什么必须做 | 状态 |
|---|---|---|---|
| **U1** | 找 `lock = L`：一块**可写、独占、全 0（至少 +0x00/+0x08/+0x10/+0x18 四个 qword 为 0）** 的内核地址 | §7。没有它 `[5]` trylock 必失败 → 死循环 retry | **阻塞第一发** |
| **U2** | 复核 H175 画布 vreg 槽位在新「写值/写地址同处 v7」下的投递编码 | §8，需把 `fmov d7/d8` 改成能填满 v7 两 lane 的形式 | 未做 |
| **U3** | `waiter->task`（`+0x50`）该填什么 | `[9]` 分支不 deref 它；但 `[11]`（`:977`）若命中会 deref。我们的走向是 `[9]` 返回 ⇒ 不 deref。**建议填 0 或 task 自身** | 未决 |
| **U4** | `wake_state`（`+0x60`）/`ww_ctx`（`+0x68`） | §3.2 表已证都不 deref（`top_waiter=NULL` 跳过 `:785` 块；PREEMPT_RT 短路 `:777`）⇒ **保持 0** | 已闭合 |
| **U5** | `init_task = 0xffffffc08217e280` vs BTF `size=0x12c0` 不符（`__start_init_task=0xffffffc082160000` ⇒ 实测 span `0x1e280`） | 说明 vendor 用了 RANDSTRUCT 或 BTF 与实际布局有 delta。**所有 task_struct 偏移必须以 BTF 为准并标注置信度**，不能拿 span 反推 | 已记录 |
| **U6** | CVE-2026-64560（`posix-cpu-timers` non-leader exec 竞争 UAF） | 独立面，仍未推进 | 未推进 |

---

## 10. 与既有报告的关系（交叉校验）

| 既有结论 | 本轮处置 |
|---|---|
| H172/H175：`&rt_waiter = SP0-0x210`，画布 `[SP0-0x280, SP0-0x80]` | **不变**（`requeue.c:790` 确认 W 栈上是局部变量） |
| H175：落点 `remove_waiter@0xffffffc081080e60` | **★ 作废**（§2：`lock` 是真实 `pi_mutex`，不可控） |
| H175/R1：`lock->waiters.rb_leftmost != waiter` 单发门 | **★ 作废**（§4：消费侧 `lock` 我方给，门不存在） |
| H175/R1：规避 `fixup_rt_mutex_waiters` | **★ 作废**（消费侧无 fixup 调用） |
| H175：`setpriority(nice=1)` 破早退闸门 | **可省**（清零 `tree.prio` 已保证不等；§3.1） |
| H142：`rt_mutex_adjust_pi` 消费点是 UAF 读 | **★ 交叉验证成立**，且本轮补全了 `[4]`→`[13]` 完整控制流 |
| H173：门 A（`owner==task`）是伪环 | **不受影响**（消费侧 `orig_lock=NULL`，`:845` 只判 owner；且 `detect_deadlock=false`） |
| H174：`-EDEADLK` 双出口（`:845` / `:704`） | **消费侧不需要 EDEADLK**（§3.4）⇒ 三环拓扑在消费侧**不必要** |
| ★ H175 vreg 槽位机器重算（`v7.d[0]`=V, `v7.d[1]`=rb_right, `v8.d[0]`=rb_left） | **成立且更优**（V 与 T 同处 v7）；但 Path 命名需改为 Case1/Case2（§6.2） |

---

## 11. 可证伪判据表

| 判据 | 若成立则应观测到 | 若不成立则结论错在 |
|---|---|---|
| 消费侧 `[7]` 会执行 `rb_erase` | `sched_setattr(pi=true)` 返回 **0**（`[9]` `return 0`），且 `boot_id` 不变 | 错在 §3.2 的 `top_waiter=NULL` 跳过逻辑，或 `rt_mutex_adjust_pi` 未被 `core.c:8014` 调用 |
| `lock` 选点正确 | `[5]` trylock 成功（不 retry）+ `[9]` owner 判空命中 | 错在 U1（选点非全 0 / 非独占） |
| 画布投递生效 | `sig_hits` 计数 == 投递次数 | 错在 vreg 槽位或帧深（H172/H175 已证，本轮不变） |
| 写原语 #2 落地 | 第一发用哑值 T/V 时无任何异常；用真值时 `task->cred` 变 `init_cred` | 错在 Case 1 判定（`rb_left==0` 未成立）或 `RB_EMPTY_NODE` 早退 |
| `remove_waiter` 不可用 | 若强行走 requeue 路径，`lock+0x08` 写真实树后必 panic 于 `fixup_rt_mutex_waiters` | 若不 panic，说明 `lock` 其实可被伪造（则 §2 需重审） |

---

## 12. 引用（本轮实读文件清单）

| 文件 | 行 | 内容 |
|---|---|---|
| `kernel/futex/requeue.c` | 786-797, 568-664, 627-629 | `rt_waiter` 是栈上局部变量；requeue 主循环 |
| `kernel/futex/futex.h` | 103, 112 | `futex_q.rt_waiter` 是指针；`__randomize_layout` |
| `kernel/locking/rtmutex_api.c` | 458-479, 344-357, 14 | `rt_mutex_adjust_pi`；`remove_waiter` 调用点；`max_lock_depth` |
| `kernel/locking/rtmutex.c` | 470-479, 663-1059, 1524-1545, 366-407, 327-336 | dequeue/enqueue；完整链走；remove_waiter；prio 比较 |
| `lib/rbtree.c` | 78-99, 425-447 | `__rb_insert`；`rb_insert_color`/`rb_erase` |
| `include/linux/rbtree_augmented.h` | 194-205, 223-323 | `__rb_change_child`；`__rb_erase_augmented` |
| `include/linux/rbtree.h` | 31-37, 116-127, 165-183 | `RB_EMPTY_NODE`；`rb_erase_cached`；`rb_add_cached` |
| `kernel/sched/core.c` | 8012-8015 | `if (pi) rt_mutex_adjust_pi(p)` |
| `kernel/sched/prio.h`, `deadline.h` | 16, 11-18 | `MAX_RT_PRIO=100`；`MAX_DL_PRIO=0` ⇒ `dl_prio(p)=p<0` 恒假 |
| `kernel/locking/rtmutex_common.h` | 32-59 | `rt_waiter_node` / `rt_mutex_waiter` 布局 |
| `analysis/scratch/mey_config.txt` | — | `DEBUG_RT_MUTEXES=n`、`PROVE_LOCKING=n`、`RT_MUTEXES=y` |
| `analysis/output/btf_offsets.txt` | 1-120, 220-246, 312 | `task_struct`（`cred+0x820`）；`struct cred`；`rt_mutex_waiter` |

★ **本机 BTF 复核（本轮新增）**：
- `struct cred` size=`0xb8`，`usage@0x00`、`uid@0x08`、`security@0x80`、`user@0x88`
- `task_struct`：`stack_canary@0x620`、`ptracer_cred@0x810`、`real_cred@0x818`、`cred@0x820`
- `init_cred = 0xffffffc082190790`（沿用基线）