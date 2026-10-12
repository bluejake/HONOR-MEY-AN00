# H173 · `remove_waiter` 触发条件闭合（H172 几何的最后一环）

基线：MEY-AN00 / SM8735 / 6.6.118-android15 / `_text=0xffffffc080000000`
证据来源：**SRC**＝`kernel_src/Code_Opensource/kernel`（6.6.56，与设备 6.6.118 同代；本轮全部为源码级逻辑推导，**未做汇编逐条复核**——见 §6）
前序：`analysis/output/l1_geometry_h172_remove_waiter.md`（几何已闭合，本文件补触发条件）

---

## 0. 一句话结论

**`rt_mutex_start_proxy_lock`（`rtmutex_api.c:353`）的 `remove_waiter` 可以纯用户态触发，EDEADLK 由「自死锁早退门」`owner == task` 制造，无需真实 PI 链；而 `lock` 恒为已锁状态（owner = requeuer 自身）保证 `ret` 不会被 `ret = 0` 重置掉。** 触发路径与 H172 的画布几何正交——两者合起来构成完整链路。

---

## 1. 问题：EDEADLK 怎么造？

`rt_mutex_start_proxy_lock` 只在 `ret != 0` 时调 `remove_waiter`：

```c
int __sched rt_mutex_start_proxy_lock(struct rt_mutex_base *lock,
				      struct rt_mutex_waiter *waiter,
				      struct task_struct *task)
{
	int ret;
	raw_spin_lock_irq(&lock->wait_lock);
	ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
	if (unlikely(ret))
		remove_waiter(lock, waiter);          // ← :353
	raw_spin_unlock_irq(&lock->wait_lock);
	return ret;
}
```

`ret` 唯一来源是 `task_blocks_on_rt_mutex()`，它有**两个**返回负值的分支。

### 1.1 早退门 A（★本轮选它★）：`owner == task` ⇒ `-EDEADLK`

```c
static int __sched task_blocks_on_rt_mutex(struct rt_mutex_base *lock,
				   struct rt_mutex_waiter *waiter,
				   struct task_struct *task, ...)
{
	struct task_struct *owner = rt_mutex_owner(lock);
	...
	if (owner == task && !(build_ww_mutex() && ww_ctx))
		return -EDEADLK;
	...
}
```
**这是纯指针比较，不进链遍历、不需要任何真实 PI 链。**

### 1.2 早退门 B：链式遍历检测（`rt_mutex_cond_detect_deadlock` + `rt_mutex_adjust_prio_chain`）

```c
static __always_inline bool
rt_mutex_cond_detect_deadlock(struct rt_mutex_waiter *waiter,
			      enum rtmutex_chainwalk chwalk)
{
	if (IS_ENABLED(CONFIG_DEBUG_RT_MUTEXES))
		return waiter != NULL;
	return chwalk == RT_MUTEX_FULL_CHAINWALK;
}
```
本机若 `CONFIG_DEBUG_RT_MUTEXES=n`（加固全启的设备通常如此，**本轮未核实**），则只有 `chwalk == RT_MUTEX_FULL_CHAINWALK` 才检测 —— 而 `start_proxy_lock` 恰好传的就是 `RT_MUTEX_FULL_CHAINWALK`（`rtmutex_api.c:311`）。
⇒ 门 B 需要构造真实的多级 PI 链（≥2 级 `pi_blocked_on` 闭环），成本高、命中概率低。
⇒ **选门 A。**

---

## 2. ★核心难点：`ret` 会不会被重置为 0？★

这是本轮最需要小心的地方。`__rt_mutex_start_proxy_lock` 末尾有：

```c
	ret = task_blocks_on_rt_mutex(lock, waiter, task, NULL,
				      RT_MUTEX_FULL_CHAINWALK);

	if (ret && !rt_mutex_owner(lock)) {
		/*
		 * Reset the return value. We might have
		 * returned with -EDEADLK and the owner
		 * released the lock while we were walking the
		 * pi chain.  Let the waiter sort it out.
		 */
		ret = 0;
	}

	return ret;
```

**若 `rt_mutex_owner(lock) == 0`，EDEADLK 会被吞掉，`remove_waiter` 不执行。** 所以必须保证 `owner` 非空。

### 2.1 `lock` 恒为「已锁定」—— 源码双证

`lock` = `&pi_state->pi_mutex`。它由 `futex_lock_pi` 创建时初始化：

```c
/* kernel/futex/pi.c:388 */
rt_mutex_init_proxy_locked(&pi_state->pi_mutex, p);
```

```c
/* kernel/locking/rtmutex_api.c:241 */
void __sched rt_mutex_init_proxy_locked(struct rt_mutex_base *lock,
					struct task_struct *proxy_owner)
{
	...
	__rt_mutex_base_init(lock);
	lockdep_set_class(&lock->wait_lock, &pi_futex_key);
	rt_mutex_set_owner(lock, proxy_owner);      // ★ owner = p = PI 等待者
}
```

⇒ **`pi_mutex` 从诞生起 owner 就非空**，直到 `futex_unlock_pi` 才清。
⇒ **`ret = 0` 重置分支在本路径上不会命中。** EDEADLK 稳定穿透到 `:353`。

---

## 3. ★矛盾：门 A 要求 `owner == task`，但 owner 是别人 ★

门 A 是 `if (owner == task) return -EDEADLK;`（`task_blocks_on_rt_mutex` 的参数 `task`）。
而 `lock` 的 owner 是 **PI 等待者**（`futex_lock_pi` 里的那个线程 `p`）。
而 `requeue` 传给 `start_proxy_lock` 的 `task` 是 **`this->task`** —— 被 requeue 的那个 waiter 线程。

**两者是不同线程 ⇒ 门 A 的 `owner == task` 天然不成立。**

⇒ **门 A 在 proxy 路径上不可用。** 这是本轮第一个被证伪的设想。

### 3.1 剩下的唯一可行门：B（链式检测）

要在 proxy 路径上产生 EDEADLK，必须让 `rt_mutex_adjust_prio_chain` 的 `again:` 循环检测到闭环。条件（`rtmutex.c:670-690`）：

```c
	if (!chain_walk || !next_lock)
		return 0;
	...
	/* 走 rt_mutex_adjust_prio_chain(task=owner, FULL_CHAINWALK, lock, next_lock, ...) */
```

其中 `chain_walk` 由前面两处之一置 1：
```c
	if (waiter == rt_mutex_top_waiter(lock)) {
		rt_mutex_dequeue_pi(owner, top_waiter);
		rt_mutex_enqueue_pi(owner, waiter);
		rt_mutex_adjust_prio(lock, owner);
		if (owner->pi_blocked_on)
			chain_walk = 1;                    // ← 门 B1：owner 自己也在等锁
	} else if (rt_mutex_cond_detect_deadlock(waiter, chwalk)) {
		chain_walk = 1;                            // ← 门 B2：我们不是 top waiter
	}
```

⇒ **门 B1**：只要 `pi_mutex` 的 owner（PI 等待者线程 `p`）**自己也阻塞在另一把锁上**（`p->pi_blocked_on != NULL`），且新 waiter 是 top waiter，就会进链遍历。
⇒ 闭环由 `rt_mutex_adjust_prio_chain` 的 `check_exit_conditions_*` 系列发现，返回 `-EDEADLK`。

**构造要求（用户态）**：
1. 线程 `P1` 对 futex A 做 `FUTEX_LOCK_PI`（拿到 `A` 的 pi_mutex，owner = P1）。
2. 线程 `P2` 对 futex B 做 `FUTEX_LOCK_PI`（拿到 `B` 的 pi_mutex，owner = P2）。
3. `P1` 阻塞等 `B`（`FUTEX_WAIT` 或 requeue 到 B）⇒ `P1->pi_blocked_on` 指向 `B` 的 waiter。
4. `P2` 发起 `FUTEX_CMP_REQUEUE_PI`，把一个**已等 A** 的 waiter `W` requeue 到 A ⇒ `start_proxy_lock(A, W->rt_waiter, W->task)`。
   - `owner(A) = P1`，`task = W`（不同）⇒ 门 A 不命中。
   - `W != top_waiter(A)`（若 A 上已有更早的 waiter）⇒ 门 B2 置 `chain_walk = 1`。
   - `next_lock = task_blocked_on_lock(P1) = B`（非 NULL）⇒ 进链遍历。
   - 链：`W → A → P1 → B → P2`；若 `P2` 又等 A（`P2->pi_blocked_on` 指向 A 的另一个 waiter）⇒ **闭环 ⇒ `-EDEADLK`**。
5. `owner(A) = P1` 非空 ⇒ `ret` 不被重置 ⇒ `remove_waiter(A, W->rt_waiter)` 执行 ⇒ **H172 的画布原语被消费**。

⚠️ **这一步的可行性本轮完全未验证**：需要 4 线程 + 2 把 PI futex + 精确的 requeue 时序。**H172 的画布只覆盖 `futex_wait_requeue_pi` 的栈 waiter，而 `W` 正是某个 `futex_wait_requeue_pi` 里的线程**（`W->rt_waiter` 指向它的栈局部）⇒ **只要 `W` 是通过 `FUTEX_WAIT_REQUEUE_PI` 进入等待的，CVE 拓扑与画布几何自动对齐。**

---

## 4. 另一条被本轮排除的路：`rtmutex.c:1707`（`__rt_mutex_slowlock`）

```c
static inline int __rt_mutex_slowlock_locked(struct rt_mutex_base *lock, ...)
{
	struct rt_mutex_waiter waiter;              // ← 栈 waiter，rtmutex.c:1726
	rt_mutex_init_waiter(&waiter);
	...
	ret = __rt_mutex_slowlock(lock, ww_ctx, state, RT_MUTEX_MIN_CHAINWALK, &waiter);
```
- `chwalk = RT_MUTEX_MIN_CHAINWALK` ⇒ **门 B 不生效**（`rt_mutex_cond_detect_deadlock` 返回 false）。
- 门 A 需要 `owner == current`（自己锁自己）—— 普通 `pthread_mutex_lock` 不会这样。
- ⇒ **在 `RT_MUTEX_MIN_CHAINWALK` 下几乎无法自然产生 EDEADLK** ⇒ 该路径**只能靠信号/超时打断**（`rt_mutex_slowlock_block` 返回 `-EINTR`/`-ETIMEDOUT`），而非 EDEADLK。

**但这条路仍可用**，且是 H172 原本设想的路：
```c
	ret = rt_mutex_slowlock_block(lock, ww_ctx, state, NULL, waiter);
	if (likely(!ret)) { ... } else {
		__set_current_state(TASK_RUNNING);
		remove_waiter(lock, waiter);            // ← :1707，EINTR 也会走到
		rt_mutex_handle_deadlock(ret, chwalk, lock, waiter);
	}
	fixup_rt_mutex_waiters(lock, true);          // ← :1715，R1 风险源
```
⇒ **给等待中的线程发一个信号**（`tgkill`）即可让它返回 `-EINTR` 进 `remove_waiter`。
⇒ 代价：① waiter 在**自己的** `__rt_mutex_slowlock_locked` 栈帧，不是 `futex_wait_requeue_pi` 的 ⇒ **H172 的 `SP0−0x210` 几何不适用**（那是 `futex` 路径的帧链）；② 返回前有 `fixup_rt_mutex_waiters` ⇒ R1 未规避。
⇒ **判为次选。**

---

## 5. 三条候选路径对比

| # | 路径 | waiter 来源 | 触发方式 | H172 画布适用？ | R1 | 难度 |
|---|---|---|---|---|---|---|
| **A** | `rtmutex_api.c:353` | `futex_q->rt_waiter` → `futex_wait_requeue_pi` 栈 | 4 线程 PI 链闭环造 EDEADLK | **✅ 是**（`SP0−0x210`） | ✅ 规避 | **高**（链构造难） |
| **B** | `rtmutex_api.c:439` | 同上 | `rt_mutex_cleanup_proxy_lock`：`rt_mutex_owner(lock) != current` ⇒ 无需 EDEADLK | **✅ 是** | ✅ 规避 | **★★ 低（值得优先评估）** |
| **C** | `rtmutex.c:1707` | 自己栈帧（`rtmutex.c:1726`） | `tgkill` 打断 ⇒ `-EINTR` | ❌ 帧链不同 | ❌ 有 fixup | 中 |

### 5.1 ★路径 B 可能是最省事的★

```c
bool __sched rt_mutex_cleanup_proxy_lock(struct rt_mutex_base *lock,
					 struct rt_mutex_waiter *waiter)
{
	bool cleanup = false;
	raw_spin_lock_irq(&lock->wait_lock);
	try_to_take_rt_mutex(lock, current, waiter);
	if (rt_mutex_owner(lock) != current) {      // ★ 条件极易满足
		remove_waiter(lock, waiter);        // ← :439
		cleanup = true;
	}
	fixup_rt_mutex_waiters(lock, false);        // ← ★ 只在 cleanup 时才调
	raw_spin_unlock_irq(&lock->wait_lock);
	return cleanup;
}
```

**`remove_waiter` 的触发条件只是 `rt_mutex_owner(lock) != current`**，比 A 的 EDEADLK 简单得多。
调用者在 `futex_requeue_pi_cleanups()`（`requeue.c`），触发时机是 **requeue 失败/取消后的清理路径**。

⚠️ **但注意**：`cleanup_proxy_lock` 后紧跟 `fixup_rt_mutex_waiters(lock, false)` ⇒ **R1（`lock+0x08` 被污染）在这条路上同样存在**，不能像 `:353` 那样规避。
⇒ **`:353` 仍是唯一「无 fixup」的调用点。**

---

## 6. 诚实标注：本轮的置信度分级

| 环节 | 置信度 | 依据 |
|---|---|---|
| `remove_waiter` 几何（P2/P3/P4 画布内、Path B 写点、单发门） | **汇编已证未实测** | H172 逐条 ASM + BTF |
| `ret` 不被重置（`pi_mutex` 恒有 owner） | **源码推断未验证** | 本轮源码双证（`pi.c:391` + `rtmutex_api.c:257`），**未做汇编复核** |
| 门 A 在 proxy 路径不成立 | **源码推断** | 纯参数比较，逻辑确定 |
| 门 B 的 4 线程 PI 链构造可行 | **未验证（最弱环节）** | 纯设计推演，**从未跑过** |
| `CONFIG_DEBUG_RT_MUTEXES` 的实际取值 | **未核实** | 影响门 B 是否需要 `FULL_CHAINWALK`（本路径已传 FULL，故不影响） |

**★ 明确未闭合**：§3.1 的 4 线程 PI 链闭环构造是**整个链路上唯一没有证据支撑的环节**。它的可行性直接决定路径 A 能否走通。

---

## 7. 可证伪判据

| 观测 | 结论 |
|---|---|
| `futex_cmp_requeue_pi` 返回 `-EDEADLK`（用户态可见） | ✔ 门 B 链构造成功，`remove_waiter` 已执行（**这是路径 A 成立的直接透镜**，不依赖内核内部观测） |
| `futex_cmp_requeue_pi` 返回 0 或成功数 > 0 | ✘ 链没闭上，EDEADLK 未产生 ⇒ 需增加链深度或改用 `FUTEX_CMP_REQUEUE_PI` 的 `FUTEX_REQUEUE` 位 |
| requeue 后**无崩溃、`boot_id` 不变** | 单发性质符合预期（干净出口 A）；但**这是零信息量判据**（循环自证禁止）⇒ 必须再看 EDEADLK 返回值 |
| 见 `brk #0x800` | 目标 waiter 成了 `leftmost`（H172 R2），需多一个竞争者 |
| page fault @ `owner+0x90c` | 误判成 top waiter，走上了 owner 路径 |

**★★ 独立透镜判据（必须用）**：路径 A 的成立与否，**唯一可信透镜是 `futex_cmp_requeue_pi` 的用户态返回值 `-EDEADLK`**。它由内核直接产生、用户态可读、且**不可能由"内核栈被控制"伪造**（因为它由链遍历逻辑决定，与画布内容无关）。这满足「独立于所用原语」的判据要求。

---

## 8. 下一步（按优先级）

1. **先做零风险的链路验证（不上内核写）**：写一个 4 线程 PI-futex 复现程序，仅验证「能让 `futex_cmp_requeue_pi` 返回 `-EDEADLK`」。这一步**不碰 sigreturn、不碰画布**，纯粹是普通用户态 futex 编程，判据是 syscall 返回值。**若这一步不成立，整条路径 A 作废，无需再投入。**
2. 第 1 步成立后，再叠加 sigreturn 画布（分段填 P2/P3/P4）。
3. 复核 `rt_mutex_start_proxy_lock` 与 `pi_mutex` 初始化的汇编（把本轮的「源码推断未验证」升为「汇编已证」）。
4. 备选：若路径 A 链构造始终不成立，转 §5 路径 C（`tgkill` 打断 `-EINTR`），并**重算该路径的 `&rt_waiter` 帧链**（不适用 `SP0−0x210`）。

**★ 纪律提示**：第 1 步是纯用户态、无内核写、判据是 syscall 返回值，**符合「一 boot 一发」的低风险要求**，可以在开火前先跑通。
