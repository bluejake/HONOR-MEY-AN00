# L1′ 几何重算 —— `remove_waiter` 落点（H172）

基线：MEY-AN00 / SM8735 / 6.6.118-android15 / `_text=0xffffffc080000000`
证据来源：**BTF**＝`analysis/output/btf_offsets.txt`（本机 BTF，唯一权威结构偏移）；**ASM**＝`analysis/scratch/dis_mey.py` capstone 裸 Image 反汇编（本轮重新逐指令读全 `0xffffffc081080e60`–`0xffffffc081081090` 与 `0xffffffc08003a9d4`–`0xffffffc08003ace4`）；**SRC**＝`kernel_src/Code_Opensource/kernel`（6.6.56，与设备 6.6.118 同代；结构布局一律以 BTF 复核，不以源码为准）

> 前序 `l1_geometry_h169.md` 针对 `rt_mutex_adjust_prio_chain`，其 P1–P5 **整体作废**。本文件取代它。

---

## 1. 卡点作答：`lock` 与 `waiter` 各从哪来？（H171 遗留的核心问题）

### 1.0 ★先修正 H171 的一个事实错误★

H171 写「`remove_waiter` 全局唯一调用点 = `rtmutex.c:1707`」。本轮全树 grep 实测：

```
kernel/locking/rtmutex.c:1707:   remove_waiter(lock, waiter);      ← __rt_mutex_slowlock
kernel/locking/rtmutex_api.c:353: remove_waiter(lock, waiter);      ← __rt_mutex_start_proxy_lock 失败分支
kernel/locking/rtmutex_api.c:439: remove_waiter(lock, waiter);      ← __rt_mutex_cleanup_proxy_lock
```

**共 3 个调用点。** H171 的「唯一」作废。这一修正很重要：后两个调用点（`rtmutex_api.c`）的 `waiter` **不是栈变量**，而是 `futex_q->rt_waiter`（`requeue.c:627-629` 传入），指向的仍是 `futex_wait_requeue_pi` 的栈局部 —— **栈帧几何与 H171 假设完全一致**，且 `lock` 是 `&pi_state->pi_mutex`（真实内核锁）。

⇒ **三个调用点共享同一个 `&rt_waiter` 栈几何（`SP0−0x210`），因此 §5.1 的画布结论对三者同时成立。** 这给了我们**三个独立的触发时机**去消费同一份画布。

### 1.1 `lock`：内核真实 rt_mutex，不可控也不需要可控

```c
int __sched rt_mutex_start_proxy_lock(struct rt_mutex_base *lock,
				      struct rt_mutex_waiter *waiter,
				      struct task_struct *task)
{
	int ret;
	raw_spin_lock_irq(&lock->wait_lock);
	ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
	if (unlikely(ret))
		remove_waiter(lock, waiter);        // ← :353
	raw_spin_unlock_irq(&lock->wait_lock);
	return ret;
}
```
`lock` = `&pi_state->pi_mutex`（`requeue.c:627`），是内核真实 futex PI 锁的地址，**不可控**。

**但不需要可控** —— 见 §3：`lock` 的全部字段都可以是"安全的非零垃圾"而不出事，唯一需要精确控制的是 `waiter` 的 4 个字段（`tree` 的 rb_node 三字段），而它们**全在画布内**（§5.1）。

### 1.2 `waiter`：`futex_wait_requeue_pi` 的栈局部

```c
int futex_wait_requeue_pi(u32 __user *uaddr, unsigned int flags, u32 val,
			  ktime_t *abs_time, u64 bitset, u32 __user *uaddr2)
{
	struct hrtimer_sleeper timeout, *to;
	struct rt_mutex_waiter rt_waiter;          // ← 栈上
	struct futex_hash_bucket *hb;
	...
}
```
`requeue.c:627-629` 把 `this->rt_waiter`（指向该栈局部）传给 `rt_mutex_start_proxy_lock`。
`__rt_mutex_slowlock_locked`（rtmutex.c:1726）也有一个栈 waiter，但那是**当前任务自己的**慢路径，不是 CVE 拓扑。

⇒ **CVE-2026-43499 的栈上 stale waiter = `futex_wait_requeue_pi` 的 `rt_waiter`，位于 `SP0−0x210`，全部 14 词在 fpsimd 画布内。**


---

## 2. `remove_waiter` 逐指令重读（本轮新读，0xe60–0xf88）

```
0x...e60: paciasp
0x...e64: stp  x29,x30,[sp,#-0x50]!
0x...e78: mov  x29,sp
0x...e7c: ldr  x24,[x0,#0x10]     ; ★ x24 = lock->waiters.rb_leftmost (top_waiter)
0x...e80: mov  x19,x0              ; x19 = lock
0x...e84: mov  x23,x1              ; x23 = waiter
0x...e88: cbz  x24,#0x...e98       ; ★★ leftmost==NULL ⇒ 直接跳过 BUG_ON 校验
0x...e8c: ldr  x8,[x24,#0x58]      ; top_waiter->lock
0x...e90: cmp  x8,x19
0x...e94: b.ne #0x...f8c           ; BUG_ON(w->lock != lock) -> brk
0x...e98: mrs  x20,sp_el0          ; x20 = current
0x...e9c: add  x21,x20,#0x90c      ; &current->pi_lock
0x...ea0: ldr  x25,[x19,#0x18]      ; ★ x25 = lock->owner (原始值，含 HAS_WAITERS 位)
0x...ea4: mov  x0,x21
0x...ea8: bl   #0x...83358          ; raw_spin_lock(&current->pi_lock)
; ---- rt_mutex_dequeue(lock, waiter) 内联 ----
0x...eac: ldr  x8,[x23]            ; node->__rb_parent_color
0x...eb0: cmp  x8,x23
0x...eb4: b.eq #0x...ee4            ; RB_EMPTY_NODE ⇒ 跳过 dequeue
0x...eb8: ldr  x8,[x19,#0x10]      ; lock->waiters.rb_leftmost
0x...ebc: add  x22,x19,#8          ; ★ x22 = &lock->waiters.rb_root
0x...ec0: cmp  x8,x23
0x...ec4: b.ne #0x...ed4            ; ★ leftmost != node ⇒ 跳过 rb_next
0x...ec8: mov  x0,x23
0x...ecc: bl   #0x...3af24          ; rb_next(node)  [仅当 node 是 leftmost]
0x...ed0: str  x0,[x19,#0x10]      ; ★ 写 lock->waiters.rb_leftmost
0x...ed4: mov  x0,x23              ; node = &waiter->tree.entry  (waiter+0x00)
0x...ed8: mov  x1,x22              ; root = lock+0x08
0x...edc: bl   #0x...3a9d4          ; ★★ rb_erase —— 全函数唯一一处
0x...ee0: str  x23,[x23]           ; RB_CLEAR_NODE(node)
0x...ee4: mov  x0,x21
0x...ee8: str  xzr,[x20,#0x938]     ; current->pi_blocked_on = NULL
0x...eec: bl   #0x...83520          ; raw_spin_unlock(&current->pi_lock)
; ---- if (!owner || !is_top_waiter) return; ----
0x...ef0: cmp  x24,x23             ; ★ is_top_waiter = (leftmost == waiter)
0x...ef4: b.ne #0x...f70            ; ★★★ 干净出口 A：直接 epilogue
0x...ef8: and  x21,x25,#0xfe       ; owner = lock->owner & ~HAS_WAITERS
0x...efc: cbz  x21,#0x...f70       ; ★ 干净出口 B：owner==NULL
; ---- 以下只有「是 top waiter 且 owner 非空」才到达 ----
0x...f00: add  x22,x21,#0x90c      ; &owner->pi_lock
0x...f04: mov  x0,x22
0x...f08: bl   #0x...83358          ; raw_spin_lock(&owner->pi_lock)
0x...f0c: ldr  x8,[x23,#0x28]!     ; ★★ x23 = &waiter->pi_tree (waiter+0x28)
0x...f10: cmp  x8,x23
0x...f14: b.eq #0x...f44            ; RB_EMPTY_NODE(pi_tree) ⇒ 跳过 dequeue_pi
0x...f18: ldr  x8,[x21,#0x928]     ; owner->pi_waiters.rb_leftmost
0x...f1c: add  x24,x21,#0x920      ; ★ x24 = &owner->pi_waiters.rb_root
0x...f20: cmp  x8,x23
0x...f24: b.ne #0x...f34           ; leftmost != node ⇒ 跳过 rb_next
0x...f28: mov  x0,x23
0x...f2c: bl   #0x...3af24          ; rb_next
0x...f30: str  x0,[x21,#0x928]     ; 写 owner->pi_waiters.rb_leftmost
0x...f34: mov  x0,x23
0x...f38: mov  x1,x24              ; root = owner+0x920
0x...f3c: bl   #0x...3a9d4          ; ★★ 第二处 rb_erase（node = waiter+0x28）
0x...f40: str  x23,[x23]
0x...f44: ldr  x8,[x19,#8]         ; lock->waiters.rb_node
0x...f48: cbnz x8,#0x...f90        ; 非空 ⇒ requeue_pi 路径（0xf90–0x1090）
0x...f4c: ldr  x8,[x21,#0x920]     ; owner->pi_waiters.rb_node
0x...f50: cbnz x8,#0x...1000
0x...f54: mov  x1,xzr
0x...f58: mov  x0,x21
0x...f5c: bl   #0x...1691c8         ; rt_mutex_adjust_prio(lock, owner)
0x...f60: ldr  x8,[x21,#0x938]     ; owner->pi_blocked_on
0x...f64: cbnz x8,#0x...100c       ; 非空 ⇒ adjust_prio_chain
0x...f68: mov  x0,x22
0x...f6c: bl   #0x...83520          ; raw_spin_unlock(&owner->pi_lock)
0x...f70: ldp  ... ; autiasp ; ret  ; ★ 出口 A / B 汇合点（纯 epilogue）
0x...f8c: brk  #0x800               ; BUG_ON 落点
0x...f90: ... requeue_pi (0xf90–0x108c，含 rb_insert_color@0x...3a860)
```

---

## 3. ★★ 决定性优势：`leftmost == 0` ⇒ 单发，且**完全不需要 owner 也不需要 tree 合法**

三重门全部被一个字段短路：

| 门 | 地址 | `leftmost==0` 时 |
|---|---|---|
| BUG_ON(top_waiter->lock != lock) | `0xe88 cbz` | **跳过**，不解引用 |
| is_top_waiter ⇒ owner 门 | `0xef0 cmp` → `0xef4 b.ne` | **必然不等**（`x24=0`, `x23=waiter≠0`）⇒ 命中出口 A |
| 第二处 erase / requeue_pi / adjust_prio_chain | `0xf00` 起 | **全部不可达** |

⇒ **`lock` 只要满足 `lock->waiters.rb_leftmost == 0` 一个条件**，`remove_waiter` 就只做：
`pi_lock 加锁` → `rb_erase(node=waiter+0x00, root=lock+0x08)` → `RB_CLEAR_NODE` → `pi_blocked_on=NULL` → `pi_lock 解锁` → 返回。

对比 H169 的 `adjust_prio_chain`：那里要求 `owner==0` 才能单发，而 `owner` 是 `lock+0x18` 的**真实内核数据**（若锁正被别人持有，owner 非 0，无法伪造）。**这里是 `leftmost`——一个可以被我们的画布间接影响的缓存指针。**

### 3.1 但这引出一个新问题：`leftmost` 怎么变成 0？

这是**本落点唯一的真障碍**，必须诚实标注。三条路：

- **路线 A（写 `lock+0x10` 为 0）**：需要先有写原语 ⇒ 循环依赖，**不可行**（除非与别的原语组合）。
- **路线 B（让 waiter 不在树里）**：`remove_waiter` 走 dequeue 时若 `RB_EMPTY_NODE(&waiter->tree.entry)` 为真（`0xeac cmp x8,x23; b.eq`）则**跳过 rb_erase** ⇒ 原语不触发。所以 waiter 必须**在**树里。
- **路线 C（接受 leftmost 非 0，但控制它指向谁）** ★ 这才是可走的：

`0xe7c` 读 `leftmost`，`0xec0` 比较 `leftmost == node`：
- 若 `leftmost != node` ⇒ `0xec4 b.ne` **跳过 rb_next** ⇒ 不污染 `leftmost`。
- 然后 `0xedc` 的 `rb_erase(node=waiter+0x00, root=lock+0x08)` **照常执行** ⇒ **写原语照样到手！**
- 之后 `0xef0` `cmp x24, x23`：`leftmost != node` ⇒ **命中出口 A** ⇒ 后面全部跳过！

⇒ **只要 `lock->waiters.rb_leftmost != waiter`，就同时满足：跳过 rb_next + 跳过 owner 门 + 单发。**

**而 `lock->waiters.rb_leftmost` 是内核真实数据，但它指向的是"另一个 waiter"（真实存在的竞争者）——这不是我们能控制的，但我们可以让它自然非 0！**

**关键洞察（CVE-2026-43499 的天然条件）**：futex PI 锁上**必然有多个竞争 waiter**（否则不会触发 PI 链）。只要有 ≥2 个 waiter 在同一把锁上排队，`leftmost` 就是其中**优先级最高的那个**，而我们的目标 waiter（栈上那个）**不是** leftmost（否则它就是 top waiter，会走 `owner` 路径）。

⇒ **P1 彻底解掉，且不需要伪造任何东西。** 只需保证：目标 waiter 入队时**不是** leftmost。

**可证伪判据**：若结论成立 ⇒ 触发时应观测到 (1) 只有一次 `rb_erase` 生效；(2) `lock+0x10`（leftmost）**值不变**（因为跳过 rb_next）；(3) 从 `0xf70` 返回；(4) `lock+0x18`（owner）即使是真实非零值也不崩、不解引用。若见 `brk #0x800` ⇒ `leftmost->lock != lock`（说明 leftmost 恰好是我们伪造的 waiter，即我们意外成了 top waiter）。若见 page fault 落在 `owner+0x90c` ⇒ 说明误判成"是 top waiter"。

---

## 4. 写几何：`rb_erase` Path B（本轮复核 `0xffffffc08003a9d4`–`0xffffffc08003ac10`）

入口：
```
0x...a9d4: ldp  x8,x10,[x0,#8]    ; ★ x8 = node->rb_right, x10 = node->rb_left
0x...a9d8: cbnz x10,#0x...aa18   ; rb_left != 0 ⇒ 走 Path B
```
⇒ **Path B 条件：`node->rb_left != 0`（x10≠0）**。且 Path B 入口 `0x...aa18: cbz x8,#0x...ab04` 要求 `node->rb_right == 0`。

Path B 主体：
```
0x...ab04: ldr  x9,[x0]          ; x9 = node->__rb_parent_color
0x...ab08: ands x8,x9,#-4        ; x8 = parent
0x...ab0c: str  x9,[x10]         ; ★★★ 写点1: *(node->rb_left) = parent_color
0x...ab10: b.eq #0x...ac0c       ; parent==0 ⇒ 跳 root 写
0x...ab14: ldr  x9,[x8,#0x10]    ; parent->rb_left
0x...ab18: cmp  x9,x0
0x...ab1c: b.ne #0x...ac8c
0x...ab20: str  x10,[x8,#0x10]   ; 写点2: parent->rb_left = node->rb_left
0x...ab24: ret
; ---- parent==0 分支 ----
0x...ac0c: str  x10,[x1]         ; 写点3: root->rb_node = node->rb_left
0x...ac10: ret
; ---- parent!=0 但不是左孩子 ----
0x...ac8c: str  x10,[x8,#8]      ; 写点4: parent->rb_right = node->rb_left
0x...ac90: ret
```

### 4.1 写点解耦分析（本落点采用 Path B）

设 `node = waiter + 0x00`（`tree.entry`，BTF 确认 `tree` off=0x00）。

| 量 | 来源 | 我们可控？ |
|---|---|---|
| **写地址** `T` | `node->rb_left` = `waiter+0x10` 的**值**（不是 waiter 自身） | ✅ **完全可控**（画布内） |
| **写值** `V` | `node->__rb_parent_color` = `waiter+0x00` 的值 | ✅ **完全可控**（画布内） |
| `parent` | `V & ~3` | ✅ 我们自己填 `V` ⇒ parent 随之确定 |
| `node->rb_right` | `waiter+0x08` | ✅ 必须填 **0**（Path B 入口条件） |

**为什么选 Path B 而非 Path A**：
- Path A（`rb_left==0 && rb_right!=0`）写 **parent 的槽**（`parent+0x10` 或 `parent+0x08`），写地址半可控（取决于 `parent->rb_left == node`），且要解引用 `parent`。
- Path B 写 `*(node->rb_left)` ⇒ **写地址就是我们自己填进去的那个值**，写值也是我们自己填的，**两者完全解耦、都不需要解引用任何我们不控制的指针**（`parent==0` 时）。

**零副作用分支**：`V ∈ {0,1,2,3}` ⇒ `parent = V & ~3 = 0` ⇒ `b.eq` 命中 ⇒ 跳 `0xac0c: str x10,[x1]`（写 `root->rb_node = T`）后 `ret`。
- ⚠️ **注意**：这条路**不是**「什么都不写」——它会写 `root->rb_node`（= `lock+0x08`）为 `T`。若 `T` 是个野指针，`lock->waiters.rb_node` 会被污染成野值 ⇒ **后续任何对该锁的 `rb_add_cached` 会 page fault**。
- 但 `remove_waiter` 之后 `__rt_mutex_slowlock` 还会调 `fixup_rt_mutex_waiters(lock, true)`（rtmutex.c:1715），它会检查 `RT_MUTEX_HAS_WAITERS` 位。**这是本落点必须处理的残留风险**，见 §6 R1。

**要真正做到「只写 T 处一处」**：需 `parent != 0` 且 `parent->rb_left != node` ⇒ 命中 `0x...ac8c: str x10,[x8,#8]`（写 `parent->rb_right = T`）。这会**多写一处** `parent+0x08`。
⇒ **权衡**：`parent==0`（1 次额外写，但污染 `lock+0x08`）vs `parent` 指向我方控制的合法内存（2 次写，第 2 次写无害处）。

---

## 5. ★★ 修正后的 P1–P5（`remove_waiter` / Path B）

BTF 权威：`rt_mutex_waiter` size=0x70，`tree`@0x00、`pi_tree`@0x28、`task`@0x50、`lock`@0x58、`wake_state`@0x60、`ww_ctx`@0x68。
`rt_waiter_node` = `{rb_node entry(0x18); int prio@0x18; u64 deadline@0x20}` ⇒ 0x28 字节。

| # | 字段 | 偏移(waiter) | 画布内？ | 要求 |
|---|---|---|---|---|
| **P1** | ~~空闲 rt_mutex 地址~~ | — | — | **★作废**：`lock` 是内核真实 futex PI 锁；只需 `lock->waiters.rb_leftmost != waiter`（天然满足，见 §3 路线 C） |
| **P2** | `tree.__rb_parent_color` | `+0x00` | ✅ 画布内 offset 0x20 | **写值 V**。`V&~3==0` ⇒ parent==0 ⇒ 额外写 `lock+0x08`；否则 `V&~3` 须指向可读内存 |
| **P3** | `tree.rb_right` | `+0x08` | ✅ 画布内 offset 0x28 | **必须 == 0**（Path B 入口 `0xaa18: cbz x8`） |
| **P4** | `tree.rb_left` | `+0x10` | ✅ 画布内 offset 0x30 | **写地址 T**（≠0）。**不需要 T 可写**（内核地址即可） |
| **P5** | `pi_tree` 相关 | `+0x28..0x4F` | ✅ 画布内 | **不需要碰**。`0xef0 cmp` ⇒ 非 leftmost ⇒ `0xef4 b.ne` 命中出口 A，`0xf0c` 起全部不可达 |

### 5.1 画布覆盖核对（本轮 ASM 实测推翻 H106 的 `sp+0`，★重大修正★）

**H106/H143c 的 `&rt_waiter = sp+0` 是错的。** 本轮在 `futex_wait_requeue_pi@0xffffffc080958e1c` 实读到决定性三行：

```
0xffffffc080958ea4: add  x0, sp, #0x90
0xffffffc080958ea8: mov  w1, wzr
0xffffffc080958eac: mov  w2, #0x70        ; ★ 0x70 = sizeof(struct rt_mutex_waiter)
0xffffffc080958eb0: add  x27, sp, #0x90   ; ★ x27 = &rt_waiter（后续一直用这个寄存器）
0xffffffc080958eb4: bl   #0xffffffc080552fc0   ; memset(dst, 0, 0x70) = rt_mutex_init_waiter
```
⇒ **`&rt_waiter = sp + 0x90`**（不是 `sp+0`）。

帧深链（**本轮逐段 ASM 实测**，非引用 H106）：

| 帧 | 序言实测 | 帧深 | 累计 | `sp` |
|---|---|---|---|---|
| `__arm64_sys_futex` `0xffffffc080119ad8` | `sub sp,sp,#0x80` ✔ | `0x80` | `0x80` | `SP0−0x80` |
| `do_futex` `0xffffffc0801edfc0` | `sub sp,sp,#0x60` ✔ | `0x60` | `0xE0` | `SP0−0xE0` |
| `futex_wait_requeue_pi` `0xffffffc080958e1c` | `sub sp,sp,#0x1c0` ✔ | `0x1C0` | `0x2A0` | `SP0−0x2A0` |
| ⇒ **`&rt_waiter = sp+0x90`** | `add x0,sp,#0x90` ✔ | | | **`SP0−0x210`** |

画布（`rt_sigreturn@0xffffffc08049b2e4` 本轮实读）：
```
0xffffffc08049b2e4: paciasp
0xffffffc08049b2e8: stp  x29,x30,[sp,#-0x60]!   ; sp -= 0x60
0xffffffc08049b304: sub  sp,sp,#0x230            ; sp -= 0x230   ⇒ 帧深 0x290
...
0xffffffc08049beac: add  x0, sp, #0x10           ; ★ 拷贝目的地
0xffffffc08049beb0: mov  w2, #0x200              ; ★ 长度 0x200
0xffffffc08049beb4: bl   #0xffffffc080195fc0     ; __arch_copy_from_user
```
⇒ **画布 = `[SP0−0x280, SP0−0x80]`，长 0x200 字节。**

**重叠结果（逐字段）**：

| waiter 字段 | waiter 偏移 | 绝对地址 | 画布偏移 | 状态 |
|---|---|---|---|---|
| `ww_ctx` | +0x68 | `SP0−0x278` | +0x08 | ✅ IN |
| `wake_state` | +0x60 | `SP0−0x270` | +0x10 | ✅ IN |
| `lock` | +0x58 | `SP0−0x268` | +0x18 | ✅ IN |
| `task` | +0x50 | `SP0−0x260` | +0x20 | ✅ IN |
| `pi_tree` | +0x28 | `SP0−0x238` | +0x48 | ✅ IN |
| `tree.deadline` | +0x20 | `SP0−0x230` | +0x50 | ✅ IN |
| `tree.prio` | +0x18 | `SP0−0x228` | +0x58 | ✅ IN |
| **`tree.rb_left`（P4 写地址 T）** | **+0x10** | **`SP0−0x220`** | **+0x60** | ✅ **IN** |
| **`tree.rb_right`（P3 必须=0）** | **+0x08** | **`SP0−0x218`** | **+0x68** | ✅ **IN** |
| **`tree.__rb_parent_color`（P2 写值 V）** | **+0x00** | **`SP0−0x210`** | **+0x70** | ✅ **IN** |

⇒ ★★ **整个 `struct rt_mutex_waiter`（0x70 字节，14 词）100% 落在画布内，画布尚余 0x70 字节（画布 0x70..0x1FF）可摆伪结构。**
⇒ **P1–P5 全部可由同一份 fpsimd 画布一次覆盖。** H171 遗留的"P2/P3/P4 在画布外"疑虑**解除**（该疑虑源于 H106 的 `sp+0` 错误值）。

⚠️ **连带修正**：`h143c_restack3.c` 文件头注释里 `&rt_waiter = SP0-0x2A0`、`waiter->lock @画布0x38`、`waiter->tree.prio @画布外` 三条**全部作废**。正确值：`&rt_waiter = SP0−0x210`、`lock @画布+0x18`、`tree.prio @画布+0x58`（也在画布内）。该工具的 S3「改 prio 破 `rt_mutex_adjust_pi` 早退闸门」在**任何 prio 值下都成立**（因为 prio 可控），不再需要「保留快照」。


---

## 6. 残留风险清单

| # | 风险 | 现状 | 缓解 |
|---|---|---|---|
| **R1** | `parent==0` 时 `0xac0c: str x10,[x1]` 会把 `lock->waiters.rb_node`（`lock+0x08`）写成野值 `T`；随后 `__rt_mutex_slowlock` 调 `fixup_rt_mutex_waiters(lock,true)`（rtmutex.c:1715） | **未解** | 令 `V&~3 != 0` 且指向可读内存，走 `0xac8c` 分支（写 `parent->rb_right`，第 2 次写落在无害处） |
| **R2** | `0xe88–0xe94` 的 BUG_ON：`leftmost->lock != lock` ⇒ `brk #0x800` | 需 `leftmost` 指向一个 `lock` 字段正确的 waiter | 自然满足（leftmost 是真实 waiter）。**判据信号：见 brk 即说明我们意外成了 top waiter** |
| **R3** | `0xec8 rb_next` 若被执行（`leftmost == waiter`）会污染 `lock+0x10` | 已被 §3 路线 C 排除（要求 `leftmost != waiter`） | 监控 `lock+0x10` 是否变化 |
| **R4** | `rb_erase` 入口 `ldp x8,x10,[x0,#8]` 先读 `node+0x08`/`node+0x10`；若画布外残留值使 `rb_left==0` ⇒ 落入 Path A | 画布外 ⇒ 用内核快照值 | 需实测确认快照值满足 `rb_left!=0 && rb_right==0` |
| **R5** | `V`（`parent_color`）若使 `parent = V&~3` 指向不可读内存 ⇒ page fault | 未解 | 令 `V ∈ {0,1,2,3}`（但触发 R1），或令 parent 指向栈上可读区 |

---

## 7. 结论与下一步

**已闭合（汇编已证 + BTF 侧证，未实测）**：
1. ★ **`remove_waiter` 有 3 个调用点**（`rtmutex.c:1707` / `rtmutex_api.c:353` / `rtmutex_api.c:439`），H171 的「唯一」作废。三个调用点的 `waiter` 都指向 `futex_wait_requeue_pi` 的栈局部 ⇒ **同一份画布几何，三条触发路径**。
2. `lock` = 内核真实 futex PI 锁（`&pi_state->pi_mutex`），**不可控也不需要可控**。
3. ★★ **画布几何实测闭合**：`&rt_waiter = SP0−0x210`（`add x0,sp,#0x90` + `mov w2,#0x70` 实读），画布 = `[SP0−0x280, SP0−0x80]`（`add x0,sp,#0x10` + `mov w2,#0x200` 实读）⇒ **waiter 全部 14 词在画布内，余 0x70 字节**。
4. **P1–P5 全部可由同一份 fpsimd 画布一次覆盖**（P2@+0x70、P3@+0x68、P4@+0x60，均 IN）。
5. `remove_waiter` **只需 `leftmost != waiter`** 即走 `0xef4` 干净出口 A：单处 `rb_erase`、无 requeue、零 `wake_up_state`、不解引用 owner、不调 `adjust_prio_chain`。
6. Path B 写点 `0x...ab0c: str x9,[x10]` 写地址/写值完全解耦，均由 `waiter+0x10`/`waiter+0x00` 的**值**决定，且两字段画布内可控。
7. `remove_waiter` 内**无 `rt_mutex_enqueue`**（全函数 grep 确认）⇒ 无 `rb_add_cached` 回插风险，这是相对 `adjust_prio_chain` 的结构性优势。

**未闭合（诚实标注）**：
- **R1（`parent==0` 时污染 `lock+0x08`）未解**：走 `0xac0c: str x10,[x1]` 会把 `lock->waiters.rb_node` 写成 `T`。随后 `__rt_mutex_slowlock` 调 `fixup_rt_mutex_waiters(lock,true)`（rtmutex.c:1715）。**对 `rtmutex_api.c` 两个调用点**，返回后是 `raw_spin_unlock_irq(&lock->wait_lock)` 直接返回，**不做 fixup** ⇒ 风险显著低于 `rtmutex.c:1707` 路径。**建议优先用 `rt_mutex_start_proxy_lock`（:353）触发。**
- **R4（画布外的内核快照值）已消解**：P2/P3/P4 现已确认画布内可控，无需赌快照。
- **R5（`V` 使 `parent` 不可读）**：令 `V∈{0,1,2,3}` 则 `parent==0` 走 R1 路径；或令 `parent` 指向栈上可读区（画布余量区）走 `0xac8c` 分支。
- ~~**帧深未实测**~~ → ✅ **本轮已补验**：`0x80` / `0x60` / `0x1C0` 三段序言逐条实读（见 §5.1 表），`do_futex` 的 `0x60` 与 H106 一致。**帧深链现已完全实测闭合，几何无残留未测常数。**
- **仍未实测**：整条链路（sigreturn 画布 → stale waiter → `remove_waiter` → `rb_erase` 写点）**从未在真机跑过**。上述全部为"汇编已证 + BTF 侧证"，置信度分级：**汇编已证未实测**。

**下一步（按优先级）**：
1. **改 `h143c_restack3.c` 的画布内容**：按 §5 的 P2/P3/P4 摆位（画布偏移 +0x70=V、+0x68=0、+0x60=T），并按 §3 路线 C 保证目标 waiter 不是 `leftmost`。同时**修正该文件头注释的作废三条**（`&rt_waiter`、`lock@画布`、`tree.prio@画布外`）。
2. **选触发点**：优先 `rt_mutex_start_proxy_lock`（`rtmutex_api.c:353`，EDEADLK 分支）—— 其返回路径只做 `raw_spin_unlock_irq`，**不做 `fixup_rt_mutex_waiters`** ⇒ 规避 R1。
3. **stage8**：写 `task+0x818`（real_cred）与 `task+0x820`（cred）= `init_cred 0xffffffc082190790`，**两发两 boot**（两个独立 qword）。
4. 开火前复核：md5 三重一致（boot.img 路线产物 / Image-mey.symtab.elf / kallsyms）、`boot_id=abc61a92` 未消耗、adb 串行、判据用独立透镜。

**可证伪判据（开火时逐条对）**：
| 观测 | 结论 |
|---|---|
| `brk #0x800` | 目标 waiter 成了 `leftmost`（`0xe94`）⇒ 需多一个竞争者 |
| page fault @ `owner+0x90c` | 误判成"是 top waiter"，`leftmost == waiter` |
| page fault @ `lock+0x08` 附近（`fixup_rt_mutex_waiters`） | R1 命中，V 使 parent==0 ⇒ 换 `V` 或换调用点 |
| `lock+0x10`（leftmost）值变化 | `leftmost == waiter` 走了 `rb_next`（R3） |
| 无崩溃但无效果 | 循环自证 prohibited ⇒ 必须用**独立透镜**：`/sys/fs/selinux/enforce` + `id` 的 uid + `boot_id` 变化 |

