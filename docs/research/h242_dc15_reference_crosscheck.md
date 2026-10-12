# H242 · dc15 参考实现对照 —— **找到正确写几何，但触发时序仍未闭合**

> 依据：`<HOME>\WorkBuddy\2026-09-26-09-04-37\dc15_repro\src`（dc15，CGA-W00 参考实现）
> 重点：`slide_app.c` L1645–1668（生产几何注释）、L2578–2600（fire）、L3280–3390（requeue 时序）
> 真机：H242 一发，**零 panic**，`boot_id` 不变

---

## §0 结果速览

| 项 | 结果 |
|---|---|
| **正确写几何** | ✅ **从参考实现拿到**（见 §1） |
| 本机 layout 换算 | ✅ 完成（0x70 vs 参考 0x58，+0x18） |
| H242 开火 | ✅ 零 panic，但**写仍未观测到** |
| 触发时序 | ❌ **仍未闭合**（见 §3） |

---

## §1 ★★★ 写原语正确几何（参考实现 L1645–1668 原文）

> "the write primitive fires on `remove_waiter`'s **SECOND rb_erase**, which erases the PI tree entry.
> For rb_erase the fixed write is the left-child case (`node->rb_right == 0 && node->rb_left != 0`),
> where `0x8040230` stores `node->__rb_parent_color` to `[node->rb_left]`.
> Therefore the write **TARGET is pi_tree_entry.rb_left**, the **VALUE is pi_tree_entry.rb_parent_color**,
> and `pi_tree_entry.rb_right` must be zero.
> `tree_entry` must carry a **sentinel parent_color=1** and both children 0
> so the **first rb_erase (lock->waiters tree) is a clean no-op**."

### 1.1 本机 layout 换算（BTF：`rt_mutex_waiter` = **0x70**，参考 compact = 0x58）

参考注释里的偏移是 compact 布局，其 `rt_waiter_node` = 0x28（含 prio/deadline 内联），
本机 `rt_waiter_node` = 0x28（`entry` 0x18 + `prio` + `deadline`），差 **+0x18**：

| 配方项 | 参考 (compact 0x58) | **本机 (0x70)** | 画布偏移 |
|---|---|---|---|
| 第一次 rb_erase 设 no-op | `tree_entry.rb_parent_color = 1` | **waiter+0x00 = 1** | 0x110 |
| 必须为 0 | `tree_entry.rb_right = 0` | **waiter+0x08 = 0** | 0x118 |
| 必须为 0 | `tree_entry.rb_left = 0` | **waiter+0x10 = 0** | 0x120 |
| **写值 VALUE** | compact +0x18 | ★ **`pi_tree.rb_parent_color` = waiter+0x28** | 0x138 |
| 必须为 0 | compact +0x20 | ★ **`pi_tree.rb_right` = waiter+0x30** | 0x140 |
| **写目标 TARGET** | compact +0x28 | ★ **`pi_tree.rb_left` = waiter+0x38** | 0x148 |

### 1.2 本机汇编交叉验证

```asm
; remove_waiter 第二次 rb_erase（擦 pi_tree）
80f0c: ldr  x8, [x23, #0x28]!    ; x8 = waiter->pi_tree.rb_parent_color; x23 += 0x28
80f10: cmp  x8, x23              ; == 自身 ⇒ RB_EMPTY_NODE ⇒ 跳过（所以不能填自身）
80f14: b.eq #0x80f44
80f18: ldr  x8, [x21, #0x928]    ; owner->pi_waiters.rb_leftmost
80f1c: add  x24, x21, #0x920     ; x24 = &owner->pi_waiters
80f20: cmp  x8, x23
80f24: b.ne #0x80f34
80f28: bl   rb_next ; 80f30: str x0,[x21,#0x928]
80f34: mov  x0, x23              ; node = &pi_tree
80f38: mov  x1, x24              ; root = &owner->pi_waiters
80f3c: bl   rb_erase             ; ★★★ 写原语执行点（Case 2）

; rb_erase Case 2（rb_left != 0）写点
aa60: str  x9, [x13]             ; ★ x9 由 *left 推出目标；语义 = *(rb_left) = rb_parent_color
```

⇒ ★★ **与 §1.1 的换算完全一致。**

---

## §2 H242 开火结果（零 panic，但写未观测）

```
TARGET=0xffffffc082136048  VALUE=0x4141414141414141
map: tree.rb_parent_color=0x110  pi_tree.rb_parent_color=0x138  pi_tree.rb_right=0x140  pi_tree.rb_left=0x148
#1 CMP_REQUEUE_PI rc=-1 errno=35 (EDEADLK) OK
  [W] <- WAIT_REQUEUE_PI rc=-1 errno=110 (ETIMEDOUT)
[M] S=0x7af9f89ba0 ...
  [W] delivered=1 sig_hits=1
#2 CMP_REQUEUE_PI rc=0 errno=0(Success)
[*] reached end of main => NO PANIC      BID 不变
```

**几何全部落界内**（0x110/0x138/0x140/0x148 ≤ 0x200）✅
**但写未发生** —— 原因同 H241：**第二次 requeue 找不到目标**（W 已超时返回）。

---

## §3 ❌ 触发时序仍未闭合（唯一剩余障碍）

### 3.1 参考实现的时序（`slide_app.c`）

```
requeue 线程：                       waiter 线程（W）：
  while(!waiter_waiting) sleep;       ① WAIT_REQUEUE_PI(...) 阻塞
  CMP_REQUEUE_PI ──────────────►      ② start_proxy_lock 失败(EDEADLK)
     ⇒ remove_waiter 在 W 的栈上执行      ⇒ remove_waiter(lock, waiter)
     ⇒ 消费 W 栈上的 pi_tree              （★ W 仍在阻塞，栈帧活跃）
  fire(waiter_tid) → SIGUSR2 ───►      ③ 信号打断 futex 睡眠 ⇒ handler 改帧的 fpsimd
                                          ⇒ rt_sigreturn 把 512B 写进内核栈（覆盖 waiter 槽）
```

★ **关键差别**：参考实现在 **`CMP_REQUEUE_PI` 之前**（甚至更早）就 `slide_sigreturn_prepare()`，
并在 requeue **返回后立刻 fire**；而 **W 在此期间一直阻塞** ⇒
`remove_waiter` 消费的是 **W 活跃栈帧上的字段**（由 ③ 的画布覆盖）。

### 3.2 我这一版的差别

我在 `#1 CMP_REQUEUE_PI` **之后**才等 W 超时返回、再投画布 ⇒
**`remove_waiter` 早在画布存在之前就跑完了** ⇒ 消费的是**真实（已被 memset 清零的）waiter**
⇒ 第一次 rb_erase 是 no-op、第二次也无效 ⇒ **写不发生**。

### 3.3 ★ 正确顺序（D-6 设计）

```
① W  : WAIT_REQUEUE_PI(f_src → f_target, to=较长超时) 阻塞，sleep
② 主 : 等 slide_waiter_waiting 置位（W 确已进入阻塞）
③ R  : CMP_REQUEUE_PI  ⇒ remove_waiter 消费 W 栈上字段
④ 主 : ★ 必须在 ③ 之前完成"画布已就位于 W 内核栈"
       ⇒ 用 SIGUSR2/rt_tgsigqueueinfo 定向打断 W 的 futex 睡眠，
         让 handler 改帧 fpsimd ⇒ rt_sigreturn 覆盖 waiter 槽
```

⚠️ **难点**：③ 与 ④ 的先后必须是 **④ ≤ ③**（画布先到）。
参考实现的做法是「prepare 在前、fire 紧随 requeue」，
但 fire（信号）会**打断 W 的睡眠**使 ③ 也受影响 ——
⇒ 需要精确的 **`SLIDE_REQUEUE_ARM_USEC` 式延时**（参考里有这个参数）。

⇒ ★★ **下一步 = 把参考的 arm-usec 式延时搬过来**：
```
W 阻塞 → 主线程 usleep(ARM_USEC) → fire(W) 打断并投画布 → 立刻 CMP_REQUEUE_PI
```
用**多次 boot 扫描 `ARM_USEC`**，或用「信号投递完成」与「requeue」的时序仲裁。

---

## §4 诚实结论

| 项 | 状态 |
|---|---|
| 写原语几何 | ✅ **已从参考实现拿到，并与本机汇编/BTF 校验一致** |
| 画布投递通道 | ✅ 成立（h230 真机） |
| 消费器选择 | ✅ `remove_waiter`（frame 不重叠） |
| SP0 获取 | ✅ `/proc/<pid>/task/<tid>/syscall` |
| **触发时序（画布先于 remove_waiter）** | ❌ **未闭合** —— 唯一剩余障碍 |
| 步 E（写 `enforcing`） | ⏸ 受阻于上一条 |

⇒ **距"写原语落地"只剩时序一步**，且参考实现已给出可仿照的机制（fire + arm 延时）。

---

## §5 铁律增补

| # | 铁律 |
|---|---|
| **㊳** | ★★★ **写原语在 `remove_waiter` 的【第二次】`rb_erase`**（擦 `pi_tree`）；写目标 = `pi_tree.rb_left`(+0x38)，写值 = `pi_tree.rb_parent_color`(+0x28)，且 `pi_tree.rb_right`(+0x30) 必须为 0；`tree_entry` 须 sentinel `parent_color=1` + 两子 0 使第一次 erase 成 no-op |
| **㊴** | ★★ **画布必须在 `remove_waiter` 消费之前就位于 W 的内核栈**。参考实现用「requeue 之后立刻 fire 定向信号」；我等 W 超时返回再投画布是**错的顺序** |
