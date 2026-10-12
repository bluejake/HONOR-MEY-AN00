# L1 (CVE-2026-43499 / rt_mutex_adjust_prio_chain) 几何重算  —— H169

基线：MEY-AN00 / SM8735 / 6.6.118-android15 / `_text=0xffffffc080000000`
证据来源全部标注：BTF=本机 `analysis/output/btf_offsets.txt`；ASM=`analysis/scratch/adj_prio_chain_h168.txt`（capstone 裸 Image 反汇编）；SRC=`kernel_src/Code_Opensource/kernel`（6.6.56，与设备 6.6.118 同代，结构布局需 BTF 复核）

## 1. 关键结论：旧"L1 无 cached leftmost、无连锁"结论**错误**
`rt_mutex_adjust_prio_chain` 内的 `rb_erase` 全部经由 `rb_erase_cached()`，**两棵树都是 `rb_root_cached`**，都带 `rb_leftmost` 缓存指针 + 前置 `rb_next` 更新。结构上与 timerqueue 同款。

## 2. 结构布局（源码 + BTF 双证）

### 2.1 `struct rb_root` 是**单指针**（6.6 新 rbtree）
SRC `include/linux/rbtree_types.h:13`:
```c
struct rb_root { struct rb_node *rb_node; };          /* 8 字节，不是 24！ */
struct rb_root_cached { struct rb_root rb_root; struct rb_node *rb_leftmost; };  /* 16 字节 */
```
=> 这解释了此前"`x24+8` 为 root 却只有 8 字节"的矛盾。旧 rbtree 的 `struct rb_root{struct rb_node rb_node;}` 是 24 字节，**本机不是**。

### 2.2 `struct rt_mutex_base`（SRC rtmutex.h:23 + ASM 验证）
| off | 字段 | ASM 证据 |
|---|---|---|
| +0x00 | `wait_lock` (raw_spinlock_t) | `mov x0,x26(=lock+0x90c)` 是 task->pi_lock，不是本字段 |
| +0x08 | `waiters.rb_root.rb_node` | `add x1, x24, #8` → `rb_erase(root=x24+8)` ✔ |
| +0x10 | `waiters.rb_leftmost` | `ldr x27,[x24,#0x10]` + `ldr x8,[x27,#0x58]; cmp x8,x24`（`w->lock != lock` 校验，BUG_ON 语义）✔ |
| +0x18 | `owner` | `ldr x8,[x24,#0x18]; cmp x8,#1`（RT_MUTEX_HAS_WAITERS）+ `and x19,x8,#~1` ✔ |

`raw_spinlock_t` 在 arm64 = `qspinlock` = 4 字节 + 4 padding → waiters 从 +0x08 起，与 `wait_lock` 只占 4 字节一致。

### 2.3 `struct rt_mutex_waiter`（BTF `rt_mutex_waiter size=0x70`）**双证闭合**
| off | 字段 | 来源 |
|---|---|---|
| +0x00 | `tree` (rt_waiter_node) | BTF |
| +0x28 | `pi_tree` (rt_waiter_node) | BTF + ASM `ldr x8,[x27,#0x28]!`（第二次 erase 的 node）✔ |
| +0x50 | `task` | BTF |
| +0x58 | `lock` | BTF + ASM `ldr x8,[x25,#0x58]` ✔ |
| +0x60 | `wake_state` | BTF |
| +0x68 | `ww_ctx` | BTF |

`rt_waiter_node` = `{rb_node entry(0x18); int prio; u64 deadline;}` → 0x28 字节，故 tree@0 / pi_tree@0x28。**与档案旧记的 "tree+0 / list+0x18 / task+0x50 / lock+0x58" 冲突项已作废：6.6 已无 `list` 成员（改 `waiter->list` 到别处/无）。以 BTF 为准。**

### 2.4 task_struct（BTF）
- `pi_waiters` @ +0x920（`rb_root_cached`，16 字节：rb_node@0x920, rb_leftmost@0x928）
- `pi_blocked_on` @ +0x938
- ASM 全对：`ldr x8,[x19,#0x920]` / `ldr x8,[x19,#0x928]; sub x8,x8,#0x28`（`task_top_pi_waiter` = rb_entry(leftmost, pi_tree) 故减 0x28）✔ / `ldr x25,[x19,#0x938]` ✔

## 3. 两处 `rb_erase` 的精确语义

### 3.1 第一处 `0xffffffc081081760` —— `rt_mutex_dequeue(lock, waiter)`
```
ldr  x27, [x24, #0x10]      ; leftmost = lock->waiters.rb_leftmost
cbz  x27, ...
ldr  x8,  [x27, #0x58]      ; leftmost->lock
cmp  x8,  x24               ; BUG_ON(w->lock != lock) 校验
ldr  x8,  [x25]             ; node->__rb_parent_color
cmp  x8,  x25               ; RB_EMPTY_NODE(node) ⇒ return
cmp  x27, x25               ; leftmost == node ?
b.ne ...
mov  x0, x25 ; bl rb_next   ; ★ 上溯取后继
str  x0, [x24, #0x10]       ; ★ 写 lock->waiters.rb_leftmost
add  x1, x24, #8 ; mov x0,x25 ; bl rb_erase
str  x25, [x25]             ; RB_CLEAR_NODE
```
**node = `waiter+0x00`（tree），root = `lock+0x08`，leftmost 槽 = `lock+0x10`。**

### 3.2 第二处 `0xffffffc081081860` —— `rt_mutex_dequeue_pi(task, waiter)`
```
ldr  x8, [x27, #0x28]!      ; ★ x27 = x25 + 0x28 ⇒ node = waiter+0x28 (pi_tree)
cmp  x8, x27                ; RB_EMPTY_NODE(pi_tree)
ldr  x8, [x19, #0x928]      ; leftmost = task->pi_waiters.rb_leftmost
cmp  x8, x27
b.ne ...
mov  x0, x27 ; bl rb_next   ; ★ 上溯
str  x0, [x19, #0x928]      ; ★ 写 task->pi_waiters.rb_leftmost
add  x1, x19, #0x920        ; root = &task->pi_waiters.rb_root
mov  x0, x27 ; bl rb_erase
str  x27, [x27]             ; RB_CLEAR_NODE
```
**node = `waiter+0x28`（pi_tree），root = `task+0x920`，leftmost 槽 = `task+0x928`。**

## 4. 写几何（rb_erase Path A：`rb_left==0 && rb_right!=0`）
`rb_erase` 写点①：`str x8, [x11]`，`x11 = parent+0x10` 或 `parent+0x08`，写值 `x8 = node->rb_right`；写点②：`str x9, [x8]`（`*(node->rb_right) = node->__rb_parent_color`），`cbnz x8` 门控（rb_right==0 则跳过）。

`parent = node->__rb_parent_color & ~3`（`ands x10,x9,#-4`）。

| 调用点 | 写地址候选 | 写值来源 |
|---|---|---|
| 第一处（dequeue） | `(lock + 0x18) & ~3` + 0x08/0x10 ⇒ **lock+0x20 / lock+0x28** | `waiter+0x08`（tree.rb_right） |
| 第二处（dequeue_pi） | `(waiter+0x28 的 parent) & ~3` + 0x08/0x10 | `waiter+0x38`（pi_tree.rb_right） |

⇒ **旧档案记的"写 waiter->lock+8"是错的**：`waiter+0x58` 是 `lock` 指针本身（我们控制它），而真正被写的是 **parent 的 rb_left/rb_right 槽**（`lock+0x20` 或 `lock+0x28`，取决于 csel）。写值 = 我们放的 `node.rb_right`。

## 5. 连锁风险判定（★决定性★）
### 5.1 第一处 dequeue：**有 leftmost 连锁风险，但被 owner 门控挡住**
`rt_mutex_dequeue` 之后紧跟 `rt_mutex_enqueue`（`rb_add_cached`），再走 `[9] if (!rt_mutex_owner(lock)) return 0;`。
ASM `0xffffffc0810817d8: ldr x8,[x24,#0x18]; cmp x8,#1; b.ls 0x...1954` —— `owner==0` 或 `HAS_WAITERS` 位处理后**跳到 0x...1954**，该路径直接 `_raw_spin_unlock_irq(lock)` 并 return，**不再回头 dequeue**。
⇒ **owner==0 ⇒ 单发即止，不会像 timerqueue 那样 while 循环反复拆。**
⇒ 这是 L1 相对 stage0-W1 的**结构性优势**：循环出口由 `lock->owner` 决定，与伪造的 leftmost 无关。

### 5.2 第二处 dequeue_pi：`again:` 回环（0xffffffc081081ad0 → 0xffffffc0810817a8，回 808 字节）**是 rb_first_cached 内联 while，不是外层链**
`0xffffffc081081a90–0xffffffc081081ad0` 是 `rb_add_cached` 的 `while (*link)` 下降循环（读 `parent->rb_left/rb_right` 找插入点）。回边 `0x...1ad0 → 0x...17a8` 落在 `rb_insert_color_cached` 之后，是**编译器把内联 while 的尾部回边接到共享代码块**，不是 cleanup_timerqueue 那种"取 leftmost → erase → 再取 leftmost"。

### 5.3 真正的外层回环只有两处，且都有界
- `retry:` 回边 `0x...16dc → 0x...1640`（`raw_spin_trylock` 失败 → `cpu_relax` → 重试）。**纯自旋，不含 erase。**
- `again:` 回边 `0x...1918 → 0x...163c`（`goto again`，受 `++depth > max_lock_depth` 限制，`max_lock_depth=0xffffffc082196da8`）。**每轮都重新 `raw_spin_lock_irq` + 重读 `task->pi_blocked_on` + `waiter->lock != next_lock` 校验**，链断了就退出。

**综合判定：L1 不存在 stage0-W1 那种"伪 leftmost 被拽回、无条件反复拆树"的连锁。**
关键区别：timerqueue 的 `cleanup_timerqueue` 是 `while ((event = timerqueue_getnext(...)))` —— 出口条件依赖 leftmost 本身，伪 leftmost 必然导致下一轮再 erase。而 `adjust_prio_chain` 的出口条件是 `lock->owner` 与 `next_lock` 链一致性，**与 leftmost 解耦**。

### 5.4 残留风险（必须在 harness 中规避）
1. `rb_next(node)` 在 Path A（rb_right=伪值）下**不会走 parent 上溯**（源码：`if (node->rb_right) return node->rb_right;`）⇒ 若我们要"写值=rb_right 且同时让 leftmost 更新"，会写 leftmost=伪值。**设计时必须让 `node.rb_right = 0`（走 Path B）避免污染 leftmost。**
   - Path A = `rb_left==0 && rb_right!=0` → 写 parent 槽；Path B = `rb_left!=0 && rb_right==0` → 写 parent 槽。两者都写 parent 槽，但 Path A 会同时执行 `rb_next` 并写 leftmost（若 node 是 leftmost）。
   - **结论：用 Path B（`rb_left=伪值`, `rb_right=0`）可拿到写 parent 槽的原语且完全不动 leftmost。**
2. `RB_EMPTY_NODE` 早退：`node->__rb_parent_color == node` ⇒ 直接 return，不写。构造时 parent 必须 ≠ node。
3. 之后 `rt_mutex_enqueue` 会 `rb_add_cached` 把 node 重新插入 ⇒ 若我们把 `lock->waiters.rb_node` 搞成野指针，插入时 `while(*link)` 会 page fault。**需要 lock->waiters 保持"空树或合法树"。**
4. `max_lock_depth` 默认 64（`0xffffffc082196da8`），链深超限返回 -EDEADLK。

## 6. 未闭合项（不得当已验证）
- **P1：空闲 `rt_mutex_base` 地址 A 未解**（要求 4 qword 全 0 ⇒ `wait_lock=0, waiters.rb_node=0, rb_leftmost=0, owner=0`）。这是 L1 的入口前提。
- `orig_waiter/next_lock/top_task` 三参数在真实调用点的取值尚未从调用方（`rt_mutex_slowlock`/`rt_mutex_postunlock`/`rt_mutex_slowlock` 内联点）逐一枚举。
- 6.6.118 设备实际源码 vs 本地 6.6.56：`struct rb_root` 单指针化是 6.6 系列统一改动（`rbtree_types.h` 已单证），但仍标注为"源码推断 + BTF 侧证"，未逐字节比对设备 vmlinux。

## 7. 判据（可证伪）
- 若 L1 成立 ⇒ 触发后 `/sys/fs/selinux/enforce` 应出现目标值变化，且**不应**出现 `page_request`/`Kernel panic`（因为 owner==0 单发即止）。
- 若出现 page_request ⇒ 说明走了 `rb_add_cached` 的 while 且 `lock->waiters.rb_node` 为野指针 ⇒ 需改用空闲 rt_mutex（P1）而非伪造 lock。


## 8. H169 补充：第三处 erase + owner==0 单发出口已逐指令确证

### 8.1 第三处 `rb_erase@0xffffffc081081b18`（`else if` 分支）
```
0x...1ae4: cmp  x27, x25        ; prerequeue_top_waiter == waiter ?
0x...1ae8: b.ne 0x...18b8
0x...1aec: ldr  x8, [x25, #0x28]!  ; node = &waiter->pi_tree
0x...1af0: cmp  x8, x25
0x...1af4: b.eq 0x...1b24
0x...1af8: ldr  x8, [x19, #0x928]
0x...1afc: cmp  x8, x25
0x...1b00: b.ne 0x...1b10
0x...1b04: mov  x0, x25 ; bl rb_next
0x...1b0c: str  x0, [x19, #0x928]     ; ★ task->pi_waiters.rb_leftmost
0x...1b10: add  x1, x19, #0x920
0x...1b14: mov  x0, x25
0x...1b18: bl   rb_erase
0x...1b1c: str  x25, [x25]
```
**三处 erase 全部为 `node = waiter+0x28 (pi_tree)`, `root = task+0x920`（第二/三处）或 `node = waiter+0x00 (tree)`, `root = lock+0x08`（第一处）。全部 rb_root_cached。**

### 8.2 `owner==0` 单发出口（决定性，0x...1968–0x...197c）
```
0x...1954: ldr  x8, [x24, #0x10]     ; lock->waiters.rb_leftmost
0x...1958: cbz  x8, 0x...1968
0x...195c: ldr  x9, [x8, #0x58]      ; leftmost->lock
0x...1960: cmp  x9, x24              ; BUG_ON(w->lock != lock)
0x...1964: b.ne 0x...1d74
0x...1968: cmp  x27, x8              ; prerequeue_top_waiter == top_waiter ?
0x...196c: b.ne 0x...1ad4           ; ★ 不等 ⇒ wake_up_state(x8->task, x8->wake_state)
0x...1970: mov  x0, x24 ; bl _raw_spin_unlock_irq   ; ← owner==0 路径直接解锁返回
0x...1978: mov  w24, wzr             ; ret = 0
0x...197c: b    0x...19ac            ; → out_put_task / return 0
```
**这是 `[9] if (!rt_mutex_owner(lock)) { ... return 0; }` 的编译产物。**
- `0x...1970` = `raw_spin_unlock_irq(&lock->wait_lock); return 0;`
- **`owner==0` ⇒ 单发即止，绝不进入 [10]/[11]/[12]，因此绝不会执行第二/第三处 erase。**
- 反之 `prerequeue_top_waiter != top_waiter` 时会走 `0x...1ad4: ldr x0,[x8,#0x50]; ldr w1,[x8,#0x60]; bl 0xffffffc08004f0c4`（`wake_up_state(top_waiter->task, top_waiter->wake_state)`）——这是**唯一**的唤醒调用点。

⇒ **L1 的"单发"语义可以精确表述为：`owner == 0` ⇒ 只有第一处 dequeue 的 rb_erase 生效。**
这比 stage0-W1（`cleanup_timerqueue` 无条件 while）干净一个量级。

### 8.3 最终写几何（第一处 dequeue，唯一在 owner==0 下生效者）

设 `node = waiter + 0x00`（`waiter->tree.entry`），`root = lock + 0x08`。

**Path B（`rb_left != 0 && rb_right == 0`）—— 推荐，写值/写地址完全解耦：**
```
0xffffffc08003ab04: ldr  x9, [x0]           ; x9 = node->__rb_parent_color
0xffffffc08003ab08: ands x8, x9, #-4        ; x8 = parent
0xffffffc08003ab0c: str  x9, [x10]          ; ★★★ 写点：*(node->rb_left) = node->__rb_parent_color
0xffffffc08003ab10: b.eq 0x...ac0c          ; parent==0 ⇒ 跳到 root 写
0xffffffc08003ab14: ldr  x9, [x8, #0x10]    ; parent->rb_left
0xffffffc08003ab18: cmp  x9, x0
0xffffffc08003ab1c: b.ne 0x...ac8c
0xffffffc08003ab20: str  x10, [x8, #0x10]   ; parent->rb_left = node->rb_left
```
- 入口条件：`0xffffffc08003ab04` 由 `0xffffffc08003aa18: cbz x8` 进入 ⇒ **要求 `node->rb_right == 0`**；而 `node->rb_left != 0`（否则走 Path A）。
- **写点 `0xffffffc08003ab0c: str x9, [x10]` 中：写地址 = `node->rb_left`（我们放 T），写值 = `node->__rb_parent_color`（我们放 V）。两者完全独立，且这一条是 `str` 后**立刻**继续，不依赖 parent 是否可解引用。**
- 随后 `parent = V & ~3`；若 `parent != 0` 还要 `ldr x9,[x8,#0x10]` 解引用 parent ⇒ **V 的低 2 位是 color，`V & ~3` 必须可读**。
  - 规避：`V & ~3 == 0`（令 `V ∈ {0,1,2,3}`）⇒ 跳 `b.eq 0x...ac0c: str x10,[x1]`（写 root）+ `ret`，**不解引用 parent，零副作用**。
  - 若必须写任意 8 字节值 V：需 `V & ~3` 指向**可读**内存（不能是 `lock` 附近的野地址，除非那里恰好可读）。

**Path A（`rb_left == 0 && rb_right != 0`）—— 写地址 = parent 的槽，不可控，不采用：**
`0xffffffc08003aa00: str x8, [x11]`，`x11 = parent+0x10` 或 `parent+0x08`，写值 = `node->rb_right`。parent 来自 `node->__rb_parent_color & ~3`，写哪一槽由 `parent->rb_left == node` 决定 ⇒ **写地址半可控**。

### 8.4 修正后的 P1–P5（第一处 dequeue / Path B）
| # | 字段 | 偏移(waiter) | 要求 |
|---|---|---|---|
| P1 | `lock` | +0x58 | 空闲 `rt_mutex_base` 地址 A，`A+0x08`(waiters.rb_node)=0（避免 enqueue 插入时 while 解引用野指针）、`A+0x10`(rb_leftmost) 可为 0、`A+0x18`(owner)=**0**（★保证单发） |
| P2 | `tree.__rb_parent_color` | +0x00 | **写值 V**。若只要 8 字节任意写则 `V & ~3` 需可读；若 V∈{0,1,2,3} 则零副作用 |
| P3 | `tree.rb_right` | +0x08 | **必须 == 0**（Path B 入口条件 `cbz x8`） |
| P4 | `tree.rb_left` | +0x10 | **写地址 T**（≠0）。T 需可写 |
| P5 | `waiter+0x18` 低32 | +0x18 | `!= task->prio`（`rt_mutex_adjust_pi@0x814d0` 早退门；BTF 证实 `+0x18` 是 `tree.prio`，非旧记的 list.next） |

### 8.5 相对 stage0-W1 的三个结构性优势（为何 L1 值得开火）
1. **单发可证**：`owner==0` ⇒ 只走一处 erase，`0x...1970` 直接解锁返回。无 while 反复拆树。
2. **左缓存可规避**：若 node 不是 `lock->waiters.rb_leftmost`（`0x...1744: cmp x27,x25; b.ne`），**直接跳过 `rb_next` 与 leftmost 写**（`0x...1748 b.ne 0x...1758`）。只要让 `lock->waiters.rb_leftmost != node`，就不会污染 leftmost。
3. **Path B 解耦**：写地址（`rb_left`）与写值（`__rb_parent_color`）互不干扰，且 V∈{0,1,2,3} 时**不解引用 parent**。
