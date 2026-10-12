# H96 · rb_erase 路径复盘 —— ★★★ 推翻 H95 的 `page_request` 真因

> 规程 v2 完整读取。阶段一（复盘）+ 阶段二（分析）完成，**未开火**。
> 结论级别：**源码 + 汇编 + Python 三方一致**，其中两项结论为**证伪既有结论**。

## 0. 一句话结论

**H90 的写原语在 `forged_child=0` 下是"干净"的：只写 1 次、不进重平衡、不踩野指针。**
⇒ H95 §2.8.5 推断的"`____rb_erase_color` 沿伪造 parent 链踩野指针导致 `page_request`"
**在 H90 的实际参数下不成立 —— 该函数根本没被调用。**
⇒ 同时暴露一处**档案级错误**：`rb_node` 字段顺序此前被记反了。

---

## 1. ★★★ 突破点一：`struct rb_node` 字段顺序（档案记反了）

**源码权威**：`kernel/include/linux/rbtree_types.h:5-9`

```c
struct rb_node {
	unsigned long  __rb_parent_color;   /* +0x00 */
	struct rb_node *rb_right;            /* +0x08  ← 注意在前 */
	struct rb_node *rb_left;             /* +0x10  ← 注意在后 */
} __attribute__((aligned(sizeof(long))));
```

**Python 复核（`h96_verify_layout.py` [A] 组，全部 PASS）**：

| 字段 | 真实偏移 | 档案旧记 | 判定 |
|---|---|---|---|
| `__rb_parent_color` | `+0x00` | `+0x00` | ✅ |
| `rb_right` | **`+0x08`** | 记为「`fc`，且 `rb_left=0`」 | ❌ **记反** |
| `rb_left` | **`+0x10`** | 记为「未提及/0」 | ❌ **错位** |

⇒ `sizeof(struct rb_node) == 0x18`（24 B）。

**这个更正在物理上意味着什么**（关键）：

- `f77.c:1740-1741` 每槽只写两段：`offset+0x00 ← forged_parent`、`offset+0x08 ← forged_child`；
- 写入前 `f77.c:1736` 有 `memset(fragment, 0, ORDER1_SIZE)`；
- ⇒ 被显式写的 `+0x08` 是 **`rb_right`**，而 **`rb_left`（`+0x10`）是靠 `memset` 归零的，从来没被显式写过**。

档案把「`fc` 写在 `+0x08`」与「`rb_left = 0`」当成同一件事，
实际上那是**两个不同字段**：`fc` 写进了 `rb_right`，`rb_left` 只是被动归零。

**`f77.c:1740-1741` 原文**：

```c
memcpy(fragment + offset, &forged_parent, sizeof(forged_parent));
memcpy(fragment + offset + sizeof(forged_parent), &forged_child, sizeof(forged_child));
memcpy(fragment + offset + FAKE_CPU_TIMER_EXPIRES_OFF, &expires, sizeof(expires));
```

`sizeof(forged_parent) == 8` ⇒ 第二段落在 `offset+0x08` = **`rb_right`**。
源码侧证据：`rbtree_augmented.h:227` `child = node->rb_right;`、`228` `tmp = node->rb_left;`
⇒ **`child` 对应 `+0x08`，`tmp` 对应 `+0x10`。** 至此档案与源码的对应关系彻底理顺。

---

## 2. ★★★ 突破点二：H90 的真实控制流（源码 ⟷ 汇编逐条对齐）

### 2.1 汇编实测（`analysis/scratch/h96_out.txt`，入口自检 `08a840a9` PASS）

```asm
0x3a9d4  ldp  x8, x10, [x0, #8]    ; x8 = node->rb_right(+0x08) = child
                                   ; x10 = node->rb_left(+0x10)  = tmp
0x3a9d8  cbnz x10, #0x3aa18         ; if (tmp != 0) goto Case2/3   ← rb_left==0 故不跳
0x3a9dc  ldr  x9, [x0]              ; x9 = pc = node->__rb_parent_color
0x3a9e0  mov  x11, x1
0x3a9e4  ands x10, x9, #-4          ; x10 = parent = __rb_parent(pc)
0x3a9e8  b.eq #0x3aa00              ; if (parent == 0) 直落写点①
0x3a9ec  mov  x11, x10
0x3a9f0  ldr  x12, [x11, #0x10]!    ; x12 = parent->rb_left;  x11 = parent+0x10
0x3a9f4  sub  x13, x11, #8          ; x13 = parent+0x08
0x3a9f8  cmp  x12, x0               ; if (parent->rb_left == node)
0x3a9fc  csel x11, x11, x13, eq     ;    x11 = parent+0x10 : parent+0x08
0x3aa00  str  x8, [x11]             ; ★ 写点①：*x11 = child
0x3aa04  cbnz x8, #0x3aa10          ; if (child != 0) → 写点②
0x3aa08  tbnz w9, #0, #0x3aa78      ; if (pc & 1) → 进重平衡
0x3aa0c  ret                        ; ★★ 否则直接返回，不进重平衡
0x3aa10  str  x9, [x8]              ; 写点②：*child = pc
0x3aa14  ret
```

### 2.2 对应源码（`rbtree_augmented.h:232-248`）

```c
if (!tmp) {                                  /* ← tmp = node->rb_left == 0 ✔ */
	pc     = node->__rb_parent_color;    /* 0x3a9dc ldr x9,[x0]        ✔ */
	parent = __rb_parent(pc);            /* 0x3a9e4 ands x10,x9,#-4     ✔ */
	__rb_change_child(node, child, parent, root);   /* 0x3a9f0..0x3aa00 ✔ */
	if (child) {                        /* 0x3aa04 cbnz x8             ✔ */
		child->__rb_parent_color = pc;  /* 0x3aa10 str x9,[x8]        ✔ */
		rebalance = NULL;
	} else
		rebalance = __rb_is_black(pc) ? parent : NULL;  /* 0x3aa08 tbnz ✔ */
	tmp = parent;
}
```

⇒ **三环在指令级完全对齐**：`b.eq`/`csel` 两处偏移分别对应
`__rb_change_child` 的 `if (!parent)` 与 `if (node == parent->rb_left)`（`rbtree.h`/`rbtree_augmented.h`）。

### 2.3 ★ 决定性推论：H90 参数下 `rebalance == NULL`

**颜色宏权威**（`rbtree_augmented.h:176-177`）：

```c
#define __rb_color(pc)     ((pc) & 1)
#define __rb_is_black(pc)  __rb_color(pc)
```

**Python 复核（[D] 组）**：

```
pc = forged_parent = 0xffffff802a3ba410
pc & 1 = 0  ⇒  __rb_is_black(pc) = False（红）
源码：rebalance = __rb_is_black(pc) ? parent : NULL  ⇒  rebalance = NULL
汇编：0x3aa08 tbnz w9,#0 不跳  ⇒  0x3aa0c ret        ⇒  rebalance = NULL
两路结论一致 ⇒ 互为正面验证
```

⇒ **`____rb_erase_color` 从未被调用。**
⇒ H95 §2.8.5 的整条推理链（"返回后沿 parent 链重平衡 → 解引用 `ss−8` → 垃圾子树指针 → 野写"）
**在 H90 的参数下整条不成立**。

### 2.4 H90 单次消费的净内存效果

| 写点 | 地址 | 值 | H90 是否触发 |
|---|---|---|---|
| 写点① `0x3aa00` | `forged_parent + 0x08` = `0xffffff802a3ba418` = **`selinux_state.enforcing`** | `child` = `forged_child` = **0** | ✅ **触发**（唯一副作用） |
| 写点② `0x3aa10` | `child` | `pc` | ❌ 不触发（`cbnz x8`，`fc=0`） |
| 写点③ `0x3aa2c/0x3aa40` | Path B | — | ❌ 不触发（`rb_left==0` 已排除 Case 2/3） |
| 重平衡 `____rb_erase_color` | — | — | ❌ **不触发**（`rebalance=NULL`） |

⇒ **9 个假槽若都被误消费，也只是对同一地址重复写 0 ⇒ 幂等、无副作用。**
⇒ 这是 H90 参数下写原语"干净"的完整证明。

---

## 3. ★★★ 推翻 H95 §2.8.5（真因证伪）

| 项 | H95 §2.8.5 的说法 | H96 的结论 | 判定 |
|---|---|---|---|
| `rb_erase` 返回后是否重平衡 | 会，且沿伪造 parent 链 | **`rebalance=NULL`，`____rb_erase_color` 根本没被调用** | ❌ **证伪** |
| `0x3f820 str x19,[x19]` 是第二风险点 | 是 | 它写的是 `node` 自身（非野地址），**仍不是 `page_request` 来源** | ⚠️ 降级 |
| 落点推导 `ss+0x00` | 成立 | 成立（`[C]` 组 PASS，且绝对地址 `0xffffff802a3ba418` 与档案一致） | ✅ 保留 |
| spray 无越界 | 成立 | 成立（`[E]` 组 PASS：区间 `[0x78,0x7d8)`，跨度 `0x760`） | ✅ 保留 |

⇒ **`page_request` 的真因仍然未知，但"重平衡"这条已被排除。**
⇒ 下一轮必须换假设（见 §5）。

---

## 4. 阳性自检组抓到的一处自身错误（方法论留痕）

`h96_verify_layout.py` 初版把 `MEY_PHYS_DELTA` 填成 `0x06800000`（凭记忆），
导致 `enforce_alias` 算出 `0xffffff8008bba418`，与档案 `0xffffff802a3ba418` 不符 ⇒ `[FAIL]`。
源码 `f77.c:351` 的真值是 **`0x28000000`**（`imagePhys 0xa8000000 - memstart 0x80000000`）。

修正后 `enforce_alias` 与档案**逐位一致**。

⇒ **这是"阳性自检组"机制的一次真实拦截**：若无自检，这个错误常数会一路带进开火脚本，
直接导致写点① 落在错误地址 ⇒ 必然 `page_request`，且会被误判为"写原语不安全"。
⇒ 新增方法论：**凡是从档案/记忆抄来的常数，必须能在源码里 grep 到定义行号，并让脚本算出的
绝对地址与已实测地址逐位比对。**

---

## 5. `page_request` 真因：候选重排（下一轮待解项）

排除"重平衡"后，剩余候选按可能性排序：

| # | 候选 | 依据 | 可证伪判据 |
|---|---|---|---|
| 1 | **`expires = UINT64_MAX` 让假 timer 永不到期，但 `timerqueue_del` 仍被别的路径调用** | 假 timer 挂在真实 `timerqueue` 上，若有代码遍历并删除 | 方案 A（boot_id 写）若**仍** panic 而写点① 已证只写 1 次 ⇒ 指向"删除调用方"而非"写点①" |
| 2 | **`0x3f7fc ldr x8,[x20,#8]` / `0x3f810 str x0,[x20,#8]`（`timerqueue_del` 内的 base 替换）** | 这两处也在我们改过的 `forged_parent` 附近 | 需反汇编 `0x3af24`（`0x3f80c bl`）确认它写什么 |
| 3 | **`node` 本身不是 timerqueue 成员，被 `rb_erase` 摘除时破坏了真实 `hrtimer` 结构** | 喷到 9 个槽，若某槽对应**活跃** timer，其 `hrtimer.function`（`+0x28`）未被动但 `expires`（`+0x18`）被改成 `UINT64_MAX` | 方案 B（自洽 fake parent）若仍崩，指向"槽本身落在活跃 timer 上" |
| 4 | **与写原语完全无关，是设备本底的既存崩溃** | H94 已证设备每天 50–380 次 panic；H90 开火 23:16:13 → panic 23:17:23 相隔 **70 s**，时序偏长 | 方案 A 在**无 panic** boot 内命中 ⇒ 彻底排除候选 4 |

★ **关键判别器**：H90 的 panic 距开火 **70 秒**。若写原语本身是野写，
崩溃通常在**毫秒到秒级**，不该等 70 秒。⇒ 候选 4（既存崩溃）优先级被显著抬高。
⇒ **方案 A（boot_id 无害写）恰好是判别候选 1/3/4 的最佳实验**：
它在**同一 boot 内**就能告诉我们"写点① 命中时到底会不会连带 panic"。

---

## 6. 三环对照表（H96）

| 对象/函数 | 源码推理（GKI 6.6.56==r17 权威） | 汇编实测（Image-mey 基址=0） | img 差异 | 一致 | 矛盾待解 |
|---|---|---|---|---|---|
| `struct rb_node` 布局 | `rbtree_types.h:5-9`：`+0x00` pc / `+0x08` **rb_right** / `+0x10` **rb_left** | `0x3a9d4 ldp x8,x10,[x0,#8]` ⇒ x8=+0x08=child, x10=+0x10=tmp | 无厂商改动（GKI 核心） | ✅ **①②③** | 档案 §3.1 表述待改 |
| `rb_erase` Case 1 控制流 | `rbtree_augmented.h:232-248` | `0x3a9d8`→`0x3aa04`→`0x3aa08`→`0x3aa0c ret` 逐条对齐 | — | ✅①② | 无 |
| `__rb_change_child` 写点 | `rbtree.h`：`!parent` / `node==parent->rb_left` 二选一 | `b.eq` + `csel x11,x11,x13,eq` 精确复现 | — | ✅①② | 无 |
| 颜色判定 | `__rb_color(pc) = pc & 1` | `0x3aa08 tbnz w9,#0` | — | ✅①② | 无 |
| **H90 是否进重平衡** | `rebalance = __rb_is_black(pc)?parent:NULL`；`fp&3==0` ⇒ 红 ⇒ **NULL** | `tbnz` 不跳 ⇒ `0x3aa0c ret` | — | ✅①② **Python 互证** | 无 |
| **H95 `page_request` 真因** | 源码+汇编均判"不重平衡" | 同左 | — | ❌ **证伪 H95 §2.8.5** | **真因未知，见 §5** |
| `page_request` 是否为既存崩溃 | — | — | — | ⚠️ **待验** | 70 s 时延倾向候选 4 |
| `selinux_state.enforcing` 偏移 | `+0x00`（MEY-TECH §4.1 定案） | `MEY_SELINUX_STATE_OFF=0x23ba418` | `vendor/honor/system` 未审 | ✅①② | 环③缺 |

---

## 7. 下轮方案（阶段三，**未开火，等确认**）

### 方案 A（★ 首选，判别性最强）

- `forged_parent = alias(sysctl_bootid) + 0x30`，`forged_child = 0`
- 判据：**同一 boot 内**回读 `/proc/sys/kernel/random/boot_id` 尾部 8 字节是否变 0
- **三判据合看**：

| 回读结果 | 结论 |
|---|---|
| 尾部变 0 **且不 panic** | 写点① 打通且无连带损伤 ⇒ H90 的 `page_request` **不是写原语引起** ⇒ 直接重打 selinux |
| 尾部变 0 **但 panic** | 写原语本身有连带损伤（候选 1/2/3）⇒ 走方案 B |
| 尾部**不变 0** | 落点或分支判断错 ⇒ 回到 H92 `csel` 条件重新设计 |

- 风险极低：boot_id 每次启动重新生成，破坏它不影响任何内核数据结构
- 纪律：同 boot 回读（铁律②）；开火前后各拉 `history.log`（H94 新增）

### 方案 B（若 A 判出"有连带损伤"）

fragment 内构造**结构完整自洽**的 fake parent（`left`/`right`/`parent_color` 三字段均指向合法可解引用处），
再跑同样判据。

### 方案 C（★ 已否决，本轮再确认）

self-loop 提前返回（`0x3f7f4 cmp x8,x1 / b.eq`）会**跳过 `rb_erase` 本身** ⇒ 无写原语。

---

## 8. 产物

| 文件 | 说明 |
|---|---|
| `analysis/scratch/h96_rb_erase_full.py` | ★★ `rb_erase` 全函数反汇编 + 45 条 store + 全量分支枚举，入口带阳性自检 |
| `analysis/scratch/h96_out.txt` | 上述脚本原始输出（含 `[SELFTEST] PASS`） |
| `analysis/scratch/h96_verify_layout.py` | ★★★ 铁律① Python 复核：布局/落点/分支/spray 几何，6 组共 24 项断言 |
| `analysis/scratch/h96_verify_out.txt` | 复核输出（终判 `ALL PASS`） |
| `analysis/output/h96_rb_erase_path_audit.md` | 本报告 |

**未开火。** 下一轮进入阶段三前需用户确认。
