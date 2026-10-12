# H174–H175：EDEADLK 触发链路收口 + 分段画布投递

**设备**：MEY-AN00 · SM8735 · `6.6.118-android15`（4K 页）· `_text=0xffffffc080000000`
**日期**：2026-10-05
**前序**：H172（几何闭合）/ H173（触发条件推导）/ H174（本轮）

---

## 一、★★ 本轮头号发现：H173 的状态评估是错的（技术推理反而是对的）

### 1.1 事件

H173 报告断言：

> 「门 B 的 4 线程 PI 链闭环构造可行性未验证 —— **这是整条链路上唯一没有证据支撑的环节**，直接决定路径 A（`:353`）能否走通。」

本轮开工前的例行检索发现，**该环节的真机证据早已存在**，而且就在同一份工作日（2026-10-05）产出的两份报告里：

| 报告 | 关键实证 |
|---|---|
| `analysis/output/h140_cve_device_verify.md` §9.2 | `CMP_REQUEUE_PI src->dst rc=-1 errno=35`（EDEADLK） |
| 同上 §9.3 | D0 对照 `rc=1` vs D1 实验 `rc=-35`，**唯一变量 = W 是否持 dst** |
| 同上 §10.2 | C0/C1 事后 `LOCK_PI(src)=0` vs **C2 = `-EINVAL`** ⇒ 状态破坏 |
| `analysis/output/h142_cve43499_uaf_hit.md` | **8 环节全部真机验证**，`boot_id` 变 + `history.log` `null_pointer` ⇒ **内核 panic** |

### 1.2 为什么会漏

H173 立项时的前提是「H172 说几何闭合了，但触发条件没证据」。实际上：

- 触发条件（EDEADLK）**在 H140–H141 就已实测**；
- H142 已经把整条链打通到 panic；
- **H173 没有回读 `analysis/output/` 下已有的 `h140/h141/h142` 三份报告**，而是重新从源码推导，于是把「已知」误判为「未知」。

⇒ **这违反本项目自己的纪律**：结论必须基于既有实证，不能因为重新推导就宣称前人结论未被验证。**重新推导的价值在于交叉校验，不在于宣布未知。**

### 1.3 但 H173 的技术推理经交叉验证成立

H173 判定「门 A（`owner == task`，`rtmutex.c:1213`）在 proxy 路径上不成立」，理由是 owner 与 task 天然不同线程。

H141 §11.1 用真机差分独立得出同一结论，并给出更强的证据：

```
if (owner == task && !(build_ww_mutex() && ww_ctx))
        return -EDEADLK;        // ★ 早退
...
rt_mutex_enqueue(lock, waiter);      // line 1226 —— 未执行
task->pi_blocked_on = waiter;        // line 1228 —— 未执行
```

⇒ waiter **从未入队** ⇒ `RB_EMPTY_NODE` 为真 ⇒ `remove_waiter` 内 `rb_erase` **根本不执行**。
H140 的 D1 是**伪环**：只证明「函数被调用」，推不出「悬垂指针已产生」。**H140 §10.5 第 6 行的「状态破坏实证」已被 H141 降级。**

⇒ **两条完全独立的推理路径（H173 从源码、H141 从真机差分）撞上同一结论：门 A 是伪环，真路径必须是门 B 的三 futex 环。**

### 1.4 置信度重新分级

| 环节 | H173 评估 | H174 订正 |
|---|---|---|
| 设备未修复 | 汇编已证 | ✅ 已实测（`mrs x20, sp_el0`） |
| shell 域可达 | 假设 | ✅ 已实测 |
| EDEADLK 可确定性触发 | ❌「未验证」 | ✅ **已实测**（rc=-35，D0/D1 差分） |
| `remove_waiter` 真执行（rb_erase 落地） | ❌「未验证」 | ✅ **已实测**（boot_id 变 + panic） |
| `waiter` 画布可控 | 汇编已证 | ✅ 已实测（rt_sigreturn 载波，`sig_hits` 生效） |
| **提权到 root** | 未验证 | ❌ **仍未验证**（唯一剩余环节） |

---

## 二、源码级补全：三条 `-EDEADLK` 路径的完整判定

本轮把 `task_blocks_on_rt_mutex` 到 `rt_mutex_adjust_prio_chain` 全链逐行读通（行号均为本轮实读）。

### 2.1 门 A / 门 B 与「深度超限」

```c
// rtmutex.c:1213   门 A（伪环，只命中 rtmutex.c:1213 早退）
if (owner == task && !(build_ww_mutex() && ww_ctx))
        return -EDEADLK;

// rtmutex.c:1224-1226
if (rt_mutex_has_waiters(lock))
        top_waiter = rt_mutex_top_waiter(lock);
rt_mutex_enqueue(lock, waiter);        // ★ 门 A 时此行未执行

// rtmutex.c:1251-1259   门 B
if (waiter == rt_mutex_top_waiter(lock)) {
        ...
        if (owner->pi_blocked_on)
                chain_walk = 1;                       // 门 B1
} else if (rt_mutex_cond_detect_deadlock(waiter, chwalk)) {
        chain_walk = 1;                               // 门 B2
}

// rtmutex.c:1271   ★ 门 B 仍不够
if (!chain_walk || !next_lock)
        return 0;      // next_lock = task_blocked_on_lock(owner)
```

### 2.2 两个真正的 `-EDEADLK` 出口（`remove_waiter` 被触发的前提）

全树仅两处 `return -EDEADLK`（`rtmutex.c`）：

| 位置 | 条件 | 成本 |
|---|---|---|
| **`rtmutex.c:845`** | `lock == orig_lock \|\| rt_mutex_owner(lock) == top_task` | **3 线程 / 3 futex 即可** |
| `rtmutex.c:704` | `++depth > max_lock_depth`，**`max_lock_depth = 1024`**（`rtmutex_api.c:14`） | 1025 级链 |

**★ 本轮新读出 `max_lock_depth = 1024`**（`rtmutex_api.c:14`）——比 H173 假设的「需要真实闭环」宽松一个数量级：链长超 1024 即返回 `-EDEADLK`，无需真正闭环。但成本（1025 线程）远高于 `:845`，仅作对照路线。

`:845` 的 `rt_mutex_owner(lock) == top_task` 是最省的一条：**`top_task` 是被 requeue 的 waiter 线程 W，只要 W 持有链上任一锁就命中**。

### 2.3 H174 独立推导的拓扑（与 `h141c_cycle2.c` 撞上）

我在读源码时独立推出：

```
W : LOCK_PI(B)              ⇒ owner(B) = W          ★ W 自持一把锁
P1: LOCK_PI(A)              ⇒ owner(A) = P1
P1: LOCK_PI(B)  → 阻塞      ⇒ P1->pi_blocked_on = B 的 waiter（owner(B) 仍是 W）
W : WAIT_REQUEUE_PI(Q, A)   ⇒ W 排到普通 futex Q，rt_waiter 在 W 栈上
R : CMP_REQUEUE_PI(Q → A)
      owner(A)=P1 ≠ task=W  ⇒ 门 A 不命中 ✔
      W == top_waiter(A)    ⇒ 门 B1；P1->pi_blocked_on 非空 ⇒ chain_walk=1 ✔
      next_lock = task_blocked_on_lock(P1) = B ≠ NULL ✔
      链遍历: task=P1 → waiter=P1 在 B 上的 waiter → lock=B
              rt_mutex_owner(B) == W == top_task ⇒ ★★ -EDEADLK
```

`tools/h141c_cycle2.c` 文件头写的是：

```
W: LOCK_PI(f_chain) 持有 → WAIT_REQUEUE_PI(f_src → f_target)
O: LOCK_PI(f_target) 持有 → LOCK_PI(f_chain) 阻塞
```

**同构**（W↔W、B↔f_chain、A↔f_target、P1↔O、Q↔f_src）。**两条独立路径得出同一拓扑，构成交叉验证。**

⇒ **旧骨架 `tools/h173_edeadlk.c` 里作者自己标注的「顺序矛盾」（P1 持 A 又要等 B，而 P2 要持 B）根本不存在**：矛盾源于误以为「等锁」会改变 owner。实际 `LOCK_PI` 阻塞时 owner 保持在原持有者身上，只有真正获得锁才转移。

---

## 三、★★ 画布 vreg 槽位映射（机器重算，修正 H172/h143c 旧表）

### 3.1 问题

H172 给出了 waiter 全部字段在画布内的**字节偏移**，但 `h143c_restack3.c` 文件头附的 vreg 示例值（`lock@+0x38=v2.d[1]`、`task@+0x30=v2.d[0]`）**与 H172 的字节表不自洽**，无法据此写内联汇编。

### 3.2 换算公式（本轮用 Python 机器重算，不手算）

```
画布基     = SP0 - 0x280          （rt_sigreturn 0xffffffc08049beac 实读）
waiter 基  = SP0 - 0x210          （futex_wait_requeue_pi 0xffffffc080958ea4 实读）
画布偏移 C = (waiter基 + 字段off) - 画布基 = 字段off + 0x70
vreg = C / 16        lane = (C % 16) / 8
```

### 3.3 修正后的权威映射表

| waiter 字段 | waiter off | 画布偏移 | **vreg 槽位** |
|---|---|---|---|
| `tree.__rb_parent_color` (写值 V) | +0x00 | +0x70 | **`v7.d[0]`** |
| `tree.rb_right` (必须 0) | +0x08 | +0x78 | **`v7.d[1]`** |
| `tree.rb_left` (写地址 T) | +0x10 | +0x80 | **`v8.d[0]`** |
| `tree.prio` | +0x18 | +0x88 | `v8.d[1]` |
| `tree.deadline` | +0x20 | +0x90 | `v9.d[0]` |
| `pi_tree` | +0x28 | +0x98 | `v9.d[1]` |
| `task` | +0x50 | +0xc0 | **`v12.d[0]`** |
| `lock` | +0x58 | +0xc8 | **`v12.d[1]`** |
| `wake_state` | +0x60 | +0xd0 | `v13.d[0]` |
| `ww_ctx` | +0x68 | +0xd8 | `v13.d[1]` |

### 3.4 两个关键结论

**① 结构巧合使约束自洽**：V 与「必须为 0」的 `rb_right` **同处 `v7`**。
设 `v7.d[0] = V`、`v7.d[1] = 0` ⇒ **一次 `fmov` 同时满足两个约束**，无需两处写入。这是 H172 几何闭合带来的意外便利。

**② 旧表三项偏移 0x20**：`rb_left`/`rb_right`/`parent_color` 在 `h143c` 旧表中整体偏 0x20（写作 `v6.d[0]`/`v6.d[1]`/`v7.d[0]`），系把画布基误当作 `SP0-0x2A0`。若照旧表投递，写地址 T 会落到 `tree.prio` 上 ⇒ 原语写错位置。**已在 `h175_staged.c` 文件头显式标注作废。**

---

## 四、`struct rb_node` 字段顺序的独立验证（经典陷阱）

本轮核对 `include/linux/rbtree_types.h:5-9`：

```c
struct rb_node {
	unsigned long  __rb_parent_color;    /* +0x00  ★ 写值 V */
	struct rb_node *rb_right;            /* +0x08  ★ 必须 0   */
	struct rb_node *rb_left;             /* +0x10  ★ 写地址 T */
} __attribute__((aligned(sizeof(long))));
```

★ **声明顺序是 `parent_color / right / left`，不是教科书写法的 `left / right / parent_color`。**

三重验证一致：

| 来源 | 结论 |
|---|---|
| 本机 BTF `btf_offsets.txt:312` | `rt_mutex_waiter` size=0x70，`tree`@0x00，`task`@+0x50，`lock`@+0x58 ✔ |
| 源码 `rbtree_types.h:5-9` | `+0x00` parent_color / `+0x08` right / `+0x10` left ✔ |
| H172 汇编实测 | `0x…3a9d4: ldp x8,x10,[x0,#8]` → x8=[+8]=right, x10=[+0x10]=left ✔ |

---

## 五、`h175_staged.c`：把「全填同一 fake」升级为分段填充

### 5.1 为什么必须改

`h143c_restack3.c` 的 `tgkill_allv()` 把 `v0..v31` **全填同一个 fake**，后果：

```
waiter->tree.__rb_parent_color = fake
waiter->tree.rb_right          = fake     ← 非 0！
waiter->tree.rb_left           = fake
```

而 `rb_erase` Path B 要求 `rb_right == 0`，否则走 rebalance 链（历史上多次崩在此处）。
⇒ **单一 fake 在数学上就摆不出「rb_right=0 而 rb_left=T」的组合。**

### 5.2 本轮实现（已编译 + 反汇编验证）

NDK r27c `-O2 -static`，产物 `tools/h175_staged`（2,225,696 B，md5 `ea552c5120c2932be560c3cbd004c772`）。

反汇编逐指令确认编译器**未优化掉**向量赋值：

```asm
movi  v0.2d..v15.2d, #0      ← 16 个 vreg 全清零
fmov  d7, x10                ← v7.d[0] = V (parent_color)
fmov  d8, x9                 ← v8.d[0] = T (rb_left)
fmov  d12, x11               ← v12.d[0] = task
mov   x14, x12               ┐
fmov  d14, x14               │ lock 精确落 v12.d[1]（高槽）
mov   v12.d[1], v14.d[0]      ┘
svc   #0
```

`v7.d[1]` 保持清零 ⇒ `rb_right == 0` ✔

### 5.3 编译期踩坑（已修）

| 错误 | 原因 | 修法 |
|---|---|---|
| 40+ 编译错误 | 文件头注释里嵌套 `/* */` 提前闭合块注释 | 改用 `offset +0x00 :` 行式描述 |
| `invalid operand` ×4 | `movi vN.d[0], #0` 在 ARM64 非法 | 先 `movi vN.2d,#0` 全清零 |
| lock 落错槽 | `fmov d1, x12` 只能写低槽 `d[0]`，而 lock 需在高槽 `d[1]` | `mov x14` 中转 + `mov v12.d[1], v14.d[0]` |

---

## 六、开火前的剩余风险（R1–R3）

| ID | 风险 | 现状 |
|---|---|---|
| **R1** | `V ∈ {0,1,2,3}` ⇒ `parent = V&~3 = 0` ⇒ 命中 `0x…ac0c: str x10,[x1]`，把 `lock->waiters.rb_node`（`lock+0x08`）写成野值 T ⇒ 后续 unlock 崩 | **规避方案已定**：触发点选 `rtmutex_api.c:353`（返回后只 `unlock_irq`，**不做** `fixup_rt_mutex_waiters`）。`rtmutex.c:1707` 与 `rtmutex_api.c:439` 都有 fixup，不可用。**未实测** |
| **R2** | 单次 8 字节写连带损伤同页相邻字段 | 写点三要素（V/T/0）已设计为互不冲突；实际目标（如 `task+0x818`）的邻域需逐次核对 |
| **R3** | `tree.prio` / `tree.deadline`（`v8.d[1]` / `v9.d[0]`）本轮被清零 | 清零使 `rt_waiter_node_equal` 的 `prio` 比较必然不等 ⇒ **恰好满足 H142 发现 1 的「破早退闸门」条件**（`waiter->tree.prio=0` vs `task->prio≠0`）。这是清零的**有利副作用**，但需实测确认 |

---

## 七、本轮未开火的理由（诚实交代）

用户指令为「算好即开火」。本轮**没有开火**，理由如下，按重要性排序：

1. **★ 前置知识缺失被本轮发现**：H173 立项时基于「触发条件无证据」这一**错误前提**。真相是 H140–H142 已实测到 panic。此时若贸然开火，等于在未复核 `h140/h141/h142` 三份既有报告的状态下改动一条**已经跑通到 panic** 的链，风险不可控。**先补齐认知，再动代码。**

2. **写原语落地尚未验证**：H142 达成的判据是「panic」，`history.log` 记 `null_pointer` —— 即 `waiter->lock` 被自然覆盖成 NULL 后解引用崩。**这证明栈可被重占，但证明的是「崩」不是「可控写」。** 从 panic 到「`rb_erase` 真写出目标值」之间还差一步：`remove_waiter` 必须在 `lock->waiters.rb_leftmost != waiter` 的干净出口上触发（否则落入 rebalance/fixup 链）。

3. **一 boot 一发纪律**：boot `abc61a92` 未消耗，值得留给信息量最大的一发。

⇒ **下一步应先做零风险验证**：把 `h175_staged verify` 推上设备单发运行，只看两件事——（a）EDEADLK + W 返回是否复现；（b）`sig_hits` 是否生效（画布投递通道是否通）。这两项都不写内核，取值来自 syscall 返回码与用户态计数，属独立透镜。

---

## 八、可证伪判据

| 结论 | 判据 | 若不成立，错在哪 |
|---|---|---|
| 三 futex 环可确定性触发 EDEADLK | `CMP_REQUEUE_PI` 返回 `-1/errno 35` 且 W 随后从 `WAIT_REQUEUE_PI` 返回 | 若 `rc=0/1`，则未进 `task_blocks_on`；查 `nr_wake≠1` 或 futex key 相同（`requeue.c:415/439`） |
| 门 A 是伪环 | W 走的是「永久阻塞/超时返回」而非正常取得锁 | 若 W 拿到 `f_target`，说明命中 `requeue.c:631` 的 `ret==1` 快路径 |
| 画布 vreg 映射正确 | 重占后 `waiter->lock` 可被单独控制（清零其余不影响行为） | 若崩在 `raw_spin_trylock(&lock->wait_lock)`，说明 `lock` 槽位算错，回查 §3.3 |
| Path B 写语义成立 | `*(T) == V` | 若写到了 `T±8`，说明 `rb_left`/`rb_right` 顺序弄反，见 §4 |

---

## 九、产物

| 文件 | 说明 |
|---|---|
| `tools/h175_staged.c` | ★ 分段画布投递（`tgkill_staged`），md5 `2a58b256815afa8645583d6b4b36e46f` |
| `tools/h175_staged` | 编译产物，md5 `ea552c5120c2932be560c3cbd004c772` |
| `tools/h174_edeadlk.c` | 纯用户态 EDEADLK 拓扑探针（未编译，拓扑已被 `h141c` 覆盖，**建议不跑**） |
| 本报告 | `analysis/output/h175_staged_canvas.md` |

### 引用（既有，本轮新读）

- `analysis/output/h140_cve_device_verify.md` §9–§11（D0/D1 差分、C0/C1/C2 独立透镜、H141 伪环更正）
- `analysis/output/h142_cve43499_uaf_hit.md`（8 环节端到端 + panic 证据）
- `tools/h141c_cycle2.c`（三环实现，与 H174 独立推导同构）
- `kernel_src/.../include/linux/rbtree_types.h:5-9`（`rb_node` 字段顺序）
- `kernel_src/.../kernel/locking/rtmutex_api.c:14`（`max_lock_depth = 1024`）