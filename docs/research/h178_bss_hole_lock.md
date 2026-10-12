# H178 / U1 求解 —— 用 BTF DATASEC 权威 st_size 定位 `lock` 落点

**日期**：2026-10-06
**前置**：H177 §5「`lock` 放画布内可解除 U1」被自我否证 ⇒ U1 重新变成阻塞项。
**结论**：**U1 已解除。`LOCK = 0xffffffc082136048`**（`.data..percpu` 段内对齐空洞）。

---

## 0. 置信度声明

| 编号 | 结论 | 等级 |
|---|---|---|
| H178-C1 | 本机 BTF 位于裸 `Image` off=`0x172f4c0` | **已实测**（重扫 + md5 比对） |
| H178-C2 | 本机 BTF **只有 1 个 DATASEC**（`.data..percpu`，283 VAR），**无 `.bss` DATASEC** | **已实测**（`parse_exact=True`，VAR 总数 283 == secinfo 数 283） |
| H178-C3 | DATASEC 基址 = `0xffffffc082136000`，**283/283 锚点全部一致** | **已实测**（众数唯一，无例外） |
| H178-C4 | 段区间 `[0x…2136000, 0x…214b8a8)` **完全落在文件支撑区内**（`.bss` 起点 `0x…2368a00` 之前） | **已实测** |
| H178-C5 | 段内空洞 28 个，**每个都：Image 字节全零 ∧ 无 kallsyms 符号 ∧ 同 4K 页内无其他符号** | **已实测**（离线读 Image） |
| H178-C6 | `CONFIG_SMP=y` ⇒ `.data..percpu` 原体在 boot 时被 `memcpy` 拷贝后**不再被内核访问** | **源码已证，未实测** |
| H178-C7 | `rt_mutex` 本机 size = **0x20**（`DEBUG_LOCK_ALLOC` 未开） | **config 已证 + 源码已证** |
| H178-C8 | `rb_erase_cached` 二次迭代会进 `rb_next`，**`rb_right` 必须 0** | **源码已证** |

---

## 1. 为什么必须换方法（U1 三条旧路全部判死）

| 旧路 | 判死原因 |
|---|---|
| 画布内 `lock = SP0-0x1a0` | 需 `SP0` 绝对地址，我方**无读原语**（H138 判死） |
| kallsyms 相邻地址差当 `st_size` | **kallsyms 不含 `st_size`**（H177 已犯，扫出的「间隙」实为数组尾部） |
| BTF 扫 `.bss` | **本机 BTF 无 `.bss` DATASEC**（本轮实测） |

★ 附带否证一条上一轮的假设：**合成 symtab ELF 的 `st_size` 也全是 0**
（`Image-mey.symtab.elf` SH3 `off=0x2368bc0 size=0x28a580` → 110,992 个符号，
`parse 成功 110992/110992`，但 `st_size` 全 0）。
⇒ `ElfSymbolizer` 只从 kallsyms 灌「地址 + 名字」，kallsyms 无 size ⇒ 它也无 size。
⇒ **`st_size` 的唯一权威来源是 BTF。**

---

## 2. ★ 决定性洞察：`.data..percpu` 原体是**死区**

### 2.1 H177 的误判

H177 §4 记：「`.data..percpu` 空洞是该区是 per-CPU 数据、有并发访问风险」⇒ 排除。

### 2.2 源码双证（本轮实读 `mm/percpu.c`）

`CONFIG_SMP=y`（`mey_config.txt:317`）⇒ `setup_per_cpu_areas()` 走两条路，**都在 boot 时做一次 memcpy**：

```c
/* percpu.c:3130  —— chunk 型（SMP 主路径）*/
for (i = 0; i < gi->nr_units; i++, ptr += ai->unit_size) {
    ...
    memcpy(ptr, __per_cpu_load, ai->static_size);   /* :3130 */
}
/* percpu.c:3313  —— vmarea 型 */
memcpy((void *)unit_addr, __per_cpu_load, ai->static_size);   /* :3313 */
```

`__per_cpu_load` 就是 `.data..percpu` 段的镜像地址。拷贝完成后：
- 内核所有 per-cpu 访问走 `SHIFT_PER_CPU_PTR` / `__this_cpu` ⇒ 指向**新分配的 per-cpu area**；
- **镜像里的原体不再被任何代码读写。**

⇒ ★★ **`.data..percpu` 原体 = 「常量已知、可写、无并发访问」的内存。**
⇒ 且它在**文件支撑区内** ⇒ **内容可以直接从 `Image` 文件离线验证**（本项目独有优势）。

---

## 3. 定位过程（四条独立取证线）

### 3.1 L1 — BTF 解析（`h178_holes_final.py`）

```
type 数 144042   parse_exact=True
DATASEC '.data..percpu' size=0x158a8 vars=283
```

★ **VAR 记录总数 283 == DATASEC secinfo 数 283** ⇒ **每个 VAR 都在这个 DATASEC 里，
没有任何 VAR 落在别的 section** ⇒ 从结构上证明「本机 BTF 无 `.bss`/`.data` 的 VAR 导出」。

这不是解析 bug，是内核 BTF 的既定行为：只有需要运行期重定位的 per-cpu 变量才需要
DATASEC/VAR secinfo，普通 `.data`/`.bss` 变量的地址由 linker 决定、内核不需要在 BTF 里描述。

### 3.2 L2 — 基址定位（283/283 全中）

用「`secinfo[i].offset` vs `kallsyms[n同名符号]`」逐个算 `base = addr - off`，取众数：

```
基址众数 0xffffffc082136000   命中 283/283
top5: [('0xffffffc082136000', 283)]      ← 唯一值，无第二候选
```

★ **283 个锚点全部落在同一个基址上** ⇒ 基址无歧义。
（手动抽查：`this_cpu_vector` off=`0x0` → kallsyms `0xffffffc082136000`；
`kde_ref_count` off=`0x94` → kallsyms `0xffffffc082136094`。）

### 3.3 L3 — 空洞扫描（`st_size` 权威）

```
覆盖 87136 字节 / 段 0x158a8  (98.8%)
空洞（>=8B）28 个
```

段区间 `[0xffffffc082136000, 0xffffffc08214b8a8)`，**完全在文件支撑区内** ✔

### 3.4 L4 — 三重校验（内容 / 符号 / 同页）

对每个空洞同时验：
1. **Image 字节全零**（从 `Image-mey` 按 `va - 0xffffffc080000000` 读）；
2. 空洞 `[a,b)` 内**无任何 kallsyms 符号地址**；
3. **同 4K 页内**、洞外的其他符号列表（防跨页误伤）。

**28/28 全部通过「全零 + 无符号」。**

---

## 4. 候选选点：`LOCK = 0xffffffc082136048`

段内 6 个最宽空洞的审计（`h178_audit.py`）：

| 候选 | span | 左邻 | 距离 | 右邻 | 同页其他符号 | Image |
|---|---|---|---|---|---|---|
| **`0xffffffc082136048`** | **0x38** | `psci_cpuidle_data` | **0x10** | `kstack_offset` | **0** | **全零** |
| `0xffffffc082138d48` | 0x38 | `cpufreq_update_util_data` | 0x8 | `system_group_pcpu` | 0 | 全零 |
| `0xffffffc0821447c4` | 0x3c | `bpf_event_output_nest_level` | **0x4** ⚠️ | `bpf_misc_sds` | 0 | 全零 |
| `0xffffffc082148cc8` | 0x38 | `cpufreq_cpu_data` | 0x8 | `cpufreq_transition_notifier_list_head_srcu_data` | 0 | 全零 |
| `0xffffffc08214b4c8` | 0x38 | `call_single_queue` | 0x8 | `csd_data` | 0 | 全零 |
| `0xffffffc082148148` | 0x38 | `discard_pa_seq` | 0x8 | `eventfs_srcu_srcu_data` | 0 | 全零 |

**选定 `0xffffffc082136048`**，理由：
- span 0x38 ≥ `rt_mutex` 需求 0x20，**余量 0x18**；
- **左邻距离 0x10**（最大）—— 8 字节写不会碰到 `psci_cpuidle_data`；
- 同 4K 页内**无任何其他符号**（整页只有这一段空洞 + 两个邻居）；
- 备选 `0xffffffc0821447c4` 左邻仅 0x4，**排除**（8 字节写会溢出到邻居）。

---

## 5. ★ 该落点必须满足的完整约束（`lock` = `rt_mutex_base`，size 0x20）

| off | 字段 | 要求 | 谁改 | 我们的值 |
|---|---|---|---|---|
| +0x00 | `wait_lock` (`raw_spinlock_t`, **4B**) | 必须 0，否则 `[5]` trylock 无限 `retry`（软挂） | `[5]` 写 1 → `[9]` 写回 0 | 0 ✔ |
| +0x08 | `waiters.rb_root.rb_node` | **必须 0**，否则 `[8] rb_add_cached` 进 while 遍历野指针 | `[8] rb_link_node` 写 `&entry` | 0 ✔ |
| +0x10 | `waiters.rb_leftmost` | 0（首轮） | `[8] rb_insert_color_cached` 写 `&entry` | 0 ✔ |
| +0x18 | `owner` | **必须 0**，否则 `[9]` 不走 owner==0 干净出口 | 只读 | 0 ✔ |

（`include/linux/rtmutex.h:23-27`：`wait_lock` + `rb_root_cached` + `owner`；
`mey_config.txt:7655` `# CONFIG_DEBUG_LOCK_ALLOC is not set` ⇒ 无 `lockdep_map`，size = 0x20。）

### 5.1 全链闸门逐条核对（`lock = 0x…048`）

| 闸门 | 源码 | 条件 | 我方状态 | 结果 |
|---|---|---|---|---|
| `:689` | `if (++depth > max_lock_depth)` | `max_lock_depth=1024` | 首轮 depth=1 | ✔ |
| `:733` | `if (!waiter) goto out` | `waiter = task->pi_blocked_on` | 画布已投递 | ✔ |
| `:740` | `orig_waiter && !rt_mutex_owner(orig_lock)` | `orig_waiter = NULL` | 短路 | ✔ |
| **`:752`** | **`if (next_lock != waiter->lock) goto out`** | 首轮 `next_lock` 就是 `waiter->lock`（`rtmutex_api.c` 传入） | **恒成立** | ✔ **（此前未记录的隐式约束）** |
| `:777` | `PREEMPT_RT && ww_ctx && detect_deadlock` | `PREEMPT_RT` 未开 | 短路 | ✔ |
| `:785` | `if (top_waiter)` | `top_waiter = orig_waiter = NULL` | 跳过整块 | ✔ |
| `:809` | `rt_waiter_node_equal(&waiter->tree, task_to_waiter_node(task))` | `tree.prio=0` vs `task->prio=120` | 不等 | ✔ |
| `:830` | `trylock(&lock->wait_lock)` | `*(u32*)(lock+0)=0` | 成功 | ✔ |
| `:845` | `lock == orig_lock \|\| owner == top_task` | `orig_lock=NULL`，`owner=0` | **不触发 EDEADLK** | ✔ |
| `:870` | `if (!requeue)` | `requeue = true` | 走 requeue 分支 | ✔ |
| `:917` | `rt_mutex_top_waiter(lock)` → `BUG_ON(w->lock != lock)` | `rb_leftmost==0` ⇒ `leftmost=false` | **不进 BUG_ON** | ✔ |

★ **`:845` 的 `owner == top_task` 分支**：`lock->owner = 0` ⇒ 恒不触发。
（MEMORY §★29 记 `-EDEADLK` 全树两处 `:845`/`:704`；本轮确认 `:845` 的两个 disjunct
在本发几何下都不成立。）

---

## 6. ★★ 连带写对 `V` / `T` 的硬约束（H177 §2 真值表 + 本轮新增 `rb_next` 约束）

### 6.1 走哪条路径

`h175_staged.c` 现有编码：`v7.d[0]=V`（`parent_color`）、`v7.d[1]=0`（`rb_right`）、
`v8.d[0]=T`（`rb_left`）。

⇒ **`rb_left = T ≠ 0`、`rb_right = 0`** ⇒ 命中 **Case 1'**（`!tmp` 为假、`!child` 为真）。
（★ H175 §3.3 原表正确；H176 §8 把两者写反了，H177 §8.1 已修正。）

### 6.2 Case 1' 的两条写

```c
tmp->__rb_parent_color = pc = node->__rb_parent_color;  /* :251  主写 *(T) = V   */
parent = __rb_parent(pc);                                /* = V & ~3              */
__rb_change_child(node, tmp, parent, root);              /* :253 连带写            */
rebalance = NULL;                                        /* :254 恒 NULL ✔         */
```
汇编（`rb_erase@0xffffffc08003a9d4`，H177 §1.3 已录）：
```
0x…ab04: ldr  x9,[x0]      ; pc = V
0x…ab08: ands x8,x9,#-4    ; parent = V&~3
0x…ab0c: str  x9,[x10]     ; ★主写 *(rb_left) = V
0x…ab10: b.eq #0x…ac0c
0x…ab14: ldr  x9,[x8,#0x10]
0x…ab18: cmp  x9,x0
0x…ab1c: b.ne #0x…ac8c
0x…ab20: str  x10,[x8,#0x10]  ; ★连带写 *(V&~3+0x10) = T
0x…ab24: ret
```
★ 二选一判据：`**(V&~3 + 0x10) == &entry`** ⇒ 写 `+0x10`；否则写 `+0x08`。

### 6.3 ★★★ 本轮新增约束：`rb_erase_cached` 二次迭代会进 `rb_next`

```c
/* rbtree.h:118-129 */
static inline struct rb_node *rb_erase_cached(struct rb_node *node,
                        struct rb_root_cached *root)
{
        struct rb_node *leftmost = NULL;
        if (root->rb_leftmost == node)                      /* :123 */
                leftmost = root->rb_leftmost = rb_next(node);  /* :124 */
        rb_erase(node, &root->rb_root);                     /* :126 */
        return leftmost;
}
```

`rt_mutex_dequeue`（`rtmutex.c:472-482`）走的是 `rb_erase_cached`。
**第一次迭代 `[8]` 已把 `lock+0x10` 写成 `&entry`** ⇒ **第二次及以后的 `[7]` 必然进 `rb_next`。**

`rb_next` 是**外部函数**（`rbtree.c:492`，本机 `0xffffffc08003af24`）：
```c
if (RB_EMPTY_NODE(node)) return NULL;      /* :496 */
if (node->rb_right) {                       /* :503 ★必须为 0，否则走野链 */
        node = node->rb_right;
        while (node->rb_left) node = node->rb_left;
        return node;
}
while ((parent = rb_parent(node)) && node == parent->rb_right)  /* :517 */
        node = parent;
return parent;
```

⇒ **三条硬约束**（前两条 H177 未区分，本轮明确）：
| # | 约束 | 违反后果 |
|---|---|---|
| a | **`rb_right` 必须 0** | `rb_next` 进 `while(node->rb_left)` 遍历野链 ⇒ 崩 |
| b | `RB_EMPTY_NODE(node)` 必须为假 | 若 `V == &entry` 则 `rb_next` 立即返回 NULL（**反而安全**，但 `V` 就失去写值意义） |
| c | 若 `rb_parent(node) = V&~3 ≠ 0` | `:517` 读 `*(V&~3 + 0x10)`（`parent->rb_right`）与 `*(V&~3+0x08)`（`parent->rb_left`）——**只读，无副作用**，但若 `V&~3` 不可读则崩 |

★ **纠正 H175 §3.3 注①与 H176 §8 的一处混乱**：
- `rb_right` 必须 0 —— **为了 `rb_next` 的 `:503`**，不是为了主写路径；
- `rb_left = T` 是 Case 1' 的必要条件（`tmp` 槽），**且 `T ≠ 0`**。

### 6.4 verify 模式的 `V`/`T` 取值（零内核语义写）

`LOCK` 的空洞有 **0x38 字节**，`rt_mutex` 只占 0x20 ⇒ **余量 0x18 字节（`LOCK+0x20 .. LOCK+0x38`）可作 `V`/`T` 的落点**。

| 量 | 取值 | 说明 |
|---|---|---|
| `LOCK` | `0xffffffc082136048` | 空洞首地址 |
| `V` | `LOCK + 0x20` = `0xffffffc082136068` | ⇒ `V&~3 = V`（8 字节对齐 ✔），且 `V&~3 + 0x10 = LOCK+0x30`，该处为 0 ≠ `&entry` ⇒ 走 **A2/B2 连带写 `*(V+0x08) = T`** |
| `T` | `LOCK + 0x28` = `0xffffffc082136070` | 主写 `*(T) = V` ⇒ `*(LOCK+0x28) = LOCK+0x20` |

⇒ 两条写全部落在空洞内（`LOCK+0x20 .. LOCK+0x30`），**零真实内核数据触碰**。

| 写 | 指令 | 落点 | 值 | 空洞内？ |
|---|---|---|---|---|
| 主写 `:251` | `str x9,[x10]` | `LOCK+0x28` | `V = LOCK+0x20` | ✔ |
| 连带写 `:253` | `str x10,[x8,#0x08]` | `LOCK+0x28`… ⚠️ | `T` | ⚠️ 见下 |

★★ **注意冲突**：`V&~3+0x08 = LOCK+0x28` **恰好等于 `T`** ⇒ 两条写打同一处。
这不是问题（后写覆盖前写，最终值 = `T`），但要记录：
- 主写先执行（`:251` 在 `:253` 之前）⇒ `*(LOCK+0x28) = V`；
- 连带写后执行 ⇒ `*(LOCK+0x28) = T`；
- **最终 `*(LOCK+0x28) = T = LOCK+0x28`**（自指）。

⇒ ★ 建议改 `V = LOCK + 0x20`、`T = LOCK + 0x30`（避开同一槽），
让两条写分离到 `LOCK+0x28` 与 `LOCK+0x38`… ⚠️ `LOCK+0x38` **超出空洞**（span 只到 `+0x38`）。
⇒ **最终定：`V = LOCK + 0x20`，`T = LOCK + 0x28`（接受同槽覆盖）**，
或 `V = LOCK + 0x28`、`T = LOCK + 0x20`（此时 `V&~3+0x08 = LOCK+0x30`、`*(T)=V` 落 `LOCK+0x20`，**两条写分离**）。

★★ **推荐后者：`V = LOCK+0x28`、`T = LOCK+0x20`** ——
- 主写 `*(T) = V` ⇒ `*(LOCK+0x20) = LOCK+0x28`；
- 连带写 `*(V&~3+0x08) = T` ⇒ `*(LOCK+0x30) = LOCK+0x20`；
- **两条写分离，且都在 0x38 空洞内** ✔

---

## 7. 可证伪判据

| # | 若此结论成立，则应观测到 | 若观测不到，说明 | 独立透镜？ |
|---|---|---|---|
| H178-J1 | `sched_setattr` 返回 **0** | `[9]` 没走到 `return 0` | ✔ 外部可见 |
| H178-J2 | `boot_id` 三重 md5 一致 | 崩了（读 `/data/log/reliability/faultdetect/history.log` 定原因） | ✔ |
| H178-J3 | `sig_hits` == 10 | 画布没落到 W 栈上 | ✔ |
| **H178-J4** | **第二次 `[7]`（第 2..10 次投递）不崩** | `rb_right ≠ 0` 或 `rb_next` 走野链（§6.3a） | ✔ |
| **H178-J5** | **`LOCK+0x08` 在 `[8]` 后 == `&entry`，第 2 次 `[7]` 后回到 0** | `rb_erase_cached` 的 leftmost 更新路径没走到 | ✔（但需读内核 ⇒ 只能靠「不崩 + 无副作用」间接判） |
| H178-J6 | 第一次 `[7]` 之后 `LOCK+0x20/+0x28/+0x30` 内容符合 §6.4 表 | `V`/`T` 取值算错 | ❌ 无读原语，只能靠第二发（stage8）的实际效果反推 |

★ **J6 是本方案的固有盲区**：无法直接读回 `lock` 区域（无读原语）。
唯一可观测的判据是 **stage8 的 `cred` 是否真被改掉** ⇒ 那就是最终判据
（`id` 显示 `uid=0` + `getenforce` 非 Enforcing）。

---

## 8. 未决项

| # | 项 | 状态 |
|---|---|---|
| **U1** | ~~`lock` 的绝对地址~~ | ✅ **本轮解除**（`0xffffffc082136048`） |
| **U12** | **`.data..percpu` 原体在运行期确实无人访问** | ⚠️ **源码已证，未实测**。若 J4 崩溃 ⇒ 立即换 `.data`/`.bss` 内候选（需另找） |
| **U13** | **`LOCK+0x00` 的 4 字节 `wait_lock` 是否真为 0** | Image 实测该字节为 0 ✔（离线） |
| **U5** | `task_struct` 绝对地址（stage8 需要 `task+0x810/+0x818`） | ❌ 仍未解，阻塞 stage8 |
| U7 | `task_struct` 偏移置信度（BTF `size=0x12c0` vs `init_task` span `0x1e280`） | ❌ 仍未解 |

---

## 9. 本轮实读/新建文件清单

**新建**
- `analysis/scratch/h178_bss_holes.py`（L1 kallsyms 范围 + L2 section header + L3 零页探测）
- `analysis/scratch/h178_btf_bss_vars.py`（VAR (linkage,sec) 分布 ⇒ 证明无 `.bss` DATASEC）
- `analysis/scratch/h178_percpu_holes.py`（percpu 段空洞扫描，含基址众数定位）
- `analysis/scratch/h178_holes_final.py`（★ 最终版：基址 283/283 + 空洞 + 三重校验）
- `analysis/scratch/h178_audit.py`（6 个宽空洞的邻居/同页/字节审计）
- `analysis/scratch/h178_base.py`、`h178_dbg.py`、`h178_dbg2.py`（布局调试）

**修改**
- `analysis/output/h177_erase_collateral_and_canvas_lock.md`（★ §5 加自我否证 §5.5，撤回「U1 解除」）

**实读**
- `kernel_src/.../kernel/mm/percpu.c`（`:3090-3145`、`:3280-3330`）★ `memcpy(__per_cpu_load)` 双路径
- `kernel_src/.../kernel/include/linux/rbtree.h`（`:59-129`）★ `rb_link_node`/`rb_erase_cached`
- `kernel_src/.../kernel/lib/rbtree.c`（`:492-520`）★ `rb_next`
- `kernel_src/.../kernel/locking/rtmutex.c`（`:636-910`）★ `:752` `next_lock` 闸门、`:845` EDEADLK
- `kernel_src/.../include/linux/rtmutex.h`（`:23-33`）★ `rt_mutex_base` = 0x20
- `kernel_src/.../kernel/locking/rtmutex_common.h`
- `analysis/output/mey_config.txt`（`:317 CONFIG_SMP=y`、`:7655 DEBUG_LOCK_ALLOC`）
- `analysis/output/mey_6.6.118.kallsyms.txt`（`rb_next=0xffffffc08003af24`）
- `analysis/scratch/h166_bootimg_to_elf.py`

---

## 10. 设备状态

**本轮全程零 adb 写操作，未开火。**
`boot_id abc61a92-7b66-4ccf-b8fe-26f70918cb30`（未消耗）、`getenforce Enforcing`、uid 2000、`AP_S_PANIC=754`。