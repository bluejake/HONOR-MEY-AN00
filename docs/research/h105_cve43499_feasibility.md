# H103 · CVE-2026-43499（GhostLock）在 MEY-AN00 上的可行性裁决

> 轮次：H103（2026-10-05 10:1x）· 阶段：零（可行性）+ 二（分析）· **未开火**
> 判据来源：设备实测（`/proc/config.gz`、`id`、`getenforce`）+ `Image-mey` 反汇编 + Python 复核
> 产物：`analysis/scratch/h103_l2_stack_geom.py`、`h103_waiter_slot.py`、`h103_which_rbtree.py`、`h103_carrier_scan.py`

---

## 0. 直接回答

**结论：当前不能利用 CVE-2026-43499 在你的 MEY-AN00 上完成提权；短期内成功率评估为「低」。**

但必须纠正一条旧结论：**该漏洞在本机内核上确实存在且未被修复**（此前 H47 判「L2 机制不成立」的理由是错的，见 §4）。
真正的阻塞是三道**具体、可验证**的关卡，而不是「机制不存在」：

| # | 关卡 | 状态 |
|---|---|---|
| ① | 漏洞存在性 | ✅ **已证存在（未修复）** —— 环② 决定性证据见 §2 |
| ② | UAF **触发**（三线程 PI 死锁 → EDEADLK） | ❌ 本机 `rt_mutex_slowlock@0x108208c` 有 `brk #0x800` 硬化，EDEADLK 路必 panic；替代拓扑未验证 |
| ③ | 栈**回收**（pselect 覆盖 stale waiter） | ❌ 几何已精确测定：waiter = stack_fds + 0x50（10 词），可控区只覆盖到 waiter+0x28，`waiter->lock` 落在归零区 ⇒ 主流消费路径必崩 |
| ④ | 写目标基址 | ⚠️ `selinux_state=0x23ba418` 已被 H99 证伪，需重定位 |

---

## 1. 设备基线（本轮实测，读操作，无风险）

| 项 | 值 |
|---|---|
| 内核 | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`（clang 18.0.0，+pgo +bolt +lto +mlgo，2026-05-31） |
| 安全补丁 | 2026-08-01 |
| `CONFIG_FUTEX_PI` | **y** ✅（漏洞前置条件满足） |
| `CONFIG_RT_MUTEXES` | y |
| `CONFIG_RANDOMIZE_KSTACK_OFFSET` | y，但 **`CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT` 未设** ⇒ 栈偏移**确定性**（无随机扰动，好消息） |
| `CONFIG_RANDSTRUCT` | `RANDSTRUCT_NONE=y` |
| seccomp（shell 进程） | `Seccomp: 0 / Seccomp_filters: 0` ⇒ futex / pselect6 均可直达 ✅ |
| 身份 | `uid=2000(shell) … context=u:r:shell:s0`，`getenforce = Enforcing` |
| `/dev/ashmem`、`/dev/binder` | 均存在 |

**受影响区间判定（环①）**：修复分支为 6.1.175 / 6.6.140 / 6.12.86 / 6.18.27 / 7.0.4（来源：`refs/cve-2026-43499/README.md`，与 `refs/asus-i005-…/09-final-report.md` 一致）。
本机 `6.6.118 < 6.6.140` ⇒ **落在受影响区间内**。

---

## 2. ★★★ 漏洞存在性：环② 决定性证据（本轮最高价值产出）

上游修复 commit `3bfdc63936dd` 的标题是 **「rtmutex: Use waiter::task instead of current in remove_waiter()」**。
因此判定本机是否修复，只需看 `remove_waiter` 用的是 `current` 还是 `waiter->task`。

`remove_waiter @ 0xffffffc081080e60`（`Image-mey` 实读）：

```
0x1080e7c  ldr x24, [x0, #0x10]        ; lock->waiters.leftmost
0x1080e80  mov x19, x0                 ; x19 = lock (struct rt_mutex)
0x1080e84  mov x23, x1                 ; x23 = waiter
0x1080e98  mrs x20, sp_el0             ; ★★★ x20 = current  （不是 waiter->task!）
0x1080e9c  add x21, x20, #0x90c        ; &current->pi_lock
0x1080ea4  mov x0, x21
0x1080ea8  bl _raw_spin_lock
0x1080ed4  mov x0, x23                 ; rb_erase(node = waiter+0x00)
0x1080ed8  mov x1, x22                 ; root  = lock+8  (&lock->waiters.rb_root)
0x1080edc  bl rb_erase (0x3a9d4)
0x1080ee8  str xzr, [x20, #0x938]      ; ★ current->pi_blocked_on = NULL
```

- **全程用 `current`（`sp_el0`），从未出现 `ldr xN, [x23, #0x50]`（= `waiter->task`）**
- 而 `rt_mutex_adjust_prio_chain` 里确实用 `[waiter+0x50]` 取 task（`0x1081ad4 ldr x0,[x8,#0x50]` 喂 `wake_up_state`）⇒ 偏移 0x50 无误，排除「我找错字段」的可能。

⇒ **本机 `remove_waiter` 是未修复版本，CVE-2026-43499 在本机内核上客观存在。**
（置信度：**汇编已证**；`remove_waiter` 是本机固件裸镜像直读，非推测。）

---

## 3. 利用链分段裁决

### 3.1 waiter 栈槽（环②，双证据）

`futex_wait_requeue_pi @ 0xffffffc080958e1c`：

```
0x958e20  sub sp, sp, #0x1c0
0x958ea4  add x0, sp, #0x90 ; mov w1, wzr ; mov w2, #0x70 ; bl __memset   ★ memset(sp+0x90, 0, 0x70)
0x958eb0  add x27, sp, #0x90
0x958ed4  add x8, x27, #0x28 ; str x8, [sp, #0xb8]   ★ RB_CLEAR_NODE(&waiter.pi_tree)  pi_tree@+0x28
0x958ef4  str x27, [sp, #0x90]                        ★ RB_CLEAR_NODE(&waiter.tree)     tree@+0x00
```

- `memset` 长度 `0x70` = BTF 实测 `sizeof(struct rt_mutex_waiter)` ✔
- 两处 `RB_CLEAR_NODE` 自指（+0x00 / +0x28）与布局 `tree@0 / pi_tree@0x28 / task@0x50 / lock@0x58` 逐项吻合 ✔
⇒ **waiter 栈槽 = `sp + 0x90`**（非 `sp+0x70`，那个是 `key2`）

### 3.2 两条 syscall 链的相对深度（本轮算出，且与历史实测互证）

| 链 | 帧 | 关键槽 | 相对 syscall 入口 SP |
|---|---|---|---|
| `__arm64_sys_futex` | `0x80`（**`do_futex` 已内联**：`0x119dd4 bl futex_wait_requeue_pi` 直调，无 `bl do_futex`） | — | — |
| `futex_wait_requeue_pi` | `0x1c0` | waiter `+0x90` | **SP0 − 0x1B0** |
| `__arm64_sys_pselect6` | `0x90`（`0x2442b0 bl core_sys_select` 直调，无 `do_pselect6`） | — | — |
| `core_sys_select` | `0x1e0` | `stack_fds` `+0x70`（`0x243f28 add x0,sp,#0x70` + `memset 0x100`） | **SP0 − 0x200** |

⇒ **waiter = stack_fds + 0x50（= 10 个 8 字节词）**

**独立互证**：历史轮次实测得到的 `PSELECT_WORD_SHIFT = 10`（`HANDOFF §7` env 速查表标注「★ 必须 10」）与本次静态计算 **完全吻合**。
⇒ 环② 与历史实测双证；同时反证「`do_futex` 未内联」的假设（若未内联会得到 shift = −2，与实测 10 矛盾）。

### 3.3 可覆盖性：`waiter = stack_fds + 0x50` 的后果

`core_sys_select` 中 `stack_fds` 后 6 个 fd_set 依次排布，用户可控的是前 3 个（in/out/ex，`copy_from_user`），后 3 个（res_*）先被 `memset` 清零：

| nfds | `FDS_BYTES(size)` | 路径 | 可控区 `3*size` | waiter 覆盖情况 |
|---|---|---|---|---|
| 256 | 32 | 栈 | 96 B | 只到 waiter+0x10 |
| **257–320** | **40** | **栈** | **120 B** | **waiter+0x00…+0x28 可控；+0x28 以后（pi_tree / task / lock / wake_state / ww_ctx）全落在 res_* 归零区** |
| ≥321 | ≥48 | kmalloc 堆 | — | 与栈不重叠 |

⇒ **`waiter->lock`（+0x58）恒为 0**。

### 3.4 为什么「主流消费路径」必崩，以及「唯一还活着」的子路线 ★★★

- `rt_mutex_adjust_prio_chain`（历史轮次用 `sched_setattr` 触发的消费者）在入口就要 `raw_spin_lock(&lock->wait_lock)`，其中 `lock = waiter->lock` ⇒ **NULL 解引用必 panic**。
  ⇒ 这解释了 H39–H46 连续八轮 oops：**不是参数没调对，而是消费路径选错**。
- 但 `remove_waiter()` 的**第一处** `rb_erase(&waiter->tree, &lock->waiters.rb_root)` 只依赖：
  - `waiter+0x00` `__rb_parent_color`（→ 写**目标**地址 `mpc + 0x08/0x10`）
  - `waiter+0x08` `rb_right`（→ 写**值**）
  - `waiter+0x10` `rb_left`（→ `csel` 条件）
  - `lock` 是**函数实参**（真实 `pi_mutex`），不从 waiter 取
  ⇒ **三个必需字段全部位于 pselect 可控区（waiter+0x00…0x18）** ✔
- 而 `remove_waiter` 的第二处（pi_tree 那一支）有门控：`0x1080ef0 cmp x24, x23; b.ne 0x1080f70`
  ⇒ **只要 stale waiter 不是 `lock->waiters.leftmost`，就整段跳过 pi_tree 分支**，不会碰到归零字段。

⇒ **方向性修正（本轮最重要结论）**：本机唯一还活着的子路线是
**「让 `remove_waiter` 而不是 `rt_mutex_adjust_prio_chain` 去消费 stale waiter」**，
而不是继续扫 nfds、也不是继续用 `sched_setattr` 当消费器。

---

## 4. ★★★ 推翻 / 修正旧结论

### 4.1 H47「容量矛盾 ⇒ 真死路」——**判据错误，予以证伪**

H47 的判决表写：`nfds=320 ⇒ FDS_BYTES=48 ⇒ 走堆`，并据此断言「任何能装下 14 词的 nfds 都走 kmalloc」。
Python 复核（`h103` 内置计算，铁律①）：

```
FDS_LONGS(320) = (320+63)/64 = 5   FDS_BYTES(320) = 40
阈值：sizeof(stack_fds)/6 = 256/6 = 42（整数除法）⇒ kmalloc 条件 size > 42
40 ≤ 42  ⇒ ★ nfds=320 走【栈】
3*40 = 120 B = 15 词 ≥ 14 词（waiter 0x70）⇒ ★ 容量够
```

汇编侧亦吻合（`0x243f78 cmp x24, #0x2b; b.hs` ⇒ `size ≥ 43` 才跳 kmalloc，与源码 `size > 256/6` 同义）。
H47 错在把「走栈」的上界写成 `n ≤ 256`（正确是 `n ≤ 320`），并把 `FDS_BYTES(320)` 算成 48。

### 4.2 但 H47 的「L2 不成立」结论**保留，理由必须更换**

真因不是容量，而是**对齐错位 0x50（10 词）**：可控区最多到 waiter+0x28，`waiter->lock` 落在归零区。
⇒ 结论一致、机制不同；**禁止再引用「容量矛盾」作为判死理由**。

### 4.3 仍然成立、禁止重复的旧结论

- H46「`nfds=640 + shift=16`」：640 ⇒ size=80 ⇒ kmalloc ⇒ 与栈不重叠，**仍然证伪**。
- 「不要再扫 nfds」：容量从来不是瓶颈，扫描 nfds 永远无解（此条由 H47 提出，**结论保留**）。
- 「不要再用 `sched_setattr` → `rt_mutex_adjust_prio_chain` 当消费器」：**本轮新增禁止项**（§3.4）。

---

## 5. 三环对照表

| 环 | 内容 | 结论 |
|---|---|---|
| ① 源码 | 修复分支 6.6.140；本机 6.6.118 未覆盖；修复语义「remove_waiter 用 waiter::task 代替 current」 | **成立（漏洞存在）** |
| ② 汇编 | `remove_waiter@0x1080e60` 全程 `sp_el0`/`current`，无 `[waiter+0x50]`；waiter 栈槽 `sp+0x90`（`memset 0x70` + 两处 `RB_CLEAR_NODE`）；waiter = stack_fds+0x50（与实测 shift=10 一致） | **成立（未修复 + 几何确定）** |
| ③ 镜像 delta | `Image-mey` 即本机固件裸镜像（`file_off = vaddr − 0xffffffc080000000`）；`do_futex` 被厂商**内联**进 wrapper（这与荣耀 6.1 的同名问题同源，但 6.6 上 offset 不同） | **成立，环②③ 同源** |
| 三环矛盾 | 无矛盾；矛盾在「漏洞存在」与「无可用的触发 + 对齐」之间 | — |

---

## 6. 若继续推进：可证伪判据（不要裸跑）

**假设 H103-A**：存在一条非 EDEADLK 的触发拓扑，使 `remove_waiter(real_lock, stale_waiter)` 被调用且 `waiter != leftmost`。

判据（**必须同 boot 内立刻回读，禁止跨重启判读**）：

1. **写原语生效（独立透镜）**：把 `waiter+0x00`（parent_color）设成 `TARGET−0x10`、`waiter+0x08` 设成已知魔数；
   消费后用**另一个通道**读 `TARGET`（如 `sysctl_bootid` 的 data 区 —— 历史上 `text=90b0292a` 就是这样读到的独立证据）。
   若 `TARGET` 变成魔数 ⇒ **假设成立**。
2. **不崩**：`boot_id` 不变 + uptime 未归零 + `history.log` 无新增条目。
3. **反证**：若仍 panic 且 `history.log` 新增 `page_request`/`null_pointer`，且反汇编定位在 `raw_spin_lock(&lock->wait_lock)` ⇒ 说明消费器仍是 `adjust_prio_chain`（或走到了 pi_tree 分支）⇒ **H103-A 证伪**，L2 真正判死。

---

## 7. 下一步（严格按序）

1. **（最高）静态确认 `remove_waiter` 的所有调用点**（`rt_mutex_slowlock_block` / `futex_wait_requeue_pi` 的 cleanup 分支），判断是否存在**不经 EDEADLK** 的到达路径；同时确认 `rt_mutex_slowlock@0x108208c` 的 `brk #0x800` 究竟 guard 什么条件（决定 EDEADLK 是否真被堵死）。
2. **改消费器**：把实验从 `sched_setattr` 换成「让 `remove_waiter` 自然执行」，并把伪 waiter 的 `+0x00/+0x08/+0x10` 三词按 §6 布置（`nfds=320`，`PSELECT_WORD_SHIFT=10` 保持）。
3. **重定位 `selinux_state`**（H99 已证伪 `0x23ba418`，候选 `0x23e2c20`）；`cred`/`real_cred` 需两次写 = 两个 boot。
4. **备选载体**（若第 1/2 步证伪）：需 `D − B = 0x1B0` 且 ≥0x60 B 可控。本轮扫描结果：`recvmsg` 只有 `0x38` B、`do_readv` 0x60 帧、`____sys_sendmsg` 0x80 帧 —— **未发现现成对齐候选**，需按 `D−B` 口径做全量 `__arm64_sys_*` 扫描（离线可做，零设备风险）。
5. L1（CVE-2026-64560）继续按 H102 的 R3 反交叉实验推进；L2 每轮只占 1 轮设备时间（交替闸门）。

---

## 8. 本轮禁止重复清单（新增）

- ❌ 再扫 `nfds`（容量不是瓶颈，H47 已定，本轮复核确认）
- ❌ 再用 `sched_setattr` → `rt_mutex_adjust_prio_chain` 当消费器（需要 `waiter->lock`，本机恒 0 ⇒ 必崩）
- ❌ 再引用 H47 的「容量矛盾」作为 L2 判死理由（已证伪，改用「对齐错位 0x50 + 触发被硬化」）
- ❌ 用「跨重启后 `enforcing=1`」判断写是否生效（重启清零，零信息量）
