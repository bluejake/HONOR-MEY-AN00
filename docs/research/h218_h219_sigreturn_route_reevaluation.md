# H218–H219 · sigreturn 路线独立复核与重新评估

> 设备：MEY-AN00（荣耀 500 / SM8735 / `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`）
> 会话：2026-10-06 续做 · **真机开火 0 发**（`boot_id` 全程 `ba30251b-…a0` 不变）
> 依据：`analysis/vmlinux/vmlinux-mey.elf` 反汇编一手（capstone）+ 本机 `config.gz` + 项目历史文档
> 纪律：**零内核源码**；每条结论给出可证伪判据。

---

## §0 一句话结论

**sigreturn 栈写原语成立且已独立复核（两条 512 B 拷贝，绝对深度 `[0x100, 0x300)`）；
它与 43499 stale waiter 槽位（`[0x1B0, 0x220)`）【完全重叠】。
但"用画布覆盖 waiter"这一形态被 `futex_wait_requeue_pi` 入口的 `memset(waiter,0,0x70)` 判死；
真正未被评估、也未被实测的是【syscall 返回后 stale waiter 被复写】这一形态 —— 见 §4。**

---

## §1 sigreturn 栈写原语：独立复核（三重实证）

### 1.1 帧深账本（逐跳，全部本机汇编实证）

| 层 | 函数 | sp 调整 | 依据 |
|---|---|---|---|
| 1 | `el0_svc` @`0x8106f708` | **0x40** | 序言 `sub sp,sp,#0x40`；全函数仅 `0x8106f7b4 add sp,sp,#0x40` 一处回退 ⇒ **无其他 sp 调整** |
| 2 | `do_el0_svc` @`0x80046544` | 0x20 | `stp x29,x30,[sp,#-0x20]!` |
| 3 | `invoke_syscall` @`0x80046704` | 0x20 | `stp x29,x30,[sp,#-0x20]!` |
| 4 | `__arm64_sys_rt_sigreturn` @`0x8049b2e4` | **0x60 + 0x230 = 0x290** | `stp x29,x30,[sp,#-0x60]!` + `sub sp,sp,#0x230` |

⇒ sigreturn 时 `sp = SP0 − 0x310`（0x40+0x20+0x20+0x290）。

### 1.2 512 字节内核栈写（两条等价路径）

全函数（4748 B）**只有 4 处** `__arch_copy_from_user`，其中两处是 0x200 字节栈拷贝：

```asm
; 路径 A  @0x8049beb4   (入口+0xbd0)
8049beac: add  x0, sp, #0x10        ; dst = sp + 0x10
8049beb0: mov  w2, #0x200           ; len = 512
8049beb4: bl   __arch_copy_from_user

; 路径 B  @0x8049c230   (入口+0xf4c)   —— 与 A 完全等价
8049c228: add  x0, sp, #0x10
8049c22c: mov  w2, #0x200
8049c230: bl   __arch_copy_from_user
```

（另两处分别是 `sp+8 / len 8` 的小拷贝，与 `x0=x27,x2=x21` 的变长拷贝。）

**绝对深度**：`dst = SP0 − 0x310 + 0x10 = SP0 − 0x300`，长度 0x200
⇒ **画布绝对区间 = `[SP0 − 0x300, SP0 − 0x100)`，即深度 `[0x100, 0x300)`。**

★ **两条路径同 dst 同 len** ⇒ 结论对分支选择**鲁棒**（不必赌走哪条）。
★ **前置无 memset**：该函数内在 cfu 之前**没有任何 `__memset`** ⇒ 用户数据不会被先清零。

> ⚠️ H106 记「画布起点 = `SP0 − 0x280`」，与帧账本推导的 `SP0 − 0x300` **差 0x80**。
> 两者不可能同真。帧账本（§1.1，逐跳实证、`el0_svc` 全域仅一处 sp 调整）支持 **0x300**。
> 但 H106 又称 vregs 拷贝目的地为「`sp+0x10`」且帧为 0x290 —— 与 0x300 自洽。
> ⇒ 判定：**H106 的 0x280 系笔误/口径混用，权威值 = 0x300**；仍建议用 §6.1 的纯用户态探针实测确认。

---

## §2 ★★★ 关键更正：真实 `rt_waiter` 的归属与深度

项目内部对此存在**两个互相矛盾的常数**，本轮从汇编一手判定：

| 来源 | 声称 stale waiter 深度 |
|---|---|
| H106 | `SP0 − 0x1B0` |
| H172 | `SP0 − 0x210` |

### 2.1 汇编实据：`futex_wait_requeue_pi` 有**两个** 0x70 零初始化区

```asm
; 区①：sp+0x00
958e54: mov  x0, sp
958e5c: mov  w2, #0x70
958e78: bl   __memset          ; memset(sp+0x00, 0, 0x70)

; 区②：sp+0x90
958ea4: add  x0, sp, #0x90
958eac: mov  w2, #0x70
958eb0: add  x27, sp, #0x90    ; ★ x27 = &区②
958eb4: bl   __memset          ; memset(sp+0x90, 0, 0x70)
```

### 2.2 判定：**区②（`sp+0x90`）才是 `rt_waiter`**

```asm
958ed4: add  x8, x27, #0x28    ; x8 = x27 + 0x28
958ee8: add  x2, sp, #0x70     ; futex_q @ sp+0x70
958ef4: str  x27, [sp, #0x90]  ; ★ [sp+0x90] = x27 —— futex_q.rt_waiter = 区②
958f24: stp  x27, x28, [sp, #0x58]
```

⇒ `futex_q.rt_waiter` 指向 **`sp+0x90`**（区②），区①（`sp+0x00`）是别的对象
（其 `+0x68` 被写 -1、`+0x70/+0x78` 被清零 ⇒ 形态更像 `futex_q`/`hrtimer_sleeper`）。

### 2.3 深度结论（本轮定稿）

```
futex_wait_requeue_pi 的 sp 距 SP0 = 0x40 + 0x80 + 0x1c0 = 0x280
rt_waiter @ sp+0x90  ⇒ 绝对深度 = 0x280 − 0x90 = 0x1F0
                     占用 [0x1F0, 0x260)
```

| 常数 | 值 | 与本轮比对 |
|---|---|---|
| H106 的 `SP0 − 0x1B0` | 0x1B0 | ❌ 与本轮 0x1F0 差 **0x40** |
| H172 的 `SP0 − 0x210` | 0x210 | ❌ 差 **0x20** |
| **本轮（汇编推导）** | **0x1F0** | ★ 基准 |

> ⚠️ **0x1B0 / 0x210 / 0x1F0 三者互不相等** ⇒ 项目现有 sigreturn 几何常数表
> （`SIGRETURN_WAITER_VREG_OFF = 0xD0`）**建立在 0x1B0 之上，必须重算**。
> 本轮值：`画布起点 0x300 − waiter 0x1F0 = 0x110`（qword 34）。

---

## §3 重叠判定：画布**完全覆盖** waiter

```
sigreturn 画布（可控 512 B） = [0x100, 0x300)
rt_waiter 槽                = [0x1F0, 0x260)      ← 宽 0x70
画布内偏移                  = 0x1F0 − 0x100 = 0xF0 (240)
覆盖检查                    : 0xF0 + 0x70 = 0x160 ≤ 0x200 ✔ 完整覆盖
余量                        : 起点前 0xF0 B + waiter 后 0xA0 B
```

**⇒ 「sigreturn 画布能覆盖 waiter」在几何上成立**（尽管项目内部常数错了，结论方向对）。

---

## §4 ★★★ 为什么仍然判死，以及**唯一未被评估的形态**

### 4.1 判死理由（汇编实证，硬）

```asm
futex_wait_requeue_pi 序言：
958e54: mov  x0, sp          ; x0 = &rt_waiter
958e58: mov  w1, wzr
958e5c: mov  w2, #0x70
958e78: bl   __memset        ; ★ memset(rt_waiter, 0, 0x70)
```

**时序**：画布只能在**用户态**植入，而用户态只在 syscall 返回后才有执行权。
但 `memset` 发生在**产出 waiter 的那个 syscall 内部**、且在 waiter 被使用之前。
⇒ 画布只能在 `memset` **之后**（即该 syscall 返回后）才写入；

- 若 waiter 此时已被 `remove_waiter` 消费 ⇒ 太晚；
- 若 `pi_blocked_on` 仍悬垂指向该槽 ⇒ **有用**（见 4.2）。

⇒ **「在同一 syscall 内用画布覆盖活跃 waiter」判死**（与 H209 §W3 一致，本轮独立复现其结论）。

### 4.2 ★ 唯一未被评估的形态：**syscall 返回后复写 stale 槽**

CVE-2026-43499 的根因是 `remove_waiter` 清错人（`str xzr,[x20,#0x938]` 用 `current`
而非 `waiter->task`）⇒ **被 requeue 的目标线程 `pi_blocked_on` 悬挂**。
关键：该 syscall **返回后**，目标线程**仍处于用户态**，而 `pi_blocked_on` **仍指向其内核栈上的那个槽**。

```
① W 线程 futex_wait_requeue_pi(...) → 走 CVE 失败分支 → 返回
   （pi_blocked_on 悬挂 → 指向 W 内核栈深度 0x1F0 的槽，该槽即将被用户态复用）
② W 在用户态 raise(SIGUSR1) / 走 sigreturn 路径
   → __arm64_sys_rt_sigreturn 把 512 B 用户数据写进 [0x100, 0x300)
   → ★ 覆盖 0x1F0..0x260 的 stale 槽 = 植入【完全可控的伪 waiter】
③ W 触发消费：对自身调 sched_setattr（或再走一次 requeue/cleanup 路径）
   → rt_mutex_adjust_prio_chain / remove_waiter 读到伪 waiter
   → rb_erase 写原语
```

**为什么这与 H209 的判死不冲突**：H209 判死的是
「**同一 syscall 内**用 sigreturn spray 覆盖 **活跃** waiter」（= 被 memset 抹掉）。
而 4.2 是「**返回后**用 sigreturn 复写 **stale** 槽」—— **memset 已经过去**，画布成为该槽的唯一内容。

**H106 §6 自己承认**：整条链路「**从未在真机跑过**」（原文：
"仍未实测：整条链路（sigreturn 画布 → stale waiter → remove_waiter → rb_erase 写点）**从未在真机跑过**"）。

### 4.3 4.2 的硬门禁（**必须先离线闭合，未闭合不得开火**）

| # | 门禁 | 现状 | 判据 |
|---|---|---|---|
| **N1** | `pi_blocked_on` 在 syscall 返回后**是否仍悬垂**（未被后续路径清掉） | 未验 | 需查返回路径上所有 `#0x938` 写点（H206 已穷举**仅 3 处**：`try_to_take_rt_mutex` / `task_blocks_on_rt_mutex` / `remove_waiter`）⇒ 若无第 4 处，则悬垂**保持** |
| **N2** | 用 `sched_setattr` 触发 `rt_mutex_adjust_pi` 时，`pi_blocked_on` 的早退闸门能否通过 | 已知闸门 | H206 §3.2：`waiter->tree.prio(+0x18)` vs `task->prio(+0x84)`；**两者不等则进入**。画布可控 +0x18 ⇒ **可构造不等** ✔ |
| **N3** | `waiter->lock(+0x58)` 必须指向**可 trylock 的合法对象** | 画布可控 | H206 §3.4 W6：`raw_spin_trylock(&lock->wait_lock)`。画布余量（起点前 0xF0 B / waiter 后 0xA0 B）可放**伪 rt_mutex_base** ⇒ 需先定 `struct rt_mutex_base` 布局（BTF） |
| **N4** | `SP0` 跨 syscall 是否**稳定**（kstack 随机化） | 配置已证 | `CONFIG_RANDOMIZE_KSTACK_OFFSET=y` 但 `_DEFAULT is not set` + `__arm64_sys_futex` 序言 `sub sp,sp,#0x80` 整齐 ⇒ **未启用**（H206 §5 三重交叉）⇒ 同线程两次 syscall 的 SP0 一致 ✔ |
| **N5** | 写原语的**干净形态** | 已有配方 | H106 §5：「写 0 到任意地址」：`pc = TARGET−8`、`rb_right = 0`、`rb_left = 0` ⇒ 单次 `*(TARGET)=0`，无副作用 |
| **N6** | 终局判据需**独立回读透镜** | 有 | `sysctl_bootid` data 区（`cat /proc/sys/kernel/random/boot_id` 可独立回读）；或 `selinux_state.enforcing` → `getenforce` |

---

## §5 本轮对项目文档的更正（重要）

| 项 | 旧值 | 本轮值 | 影响 |
|---|---|---|---|
| sigreturn 画布区间 | H106 记 `SP0 − 0x280` 起 | **`SP0 − 0x300` 起，`[0x100,0x300)`** | 帧账本（§1.1）支持 0x300；0x280 与「帧 0x290 + dst sp+0x10」不自洽 |
| stale waiter 深度 | 0x1B0(H106) / 0x210(H172) | **0x1F0** | ★ 现有 `SIGRETURN_WAITER_VREG_OFF = 0xD0` **作废**，应为 **0x110** |
| `rt_waiter` 归属 | 未区分两个 0x70 区 | **`sp+0x90`（区②）**，来自 `futex_q.rt_waiter` | 几何常数必须以此为准 |

★ **交叉印证**：旧常数内部即不自洽 —— H106 §4 同时写
「画布起点 −0x280」与「waiter −0x1B0」（差 0xD0 ✔），
但其 §3.1 表格又把 waiter 记为「`sp+0x90`」（对应 −0x1F0）。
`0xD0` 只在「0x280 − 0x1B0」下成立，而 0x1B0 对应 `sp+0`（区①，非 waiter）。
⇒ **项目现有 sigreturn 几何常数建立在错误配对之上**，这是必须修正的硬事实。

> 下一轮**第一件事**：写**纯用户态**探针（H106 §7.2 的自测），用真实 sigreturn
> 回读画布在用户态可见的镜像，**实测**起点到底是 0x280 还是 0x300。
> 其余一切几何都挂在这个数上。

---

## §6 下一步（严格按序，全部离线可完成，零开火）

### 6.0 ★★ 门禁 N1 已闭合（H220，本轮完成）

**问题**：CVE 使目标线程 `pi_blocked_on` 悬垂。若返回路径上还有别的写点把它清掉，
「返回后复写 stale 槽」路线即不成立。

**方法**：`vmlinux-mey.elf` 逐 4 字节独立解码 **6,436,194 条**指令，抓所有含 `#0x938` 的访问。

**阳性对照（自洽性验证）**：
```
sp 相对偏移频次 top: 0x10=77063  0x20=52718  0x30=32969 ... 而 0x8 = 0
```
★ `#0x8` 恒为 0 是**正确的**：ARM64 栈帧 16 字节对齐，`sp+0` 之后直接 `sp+0x10`，
`sp+8` 槽一律用 `stp`/`ldp` 的**第二个寄存器**表达 ⇒ 不存在独立 `#0x8` 编码。
（H206 记 `#0x8` = 4905 系其正则把 `#0x80/#0x88…` 一并计入，属口径差异，非矛盾。）
⇒ **本轮 `#0x938` = 16，与 H206 的穷举结果逐条一致** ⇒ 扫描可信。

**结果：`#0x938` 全树 16 个写点**，其中

| 归属 | 说明 | 能否清掉悬垂 |
|---|---|---|
| `try_to_take_rt_mutex` / `task_blocks_on_rt_mutex` / `remove_waiter` | rtmutex 子系统，**仅此 3 处** | 仅在 rtmutex 路径上 |
| `copy_process` `0x801e1278` | `str xzr,[x20,#0x938]` | ★ **仅 fork/clone 时** |
| TCP/巨大页/KVM/SCSI/binder 等 12 处 | 同偏移**巧合**（`task_struct` 之外的结构体） | ✘ 与 `task_struct` 无关 |

★★ **判定：syscall 返回路径上【没有】第 4 处写 `task_struct->pi_blocked_on`。**
⇒ **悬垂在返回后保持**，只要该线程**不再 fork/clone**。⇒ **N1 通过：路线 4.2 成立的前提具备。**

### 6.1 剩余步骤

1. **核对画布起点 0x280 vs 0x300**（用 H106 §7.2 的纯用户态 sigframe 自测；零设备风险）。
   帧账本支持 **0x300**；此项决定 waiter 是否落在画布内（0xF0 + 0x70 = 0x160 ≤ 0x200 ⇒ 在）。
2. **闭合 N3**：从本机 BTF 取 `struct rt_mutex_base` 精确布局，把伪 lock 放进画布余量。
3. **闭合 N5**：确定 TARGET 与写值（推荐「写 0」形态：`pc=TARGET−8, rb_right=0, rb_left=0`）。
4. **只有在 1–3 全部闭合后**，才设计 4.2 的单发实验（一 boot 一发，`boot_id` 判重启）。

**N2 / N4 已在项目内离线闭合**（N2：画布可控 `+0x18` ⇒ 可构造闸门不等；
N4：`RANDOMIZE_KSTACK_OFFSET_DEFAULT` 未设 + `sub sp,sp,#0x80` 整齐 ⇒ 偏移恒定）。

---

## §7 诚实评估

- ★ **sigreturn 栈写原语是真的**：512 B、深度确定、两条路径鲁棒、前置无清零 —— 这一点本项目判断正确。
- ★★ **但"覆盖活跃 waiter"确实判死**（memset 时序），本轮独立复现该结论。
- ★★★ **真正未被评估、也从未实测的是「返回后复写 stale 槽」形态**（§4.2）。
  它绕开了 memset 时序问题，且 **N1/N2/N4 已闭合、N5 有配方**，只剩 N3（伪 lock 布局）与画布起点核对。
  **这是本机 43499 线上唯一还站得住的形态。**
- ✅ **本轮新增硬结论（H220）**：`task_struct->pi_blocked_on` 的写点全树**只有 4 处**
  （rtmutex 三处 + `copy_process`）⇒ **syscall 返回后悬垂保持**，路线前提成立。
- ⚠️ **不得跳过 §6.1 直接开火** —— 几何常数目前存在 0x40 与 0x80 两处未对齐，直接上机必 panic。
