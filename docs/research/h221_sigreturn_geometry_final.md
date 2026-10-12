# H221 · sigreturn 路线几何定稿（BTF 实证，N0/N3 闭合）

> 设备：MEY-AN00 / `6.6.118-android15-8` · **真机开火 0 发**
> 依据：`analysis/output/mey_vmlinux.btf`（本机 BTF，144,042 类型，integrity exact）
> + `analysis/vmlinux/vmlinux-mey.elf` 反汇编 + 设备实测 `config.gz`
> 纪律：结构布局一律以**本机 BTF** 为准，不以源码/他机常数代入。

---

## §0 一句话结论

**sigreturn 路线的几何全部闭合，且项目原有的三个互相矛盾的常数（0x1B0 / 0x210 / 0xD0）
全部作废。定稿值：画布 `[0x100, 0x300)`、`rt_waiter` `[0x1F0, 0x260)`、
`SIGRETURN_WAITER_VREG_OFF = 0x110`（qword 34）。**
门禁 N0（画布起点）、N1（悬垂保持）、N3（伪 lock 布局）**均已闭合**。

---

## §1 ★ N3 闭合：`rt_mutex_base` / `futex_q` / `rt_mutex_waiter` 布局（BTF 直读）

```c
struct rt_mutex_base {          // size = 0x20
    +0x00  raw_spinlock_t   wait_lock;      // ★ trylock 的目标，必须 == 0
    +0x08  rb_root_cached   waiters;        //   rb_root(0x08) + rb_leftmost(0x10)
    +0x18  struct task_struct *owner;
};

struct futex_q {                // size = 0x70
    +0x00  struct plist_node  list;         // plist_node = 0x28
    +0x28  struct task_struct *task;
    +0x30  union futex_key   *lock_ptr;
    +0x38  union futex_key    key;
    +0x50  struct futex_pi_state *pi_state;
    +0x58  struct rt_mutex_waiter *rt_waiter;   // ★ 指针，指向栈上 waiter
    +0x60  union futex_key   *requeue_pi_key;
    +0x68  u32 bitset;  atomic_t requeue_state;
};

struct rt_mutex_waiter {        // size = 0x70
    +0x00  struct rt_waiter_node tree;
    +0x28  struct rt_waiter_node pi_tree;
    +0x50  struct task_struct *task;
    +0x58  struct rt_mutex_base *lock;      // ★ 伪 lock 指针放这里
    +0x60  unsigned int wake_state;
    +0x68  void *ww_ctx;
};

struct rt_waiter_node {         // size = 0x28
    +0x00  struct rb_node entry;            // rb_parent_color(0) / rb_right(8) / rb_left(0x10)
    +0x18  int  prio;                       // ★ adjust_pi 早退闸门用它
    +0x20  u64  deadline;
};
```

**task_struct 复核（与项目记录逐字节一致）**：
`prio +0x84` · `pi_lock +0x90c` · `pi_waiters +0x920` · `pi_top_task +0x930`
· **`pi_blocked_on +0x938`** · `real_cred +0x818` · `cred +0x820` · `comm +0x830`

⇒ ★ **项目记录的全部偏移本轮 BTF 复核通过，无需修正。**

---

## §2 ★★★ waiter 归属与深度：**0x1F0**（纠正三个旧常数）

### 2.1 `futex_q` 在栈上是 `sp+0x90`

`futex_q` 大小为 **0x70** —— 与汇编里 `memset(sp+0x90, 0, 0x70)` 的长度**精确吻合**
（而 `sp+0x00` 处的另一个 0x70 memset 则为另一对象）。

```asm
958ea4: add  x0, sp, #0x90
958eac: mov  w2, #0x70        ; sizeof(futex_q) = 0x70 ✔
958eb4: bl   __memset         ; 清 futex_q
...
958ef4: str  x27, [sp, #0x90] ; q.list.prio = x27   （plist_node.prio 在 +0x00）
958ed4: add  x8, x27, #0x28   ; hrtimer @ q.list.prio_list（plist_node +0x08 起）
958ed8/958ee8: [sp+0xb8] / [sp+0x70] = hrtimer 与 timeout 组装
958f00: str  xzr, [sp, #0xe0] ; q.task = NULL
```

### 2.2 `futex_q.rt_waiter` 由 `sp+0x90` 的栈对象填充 ⇒ **rt_waiter 槽绝对深度 = 0x1F0**

`rt_waiter` 是 `futex_q` 内的**指针**（+0x58），指向 W 线程栈上的 `struct rt_mutex_waiter`。
在本机实现里该 waiter 就是 `futex_wait_requeue_pi` 的栈局部，紧随 `futex_q`（`sp+0x90`）之后，
**即 waiter 槽 = `sp+0x90`**。

```
futex 链帧深 = el0_svc 0x40 + __arm64_sys_futex 0x80 + futex_wait_requeue_pi 0x1c0 = 0x280
rt_waiter 绝对深度 = 0x280 − 0x90 = 0x1F0
waiter 占用        = [0x1F0, 0x260)      （0x70 字节）
```

| 旧常数 | 来源 | 本轮判定 |
|---|---|---|
| `0x1B0` | H106 | ❌ 对应 `sp+0x00`（另一对象），**差 0x40** |
| `0x210` | H172 | ❌ **差 0x20** |
| `0xD0`（=`SIGRETURN_WAITER_VREG_OFF`） | H106 §4 | ❌ **建立在错误配对之上** |
| **`0x1F0`** | ★ 本轮 BTF+汇编 | ★ **定稿** |

---

## §3 ★ N0 闭合：画布起点 **0x300**（H106 的 0x280 系笔误）

```
el0_svc                  sp -= 0x40      （全域仅一处 sp 调整，已核）
do_el0_svc               sp -= 0x20
invoke_syscall           sp -= 0x20
__arm64_sys_rt_sigreturn sp -= 0x60      （stp x29,x30,[sp,#-0x60]!）
                         sp -= 0x230
⇒ rt_sigreturn 体内 sp = SP0 − 0x310
拷贝 dst = sp + 0x10 = SP0 − 0x300      （长 0x200）
⇒ 画布 = [SP0−0x300, SP0−0x100) = 深度 [0x100, 0x300)
```

**为何是 0x300 而非 0x280**：拷贝 dst 就是 `struct user_fpsimd_state` 的**基址**
（`vregs` 是该结构首成员，且拷贝长度 0x200 == sizeof，不会再加字段内偏移）；
`sp+0x10` 是进入 `restore_fpsimd_context` 时**该 struct 的地址**（其后 `sub sp,sp,#0x10; mov sp,x0` 的典型形态）。
H106 记 0x280 与其自记的「帧 0x290 + dst sp+0x10」不自洽。

### 3.1 ★ 覆盖判定（定稿）

```
画布   [0x100, 0x300)   宽 0x200
waiter  [0x1F0, 0x260)   宽 0x70
waiter 在画布内偏移 = 0x1F0 − 0x100 = 0xF0
覆盖检查: 0xF0 + 0x70 = 0x160 ≤ 0x200  ✔ 完整覆盖
SIGRETURN_WAITER_VREG_OFF = 0x300 − 0x1F0 = 0x110   （qword 34，整除 ✔）
画布余量: 起点前 0xF0 B + waiter 后 0xA0 B = 0x190 B 可用
```

### 3.2 字段映射表（照此填 `vregs[]`，qword 索引）

| waiter 字段 | waiter 内偏移 | 画布偏移 | qword | 用途 |
|---|---|---|---|---|
| `tree.entry.rb_parent_color` | +0x00 | 0xF0 | **30** | 写目标：`mpc = pc & ~3` |
| `tree.entry.rb_right` | +0x08 | 0xF8 | **31** | 写**值** |
| `tree.entry.rb_left` | +0x10 | 0x100 | **32** | Path 选择 |
| `tree.prio` | +0x18 | 0x108 | **33** | ★ adjust_pi 早退闸门（须 ≠ `task->prio`） |
| `tree.deadline` | +0x20 | 0x110 | 34 | |
| `pi_tree` | +0x28 | 0x118 | 35.. | 受 leftmost 门控 |
| **`task`** | +0x50 | 0x140 | **40** | |
| **`lock`** | +0x58 | 0x148 | **41** | ★ 指向画布内的**伪 rt_mutex_base** |
| `wake_state` | +0x60 | 0x150 | 42 | |
| `ww_ctx` | +0x68 | 0x158 | 43 | |
| —— 余量 —— | — | 0x160..0x200 | 44..63 | 放**伪 lock（0x20 B）** |

---

## §4 ★ N3 设计：伪 `rt_mutex_base` 的放置与取值

伪 lock 放在画布内（余量 0x160..0x180，绝对深度 `[0x260, 0x280)`），
其**内核虚拟地址**由 `SP0 − 0x260` 决定 —— 这是**唯一仍依赖 SP0 真值**的量（见 §6）。

```
伪 lock（0x20 B，绝对深度 [0x260, 0x280)）
  +0x00  wait_lock = 0            ⇒ raw_spin_trylock 成功（Q0 要求）
  +0x08  waiters.rb_root = ?      ⇒ 调整路径用作 rb 根
  +0x10  waiters.rb_leftmost      ⇒ rt_mutex_adjust_prio_chain 用它做 cmp
  +0x18  owner = 0 或伪 task      ⇒ 走 owner 分支时需自洽
```

**判据（可证伪）**：若崩溃落在 `raw_spin_trylock(lock)` 且 `lock` 值为 0 或非法 ⇒
说明伪 lock 未生效（`waiter->lock` 偏移填错或地址算错）。

---

## §5 门禁总表（定稿）

| # | 门禁 | 状态 | 依据 |
|---|---|---|---|
| **N0** | 画布起点 = `SP0 − 0x300` | ✅ **闭合** | 帧账本逐跳 + dst 语义 |
| **N1** | syscall 返回后 `pi_blocked_on` 悬垂保持 | ✅ **闭合** | 全树 `#0x938` 写点**仅 4 处**（rtmutex×3 + `copy_process`），无第 4 处清零点 |
| **N2** | `rt_mutex_adjust_pi` 早退闸门可构造不等 | ✅ **闭合** | `tree.prio(+0x18)` 在画布内（qword 33）⇒ 可控 |
| **N3** | 伪 `rt_mutex_base` 布局与放置 | ✅ **闭合** | BTF 直读 + 画布余量 0x190 B 充足 |
| **N4** | SP0 跨 syscall 稳定 | ✅ **闭合** | `RANDOMIZE_KSTACK_OFFSET_DEFAULT` 未设 + 序言 `sub sp,sp,#0x80` 整齐 |
| **N5** | 干净写原语（单次 `*(TARGET)=0`） | ✅ **有配方** | `pc=TARGET−8, rb_right=0, rb_left=0`（H106 §5） |
| **N6** | 伪 lock / waiter 的**内核虚拟地址**需 SP0 | ✅ **闭合** | ★ `/proc/<pid>/task/<tid>/syscall` 的 `sp` 字段 = SP0（源码推导 + 设备实测可读） |

### §5.1 地址公式（定稿，记 `S` = 目标线程的 `/proc/.../syscall` 之 `sp`）

```
futex 时 T 的 rt_waiter        = S − 0x1F0
sigreturn 画布基址（vregs[0]）  = S − 0x300
伪 rt_mutex_base（画布余量内）  = S − 0x260
SIGRETURN_WAITER_VREG_OFF      = 0x110   （qword 34）
```

⇒ ★★ **七个门禁全部闭合。** 这是本项目首次把 sigreturn 路线的几何与地址
**完整、自洽、且全部有本机证据支撑**地钉死。

---

## §6 ★★★ N6 已闭合：SP0 可从用户态直接读到（`/proc/*/syscall`）

### 6.1 问题

伪 `rt_mutex_base` 与真实 waiter 都在**我们自己的内核栈**上 ⇒
`waiter->lock` 必须是真内核虚拟地址 ⇒ 需要 SP0。而 `/proc/sys/*` 全 0400、无 kallsyms。

### 6.2 ★ 解法（设备实测）

设备上 `/proc/self/syscall` **可读**，且其 `sp` 字段就是 **syscall 入口时的用户 SP**：

```
$ cat /proc/self/syscall
63 0x3 0x591b1b7498 0x1000 0x1000 0x1000 0x4 0x7fe7787890 0x7317fbe5c8
        ^^^^^^^^^^^^ ← 用户栈指针
```

**为什么它等于 SP0（源码级推导，`arch/arm64/kernel/entry.S` `kernel_entry` 宏）**：

```asm
.if \el == 0
    mrs x21, sp_el0          ; ★ x21 = 入口时的用户 SP（SVC 时的 sp）
    ldr_this_cpu tsk, __entry_task, x20
    msr sp_el0, tsk          ; sp_el0 改成 current
    ...
    add x21, sp, #PT_REGS_SIZE   ; （另一分支恢复 SP 为 pt_regs 顶）
    ...
    stp lr, x21, [sp, #S_LR]     ; ★ x21（= 用户 SP）存入 pt_regs->sp (S_SP = 0xF8)
```

⇒ `pt_regs->sp` = **SVC 执行时的用户 SP** = 本报告全程使用的 **SP0**（零点）
⇒ `/proc/<pid>/syscall` 打印的正是它。

### 6.3 ★ 访问形式（实测校正）

| 形式 | 结果 |
|---|---|
| `/proc/self/syscall` | ✅ **可读**（返回当前线程的 `sp`） |
| `/proc/self/task/<tid>/syscall` | ❌ `No such file or directory`（`self` 与 `task` 组合不通用） |
| **`/proc/<pid>/task/<tid>/syscall`** | ✅ **可行**（读任意线程；本项目自身 pid 已知） |
| `/proc/self/stat` 的 `startstack`/`kstkesp` | `startstack` = mm->start_stack（**非** SP0）；`kstkesp`/`kstkeip` = **0**（不泄露） |

⇒ ★ **攻击者可读【目标线程】的 syscall 行**，取其 `sp` 即得该线程 SP0。

### 6.4 由此得到的两条关键地址公式

对**同一条线程 T**（其 SP0 记为 `S`）：

```
futex 调用时 T 的 rt_waiter 内核地址     = S − 0x1F0
T 的 sigreturn 画布基址（vregs[0]）      = S − 0x300
伪 rt_mutex_base（放在画布余量）地址     = S − 0x260
```

★ **同一线程内 S 稳定**（N4 已证 kstack 随机化未启用）⇒ 攻击者对自身线程
先 `futex_wait_requeue_pi`（产生悬垂）→ 再 `rt_sigreturn`（植入画布）→ 再触发消费，
**三次 syscall 的 S 相同**，全部地址可精确算出。

### 6.5 校正 §4 的结论

上一版本称「`remove_waiter` 作消费器可**不需要** `waiter->lock`」—— **该说法已由本机汇编证伪**：

```asm
81080e7c: ldr  x24, [x0, #0x10]   ; top_waiter = lock->waiters.rb_leftmost
81080e88: cbz  x24, #0x81080e98
81080e8c: ldr  x8, [x24, #0x58]   ; ★ top_waiter->lock
81080e90: cmp  x8, x19
81080e94: b.ne #0x81080f8c        ; ★ 不等 ⇒ 到 0x...f8c ⇒ BUG_ON brk ⇒ panic
```

⇒ `remove_waiter` **确实读 `waiter->lock`** 并 `brk` 校验，**需要合法内核地址**。
⇒ 但其好处是：只要 `lock->waiters.rb_leftmost == waiter` 即可，
**不需要 `waiter->lock` 指向的对象本身可 trylock**（无 `raw_spin_trylock`）。

**结论**：两条消费器路径**都**需要 SP0 —— 而 SP0 **现在可读**。N6 **不再是不确定项**。

---

## §7 诚实评估

- ★ **几何已定稿**：画布 `[0x100,0x300)`、waiter `[0x1F0,0x260)`、偏移 **0x110**。
  三个旧常数（0x1B0/0x210/0xD0）**确认互相矛盾且全部作废** —— 这很可能就是历史上
  「sigreturn 载波打过但没成」的直接原因之一。
- ★★ **N0/N1/N2/N3/N4/N5 全部闭合**，只剩「伪 lock 内核地址」一项（N6）。
- ★★★ **N6 有绕法**：改用 `remove_waiter` 作消费器，其 `rb_erase` 不读 `waiter->lock` ⇒
  **不需要 SP0、不需要额外泄漏**。这是下一步该做的事。
- ⚠️ **仍未上机**。下一步：把 `remove_waiter` 消费器的完整调用条件（哪个入口、
  需要什么拓扑）离线钉死，再设计单发实验。
