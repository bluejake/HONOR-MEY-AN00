# H108 · L3 主攻「EL1 落点」：`do_notify_resume` 关闸前窗口解剖

> 生成时间：2026-10-05 11:45
> 规程依据：`MEY-AN00-exploit-prompt.md` §三 五阶段（**本环 = 阶段二 分析**）+ §一 未解矛盾
> 前置：H107 环② 已闭合、L3 专项门禁已通过，进入 §一「EL1 落点」唯一技术难关
> 镜像：`analysis/scratch/Image-mey`（裸 arm64 Image，基址 `0xffffffc080000000`）
> 符号：`analysis/output/kallsyms_mey_an00.txt`（110,992 行，外部独立 kallsyms）
> 工具：capstone 5.0.7（`skipdata=True`）+ **原始 BL 位域扫描**（4 字节对齐，`100101` 前缀）

---

## 0. 结论（一句话）

**`do_notify_resume+0x260` 不是「内核侧被动关闸」，而是 `do_signal → handle_signal → signal.c:1197` 的 `ret |= !valid_user_regs()`。** 它位于**信号投递路径**（`setup_rt_frame` 之后、`signal_setup_done` 之前），**只在有信号投递时执行**，不是「每次内核→用户态返回都过」。

**⇒ H107 §4.3 的战略指认方向需修正：`do_notify_resume+0x260` 与 `rt_sigreturn+0x3d4` 是同一个关闸的两次出现（投递侧 / 恢复侧），二者同源同锁。** 全镜像 6 个 `valid_user_regs` 调用点里，**没有任何一个是「不经过信号路径、能被 exploit 独立触发的 pt_regs 改写后内核态落点」**。

**本轮同时收获一条更重要的东西**：`setup_return` 的 `regs->pc = ka->sa.sa_handler` 写入**发生在 `valid_user_regs` 之前**，且 `handle_signal` 的 `err` 累加语义（`ret |= !valid_user_regs`）**决定了即使 `valid_user_regs` 返回 0，`regs->pc` 也已经被写成了 `sa_handler`**。这条时序差是 SROP 路线的**唯一实质可利用面**（见 §4）。

---

## 1. 「6 个调用点」到「函数归属」的完整映射（本轮新产出）

用**原始 BL 位域扫描**（`w>>26 == 0b100101`，直接 4 字节对齐遍历全镜像，不经 capstone）复核 H107 的 6 调用点：

```
valid_user_regs @ 0xffffffc080445248   调用点 = 6（与 H107 逐位一致 ✓）
  0xffffffc08049b6b8   → __arm64_sys_rt_sigreturn+0x3d4   ← 恢复侧（SROP 本身）
  0xffffffc08049c7d0   → do_notify_resume+0x260           ← 投递侧 ★ 本轮解剖对象
  0xffffffc0808d08b8   → compat_gpr_set+...               ← compat ptrace（不适用）
  0xffffffc0808d0eb4   → compat_arch_ptrace+...           ← compat ptrace（不适用）
  0xffffffc0808d220c   → gpr_set+0x98                     ← ptrace 写 GPR（需 ATTACH）
  0xffffffc0808d7d40   → compat_restore_sigframe+...      ← compat 信号帧（不适用）
```

**⇒ 对 64 位进程（本机 exploit 场景），实际真闸点收敛为 3 个**：
`__arm64_sys_rt_sigreturn+0x3d4`（恢复侧）｜**`do_notify_resume+0x260`（投递侧）**｜`gpr_set+0x98`（ptrace）。

**H107 §4.3 的表述修正**：`do_notify_resume+0x260` **不是「唯一内核侧被动关闸」**。它是 `do_signal()` 内联体里的关闸，**只在 `_TIF_SIGPENDING|_TIF_NOTIFY_SIGNAL` 置位时才有信号可投递**（`signal.c:1306-1307`）—— 即**有信号 → 走 `do_signal` → `handle_signal` → 关闸**；无信号 → 直接跳过（`do_notify_resume` 里 `do_signal` 的调用本身受 flag 门控）。

---

## 2. `do_notify_resume` 的反汇编剖面（0x49c570..0x49cd00，全函数）

**★ 关键发现：`do_signal` / `handle_signal` / `setup_rt_frame` / `setup_return` 四个 `static` 函数全部被内联进 `do_notify_resume`** ⇒ 符号表只显示 `do_notify_resume`，但函数体包含了整条信号投递链。

### 2.1 `do_signal` 入口与 syscall restart 处理（`+0x15c`..`+0x1c4`）

```
0x49c6cc  str   wzr, [sp, #0x20]        ; ← do_signal 局部（restart 状态）
0x49c6d0  msr   daif, x24
0x49c6d4  bl    schedule                ; (另一分支)
0x49c6d8  b     0x49d264
...
0x49c648  ldr   w8, [x19, #0x118]       ; x19 = regs (pt_regs*)
0x49c64c  cmn   w8, #1                  ; regs->orig_x0 == -1? (forget_syscall 标记)
0x49c650  b.eq  0x49c6dc
0x49c654  ldp   x21, x8, [x19, #0x100]  ; x21 = regs->pc, x8 = regs->pstate
0x49c65c  ldr   w22, [x19]              ; w22 = regs->regs[0] (syscall retval)
0x49c67c  str   w9, [x19, #0x118]       ; forget_syscall(regs): orig_x0 = -1
0x49c690  str   x23, [x19, #0x100]      ; ★ regs->pc = restart_addr   ← do_signal 的 syscall restart
0x49c694  str   x8, [x19]               ; regs->regs[0] = orig_x0
```
✅ 与 `signal.c:1212-1247` 逐条对应（`syscall`/`continue_addr`/`restart_addr`/`forget_syscall`）。

### 2.2 `get_signal` 与 `handle_signal` 分派（`+0x1c8`..`+0x260`）

```
0x49c698  sub   x0, x29, #0x68          ; &ksig
0x49c69c  bl    get_signal              ; ← signal.c:1247 if (get_signal(&ksig))
0x49c6a0  tbnz  w0, #0, 0x49c6f4        ; 有信号 → 进 handle_signal
0x49c6a4  ldr   x8, [x19, #0x100]       ; regs->pc
0x49c6a8  cmp   x8, x23                 ; == restart_addr?
0x49c6ac  b.ne  0x49d218
...
0x49c6f4  ldr   x8, [x19, #0x100]       ; ★ handle_signal 入口
0x49c6f8  cmp   x8, x23
0x49c6fc  b.ne  0x49c73c
0x49c700  and   w8, w22, #0xfffffffd    ; 源码 retval 判定
0x49c704  cmn   w8, #0x204
0x49c708  b.ne  0x49c72c
0x49c70c  ldr   x8, [x20]               ; x20 = task_struct*
0x49c714  str   x21, [x19, #0x100]      ; ★ regs->pc = continue_addr
0x49c724  str   x8, [x19]               ; syscall_set_return_value(-EINTR)
...
0x49c744  add   x24, x20, #0x888        ; x24 = &task->... (sa 相关)
0x49c748  ldursw x22, [x29, #-0x18]     ; usig
0x49c754  bl    fpsimd_signal_preserve_current_state   ; ← setup_rt_frame:1139
0x49c758  add   x0, sp, #0x30           ; &user (rt_sigframe_user_layout)
0x49c764  bl    memset
0x49c770  add   x0, sp, #0x30
0x49c778  stp   x9, x8, [sp, #0x40]
0x49c77c  bl    setup_sigframe_layout   ; ← setup_rt_frame:1141 get_sigframe
0x49c780  cbz   w0, 0x49c7f8            ; err==0 → 继续
0x49c784  mov   w25, #1                 ; err = 1
0x49c788  mov   w28, #4
0x49c78c  b     0x49c7c8
```
```
0x49c790  ldurb w8, [x29, #-0x60]
0x49c794  tbnz  w8, #2, 0x49c7b0        ; is_compat_task? (signal.c:1185)
0x49c798  sub   x1, x29, #0x68          ; (native: setup_rt_frame)
0x49c79c  mov   w0, w22                 ; usig
0x49c7a0  mov   x2, x24                 ; set
0x49c7a4  mov   x3, x19                 ; ★ regs
0x49c7a8  bl    compat_setup_frame      ; ★ (native 分支实际是 setup_rt_frame 内联，见下)
0x49c7ac  b     0x49c7c4
0x49c7b0  sub   x1, x29, #0x68
0x49c7b4  mov   w0, w22
0x49c7b8  mov   x2, x24
0x49c7bc  mov   x3, x19
0x49c7c0  bl    compat_setup_rt_frame   ; ★ SA_SIGINFO 分支
0x49c7c4  mov   w25, w0                 ; ret = setup_rt_frame(...)
```

**⚠️ 注意 `0x49c7a8` 的目标是 `compat_setup_frame+0x0`、`0x49c7c0` 是 `compat_setup_rt_frame+0x0`** —— 这说明此处**不是 muxing 的两个分支**，而是**两个分支各自跳进 compat 实现**（`is_compat_task()` 为真时）。**native 进程走的是内联的 `setup_rt_frame`，其 `setup_return` 也在上游更早处内联**（见 §3）。

### 2.3 ★ `valid_user_regs` 调用（`+0x260`）与 `signal_setup_done`（`+0x27c`）

```
0x49c7c8  mov   x0, x19                 ; ★ x0 = regs (pt_regs*)  —— 注意与 rt_sigreturn 一致
0x49c7cc  mov   x1, x20                 ; x1 = task
0x49c7d0  bl    valid_user_regs         ; ★★ signal.c:1197  ret |= !valid_user_regs(&regs->user_regs, current)
0x49c7d4  ldr   x8, [x20]
0x49c7d8  cmp   w0, #0
0x49c7e0  cset  w9, eq                  ; (ret==0)
0x49c7e4  ubfx  w2, w8, #0x15, #1       ; test_thread_flag(TIF_SINGLESTEP)
0x49c7e8  orr   w0, w25, w9              ; ★ ret |= !valid_user_regs(...)
0x49c7ec  bl    signal_setup_done        ; ← signal.c:1200
```

**⇒ 与源码 `signal.c:1194-1200` 逐条一致**：
```c
ret |= !valid_user_regs(&regs->user_regs, current);   /* :1197 */
signal_setup_done(ret, ksig, test_thread_flag(TIF_SINGLESTEP)); /* :1200 */
```

**⇒ 关键语义差（与 `rt_sigreturn` 的对比）**：

| | `rt_sigreturn`（`0x49b6b8`） | `do_notify_resume`（`0x49c7d0`） |
|---|---|---|
| 源码位置 | `restore_sigframe`（`signal.c:794`） | `handle_signal`（`signal.c:1197`） |
| `valid_user_regs` 返回 0 时 | `err=1` ⇒ **`badframe`，`regs` 全不恢复** | `ret=1` ⇒ **`signal_setup_done(1,...)`，但 `regs->pc` 已被 `setup_return` 写成 `sa_handler`** |
| 用户可控面 | `sigframe` 全量字段 | **`sa_handler`（通过 `sigaction` 自设）+ `pstate` 被洗** |
| 是否可被用户态直接触发 | ✅ 自己执行 `rt_sigreturn` | ✅ **自己给自己发信号**（`kill(getpid(), sig)`） |

---

## 3. `setup_return` 的内联位置与 `regs->pc` 写入时序（★ 本轮最关键）

`setup_return`（`signal.c:1076-1130`）**在 `setup_rt_frame` 内部被内联**，而 `setup_rt_frame` 又被内联进 `handle_signal`/`do_notify_resume`。因此 `regs->pc = ka->sa.sa_handler` 的写入**在 `do_notify_resume` 函数体内**，但被优化拆分到多个位置。

**源码关键点**：
```c
static void setup_return(regs, ka, user, usig) {
	regs->regs[0] = usig;                         /* :1081 */
	regs->sp = (unsigned long)user->sigframe;     /* :1082  ← sp 改为内核构造的新帧 */
	regs->regs[29] = (unsigned long)&user->next_frame->fp;
	regs->pc = (unsigned long)ka->sa.sa_handler;  /* :1084  ★★ 用户可通过 sigaction 完全控制 */
	...
	regs->regs[30] = sigtramp;                    /* :1129 */
}
```

**`regs->pc` 写入点（本轮在 `do_notify_resume` 范围内扫描到的两处 `str xN,[x19,#0x100]`）**：
```
0x49c690  str   x23, [x19, #0x100]      ; ← do_signal 的 syscall restart（regs->pc = restart_addr）
0x49c714  str   x21, [x19, #0x100]      ; ← do_signal 的 -ERESTART 回滚（regs->pc = continue_addr）
```
**⚠️ 这两处都是 `do_signal` 的 syscall-restart 逻辑，不是 `setup_return`。** `setup_return` 的 `regs->pc = sa_handler` 写入点在**更下游**（`setup_rt_frame` 的 `setup_sigframe` 成功分支之后），本轮未在 `0x49c570..0x49c7f4` 窗口内捕获到该 `str`，说明它位于 `0x49c7f8` 之后的分支（`cbz w0, 0x49c7f8` 的 `err==0` 路径）。

### 3.1 时序结论（可证伪判据）

**判据**：`setup_return` 的 `regs->pc = sa_handler` 必须**先于** `signal.c:1197` 的 `valid_user_regs` 执行（因为源码顺序是 `setup_rt_frame`(含 setup_return) → `ret |= !valid_user_regs`）。

**⇒ 若该时序成立，则应观测到**：在 `0x49c7d0 bl valid_user_regs` **之前**已有一条向 `[x19,#0x100]`（或通过其他基址寄存器）写 `sa_handler` 的 `str`。

**本轮观测**：`0x49c7a8`/`0x49c7c0` 之后、`0x49c7d0` 之前**只有 `mov w25,w0`**。⇒ **native 路径的 `setup_rt_frame` 是内联体，它的 `regs->pc` 写入点必须由 `0x49c7a8` 这个 `bl` 的**调用方**（即 `handle_signal`）之外的路径完成**，或 `0x49c7a8` 的符号归属需重查。

**⚠️ 本轮发现的矛盾（待下轮解）**：`0x49c7a8` 反查符号 = `compat_setup_frame+0x0`，但源码 `signal.c:1185` 的 `is_compat_task()` **为假**时应走 `setup_rt_frame`（非 compat）。⇒ **两种可能**：
1. **`0x49c7a8` 的 `bl` 目标确实是 compat 版** —— 说明这段是 **compat 分支的内联**，而 native 分支在另一个位置（本窗口未覆盖）；
2. 符号表把 native `setup_rt_frame` 与 compat 版合并/重叠 —— 需按 `0x49c7f8` 之后的分支重 dump。

**⇒ 下轮第一步：从 `0x49c7f8`（`cbz w0` 的 err==0 目标）开始 dump，追到 `signal_setup_done` 之前，定位 native `setup_return` 的 `regs->pc` 写入点。**

---

## 4. ★★★ 战略结论：6 个闸点无一可用 ⇒ EL1 落点必须换思路

### 4.1 6 个调用点的性质归类

| 调用点 | 路径 | 用户态可触发？ | 能否作为「pt_regs 改写后走内核态」的落点 |
|---|---|---|---|
| `rt_sigreturn+0x3d4` | 信号恢复 | ✅ | ❌ 返回 0 = badframe；返回 1 = EL0t（双向死锁） |
| `do_notify_resume+0x260` | 信号投递 | ✅（自发信号） | ❌ **同上双向死锁**（同一个 `valid_native_regs`，同锁） |
| `gpr_set+0x98` | ptrace | 需 ATTACH | ❌ 同锁；且 ptrace 需同 uid 或被调试权限 |
| `compat_*` ×3 | compat | ❌（本机 64 位进程） | 不适用 |

**⇒ 结论：`valid_user_regs` 是 SROP 路径上的「统一总闸」，无论从投递侧还是恢复侧进入，都被同一把 `valid_native_regs` 锁死。** **「找一条不经过 `valid_user_regs` 的 `pt_regs` 改写路径」在信号/ptrace 域内无解。**

### 4.2 唯一残留可利用面：`handle_signal` 的 `ret |=` 语义差

**★ 这是本轮最重要的正面发现。** 与 `rt_sigreturn` 的 `err |=` → `badframe`（**全盘中止**）不同，`handle_signal` 的 `ret |= !valid_user_regs(...)` **不中止流程**：
```c
ret |= !valid_user_regs(&regs->user_regs, current);   /* ret = 0|1 = 1 */
signal_setup_done(ret, ksig, ...);                    /* ret=1 ⇒ force_sigsegv? */
```
`signal_setup_done(ret, ...)`（`signal.c:1200` → `signal.c` 内实现）在 `ret != 0` 时会 `force_sigsegv(SIGSEGV)` **并重置 `regs` 到初始状态**（`signal.c` 的 `signal_setup_done` 内 `if (failed) force_sigsegv(SIGSEGV); else ...`）——**需下轮核实本机实现**。

**⇒ 若 `signal_setup_done(1,...)` 只是 `force_sigsegv` 而不立即崩溃，则存在一个窗口**：`regs->pc` 已被 `setup_return` 写成 `sa_handler`，`regs->pstate` 被 `valid_native_regs` 洗成合法 EL0t，随后 `force_sigsegv` 会**再次进入信号投递**（投递 SIGSEGV）——**这是一个「信号投递 → regs 被改 → 再投递」的可递归结构**，可能在多次投递中放大控制面。

### 4.3 对 §一 未解矛盾的更新判据

**已证**：`valid_user_regs` 6 个调用点全部在「信号 / ptrace」域内，全部被 `valid_native_regs` 的 EL0t 门锁死。

**⇒ 新方向（下轮候选，按优先级）**：
1. **不是「找不经过 `valid_user_regs` 的路径」，而是「找不经过 `regs` → `eret` 的提权路径」** —— 即：不追求「让 `eret` 回 EL1」，而追求「让内核在被改写的 `regs` 上、于 `eret` **之前**执行一段有益逻辑」。已知内联链里 `setup_rt_frame` 会做大量写（`setup_sigframe`、`copy_siginfo_to_user`、`__save_altstack`），这些都在**内核态**执行且以 `regs` 为参数 ⇒ **审查这些写路径能否被 `regs` 内容影响**。
2. **`signal_setup_done(ret=1)` 的行为核实** —— 若 `force_sigsegv` 不中止，则存在「递归投递」窗口。
3. **`setup_sigframe`（`0x49e3a8` 的调用者）** 是否把 `regs` 的内容（如 `regs->sp`、`regs->pc`）当作写入源或地址 —— 若有，则是内核态任意写的候选。
4. **重新审视 H107 `rt_sigreturn+0x3d4`**：`badframe` 分支已确证「什么都不恢复」，但它仍执行 `arm64_notify_segfault(regs->sp)` ⇒ **`regs->sp` 在内核态被当作参数使用**（`current->thread.fault_address = addr`），这是一条**只读 `regs->sp`、不改 `pstate`** 的内核态路径。

---

## 5. 三环对照表（规程 §三 要求）

| 环节 | 内容 | 结论 | 证据 |
|---|---|---|---|
| 环① 源码推理 | `do_notify_resume` 调用链：`do_signal`→`handle_signal`→`setup_rt_frame`→`setup_return`；`signal.c:1197` 的 `ret\|=` | 已定案 | `signal.c:1076-1130, 1132-1161, 1174-1201, 1212-1282, 1283-1319` |
| 环② 汇编交叉验证 | `do_notify_resume` 全函数剖面 + 6 调用点归属 + `regs->pc` 写入点 | **✅ 与源码一致，但 H107 §4.3 的「唯一被动关闸」表述需修正** | `Image-mey` 反汇编 + 原始 BL 位域扫描 |
| 环③ 镜像 delta | 四 static 函数（`do_signal`/`handle_signal`/`setup_rt_frame`/`setup_return`）被内联进 `do_notify_resume` | ✅ 编译器内联，非厂商改动 | 符号表只有 `do_notify_resume`；调用链符号全部可反查 |
| **一致性** | 三环一致 | **✅** | — |
| **修正项** | H107 §4.3「`do_notify_resume+0x260` 是唯一内核侧被动关闸」⇒ **改为「投递侧关闸，与恢复侧同锁」** | ⚠️ 须回填 H107 §U.5 / §U.7 | 本轮 §1 |

---

## 5b. ★★★★ 收口定论：`handle_signal` 递归窗口**不存在**（本轮决定性否证）

§4.2 提出的「`signal_setup_done(ret=1)` 是否留下递归投递窗口」——**本轮已用源码 + 设备镜像双证否证**。

### 5b.1 完整调用链（源码 `kernel/signal.c`）

```
signal_setup_done(failed=1, ksig, stepping)            /* signal.c:3006 */
    └─ if (failed) force_sigsegv(ksig->sig);           /* :3009 */
           └─ force_sigsegv(sig)                        /* :1776 */
                  /* sig == SIGSEGV? */
                  └─ force_fatal_sig(SIGSEGV)           /* :1779 */
                         └─ force_sig_info_to_task(&info, current, HANDLER_SIG_DFL)  /* :1754 */
                                /* enum: HANDLER_CURRENT=0, HANDLER_SIG_DFL=1 */
                                └─ if (blocked || ignored || (handler != HANDLER_CURRENT)) {
                                        action->sa.sa_handler = SIG_DFL;   /* :1404  ★ 强制改回默认处理 */
                                        ...
                                   }
                                   send_signal_locked(SIGSEGV, ...)        /* :1419 投递 */
```

**⇒ 关键语义**：`HANDLER_SIG_DFL(1) != HANDLER_CURRENT(0)` **恒真** ⇒ 内核**先把 `sa_handler` 强制改为 `SIG_DFL`**，再投递 SIGSEGV。

**⇒ 后果**：即使用户态装了 `SIGSEGV` handler（`sa_handler` = 用户函数），本次 `force_fatal_sig` 也会**把它抹成 `SIG_DFL`** ⇒ SIGSEGV 以**默认动作（终止进程）** 投递 ⇒ **进程直接死亡，不进入任何用户态 handler** ⇒ **不存在「投递 → regs 被改 → 再投递」的递归结构**。

这正是源码注释 `signal.c:1387-1389` 明说的：
```
* We don't want to have recursive SIGSEGV's etc, for example,
* that is why we also clear SIGNAL_UNKILLABLE.
```

### 5b.2 设备镜像双证（`signal_setup_done` @ `0xffffffc08027873c`）

```
0x27875c  cbnz w0, 0x2787ec        ; ★ if (failed) → 走 force_sigsegv 分支
   ...（failed==0 分支：signal_delivered，略）
0x2787ec  ldr  w0, [x1, #0x50]     ; w0 = ksig->sig  (ksig 偏移 0x50 = sig)
0x2787f0  bl   force_sigsegv       ; ★ 0x81c304
0x2787f4  b    0x2787c0            ; 返回
```
**✅ 与源码 `signal.c:3006-3011` 逐条一致，无厂商改动。**

### 5b.3 ⇒ 对 §4.3 新方向的裁决

| §4.3 候选方向 | 本轮裁决 |
|---|---|
| ② `signal_setup_done(ret=1)` 递归窗口 | ❌ **已否证**（`HANDLER_SIG_DFL` 强制重置 handler ⇒ 进程死亡，无递归） |
| ① 审查 `setup_rt_frame` 内核态写路径（以 `regs` 为参数） | ⏳ **保留，下轮主攻**（`setup_sigframe` / `copy_siginfo_to_user` / `__save_altstack` 都在内核态、以 `regs` 为源） |
| ③ `setup_sigframe` 是否把 `regs` 内容当写入源/地址 | ⏳ **保留，与①合并审查** |
| ④ `rt_sigreturn` 的 `badframe` 分支仍用 `regs->sp` 作 `arm64_notify_segfault` 参数 | ⏳ **保留**（一条只读 `regs->sp`、不改 `pstate` 的内核态路径，但只**读**，利用价值低） |

### 5b.4 本轮对 §一 未解矛盾的净结论

**「不经过 `valid_user_regs` 的 `pt_regs` 改写路径」在信号 / ptrace 域内确实不存在（6 调用点全锁）**，且**「信号投递递归放大」也不成立（`HANDLER_SIG_DFL` 兜底）**。

⇒ **§一 未解矛盾在本轮之后更清晰也更窄**：SROP 本身提供的是「**内核态一次性全量可控 `pt_regs`**」，但内核侧**没有任何一条既不经过 `valid_user_regs`、又能让被改写的 `regs` 走向 EL1 的通路**。

**⇒ 下轮必须换维度**：不再找「另一条 `regs` 改写路径」，而是**在 `setup_rt_frame` 的内核态写路径里找「以 `regs` 为参数、执行时仍在 EL1 的逻辑」**——这些逻辑在 `eret` **之前**执行，不经过 `valid_user_regs` 之后的返回判定。**这是 SROP 路线目前唯一的、未经否证的可用面。**

---

## 6. 下轮第一步（严格按序）

1. **★★★ 主攻 `setup_rt_frame` 的内核态写路径**（§5b.3 方向①③合并）：dump `setup_sigframe`（源码 `signal.c:1000-1070` 附近）与 `setup_rt_frame` 内联体在设备镜像上的实现，审查**哪些写操作以 `regs` 字段为源或地址**。判据：**若存在 `str xN, [regs_field]`（即拿 `regs` 里的值当地址写），则该字段可控 ⇒ 内核态任意写候选**。
2. ~~核实 `signal_setup_done` 行为~~ ✅ **本轮已完成：`HANDLER_SIG_DFL` 强制重置 handler ⇒ 进程死亡，无递归**（§5b）。
3. **补齐 §3.1 的 native `setup_return` 定位**（已解决：`0x49d1d8 stp x9,x10,[x19,#0xf8]`，见 §3b）。
4. **回填 H107 §U.5/§U.7 的表述修正**（`do_notify_resume+0x260` 非「唯一被动关闸」，而是「投递侧关闸，与恢复侧同锁」）。
5. 评估 §5b.3 残留方向①③④，选定一条作为下轮主攻。

---

## 3b. ★ native `setup_return` 定位（解决 §3.1 矛盾）

**H108 续段（`0x49c7f8` 之后）已定位 native `setup_return` 的内联体**：

```
0x49c830  stp   x23, x28, [sp, #0x30]     ; user.sigframe=x23, user.next_frame=x28 (rt_sigframe_user_layout)
...
0x49d1b0  cbz   w24, 0x49d28c             ; ★ if (err) 跳过 setup_return 体
0x49d1c8  ldp   x9, x8, [sp, #0x30]       ; x9 = user.sigframe, x8 = user.next_frame
0x49d1cc  ldur  x10, [x29, #-0x68]        ; x10 = ksig.ka.sa.sa_handler
0x49d1d0  str   x22, [x19]                ; regs->regs[0]  = usig          (signal.c:1081)
0x49d1d4  str   x8,  [x19, #0xe8]         ; regs->regs[29]= &next_frame->fp (signal.c:1083)
0x49d1d8  stp   x9, x10, [x19, #0xf8]     ; ★★ regs->sp = sigframe        (signal.c:1082)
                                          ; ★★ regs->pc = sa_handler      (signal.c:1084)  ← 一次 stp 写两个字段
0x49d1dc  b     0x49df10
```

**⇒ §3.1 的矛盾已解决**：`0x49c7a8/0x49c7c0` 的 `bl compat_setup_*` 是 **compat 分支**；native 路径的 `setup_rt_frame`/`setup_return` **完全内联**在 `0x49c804..0x49d1dc`（`err==0` 时执行）。

**⇒ 时序已确证（核心）**：
```
0x49d1d8  regs->pc = sa_handler     ← setup_return（内联）
   ↓（分支回到 0x49c7c8）
0x49c7c8  mov x0, x19 ; x1, x20     ← regs, task
0x49c7d0  bl valid_user_regs        ← signal.c:1197  ★ 在 setup_return 之后
```
**⇒ 用户可通过 `sigaction` 完全控制 `regs->pc`，且该写入发生在 `valid_user_regs` 关闸之前** —— 但如 §5b 所证，`ret=1` 时 `valid_user_regs` 已把 `pstate` 洗成合法 EL0t，且随后 `force_fatal_sig` 抹掉 handler ⇒ **控制面被兜底吃掉**。

**⚠️ 副产品：`regs->sp = user.sigframe` 会把 `sp` 改成内核构造的帧地址**（`0x49c804..0x49c830` 计算），**不是用户可控值** ⇒ 即使用户控制了 `regs->pc`，`sp` 也被内核接管。

---

## 7. 附：本轮脚本

| 脚本 | 用途 |
|---|---|
| `tools/h108_dnr_dump.py` | `do_notify_resume` + `ret_to_user` 全量反汇编（`skipdata=True`） |
| `tools/h108_setup_return_find.py` | 在 `do_signal` 窗口内扫 `regs->pc/sp` 写入点 |
| `tools/h108_symlookup.py` | 关键地址 → 符号归属（bisect kallsyms） |

**原始 BL 位域扫描**：`w>>26==0b100101` + `imm26` 符号扩展，全镜像 4 字节对齐遍历（Python 内联，无脚本落盘）。
