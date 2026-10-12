# H115 — SROP 最后一条缝：「`svc` 处理中重用 `pt_regs`」全树穷尽 + regset 钳位真机验证

**轮次**：H115 ｜ **日期**：2026-10-05 ｜ **路线**：SROP（`rt_sigreturn`）唯一路线（用户指令）
**设备**：MEY-AN00 ｜ `boot_id=2888f136-4ff1-487b-8d4c-58e02e1897e0`（**未变，未 panic**）｜ `uptime=6155s` ｜ `getenforce=Enforcing` ｜ `id=uid=2000(shell)`
**判据**：本轮为**源码穷尽 + 真机观测**，不涉及提权判据（`id`/`getenforce`）。

---

## 零、本轮任务

用户最高约束：**只走 SROP 一条路线，不并行、不设闸门、不保留兜底。**

H114 结束时剩余唯一未测方向 = **「内核在 `svc` 处理过程中，以别的机制重新使用 `pt_regs`」**。
本轮把这最后一条缝走完，并对 H111 判死清单第 ③ 条（`orig_x0`/`syscallno` 够不到）做**真机复核**。

---

## 一、源码侧结论（三条，全部可证伪）

### C1 — `restart_block` 对 arm64 是死路【判死】

| 证据 | 内容 |
|---|---|
| 结构体定义（`include/linux/restart_block.h`） | `unsigned long arch_data; long (*fn)(struct restart_block *); union { futex / nanosleep / poll };` —— **不含任何 `pt_regs` 字段** |
| `fn` 全树赋值集合 | **唯一取值 = `do_no_restart_syscall`**（38 处赋值点，非 `do_no` 赋值 **0 处**） |
| `fn` 唯一调用点 | `kernel/signal.c:3108` `SYSCALL_DEFINE0(restart_syscall) { return restart->fn(restart); }` |
| `do_no_restart_syscall` 实现 | `kernel/signal.c:3111` —— `{ return -EINTR; }`（纯桩，不碰 `pt_regs`） |
| `arch_data` 使用者 | 仅 **s390**（`p->restart_block.arch_data = 1`；`regs->psw.addr = arch_data`）与 **x86**（`TS_COMPAT` 标记）。**`grep arch_data arch/arm64/` 全空 ⇒ arm64 零语义** |

**可证伪判据**：若 C1 错，应能在 `arch/arm64` 下找到 `restart_block.arch_data` 的赋值点，或找到 `fn` 的第二个取值。**两者均零命中。**

⇒ **`restart_block` 不可作为 `pt_regs` 的「跨 syscall 保留载体」。**

### C2 — 通用内核树零 `pt_regs` 寄存器写点【判死】

```
grep -rn "regs->regs\[[0-9]\+\]\s*=\|regs->pc\s*=\|regs->sp\s*=\|regs->pstate\s*=" \
     --include=*.c kernel/ fs/ security/ mm/ ipc/ io_uring/
⇒ 零命中
```

`syscallno` 全树出现位置统计（含 `include/`）：

| 文件 | 次数 | 性质 |
|---|---|---|
| `arch/arm64/kernel/ptrace.c` | 8 | `PTRACE_GET_SYSCALL_INFO` 报告给 tracer |
| `arch/arm64/include/asm/ptrace.h` | 5 | 定义 / `forget_syscall` / `syscallno_is_valid` |
| `arch/arm64/include/asm/processor.h` | 2 | 定义 |
| `arch/arm64/kernel/syscall.c` | 1 | `el0_svc_common` 写入 |
| `arch/arm64/kernel/asm-offsets.c` | 1 | 偏移生成 |
| `arch/arm64/include/asm/syscall.h` | 1 | `syscall_get_nr` |
| **`kernel/ fs/ security/ mm/ ipc/ io_uring/ include/`** | **0** | ★ **完全零出现** |

**⇒ 全树不存在「通用子系统在 syscall 处理中重用 `pt_regs`」的机制。**

### C3 — `gpr_set` 够不到 `orig_x0`/`syscallno`，机制是「钳位」而非「iov 上限」

**源码链（三处硬约束）：**

```c
// ① kernel/ptrace.c:915-920  ptrace_regset()
if (!regset || (kiov->iov_len % regset->size) != 0)  return -EINVAL;
kiov->iov_len = min(kiov->iov_len, (__kernel_size_t)(regset->n * regset->size));   // ★ 钳位到 0x110
return copy_regset_from_user(task, view, regset_no, 0, kiov->iov_len, kiov->iov_base);

// ② arch/arm64/kernel/ptrace.c:564-580  gpr_set()
struct user_pt_regs newregs = task_pt_regs(target)->user_regs;   // ★ 类型是 user_pt_regs (0x110)
ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &newregs, 0, -1);  // end_pos=-1 无上限，但 data 只有 0x110
if (!valid_user_regs(&newregs, target))  return -EINVAL;
task_pt_regs(target)->user_regs = newregs;                        // ★ 只写回 user_regs

// ③ arch/arm64/include/asm/ptrace.h:216
#define MAX_REG_OFFSET offsetof(struct pt_regs, pstate)           // ★ = 0x108
```

**`pt_regs` 真实布局（`arch/arm64/include/asm/ptrace.h` 源码直读）：**

| 字段 | 偏移 | 大小 |
|---|---|---|
| `regs[31]` | `0x00` | `0xF8` |
| `sp` | `0xF8` | `0x8` |
| `pc` | `0x100` | `0x8` |
| `pstate` | `0x108` | `0x8` |
| **`orig_x0`** | **`0x110`** | `0x8` ← ★ 钳位外 |
| **`syscallno`** | **`0x118`** | `0x4` ← ★ 钳位外 |
| `unused2` | `0x11C` | `0x4` |
| `sdei_ttbr1` | `0x120` | `0x8` |
| `pmr_save` | `0x128` | `0x8` |
| `stackframe[2]` | `0x130` | `0x10` |
| `lockdep_hardirqs` / `exit_rcu` | `0x140` / `0x148` | `0x8`×2 |

⇒ **`gpr_set` 的可写域 = `[0x00, 0x110)`，`orig_x0`/`syscallno` 严格在域外。H111 第 ③ 条结论正确，机制表述由「iov 上限」更正为「`ptrace_regset` 钳位 + `newregs` 是 `user_pt_regs`」。**

---

## 二、本轮新发现的 `pt_regs` 读取点（H111 未覆盖）

### `arch/arm64/kernel/ptrace.c:2209` — `audit_syscall_entry`

```c
int syscall_trace_enter(struct pt_regs *regs)
{
	if (flags & (_TIF_SYSCALL_EMU | _TIF_SYSCALL_TRACE))
		report_syscall(regs, PTRACE_SYSCALL_ENTER);       // ← 内含 regs[7] 写点
	if (secure_computing() == -1)  return NO_SYSCALL;
	if (test_thread_flag(TIF_SYSCALL_TRACEPOINT))
		trace_sys_enter(regs, regs->syscallno);
	audit_syscall_entry(regs->syscallno, regs->orig_x0, regs->regs[1],   // ★ 新读取点
	                    regs->regs[2], regs->regs[3]);
	return regs->syscallno;                                  // ★ 返回值 = 实际派发的 syscall 号
}
```

**分析：**

- `audit_syscall_entry` 的 5 个参数全部流向 `audit_log_*`（**只读记录**，不执行特权动作）⇒ 非提权落点。
- 其 `syscallno` 参数来自 `regs->syscallno`，**不可控**（钳位外）。
- **`return regs->syscallno;` 决定 `invoke_syscall(regs, scno, ...)` 派发的 syscall** —— 但 `regs->syscallno` 的唯一写入者是 `el0_svc_common` 开头的 `regs->syscallno = scno;`（`scno` = `regs->regs[8]`），**在 `syscall_trace_enter` 之前定型**。

### `report_syscall`（`ptrace.c:2148`）内的 `regs[7]` 写点

```c
regno = (is_compat_task() ? 12 : 7);
saved_reg = regs->regs[regno];
regs->regs[regno] = dir;                    // ★ 写 regs[7]（64位进程）
if (dir == PTRACE_SYSCALL_ENTER) {
	if (ptrace_report_syscall_entry(regs)) forget_syscall(regs);
	regs->regs[regno] = saved_reg;          // ★ 恢复
}
```

**这是「内核在 syscall 处理中写 `pt_regs->regs[7]`」的真实例** —— 但：

- `regno` 是**编译期常量** `7`（或 compat 的 `12`），非 `x8`。
- `x7` **不是** syscall number（arm64 是 `x8`）⇒ 改它不改变派发目标。
- 写值 `dir` 只有 `0`/`1` 两个取值，随后**无条件恢复原值**。

⇒ **非落点。**

### `el0_svc_common`（`arch/arm64/kernel/syscall.c:84`）的两行 `pt_regs` 写

```c
void do_el0_svc(struct pt_regs *regs) {
	el0_svc_common(regs, regs->regs[8], __NR_syscalls, sys_call_table);   // ★ regs[8] 每次 svc 入口重新求值
}
static void el0_svc_common(...) {
	regs->orig_x0 = regs->regs[0];      // 写 0x110
	regs->syscallno = scno;             // 写 0x118
	...
	scno = syscall_trace_enter(regs);   // 返回值 = 实际派发号
	invoke_syscall(regs, scno, ...);
}
```

**H111 判死清单 ⑦ 的「`x8` 改了不生效」在此源码下得到精确表述**：`regs->regs[8]` 只在 `do_el0_svc` 入口读一次，之后 `scno` 已定型，任何后续 `x8` 改动不影响派发。

---

## 三、真机验证（H115，`boot_id` 未变）

**探针**：`tools/h115_regset.c` → 设备 `/data/local/tmp/h115_regset`（md5 `d170f94013b646636d7a087dc48ab51d`，推送前后一致）。纯观测 + fork 隔离子进程，**零内核状态破坏**。

```
=== H115 ptrace regset 钳位行为验证 ===
[M1] 子进程已停, 开始 regset 探测

[T1] GETREGSET iov_len=0x110 -> rc=0 out_len=0x110
     regs[0]=0x0000000000000000 regs[8]=0x0000000000000081
     sp=0x0000007fff4ef0e0 pc=0x00000000002610ac pstate=0x0000000000001000

[T2] GETREGSET iov_len=0x200 -> rc=0 out_len=0x110   <== 关键观测
     ★ 钳位成立: 0x200 -> 0x110  (C3 成立)

[T3] GETREGSET iov_len=0x107 (非 8 倍数) -> rc=-22 (EINVAL 预期)
[T4] GETREGSET iov_len=0x108 (8 的倍数) -> rc=0 out_len=0x108

[T5] PEEKUSER off=0x108 (pstate, ==MAX_REG_OFFSET) -> val=0xffffffffffffffff errno=5(I/O error)
[T6] PEEKUSER off=0x110 (orig_x0, >MAX_REG_OFFSET)   -> val=0xffffffffffffffff errno=5(I/O error)
[T7] PEEKUSER off=0x100 (pc)                          -> val=0xffffffffffffffff errno=5(I/O error)

[T8] SETREGSET iov_len=0x110 pstate=0        -> rc=0 iov_len=0x110 errno=0(OK)
[T9] SETREGSET pstate=0x3c0 (非法)           -> rc=-1 errno=22(Invalid argument)
[T10] SETREGSET iov_len=0x200 -> rc=0 out_len=0x110 errno=0(OK)   <== 钳位观测
=== H115 完成 ===
```

### 结果解读（三条升级为「真机已证」）

| # | 观测 | 结论 | 置信度升级 |
|---|---|---|---|
| **1** | T2/T10：`iov_len 0x200 → out_len 0x110`（读+写双方向） | `ptrace_regset` **钳位成立** = `regset->n * regset->size` = `sizeof(user_pt_regs)` | 源码推断 → **真机已证** |
| **2** | T9：`SETREGSET pstate=0x3c0` → **`EINVAL(22)`**；T8：`pstate=0` → `rc=0` | **`gpr_set` 的 `valid_user_regs` 是硬闸门**，与 H113 `rt_sigreturn` 路径**同一把锁**（`pstate & 0x3df` 条件） | **双路径真机互证** |
| **3** | T5/T6/T7：`PEEKUSER` 任意偏移（含 `0x100`/`0x108`/`0x110`）全部 `errno=5 EIO` | **`PTRACE_PEEKUSER`/`POKEUSER` 在 arm64 整个 request 未实现**（非「偏移错」） | H111 第 ① 条 → **真机已证** |

**副产品（与 H113 完全一致）**：T1 的 `pstate=0x1000`（DIT 位）⇒ 与 H113 内核自产帧吻合；`pc=0x2610ac` 是静态 PIE 固定地址；`regs[8]=0x81` 是子进程 `kill` 的 syscall 号（129=SIGSTOP 之前调用的 `syscall`）。

---

## 四、本轮判死汇总（新增 4 条）

| # | 判死对象 | 依据 | 环节 |
|---|---|---|---|
| **D1** | `restart_block` 作 `pt_regs` 载体 | 结构体无 `pt_regs` 字段；`fn` 唯一取值 `do_no_restart_syscall`；`arch_data` arm64 零语义 | C1 源码 |
| **D2** | 通用内核树重用 `pt_regs` | `kernel/ fs/ security/ mm/ ipc/ io_uring/` 寄存器写点**零命中**；`syscallno` 在 `include/`+通用树**零出现** | C2 源码 |
| **D3** | `audit_syscall_entry` 参数流向特权 | 5 参数全进 `audit_log_*`（只读记录）；`syscallno` 不可控 | 源码 |
| **D4** | `report_syscall` 的 `regs[7]` 写点 | `regno` 编译期常量 `7`；写值只有 `0/1`；无条件恢复 | 源码 |

**另有 3 条由「源码推断」升级为「真机已证」**（见 §三）：regset 钳位 / `gpr_set` 硬闸门 / `PEEKUSER` 全废。

---

## 五、SROP 现状（H115 后）

| 环节 | 状态 |
|---|---|
| 手工帧被内核采信 | ✅ H113 真机跑通 |
| `regs[0..30]`+`sp`+`pc` 全量可控 | ✅ H113 真机 |
| `pstate` 通过条件 `(pstate & 0x3df)==0` | ✅ H113 真机 11/11 |
| 返回路径 / trampoline / 出口侧 | ❌ H114 三向判死 |
| **「`svc` 处理中重用 `pt_regs`」** | ❌ **H115 判死（D1–D4）** |
| **EL1 落点** | ❌ **仍未解 —— 且「控制流劫持到 EL1」维度已彻底穷尽** |

### 剩余未穷尽维度（按可行性排序）

| # | 维度 | 判据 | 备注 |
|---|---|---|---|
| **A** | **厂商 cdev ioctl 面** | H112 反向收敛结论：shell 域唯一未穷尽类别 | 需枚举 `/dev` 下 0666 厂商节点 + ioctl 号 + 反汇编私有驱动 |
| **B** | **L1/L2 存档原语复活** | `rb_erase@0x3a9d4`（L1）/ `rt_mutex`（L2）已有写原语 | 用户指令「只走 SROP」⇒ 当前**冻结** |
| **C** | 非 `pstate` 的控制流落点 | 需「内核带被改写 GPR 执行既有提权逻辑」的函数 | H111 §⑨ 已列候选（`install_child_root` 类），本轮扫描全树**零命中** |

---

## 六、产物

| 类型 | 路径 |
|---|---|
| 探针源码 | `tools/h115_regset.c` |
| 探针二进制 | `tools/h115_regset`（2,231,464 B，静态 PIE） |
| md5 | `d170f94013b646636d7a087dc48ab51d`（推送前后一致） |
| 本报告 | `analysis/output/h115_svc_ptregs.md` |

**设备状态**：`boot_id` 未变（`2888f136-4ff1-487b-8d4c-58e02e1897e0`），`getenforce=Enforcing`，零 panic。
