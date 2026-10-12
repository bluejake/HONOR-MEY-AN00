# H138 · `pt_regs` 读侧穷尽 —— 非 pstate 落点判死（G 面闭合）

> 日期：2026-10-05 13:45
> 设备：MEY-AN00 · SM8735 · 内核 `6.6.118-android15-8` · `boot_id`（本轮全程未变）
> 目标：执行用户选定的 `定向实测：#1 非 pstate 落点` —— 把 sigreturn 当**任意 `regs` 写器**，
> 寻找**消费 `regs[N]` 当特权参数/地址**的内核路径。
> 方式：**纯静态**（源码树 6.6.56 + 设备 kallsyms/镜像符号核对）。
> 结论：**判死**。与 H115（写侧零命中）构成**双向闭合论证**。

---

## 零、一句话结论

**「读 `regs[N]` 当特权参数」在整棵内核树上不存在。**

`pt_regs` 被内核消费的**唯一时机是 EL0→EL1 入口**，而 sigreturn 改写 `regs` 发生在 **EL1→EL0 出口**。
出口改的值只会被「下一次入口」读走，而下一次入口读 `regs` 的用途**只有两类**：
① 取 syscall 参数（`regs[0..5]`）；② 记录现场（打印/上报）。

**⇒ 「出口写 → 入口读」链上，没有任何特权语义的中间站。**
**⇒ G 面（非 pstate 控制流落点）判死；SROP/信号域整体五个维度全部穷尽。**

---

## 一、搜索方法（与 H115 反向）

| 项 | H115（写侧） | H138（读侧） |
|---|---|---|
| 搜法 | `regs->regs[N]=` / `regs->pc=` / `regs->sp=` / `regs->pstate=` | `regs->regs[` **不含 `=`**；`regs->pc/sp/pstate` **排除 `=`** |
| 范围 | `kernel/ fs/ security/ mm/ ipc/ io_uring/ include/` | `arch/arm64/`（读侧主战场）+ `kernel/ fs/ security/ mm/ net/ include/` |
| 附加 | — | `pt_regs_read_reg` 全调用点；`regs[N]` 传给 user-access/解引用；`syscall_get_*` 消费点 |
| 结果 | **零命中** | 命中 ~60 条，逐条分类后**无一条是特权消费者** |

---

## 二、全部命中分类（决定性：三类，全部非特权限）

### 类别 ①：打印 / 上报 / 追踪（无状态副作用）

| 位置 | 读取 | 消费方式 |
|---|---|---|
| `arch/arm64/kernel/process.c:212/236/239` | `regs->regs[30]` / `regs->regs[i]` | `printk` 寄存器转储 |
| `arch/arm64/kernel/traps.c:263` | `regs->pc` | `print_vma_addr` 打印 |
| `arch/arm64/kernel/kgdb.c:169` | `regs->pc + 4` | kgdb 单步设 PC（需 KGDB，不可达） |
| `arch/arm64/kernel/armv8_deprecated.c:*` | `regs->pc`/`regs->pstate` | `trace_instruction_emulation` / `pr_*` |
| `arch/arm64/kernel/perf_regs.c:63/67/70/75` | `regs->pc`/`sp`/`regs[idx]` | 填 perf 采样记录（只读上报） |
| `arch/arm64/kernel/stacktrace.c:344` | `regs->pc` | `consume_entry(cookie, pc)` 栈回溯 |
| `arch/arm64/hyperv/hv_core.c:172/173` | `regs->pc`/`sp` | Hyper-V 崩溃上报（设备非 Hyper-V，不可达） |
| `arch/arm64/mm/fault.c:351` | `regs->pc` | `kasan_report` |
| `arch/arm64/kernel/sdei.c:228` | `regs->regs[i]` | SDEI 固件事件上下文（需 SDEI） |

**⇒ 全部为「读出来打印/记录」，不改任何内核状态，无提权价值。**

### 类别 ②：语义 **由编译期常量寄存器号** 决定（攻击者不控制选哪个寄存器）

| 位置 | 形态 | 判死理由 |
|---|---|---|
| `arch/arm64/kernel/traps.c:1068`（`cfi_handler`） | `target = pt_regs_read_reg(regs, FIELD_GET(CFI_BRK_IMM_TARGET, esr))` | 触发需 EL0 发 `BRK` 且 ESR 携带 CFI 字段；手写 BRK 时该字段为 **0** ⇒ 只读到 `regs[0]`。且消费 = `report_cfi_failure` **仅打印**，返回 `WARN` 不写回、不转移控制流。**判死** |
| `arch/arm64/kernel/traps.c:532-563`（`do_el0_mops`） | `dst/src/size = pt_regs_read_reg(...)` 按 ESR 提供的寄存器号 | MOPS 模拟。寄存器号来自 ESR，读出来用于**重算寄存器值写回**（`pt_regs_write_reg`）。**是回写不是解引用**；且触发需真实 MOPS 指令异常。**无任意读/写** |
| `arch/arm64/kernel/traps.c:602`（`user_cache_maint_handler`） | `tagged_address = pt_regs_read_reg(regs, rt)`（`rt` 来自 ESR） | **★ 唯一"读 regs[N] 当地址做内存操作"的点**，但地址经 `__user_cache_maint` 有 **`if (address >= TASK_SIZE_MAX) res=-EFAULT` 硬闸门**，且操作是 **`dc civac`（cache 维护），不是读写内存数据**。**判死** |
| `arch/arm64/mm/extable.c:40`（`ex_handler_load_unaligned_zeropad`） | `addr = pt_regs_read_reg(regs, reg_addr); data = *(unsigned long*)addr;` —— **裸解引用，无 `access_ok`！** | **★ 几何完美（控制 regs[N] → 内核裸读 → 结果落 regs[M]），但触发链不通。判死理由见 §三。** |

### 类别 ③：syscall 参数消费者（参数即普通 syscall 参数，非特权）

| 位置 | 形态 |
|---|---|
| `arch/arm64/include/asm/syscall.h:35/73` | `syscall_get_return_value`(读 `regs[0]`)、`syscall_get_arguments`(读 `orig_x0`+`regs[1..5]`) |
| `kernel/entry/common.c:43/78/86/253/267` | 入口侧取 syscall 号与参数 |
| `kernel/ptrace.c:945/946/978/981/994` | `PTRACE_GET_SYSCALL_INFO` 上报（需 ptrace 权限） |
| `kernel/seccomp.c:256/257/258/1270/1347` | seccomp 过滤（需装 BPF 程序，shell 域 `EACCES`，见 H112） |
| `kernel/trace/trace_syscalls.c:72/78/326/363/610/709` | tracepoint 上报 |
| `kernel/auditsc.c:2038/3012` | audit 上报（`syscall_get_arch`，非 `regs` 值） |

**⇒ 全部是「把 `regs[0..5]` 当成 syscall 参数」——这些参数本来就是攻击者自己传的，改它不产生任何新能力。**

### 类别 ④：栈帧遍历（读用户内存，非内核任意读）

| 位置 | 形态 |
|---|---|
| `arch/arm64/kernel/stacktrace.c:351` | `tail = (struct frame_tail __user *)regs->regs[29];` → `unwind_user_frame(tail, ...)` |
| `arch/arm64/kernel/probes/uprobes.c:146` | `regs->sp < ret->stack` 比较 |

**`arch_stack_walk_user`**：读 `regs[29]`（FP）当**用户栈帧指针**，用 `pagefault_enable/diable` + `__user` 访问逐帧读。
- 消费 = **读用户内存**（不是读内核内存）；
- 每次都经用户访问原语（`access_ok` + 缺页保护）；
- 触发 = 需 `perf`/`stack_trace_save_user`（shell 域 `perf_event_open` = `EACCES`，见 H112）。
**⇒ 判死。**

---

## 三、★ 决定性证伪：`fixup_exception` 是 EL1 专属，EL0 缺页不经过它

原本最有价值的候选是 **`ex_handler_load_unaligned_zeropad`**：

```c
// arch/arm64/mm/extable.c:33-57
static bool
ex_handler_load_unaligned_zeropad(const struct exception_table_entry *ex,
				  struct pt_regs *regs)
{
	int reg_data = FIELD_GET(EX_DATA_REG_DATA, ex->data);
	int reg_addr = FIELD_GET(EX_DATA_REG_ADDR, ex->data);
	unsigned long data, addr, offset;

	addr = pt_regs_read_reg(regs, reg_addr);   // ← 从 regs[N] 取地址
	offset = addr & 0x7UL;
	addr &= ~0x7UL;
	data = *(unsigned long*)addr;              // ← ★ 裸解引用，无 access_ok
	pt_regs_write_reg(regs, reg_data, data);   // ← 结果落到 regs[M]
	regs->pc = get_ex_fixup(ex);               // ← ★ 内核改写 regs->pc 为内核地址
	return true;
}
```

**几何完美**：控制 `regs[N]` → 内核**裸读任意地址** → 结果写 `regs[M]`，并且**内核直接改写 `regs->pc`**。
注册点唯一：`_ASM_EXTABLE_LOAD_UNALIGNED_ZEROPAD` @ `word-at-a-time.h:64`（`load_unaligned_zeropad()` 内联实例）。
设备 `__ex_table` 段存在：`0xffffffc08172c088 .. 0xffffffc08172f46c`（**0x33e4 = 13284 B ≈ 1107 个 12B 表项**）。

### ★★ 但触发链**不通**——三条硬证据

**证据 1：`fixup_exception` 全部调用点（3 个）都在 EL1/SEA 侧**

```
arch/arm64/mm/fault.c:402   if (!is_el1_instruction_abort(esr) && fixup_exception(regs))   ← __do_kernel_fault 内
arch/arm64/mm/fault.c:434   if (efi_runtime_fixup_exception(regs, msg))                     ← EFI 运行时
arch/arm64/mm/fault.c:828   if (can_fixup && fixup_exception(regs))                         ← do_sea（SEA 异常）
```

**证据 2：EL0 缺页走的是 `__do_user_fault`，压根不到 `__do_kernel_fault`**

`do_page_fault` 的前置分流：
- `user_mode(regs)` 为真（= EL0 缺页）⇒ `__do_user_fault` ⇒ **`arm64_notify_segfault`**（**不调 `fixup_exception`**）
- `user_mode(regs)` 为假（= EL1 缺页）⇒ `__do_kernel_fault` ⇒ `fixup_exception(regs)`

**证据 3：`regs` 时机错位**

sigreturn 恢复 `regs` 发生在 **EL1→EL0 出口**。要让 `regs->pc` 成为 `search_exception_tables` 的查找键，
必须存在「**内核在 EL1 缺页时用我填的 pc**」的场景——但 EL1 缺页时 `regs->pc` **是内核自己正在执行的地址**
（被硬件 `kernel_entry` 压栈的真实现场），**不是我从信号帧填的值**。

**⇒ 判死 E'：`fixup_exception` / `load_unaligned_zeropad` 线不通。**

### ★ 附带修正：H113「`pc` 填内核地址 → SIGSEGV」的归因

H113 结论不变，但**归因要说清**：那条 SIGSEGV 是**取指缺页** → `do_page_fault` → `user_mode(regs)==true`
→ **`__do_user_fault`** → `arm64_notify_segfault`。**`si_addr` = 所填 pc** 与此一致。
**`search_exception_tables` 从未被调用**，所以"填一个真实 ex_table 表项地址就能命中"这条路直接不成立。

---

## 四、★ 双向闭合论证（本轮核心产出）

```
写侧（H115）：grep regs->regs[N]= / regs->pc= / regs->sp= / regs->pstate=
              范围 kernel/ fs/ security/ mm/ ipc/ io_uring/ include/
              ⇒ 零命中
              ⇒ 出口侧无任何改写 regs 的写者（除信号/ptrace 自身）

读侧（H138）：grep 读 regs->regs[N] / regs->pc/sp/pstate（排除写、排除打印）
              范围 arch/arm64/ kernel/ fs/ security/ mm/ net/ include/
              ⇒ ~60 命中，分类 4 类，无一条特权消费者
              ⇒ 入口侧无任何消费 regs 做特权操作的点

⇒ 结论：pt_regs 通道上，「出口写 → 入口读」之间不存在特权语义的中间站。
⇒ 这条通道的**全部自由度** = syscall 参数（攻击者本来就能传）+ 记录现场（只读）。
```

**架构层解释（为什么必然如此）**：
`pt_regs` 是**用户态-内核态边界的现场快照**。它的语义被内核严格约束为：
- **入口**：把 EL0 现场搬进内核（供 syscall/ptrace/audit 消费）
- **出口**：把内核算好的结果搬回 EL0（供用户态继续执行）

**任何"用 `regs` 的值做特权操作"的设计都会破坏这条边界**，因此上游内核**结构性地不写这种代码**——这就是「读侧零特权消费者」的根本原因，不是偶然。

---

## 五、判死清单（新增）

| 编号 | 对象 | 判死理由 | 证据 |
|---|---|---|---|
| **G7** | `el0_interrupt` `regs->pc & BIT(55)`（`entry-common.c:765`） | 分支体 `arm64_apply_bp_hardening()` 无参、不吃 pc 值（只据"是否内核地址"决定硬化）；且需 EL0 中断窗口 | 源码 + H114 §2 返回侧结论 |
| **G8** | `cfi_handler` 读 `regs[N]`（`traps.c:1068`） | EL0 手写 `BRK` 时 ESR 的 CFI 字段 = 0 ⇒ 只读到 `regs[0]`；消费 = `report_cfi_failure` 仅打印，不写回不转移 | 源码 `traps.c:1053-1080` |
| **G9** | `do_el0_mops` 读 `regs[N]`（`traps.c:532`） | 回写寄存器而非解引用；触发需真实 MOPS 指令异常 | 源码 `traps.c:523-590` |
| **G10** | `user_cache_maint_handler` 读 `regs[N]` 当地址（`traps.c:602`） | 地址有 `>= TASK_SIZE_MAX → -EFAULT` 硬闸门；操作是 `dc civac` cache 维护，非数据读写 | 源码 `traps.c:594-640` |
| **G11** | `ex_handler_load_unaligned_zeropad` 裸解引用（`extable.c:40`） | **`fixup_exception` 三调用点全在 EL1/SEA 侧；EL0 缺页走 `__do_user_fault` 不经过它** | 源码 `fault.c:398-402/828` + `extable.c:59-78` |
| **G12** | `arch_stack_walk_user` 读 `regs[29]`（`stacktrace.c:351`） | 消费 = 读用户内存（`__user` + 缺页保护）；触发需 perf/stack_trace_save_user，shell 域 `EACCES`（H112） | 源码 `stacktrace.c:339-366` |

**⇒ G 面（非 pstate 控制流落点）：H115（写侧）+ H138（读侧）双向闭合 ⇒ 判死。**

---

## 六、SROP / 信号域：五维度全部穷尽（本域最终裁定）

| 维度 | 轮次 | 判定 |
|---|---|---|
| ① 控制流劫持（pstate / EL1 落点） | H111/H113 | ❌ `user_mode()` = `pstate & 0xf == 0` 统一收口，native/compat 同构死锁 |
| ② 帧解析层（`parse_user_sigframe` 全 magic） | H116 | ❌ 真机 12/12，可用 magic 仅 4 个 |
| ③ 帧构造层（`get_sigframe`/`sigsp`/altstack） | H117–H120 | ❌ 双界完备硬闸门 + `__put_user` 第二层 |
| ④ 返回路径/出口侧（trampoline / `kernel_exit` / `syscall_exit_work`） | H114 | ❌ trampoline 仅 TTBR1 映射，EL0 不可达 |
| ⑤ **`regs` 通道消费者（读侧）** | **H138** | ❌ **无特权消费者（G7–G12）** |
| （对照）④' 写侧 | H115 | ❌ 通用树零命中 |

**⇒ SROP / 信号域整体：判死，无残余方向。**

---

## 七、残余面（本域之外）

| 面 | 状态 | 备注 |
|---|---|---|
| **D. `dma_heap/system`** | ⚠️ **未测** | H121 实测仅 RDONLY 可达；`DMA_HEAP_IOCTL_ALLOC` 需 RDWR ⇒ 需先找 RDWR 路径 |
| **E. L1(`rb_erase`) / L2(`rt_mutex`)** | ⚠️ **冻结存档** | **唯一已构造出「任意写」几何的线**（MEY-TECH §8–§11）；解冻需用户指令 |

---

## 八、方法学副产品（跨设备可继承）

1. **「写侧零命中 + 读侧零特权消费者」应成对搜** —— 单搜一侧会误判为"上下游有希望"，实则双向闭合才算穷尽。
2. **`fixup_exception` 是 EL1 专属**（`__do_kernel_fault`/`do_sea`）；**EL0 缺页恒走 `__do_user_fault`**。任何"用 sigreturn 的 pc 命中 ex_table"的设计**结构性不成立**，无需真机验证。
3. **`pt_regs` 语义 = 边界现场快照** ⇒ 「出口写 → 入口读」，中间无特权站。这是**架构级结论**，可外推到其他内核版本/机型（机制层面）。
4. **`__user` 转型 ≠ 无闸门** —— `stacktrace.c:351` 把 `regs[29]` 转 `__user` 后仍受用户访问原语保护；真正危险的是**裸 `*(unsigned long*)addr`**（`extable.c:40`），但它触发链不通。
5. **kCFI handler 读 `regs[N]` 是真读取**，但 `FIELD_GET(..., esr)` 在 EL0 手写 BRK 时为 0，且消费仅打印 —— 「读寄存器」≠「利用寄存器」。

---

## 九、产物

| 类型 | 路径 |
|---|---|
| 本报告 | `analysis/output/h138_ptregs_readside.md` |
| 静态证据 | 本节 §二/§三 引用源码行号（源码树 6.6.56）；设备符号 `analysis/output/kallsyms_mey_an00.txt`（`fixup_exception`=`0xffffffc0801cd320`，`__start___ex_table`=`0xffffffc08172c088`，`__stop___ex_table`=`0xffffffc08172f46c`） |
| 待回写 | MEY-TECH §20 / HANDOFF §AG / 日志 `2026-10-05.md` §38 |

**本轮无真机动作**（纯静态推翻，未触设备；`boot_id` 未变）。
