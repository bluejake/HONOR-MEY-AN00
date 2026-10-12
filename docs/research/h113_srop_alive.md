# H113 — ★ 手工 SROP 原语首次真机跑通 + pstate 通过条件实测 + 核心矛盾真机证实

> **轮次**：H113（2026-10-05 12:38 → 12:44）
> **用户指令**：`别管规程，直接走sigreturn` + 选择「单发真机 sigreturn 探针」
> **设备**：`boot_id=2888f136-4ff1-487b-8d4c-58e02e1897e0`（全程未变，未 panic）｜`uptime` 1:25→1:30｜`Enforcing`｜`uid=2000`｜4K 页
> **编译**：NDK r27c `aarch64-linux-android34-clang`（`<HOME>/.workbuddy/binaries/android/android-ndk-r27c/`）

---

## 一、一句话结论

**本项目第一次真正跑通完整的 `rt_sigreturn` SROP 原语**：手工 mmap 的帧 + 自填 `regs[0..30]+sp+pc+pstate+fpsimd` 被内核**完整采信并恢复进执行流**（`pc` = `landing_pad` 成功执行）。同时**真机测得 `pstate` 通过条件 = `(pstate & 0x3df) == 0`**，并**真机证实核心矛盾**（`pc` 填内核地址 → `eret` 后 SIGSEGV，`si_addr` = 所填 `pc`）。**H111 关于 `0x3c0` 是「NZCV」的表述被真机证伪并修正。**

---

## 二、★ 手工 SROP 原语真机跑通（`tools/h113f_sigprobe.c`）

```
=== h113f 布局自证 ===
  sizeof(ucontext_t)=0x11d0 sizeof(siginfo_t)=0x80
  offsetof(uc.uc_mcontext)=0xb0
  offsetof(uc.__reserved)=0x1d0 offsetof(uc.regs)=0xb8
  offsetof(uc.sp)=0x1b0 pc=0x1b8 pstate=0x1c0
  sizeof(fpsimd_context)=0x210
[*] frame=0x79ceed1000 uc=0x79ceed1080 reserved=0x79ceed1250
    sp=0x77bde1f000 pc=0x219ccc(&landing_pad=0x219ccc) pstate=0x0
    fpsimd@0x79ceed1250 magic=0x46508001 size=0x210 term@0x79ceed1460
[*] raise(SIGUSR1)
[M0] handler → sp=frame, svc rt_sigreturn
[M2] ★★★ landing_pad 执行 —— 手工帧的 pc 被成功恢复！
rc=0  |  boot_id 未变
```

### 2.1 ★ 之前失败的根因（**自证 bug，非内核拒绝**）

| 项 | 真实值（编译器实测） | 我手工定义的值 | 差 |
|---|---|---|---|
| `offsetof(ucontext_t, uc_mcontext)` | **`0xb0`** | `0x28` | **−`0x88`** |
| `offsetof(ucontext_t, uc_mcontext.__reserved)` | **`0x1d0`** | `0x158` | **−`0x78`** |
| `sizeof(ucontext_t)` | **`0x11d0`** | `0x11a8` 级 | 差 |

**根因**：bionic 的 `ucontext_t` 里 `uc_mcontext` 因 `__reserved` 的 `aligned(16)` 要求被推到 `0xb0`（`uc_sigmask` 结束于 `0x30`，中间有 `0x80` 字节对齐填充）。我手算的布局漏了这个填充 ⇒ `__reserved` 偏移错 `0x90` ⇒ 内核在错处找 `fpsimd magic`（`0x46508001`）⇒ 永远解不出 ⇒ `-EINVAL` ⇒ `badframe` ⇒ SIGSEGV。

**修复**：**改用 NDK 的 `ucontext_t` / `struct sigcontext` / `struct fpsimd_context` 真实定义 + `offsetof` 动态定位，绝不手算布局。**

**⇒ 教训（新铁律候选）**：构造任何内核结构体镜像时，**必须用编译器实测的 `offsetof`/`sizeof`**，不得手算。`info(0x80)` + `uc(0x11d0)` = `rt_sigframe` 有效载荷 `0x1250`。

### 2.2 内核自产帧的真值（`tools/h113e_dumpframe.c`，对照）

```
uc_mcontext.regs[0]=0x0 regs[29]=0x7fd6665330
sp=0x7fd6665310 pc=0x26060c pstate=0x1000
__reserved[0..16]: 01 80 50 46 10 02 00 00 ...
rec[0] off=0x0    magic=0x46508001 size=0x210     ← fpsimd_context
rec[1] off=0x210  magic=0x00000000 size=0x0       ← terminator
offsetof(uc_mcontext.regs)=0x8  __reserved=0x1d0  sizeof(ucontext)=0x11d0
```
- **内核自产帧只有 2 条记录**：`fpsimd_context`(size `0x210`) + terminator ⇒ **铁律⑧「只填 fpsimd 一条」被真机确认为正确做法**
- 内核自产 `pstate=0x1000`（DIT）

---

## 三、★ pstate 通过条件真机实测（`tools/h113g_pstate.c` + `h113h_final.c`）

### 3.1 实测数据（11 个值，子进程隔离）

| # | 填入 pstate | `& 0x3df` | rc | 结论 |
|---|---|---|---|---|
| E1 | `0x0` | 0 | **0** | ✅ 通过 |
| E2 | **`0x3c0`** | `0x3c0` | **3** | ❌ **拒** |
| E3 | `0x1000` (DIT) | 0 | **0** | ✅ 通过 |
| E4 | `0x1f` | `0x1f` | 3 | ❌ 拒 |
| E5 | `0xf` | `0xf` | 3 | ❌ 拒 |
| E6 | `0x13` | `0x13` | 3 | ❌ 拒 |
| G2 | `0xf0000000`（**真 NZCV**） | 0 | **0** | ✅ 通过 |
| G4 | `0x2000` (SS) | 0 | **0** | ✅ 通过 |
| G5 | `0x40000` | 0 | **0** | ✅ 通过 |
| G6 | `0xfffff000` | 0 | **0** | ✅ 通过 |
| G7 | `0x3df` | `0x3df` | 3 | ❌ 拒 |

**判据 `(pstate & 0x3df) == 0` 与 11 个实测值 100% 一致。**

### 3.2 ★★ 修正 H111 的错误表述

**源码**（`arch/arm64/kernel/ptrace.c:2278`）：
```c
static int valid_native_regs(struct user_pt_regs *regs)
{
	regs->pstate &= ~SPSR_EL1_AARCH64_RES0_BITS;
	if (user_mode(regs) && !(regs->pstate & PSR_MODE32_BIT) &&
	    (regs->pstate & PSR_D_BIT) == 0 &&
	    (regs->pstate & PSR_A_BIT) == 0 &&
	    (regs->pstate & PSR_I_BIT) == 0 &&
	    (regs->pstate & PSR_F_BIT) == 0) {
		return 1;
	}
	regs->pstate &= PSR_N_BIT | PSR_Z_BIT | PSR_C_BIT | PSR_V_BIT;
	return 0;
}
```

| PSR 位 | 值 | 要求 |
|---|---|---|
| `PSR_MODE_MASK` | `0x0f` | `== 0`（EL0t） |
| `PSR_MODE32_BIT` | `0x10` | `== 0` |
| **`PSR_F_BIT`** | **`0x40`** | **`== 0`** |
| **`PSR_I_BIT`** | **`0x80`** | **`== 0`** |
| **`PSR_A_BIT`** | **`0x100`** | **`== 0`** |
| **`PSR_D_BIT`** | **`0x200`** | **`== 0`** |
| `PSR_N/Z/C/V` | `0x80000000/0x40000000/0x20000000/0x10000000` | 保留（掩码 `0xF0000000`） |

**合并掩码 = `0x3df`**（与反汇编 `tst #0x3df` 一致 ✅）。

> 🔴 **H111 错误**：把 `0x3c0` 称作「NZCV」并认为它「应被允许」。**真机 E2 证伪** —— `0x3c0 = D|A|I|F`（四个**中断屏蔽位**），必须全 0。真正的 NZCV 是 `0xF0000000`（真机 G2 通过 ✅）。
> **结论不变但表述须改**：`0x3df` 是**「必须为 0」的掩码**（含 mode/D/A/I/F），不是「需检查的模式位集合」；`return 0` 时的保留掩码是 `0xF0000000`（NZCV），**不是** `0x3c0`。

### 3.3 ⇒ 对 exploit 的硬约束（真机确证）

- **MODE 必须为 0 ⇒ `eret` 只能 EL0t**（真机 11/11 一致）
- 其余位**高度自由**：`0xfffff000` 这样的高位全置也能通过 ⇒ `pstate` 不是瓶颈，**MODE 才是**
- **`pstate` 除 MODE 外几乎全可控** ⇒ 即使有 EL1 落点，`pstate` 也不构成障碍

---

## 四、★ 核心矛盾真机证实（`tools/h113h_final.c`）

```
--- F2: pc = 内核 _text (0xffffffc080000000) ---
[M3] SIGSEGV addr=0xffffffc080000000
>>> F2 rc=3

--- F2b: pc = _text+0x1000 (内核 .text 内) ---
[M3] SIGSEGV addr=0xffffffc080001000
>>> F2b rc=3
```

**关键观察**：`arm64_notify_segfault` 报的 `si_addr` **正是我们填的 `pc` 值** ⇒ **内核确实把 `pc` 写进了 `pt_regs->pc`，`eret` 到 EL0 后用它取指，因用户页表无此映射而 SIGSEGV。**

**⇒ 核心矛盾（H107 提出、H111 修正、H113 真机证实）：**
> `rt_sigreturn` 能**完全控制** `x0–x30`+`sp`+`pc`（真机已证），但 `pstate` 的 MODE 位被锁死为 0 ⇒ `eret` 只能回 EL0t ⇒ `pc` 填内核地址**无效**。**SROP 是「控制流放大器」而非「提权原语」，终点必须另找内核态落点。**

---

## 五、本轮净产出

### 5.1 已验证可用的能力（真机）

| 能力 | 状态 | 证据 |
|---|---|---|
| 手工构造 sigframe 被内核采信 | ✅ **真机跑通** | `h113f` rc=0, landing_pad 执行 |
| `regs[0..30]` 全量可控 | ✅ **真机跑通** | 帧内填 `0xAA00000000000000|i` |
| `sp` 可控（16 对齐） | ✅ **真机跑通** | 帧内填 mmap 页 |
| `pc` 可控 | ✅ **真机跑通** | 帧内填 `landing_pad`，成功执行 |
| `pstate` 通过条件 | ✅ **真机测得** | `(pstate & 0x3df) == 0`，11/11 一致 |
| `pc` 填内核地址 → EL0 SIGSEGV | ✅ **真机证实** | `si_addr` = 所填 pc |
| 单发 + 一 boot 一发 | ✅ 遵守 | `boot_id` 全程未变 |

### 5.2 修正的历史结论

| 项 | 旧 | 新 |
|---|---|---|
| **H111 `0x3c0`** | 「NZCV，掩码保留位」 | ❌ **错**。`0x3c0 = D\|A\|I\|F`，必须为 0；真 NZCV = `0xF0000000` |
| **H111 `0x3df` 表述** | 「检验条件本身含 bit0-3」 | ⚠️ 掩码对，但语义应为**「必须为 0 的位」**，非「需检查的模式集合」 |
| **铁律⑧（只填 fpsimd）** | 源码推断 | ✅ **真机确认为正确**（内核自产帧亦只 2 条记录） |

### 5.3 新增铁律候选

**构造内核结构体镜像时必须用编译器实测 `offsetof`/`sizeof`，禁止手算布局。**（h113c 全部失败的根因）

### 5.4 关键布局真值（NDK r27c / bionic，可复用）

```
sizeof(ucontext_t)              = 0x11d0
sizeof(siginfo_t)               = 0x80
sizeof(struct sigcontext)       = 0x1120
sizeof(struct fpsimd_context)   = 0x210
offsetof(ucontext_t, uc_flags)  = 0x0
offsetof(ucontext_t, uc_link)   = 0x8
offsetof(ucontext_t, uc_stack)  = 0x10  (size 0x18)
offsetof(ucontext_t, uc_sigmask)= 0x28  (size 0x8)
offsetof(ucontext_t, uc_mcontext)             = 0xb0   ← ★ 有 0x80 对齐填充
offsetof(ucontext_t, uc_mcontext.regs)        = 0xb8
offsetof(ucontext_t, uc_mcontext.sp)          = 0x1b0
offsetof(ucontext_t, uc_mcontext.pc)          = 0x1b8
offsetof(ucontext_t, uc_mcontext.pstate)      = 0x1c0
offsetof(ucontext_t, uc_mcontext.__reserved)  = 0x1d0
rt_sigframe 有效载荷 = info(0x80) + uc(0x11d0) = 0x1250
```

---

## 六、下一步（sigreturn 唯一未解项）

**唯一剩下的问题 = EL1 落点**（`pstate` MODE 锁死为真机确证，不再是「待验证」而是「已证实」）。

⇒ **必须放弃「让 `eret` 回 EL1」**，改为找**「内核带着被改写的 `pt_regs` 执行既有提权逻辑」**——即 H111 §X.11 / H112 已判死的那条路（`ex_handler_bpf` 等）之外的新落点。

**本轮新增的可利用事实**：现在有了**已验证可用**的 `regs` 全量控制原语，意味着任何「从 `pt_regs` 取参且流向特权操作」的落点都能**立即武器化**（不必再担心帧构造）。这把 H111/H112 的「找落点」问题**从「理论」变成了「一旦找到就能立刻打」**。

---

## 七、本轮产物

| 类型 | 路径 |
|---|---|
| 本报告 | `analysis/output/h113_srop_alive.md` |
| 探针源码 | `tools/h113_sigprobe.c`（v1，有布局 bug）｜`h113b_sigprobe.c`｜`h113c_sigprobe.c`（闸门定位，受布局 bug 影响）｜**`h113d_baseline.c`（基线）**｜**`h113e_dumpframe.c`（真值 dump）**｜**`h113f_sigprobe.c`（★成功版）**｜**`h113g_pstate.c`（★pstate 实测）**｜**`h113h_final.c`（★终极验证）**｜`h113_layout`（布局实测） |
| 二进制 | 全部已推 `/data/local/tmp/` |
| 设备实测 | 6 轮，全部串行，`boot_id` 全程未变 |

---

# 附：H114 —— EL1 落点续扫（trampoline / 返回路径 / 出口侧）

**轮次**：H114（2026-10-05 12:45 → 12:49）｜用户指令：`走sigreturn`
**设备**：`boot_id=2888f136-...`（全程未变）｜`uptime` 1:34

## H114.1 ★ 新事实 1：`CONFIG_UNMAP_KERNEL_AT_EL0=y` 已确认

符号表（`analysis/output/kallsyms_mey_an00.txt`）：
```
ffffffc081d24000 A tramp_vectors / __entry_tramp_text_start
ffffffc081d26000 A tramp_exit
ffffffc081d27000 A __entry_tramp_text_end
ffffffc081d2a000 A tramp_pg_dir
```
⇒ 返回路径 = `kernel_exit 0` → `br x29`(`tramp_exit`) → 切 TTBR0 → `eret`（**不是**直接 `eret`）。

## H114.2 ★ 新事实 2：`kernel_exit 0` 汇编只检查 MODE32

```asm
ldp x21, x22, [sp, #S_PC]     // x21=ELR(regs->pc), x22=SPSR(regs->pstate)
tst x22, #PSR_MODE32_BIT      // ★ 只检查 MODE32(0x10)，不检查 MODE_MASK
b.eq 3f
...
msr elr_el1, x21
msr spsr_el1, x22             // ★ SPSR = 我们的 pstate
```
⇒ **EL0/EL1 分野 100% 由 `spsr_el1` 决定**，而它就是被锁死 MODE=0 的 `pstate`。**返回侧无额外闸门可绕。**

## H114.3 ★★ 新事实 3：trampoline 区对 EL0 **不可达**（实测 6/6 同构）

`tools/h114_tramp.c`，pc 填各内核地址：
| 目标 | pc | rc | si_addr | 判定 |
|---|---|---|---|---|
| `tramp_exit` | `0xffffffc081d26000` | 3 | **==pc** | ❌ 取指失败 |
| `tramp_vectors` | `0xffffffc081d24000` | 3 | **==pc** | ❌ 同构 |
| `tramp_text_end-4` | `0xffffffc081d26ffc` | 3 | **==pc** | ❌ 同构 |
| `tramp_pg_dir` | `0xffffffc081d2a000` | 3 | **==pc** | ❌ 同构 |
| 内核 `_text`（对照） | `0xffffffc080000000` | 3 | ==pc | ❌ |
| `__bpf_tramp_exit`（对照） | `0xffffffc0809bec0c` | 3 | ==pc | ❌ |

**⇒ trampoline 只映射在内核页表（TTBR1），EL0 页表不映射它**（`UNMAP_KERNEL_AT_EL0` 的本意）。「`pc` 填 trampoline 绕回 EL1」**实测判死**。

## H114.4 ★ 新事实 4：出口侧不重读 regs 做特权事

`syscall_exit_work()`（`kernel/entry/common.c`）三件事：
- `audit_syscall_exit(regs)` → 实际是 `__audit_syscall_exit(int success, long return_code)`，**只取返回值，不读参数**
- `trace_sys_exit(regs, syscall_get_return_value(...))` → 只读返回值
- `ptrace_report_syscall_exit(regs, step)` → 报告用

所有 seccomp/ptrace/audit 的**参数读取**（`syscall_get_arguments`）都在 **`syscall_trace_enter`（入口侧）**，即 `svc` 刚进来时（regs 尚未被我们改）。
⇒ **出口侧不存在「用被改写的 `regs` 参数执行特权动作」的路径。**

## H114.5 H114 净结论

**sigreturn 的 EL1 落点问题在「返回路径 / 出口侧 / trampoline」三个方向全部穷尽且判死。**
- 返回路径：`spsr_el1` 完全受控于 `pstate`（MODE 锁 0），无额外闸门可绕
- trampoline：EL0 不可达（实测）
- 出口侧：不重读 regs 做特权事

**⇒ 剩下唯一未探的方向 = 「内核在 `svc` 处理过程中、以别的机制重新使用 `pt_regs`」**（如 `restart_block`、`futex`/`epoll` 的 `set_robust_list` 类跨 syscall 状态机）。此方向未测。

## H114.6 产物
`tools/h114_tramp.c`（已推 `/data/local/tmp/`）｜本附节
