# 继续深挖sigreturn：CVE-2026-43499、CVE-2026-64560H139 · sigreturn 真机重跑 + H138 推论实证

> 日期：2026-10-05 13:48  
> 设备：MEY-AN00 · SM8735 · 内核 `6.6.118-android15-8` · `boot_id = 2888f136-4ff1-487b-8d4c-58e02e1897e0`（**全程未变**）  
> 用户指令：**重跑 sigreturn 真机探针**  
> 方式：真机单发（5 针，各自独立 fork 子进程），**纯用户态**（不碰内核结构）  
> 结论：**T1/T2 复现成功（H113 结论成立）；T3/T4/T5 钉死 H138 推论**

---

## 零、一句话结论

**H113「手工 SROP 帧被完整采信、`pc` 被恢复」在本 boot 上复现成功（T1/T2 rc=0）。**  
**H138「EL0 取指缺页走 `__do_user_fault`，不进 `search_exception_tables`」真机实证（T4/T5 填真实 `__ex_table`/`fixup_exception` 地址，仍得普通 `SEGV_MAPERR`，无任何 fixup 迹象）。**

---

## 一、探针设计（5 针，各自独立 fork）

| 针       | `pc` 填值                                       | 期望      | 意义                             |
| ------- | --------------------------------------------- | ------- | ------------------------------ |
| T1      | `landing_pad`（用户态）+ `pstate=0`                | rc=0    | 复现 H113「帧被采信」                  |
| T2      | 同上（对照重复）                                      | rc=0    | 确认稳定                           |
| T3      | `_text+0x100000`（内核 text）                     | SIGSEGV | 复现 H113「内核 pc → SIGSEGV」       |
| **T4★** | **`__start___ex_table = 0xffffffc08172c088`** | SIGSEGV | **H138 推论：真实异常表段内也不 fixup**    |
| **T5★** | **`fixup_exception = 0xffffffc0801cd320`**    | SIGSEGV | **H138 推论：即便指向 fixup 本体也不被调用** |

**帧构造**：`struct frame_t { char pad[0x80]; ucontext_t uc; }`（`siginfo` 0x80 之后紧接 `ucontext`），  
用**真实 `ucontext_t`/`mcontext_t` 类型**（**禁手算**，遵守 H113 铁律），`fpsimd_context` 写在 `__reserved` 起始。

---

## 二、★ 真机结果（h139f，md5 `1a769362741d1d4215584bbd7cc205e0`）

```
=== h139f uid=2000 ===
sizeof(ucontext_t)=0x11d0 uc_mcontext@0xb0 sp@0x100 pc@0x108 pstate@0x110

=== T1 pc=landing_pad pstate=0 ===
 pc=0x0000000000219e0c pstate=0x0
[T1] ★★★ landing_pad EXECUTED
[T1] rc=0 (期望0)                            ← ✅ 帧被完整采信

=== T2 pc=landing_pad pstate=0x0 ===
[T1] ★★★ landing_pad EXECUTED
[T2] rc=0 (期望0)                            ← ✅ 稳定复现

=== T3 pc=K_TEXT+0x100000 ===
 pc=0xffffffc080100000 pstate=0x0
[SEGV] sig=11 code=1 si_addr=0xffffffc080100000  frame.pc=0xffffffc080100000 frame.sp=0x0000007d0887c000
[T3] rc=2                                     ← ✅ si_addr == 所填 pc

=== T4* pc=__start___ex_table ===
 pc=0xffffffc08172c088 pstate=0x0
[SEGV] sig=11 code=1 si_addr=0xffffffc08172c088  frame.pc=0xffffffc08172c088
[T4] rc=2                                     ← ★ si_addr == ex_table 地址，无 fixup

=== T5* pc=fixup_exception ===
 pc=0xffffffc0801cd320 pstate=0x0
[SEGV] sig=11 code=1 si_addr=0xffffffc0801cd320  frame.pc=0xffffffc0801cd320
[T5] rc=2                                     ← ★ 同上

=== 完成 ===
__EXIT=0
boot_id = 2888f136-4ff1-487b-8d4c-58e02e1897e0（未变）｜uptime 2:34（仅 +1 min）
```

| 针         | 结果                                      | 判读                                                       |
| --------- | --------------------------------------- | -------------------------------------------------------- |
| **T1/T2** | `landing_pad EXECUTED`，rc=0             | **★ H113 复现成功**：`rt_sigreturn` 确实恢复了 `pc`；`pstate=0` 被接受 |
| **T3**    | `code=1`（`SEGV_MAPERR`），`si_addr == pc` | 内核地址取指缺页 → 普通 SIGSEGV                                    |
| **T4**    | `code=1`，`si_addr == 0x81572c088`       | **★ 落在真实 `__ex_table` 段内，仍未触发 fixup**                    |
| **T5**    | `code=1`，`si_addr == fixup_exception`   | **★ 即便 `pc` 指向 `fixup_exception` 本体，它也不被调**              |

---

## 三、★ H138 推论 → 真机实证

**H138 静态论证**：`fixup_exception` 三调用点全在 EL1/SEA 侧（`fault.c:402` `__do_kernel_fault`｜`:434` EFI｜`:828` `do_sea`）；  
**EL0 缺页走 `__do_user_fault` ⇒ `arm64_notify_segfault`，压根不到 `search_exception_tables`**。

**T4/T5 真机钉死**：`pc` 精确填在

- **真实 `__start___ex_table`（`0xffffffc08172c088`）** —— T4
- **`fixup_exception` 函数本体（`0xffffffc0801cd320`）** —— T5

内核给的**仍是普通 `SEGV_MAPERR` + `si_addr` == 所填 pc**，**无任何 fixup 迹象**（若 fixup 被触发，`regs->pc` 会被改成 `get_ex_fixup(ex)`，`si_addr`/行为完全不同）。

**⇒ 「用 sigreturn 的 pc 命中 `ex_table` 拿裸解引用（`extable.c:40`）」这条路：静态（H138）+ 真机（H139 T4/T5）双证死透。**

---

## 四、★ 探针纪律教训（本轮实际发生的坑）

### 坑①：手算 `ucontext` 布局（浪费 4 轮）

**第一版探针（h139/h139b/h139c/h139d）全部"失败"**（T1 也 SIGSEGV），一度疑似 H113 结论不可复现。

**根因**：我**手算**了 `ucontext_t` 布局：

| 字段                                  | 真值（`offsetof` 实测） | 我手算   | 偏差         |
| ----------------------------------- | ----------------- | ----- | ---------- |
| `offsetof(ucontext_t, uc_mcontext)` | **0xb0**          | 0x30  | **差 0x80** |
| `offsetof(mcontext_t, sp)`          | **0x100**         | 0xF8  | 差 8        |
| `offsetof(mcontext_t, pc)`          | **0x108**         | 0x100 | 差 8        |
| `offsetof(mcontext_t, pstate)`      | **0x110**         | 0x108 | 差 8        |

- `uc_mcontext` 前有 `uc_flags`(8)+`uc_link`(8)+`uc_stack`(24)+**`uc_sigmask` 内联副本(0x80)** = **0xb0**
- `mcontext_t` 里 `regs` 前有 **`fault_address`(8)** ⇒ `sp=0x8+0xF8=0x100`

**⇒ 违反 H113 铁律「构造内核结构体镜像必须用编译器实测 `offsetof`/`sizeof`，禁止手算」**（我明知有此铁律仍手算）。  
**修正**：h139f 改用**真实 `ucontext_t`/`mcontext_t` 类型**（`#include <ucontext.h>`），一次通过。

### 坑②：`mov sp` 后 handler 自身栈不可用 ⇒ SIGSEGV 绕过 handler

**现象**：早期版本崩溃时 `segv_handler` **完全无输出**，疑似"内核绕过 handler"。  
**根因**：`usr1_handler` 里 `mov sp, frame` 之后，**handler 自己的 C 代码/`write(2)` 调用无有效栈** ⇒ 二次 fault ⇒ 进程被强杀。  
**修正**：给 SIGSEGV handler 挂 **`sigaltstack` + `SA_ONSTACK`** ⇒ handler 立刻收到信号，拿到干净 `si_addr`。  
**教训**：**任何"移动 `sp`"的探针，其 handler 必须用 `sigaltstack`**（跨设备可继承）。

### 坑③：`-fno-stack-protector` 必须保留（沿用）

---

## 五、★ 对 SROP 判死的最终确认

本轮**真机复现**了 H113 的两个关键事实（帧被采信 + 内核 pc → SIGSEGV），**未发现任何新可利用面**。  
结合 H138 的读侧穷尽，SROP/信号域**六维度全部闭合**（控制流 / 帧解析 / 帧构造 / 返回侧 / 写侧 / 读侧）。

**本轮新增的数据点（T4/T5）是判死链条的最后一块拼图**：证明「`pc` 命中 `ex_table` 拿任意读」不可行。

---

## 六、产物

| 类型   | 路径 / 值                                                                                                       |
| ---- | ------------------------------------------------------------------------------------------------------------ |
| 正式探针 | `tools/h139f_final.c` → 设备 `/data/local/tmp/mey/h139f`（md5 `1a769362741d1d4215584bbd7cc205e0`）               |
| 布局实测 | `tools/h139e_offset.c`（`uc_mcontext@0xb0 sp@0x100 pc@0x108 pstate@0x110`）                                    |
| 失败存档 | `h139_sigprobe_diff.c`（fork 版）、`h139b_diag.c`、`h139c_mark.c`、`h139d_altstk.c`（**留作教训：手算布局 + 缺 sigaltstack**） |
| 设备符号 | `__start___ex_table=0xffffffc08172c088`｜`fixup_exception=0xffffffc0801cd320`                                 |

**设备状态**：`boot_id` 全程未变｜`uptime` 2:33→2:34（无重启）｜`Enforcing`｜`uid=2000(shell)`
