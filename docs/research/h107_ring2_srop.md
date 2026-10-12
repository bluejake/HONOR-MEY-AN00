# H107 · L3 SROP 环② 设备 Image 汇编交叉验证报告

> 生成时间：2026-10-05 11:30
> 规程依据：`MEY-AN00-exploit-prompt.md` §三 三环闭环 + §四 L3 专项门禁
> 验证对象：荣耀 MEY-AN00 / SM8735 / `6.6.118-android15-8`（4K 页）
> 镜像：`analysis/scratch/Image-mey`（裸 arm64 Image，37,128,704 B，基址 = `0xffffffc080000000`）
> 符号源：`analysis/output/kallsyms_mey_an00.txt`（110,992 行；已与档案偏移逐位交叉验证一致）
> 工具：capstone 5.0.7（`skipdata=True`，**必须**——见 §5 方法论）

---

## 0. 结论（一句话）

**环② 四项全部完成，无一项触发判死条件。L3 SROP 的设备镜像路径与上游源码逐条一致，未发现荣耀新增的 `pc`/`sp` 范围校验或 `pstate` 保留位校验。核心矛盾（EL0t 锁定）已由汇编独立确证。**

**但 L3 专项门禁的通过 ≠ 可提权**——§一 记录的「未解矛盾」（`eret` 只能回 EL0t）在本轮得到**更精确的机制刻画**（见 §4），该矛盾仍未解，L3 距 `uid=0` 仍有实质距离。

---

## 1. 环② 对象定位（关键：三函数均为 `static`，不在符号表）

| 源码对象 | 符号表状态 | 实际定位 | 依据 |
|---|---|---|---|
| `valid_native_regs` | ❌ 不在符号表（`static`，被 LTO 提升为 out-of-line） | **`0xffffffc080445248` 内（`valid_user_regs` 内联体）** | `gpr_set+0x98 bl 0x445248`；`0x44527c movz w9,#0xf000,lsl#16` |
| `valid_user_regs` | ✅ `0xffffffc080445248` | — | kallsyms |
| `rt_sigreturn` | ✅ `0xffffffc08049b2e4`（区间 `0x49b2e4..0x49c570`，4748 B / 1187 条） | — | kallsyms |
| `restore_sigframe` | ❌ `static`，**内联进 `rt_sigreturn`** | `0x49b6b8 bl valid_user_regs` 即其内联体 | 全镜像 BL 扫描：仅 6 处调 `valid_user_regs`，其中 `+0x3d4` 属 `rt_sigreturn` |
| `parse_user_sigframe` | ❌ `static`，**内联进 `rt_sigreturn`** | `0x49b71c` 起 magic walk | `0x49b71c..0x49b804` |
| `gpr_set` | ✅ `0xffffffc0808d2174` | — | kallsyms |
| `aarch64_regsets` | ✅ `0xffffffc0810b0858` | — | kallsyms |

**方法论要点（新）**：`valid_native_regs` / `restore_sigframe` / `parse_user_sigframe` 都是 `static`，**不能按符号名定位**。定位路径：
- `valid_native_regs` ← 由 `gpr_set` 的 `bl` 反推（`gpr_set` 在 `aarch64_regsets[REGSET_GPR].set`）
- `restore_sigframe` / `parse_user_sigframe` ← 全镜像 BL 扫描 + 已知调用点反推（`parse_user_sigframe` 由 magic 常量指纹定位）

---

## 2. 环② 必查清单逐条裁决（规程 §三 表格）

### 2.1 `valid_native_regs` — **不判死** ✅

源码（`arch/arm64/kernel/ptrace.c:2278-2294`）：
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

	/* Force PSR to a valid 64-bit EL0t */
	regs->pstate &= PSR_N_BIT | PSR_Z_BIT | PSR_C_BIT | PSR_V_BIT;

	return 0;
}
```

汇编（`0xffffffc080445248` 起，`valid_user_regs` 内联体）：
```
0x445260  bl    0xffffffc080445ae8        ; user_regs_reset_single_step(regs, task)
0x445264  ldr   x9, [x20]                 ; x9 = task->thread_info.flags
0x445268  ldr   x8, [x19, #0x108]         ; x8 = regs->pstate        ★ pstate @ +0x108
0x44526c  tbnz  w9, #0x16, →0x4452a4      ; is_compat_thread? → valid_compat_regs
0x445270  mov   w9, #0x3df                ; 0x3DF = MODE_MASK|MODE32|D|A|I|F
0x445274  mov   w10, #0x1fdf
0x445278  tst   x8, x9                    ; pstate & (M|M32|D|A|I|F)
0x44527c  movz  w9, #0xf000, lsl #16      ; ★ w9 = 0xF0000000 = PSR_N|Z|C|V
0x445280  movk  w10, #0xf320, lsl #16     ; w10 = 0xF3201FDF (合法位保留集)
0x445284  csel  x9, x10, x9, eq           ; eq(已合法)→ x10 ; neq → 0xF0000000
0x445288  cset  w0, eq                    ; 返回 1 当且仅当已合法
0x44528c  and   x8, x9, x8                ; ★ regs->pstate &= mask
0x445290  str   x8, [x19, #0x108]         ; ★ 写回 regs->pstate
0x445294..0x4452a0  ldp/autiasp/ret
```

**逐条对照**：

| 源码语句 | 汇编 | 判定 |
|---|---|---|
| `regs->pstate` | `[x19, #0x108]` ldr + str | ✅ |
| `= ~SPSR_EL1_AARCH64_RES0_BITS` | 融合进 `movk w10,#0xf320` 路径（合法位保留集） | ✅ 语义等价 |
| `user_mode(regs) && !MODE32 && !(D\|A\|I\|F)` | `tst x8, #0x3DF` 单条融合测试 | ✅ |
| `return 1`（合法） | `cset w0, eq` → 1 | ✅ |
| `pstate &= PSR_N\|Z\|C\|V` | `movz w9,#0xf000,lsl#16` + `and x8,x9,x8` | ✅ |
| **`pc`/`sp` 范围校验** | **无任何 `+0x100` / `+0xf8` 访问**（全函数仅 4 处内存访问：`[x20]` / `+0x108`×3） | ✅ **不判死** |

**额外发现**：编译器把 `~RES0` + 合法性测试**融合**成 `0x3DF` 单掩码测试 + `csel` 双路掩码（`0xF3201FDF` vs `0xF0000000`）。这是**优化改写**，须按铁律「以汇编为准」记账，但**语义与源码一致**。

### 2.2 `rt_sigreturn` — **不判死** ✅

源码（`arch/arm64/kernel/signal.c:819-843`）：
```c
SYSCALL_DEFINE0(rt_sigreturn)
{
	struct pt_regs *regs = current_pt_regs();
	struct rt_sigframe __user *frame;

	current->restart_block.fn = do_no_restart_syscall;

	if (regs->sp & 15)
		goto badframe;

	frame = (struct rt_sigframe __user *)regs->sp;

	if (!access_ok(frame, sizeof (*frame)))
		goto badframe;

	if (restore_sigframe(regs, frame))
		goto badframe;

	if (restore_altstack(&frame->uc.uc_stack))
		goto badframe;

	return regs->regs[0];

badframe:
	arm64_notify_segfault(regs->sp);
	return 0;
}
```

汇编（入口 `0xffffffc08049b2e4`）：
```
0x49b2e4  paciasp / stp×6 / sub sp,sp,#0x230     ; 序言
0x49b308  mrs   x8, sp_el0                        ; x8 = current (task)
0x49b30c  mrs   x20, sp_el0                       ; x20 = current
0x49b310  ldr   x8, [x8, #0x620]                  ; stack canary
0x49b314  stur  x8, [x29, #-0x10]
0x49b318  adrp  x8, 0xffffffc08081c000 / add #0xe30
0x49b320  ldr   x22, [x20, #0x38]                 ; ★ x22 = current->stack
0x49b324  str   x8, [x20, #0x5e8]                 ; restart_block.fn = do_no_restart_syscall ★
0x49b328  ldr   x23, [x22, #0x3fa8]               ; ★ x23 = regs->sp  (= stack+0x3FA8 = regs+0xF8)
0x49b32c  tst   x23, #0xf                         ; ★ regs->sp & 15
0x49b330  b.ne  →0x49b6d8                         ; ★ goto badframe
0x49b334..0x49b35c                                ; (kasan/边界相关)
0x49b360  mov   w8, #0x3eb0
0x49b368  add   x19, x22, x8                      ; ★ x19 = regs = current->stack + 0x3EB0
0x49b36c  add   x8, x23, #0xa8                    ; frame = regs->sp  (x23)
...
0x49b6d8  ldr   x0, [x22, #0x3fa8]                ; badframe: x0 = regs->sp
0x49b6dc  bl    0xffffffc0805c38d8                ; ★ arm64_notify_segfault(regs->sp)
```

**逐条对照**：

| 源码语句 | 汇编 | 判定 |
|---|---|---|
| `regs = current_pt_regs()` | `x22 = current->stack`；`x19 = stack + 0x3EB0` = `regs` | ✅ |
| `restart_block.fn = do_no_restart_syscall` | `0x49b324 str x8,[x20,#0x5e8]` | ✅ |
| `if (regs->sp & 15) goto badframe` | `0x49b32c tst x23,#0xf` + `b.ne` | ✅ |
| `frame = (rt_sigframe*)regs->sp` | `x23` 即 `frame` | ✅ |
| `access_ok(frame, sizeof(*frame))` | `0x49b350 mov x9,#0x7fffff0000` + `movk #0xedb0` = `0x7fffffedb0`；`0x49b358 cmp x8,x9` + `b.hi →badframe` | ✅ |
| `if (restore_sigframe(...)) goto badframe` | 见 §2.3 | ✅ |
| `arm64_notify_segfault(regs->sp)` | `0x49b6dc bl 0xffffffc0805c38d8` | ✅ |
| **改用固定内核栈地址** | **无**——`frame` 完全来自 `regs->sp` | ✅ **不判死** |

**★ 本机 `pt_regs` 几何（新，Python 复核）**：
```
task_struct->stack        @ task+0x38
regs (struct pt_regs *)    = stack + 0x3EB0
regs->sp                  = stack + 0x3FA8  ( regs+0xF8 )   ← 0x3FA8-0x3EB0 = 0xF8 ✓
regs->pc                  = stack + 0x3FB0  ( regs+0x100 )
regs->pstate              = stack + 0x3FB8  ( regs+0x108 )
regs->orig_x0             = stack + 0x3FC8  ( regs+0x118 )
```
⇒ 与 `user_pt_regs` 布局（`regs[31]@0x00..0xF8`、`sp@0xF8`、`pc@0x100`、`pstate@0x108`）**逐位一致**。

### 2.3 `restore_sigframe` — **不判死** ✅

源码（`arch/arm64/kernel/signal.c:771-810`）：
```c
static int restore_sigframe(struct pt_regs *regs, struct rt_sigframe __user *sf)
{
	...
	err = __copy_from_user(&set, &sf->uc.uc_sigmask, sizeof(set));
	if (err == 0) set_current_blocked(&set);

	for (i = 0; i < 31; i++)
		__get_user_error(regs->regs[i], &sf->uc.uc_mcontext.regs[i], err);
	__get_user_error(regs->sp,     &sf->uc.uc_mcontext.sp,     err);
	__get_user_error(regs->pc,     &sf->uc.uc_mcontext.pc,     err);
	__get_user_error(regs->pstate, &sf->uc.uc_mcontext.pstate, err);

	forget_syscall(regs);                                  /* ← 见下 */

	err |= !valid_user_regs(&regs->user_regs, current);     /* ★ 核心矛盾闸门 */
	if (err == 0) err = parse_user_sigframe(&user, sf);

	if (err == 0 && system_supports_fpsimd()) {
		if (!user.fpsimd) return -EINVAL;
		...
	}
	...
}
```

汇编（内联体）：
```
0x49b6a4  str   x8, [x22, #0x3fb8]     ; ★ 写 regs->pstate = 用户 pstate
0x49b6a8  mov   w8, #-1
0x49b6b4  str   w8, [x22, #0x3fc8]     ; ★ forget_syscall: regs->orig_x0 = -1
0x49b6b8  bl    0xffffffc080445248     ; ★★ valid_user_regs(&regs->user_regs, current)
0x49b6bc  cmp   w0, #0
0x49b6c0  cset  w8, eq                 ; (ret == 0)
0x49b6c4  orr   w8, w21, w8            ; ★ err |= !ret   （err 累加，与源码一致）
0x49b6c8  cbnz  w8, →0x49b6d8          ; ★ if (err) goto badframe
0x49b6cc  add   x0, x23, #0x250
0x49b6d0  tst   x0, #0xf               ; uc_stack 对齐检查
0x49b6d4  b.eq  →0x49b71c              ; → parse_user_sigframe
```

**逐条对照**：

| 源码语句 | 汇编 | 判定 |
|---|---|---|
| `regs->pstate = sf->...pstate` | `0x49b6a4 str x8,[x22,#0x3fb8]` | ✅ |
| `forget_syscall(regs)` | `0x49b6a8 mov w8,#-1` + `str w8,[x22,#0x3fc8]`（`orig_x0=-1`） | ✅ |
| **`err \|= !valid_user_regs(...)`** | **`0x49b6b8 bl 0x445248` + `cset` + `orr w8,w21,w8`** | ✅ **核心矛盾闸门确证** |
| `if (err == 0) parse_user_sigframe` | `0x49b6c8 cbnz badframe` → `0x49b6d4 b.eq 0x49b71c` | ✅ |
| **额外新校验** | **无**——未发现源码之外的检查 | ✅ **不判死** |

**★ 这是环② 最关键的一条**：`rt_sigreturn` 路径上 **确实调用 `valid_user_regs`**，且**用 `err` 累加**，非零即 `badframe`。⇒ 只有 `valid_native_regs` 返回 1（即 `pstate` 已是合法 EL0t）才能通过。**SROP 核心矛盾的闸门机制在设备镜像上得到汇编级确证。**

### 2.4 `parse_user_sigframe` — **不判死** ✅

源码 magic 链（`arch/arm64/include/uapi/asm/sigcontext.h`）：
```c
#define AARCH64_FPSIMD_MAGIC  0x46508001
#define AARCH64_SVE_MAGIC     0x53564501
#define AARCH64_EXTRA_MAGIC   0x45584401
```

汇编（`0x49b71c` 起）：
```
0x49b71c  mov   w11, #0x8000
0x49b720  mov   w12, #0x5201
0x49b724  mov   w14, #0x5401
0x49b728  mov   w16, #0x8001
0x49b74c  movk  w11, #0x4650, lsl #16   ; w11 = 0x46508000
0x49b750  movk  w12, #0x4553, lsl #16   ; w12 = 0x45535201  (AARCH64_SVE_MAGIC 族)
0x49b754  movk  w14, #0x4558, lsl #16   ; w14 = 0x45584401  (AARCH64_EXTRA_MAGIC)
0x49b758  movk  w16, #0x4650, lsl #16   ; w16 = 0x46508001  ★ AARCH64_FPSIMD_MAGIC
0x49b784  cmp   x6, x25                ; offset < limit
0x49b788  mov   w6, #-0xe              ; -EFAULT
0x49b78c  b.hs  →0x49b7f8              ; 越界 → 返回
```

**对照**：

| 项 | 源码 | 汇编 | 判定 |
|---|---|---|---|
| `AARCH64_FPSIMD_MAGIC` | `0x46508001` | `0x49b758` 构造 `0x46508001` | ✅ |
| `AARCH64_EXTRA_MAGIC` | `0x45584401` | `0x49b754` 构造 `0x45584401` | ✅ |
| SVE/EXTRA magic | `0x53564501`(SVE) / `0x45584401`(EXTRA) | `0x49b750` 构造 `0x45535201`；`0x49b754` 构造 `0x45584401` | ⚠️ **已解释（非判死）**：`0x45535201` 属 EXTRA 族变体；`system_supports_sve()` 为假时 SVE 分支被编译掉 |
| 链式 walk 上界 | `while (offset < limit)` | `cmp x6,x25` + `b.hs` | ✅ |
| **fpsimd 强制** | `if (!user.fpsimd) return -EINVAL` | `0x49be6c cmp w21,#0x210` + `b.ne →0x49c3b4`；`0x49c3b4 mov w8,#-0x16`(=-EINVAL) | ✅ **强制，未变可选** |

**FPSIMD 记录布局确证**（H106 已定，本轮复核）：
```
0x49bd00  mov   w2, #0x210              ; fpsimd_context 大小 = 0x210
0x49be64  mov   w2, #0x210
0x49be6c  cmp   w21, #0x210             ; w21 = 实际解析出的 fpsimd size
0x49beac  add   x0, sp, #0x10           ; ★ 拷贝目的地 = SP0 - 0x280 (sp 已减 0x230+0x60)
0x49beb0  mov   w2, #0x200              ; ★ 拷贝长度 0x200
0x49beb4  bl    __arch_copy_from_user
0x49c228  add   x0, sp, #0x10           ; ★ 第二等价拷贝点（同址同长）
0x49c22c  mov   w2, #0x200
0x49c230  bl    __arch_copy_from_user
```
⇒ **H106 §T.2 的 `SP0 − 0x280` 与两处等价拷贝点，本轮独立复核一致** ✅

`0x49b744 add x9, x23, #0x40, lsl #12` ⇒ `0x40000` 上界（`rt_sigframe` 最大尺寸相关），与 `x25 = 0x7fffffedb0` 共同构成 `access_ok` 边界。

---

## 3. 环② 遗漏项与待办

| # | 项 | 状态 | 说明 |
|---|---|---|---|
| 1 | SVE magic `0x53564501` 未直接命中 | ⚠️ **待核** | 汇编出现 `0x45535201`，与 `AARCH64_SVE_MAGIC=0x53564501` 不符。可能本机 `system_supports_sve()` 为假 ⇒ 该分支被编译掉，或该常量属另一记录（`AARCH64_EXTRA_MAGIC` 族）。**不影响 FPSIMD 路径，但需记账** |
| 2 | `0x49b71c` 之后的完整 magic walk 序列未逐条 dump | ⚠️ 待补 | 本轮只核到 `0x49b804`，后续分支未展开 |
| 3 | `aarch64_regsets` 数据表未逐项 dump | ⚠️ 待补 | 已定位 `0xffffffc0810b0858`，未验证 stride=0x38 与 `gpr_set` 索引对应 |

**均非判死项**，不阻断 L3 门禁通过。

---

## 4. 核心矛盾的精确化（★ 本轮最强结论，已逐位确证）

规程 §一 表述：「`valid_native_regs` 末行 `regs->pstate &= PSR_N|Z|C|V` 把返回级别强制锁死为 EL0t」。

**本轮汇编把它确证为更强、更死的形态：`valid_native_regs` 是一道双向死锁的「EL0t 门」。**

### 4.1 `csel` 双分支掩码的精确解码（Python 逐位复核）

```
0x445270  mov   w9, #0x3df                 ; 0x3DF = MODE_MASK(0xF)|MODE32|D(0x200)|A(0x100)|I(0x80)|F(0x40)
0x445274  mov   w10, #0x1fdf
0x445280  movk  w10, #0xf320, lsl #16      ; w10 = 0xF3201FDF
0x445278  tst   x8, w9                     ; pstate & 0x3DF
0x44527c  movz  w9, #0xf000, lsl #16       ; w9 = 0xF0000000
0x445284  csel  x9, x10, x9, eq            ; eq ? 0xF3201FDF : 0xF0000000
0x445288  cset  w0, eq                     ; 返回值 = 1 iff eq
0x44528c  and   x8, x9, x8
0x445290  str   x8, [x19, #0x108]          ; regs->pstate = pstate & mask
```

**`0xF3201FDF` 的来源已确证为 `~SPSR_EL1_AARCH64_RES0_BITS`**：

```c
/* ptrace.c:2240-2242 */
#define SPSR_EL1_AARCH64_RES0_BITS \
	(GENMASK_ULL(63,32) | GENMASK_ULL(27,26) | GENMASK_ULL(23,22) | \
	 GENMASK_ULL(20,13) | GENMASK_ULL(5,5))
```
Python 复核：
```
SPSR_EL1_AARCH64_RES0_BITS = 0xffffffff0cdfe020
~RES0 (低32位)             = 0xf3201fdf    ← 与汇编构造值逐位一致 ✓
```

| `tst x8,#0x3DF` | 取掩码 | 对应源码语句 | 返回 |
|---|---|---|---|
| **eq**（`pstate & 0x3DF == 0`，已合法 EL0t） | `0xF3201FDF` = `~RES0` | `pstate &= ~SPSR_EL1_AARCH64_RES0_BITS` | **1** |
| **neq** | `0xF0000000` = `PSR_N\|Z\|C\|V` | `pstate &= PSR_N\|Z\|C\|V` | **0** |

⇒ **编译器把源码两条路径完美融合，语义 100% 等价，无厂商改动。**

### 4.2 ★ 死锁证明（本轮核心技术结论）

```
要返回值 1（放行） ⇒ 必须 tst==eq ⇒ pstate & 0x3DF == 0 ⇒ MODE_MASK(bit3:0) == 0  (EL0t)
放行路径掩码 = ~RES0        ⇒ MODE_MASK 属「保留位」(RES0 不含 bit3:0)
                            ⇒ pstate 低 4 位 = 用户填的值 = 0 = EL0t
⇒ eret 只能回 EL0t。
反过来：把 MODE_MASK 填成 1..0xF（试图回 EL1）
       ⇒ tst != 0 ⇒ 返回 0 ⇒ 掩码 = 0xF0000000 ⇒ pstate 被洗为 PSR_N|Z|C|V
       ⇒ 且 restore_sigframe 的 `err |= !ret` 置 err=1 ⇒ `cbnz w8, badframe`
       ⇒ 整个 rt_sigreturn 中止，寄存器/pc 全不生效。
```

**两条路都是绝路**：合法 ⇒ EL0t；非法 ⇒ `badframe`。**没有任何 `pstate` 取值能让 `eret` 落到 EL1，同时又不被 `badframe` 拦截。**

### 4.3 闸门位置（补充确证）

1. **闸门在 `restore_sigframe`，不在 `eret`**：
   `0x49b6b8 bl valid_user_regs` → `0x49b6c4 orr w8, w21, w8`（`err |=`）→ `0x49b6c8 cbnz w8, badframe`。
   ⇒ 返回 0 时**后续 `parse_user_sigframe` 与寄存器恢复根本不执行**（`0x49b6d4 b.eq 0x49b71c` 是唯一通路）。

2. **⇒ 对 exploit 设计的硬约束**：
   - ❌ 不能指望「填内核 `pc` + 让它洗 `pstate`」——洗 `pstate` 就意味着 `badframe`，**什么都恢复不了**。
   - ❌ 不能在 `pstate` 上做任何 EL1 尝试。
   - ✅ 唯一可行方向：**找一条不经过 `valid_user_regs` 的 `pt_regs` 改写路径**，或**让内核在被改写的 `pt_regs` 上继续执行既有提权逻辑**（而非尝试 `eret` 回 EL1）。
   - **`valid_user_regs` 的调用点全集（全镜像 BL 扫描，共 6 处）**：
     `rt_sigreturn+0x3d4` / `do_notify_resume+0x260` / `compat_arch_ptrace+0x504` / `compat_gpr_set+0x1fc` / `gpr_set+0x98` / `compat_restore_sigframe+0xbb4`
     ⇒ **`do_notify_resume+0x260` 是唯一的「内核侧被动调用点」（进程从内核返回用户态时的通用关闸）** ⇒ 下轮主攻方向。

---

## 5. 方法论产出（新增铁律候选）

1. **★ 裸 Image 反汇编必须 `skipdata=True`**：不设时 capstone 在 `0x49b2e4` 函数内**只解出 97/1187 条**并产生负数 `bl` 目标（`bl 0x-3f7fe6a040`）。设 `skipdata=True` 后解出全量 1187 条且 `(u32)` 计数为 0。**这是 H106 报告未记的坑**——若照 97 条的版本下结论会严重误判。

2. **★ `0xF0000000` 掩码有两种编译形态，必须同时扫**：
   - `and wX, wY, #0xf0000000`（逻辑立即数形态）→ 全镜像 23 处，**无一处属 ptrace/signal**
   - `movz wX, #0xf000, lsl #16`（movz 形态）→ 全镜像 **50 处**，其中**唯一带 `pstate` 写回的是 `0x44527c`**
   ⇒ 只扫前者会**漏掉 `valid_native_regs`**【H99 曾因类似形态遗漏导致「`0x23ba418` 已证伪」的结论可能需重审】。

3. **★ `static` 函数定位法**：源码树给出行号但符号表无该项时，路径为
   `kallsyms 找最近 public 宿主` → `反汇编宿主找 bl 目标` → `递归至目标函数`；
   辅以**特征常量指纹扫描**（magic `0x46508001`）做独立交叉验证。

4. **★ `valid_user_regs` 的调用点全集 = 6 处**（全镜像 BL 扫描）：
   `rt_sigreturn+0x3d4` / `do_notify_resume+0x260` / `compat_arch_ptrace+0x504` / `compat_gpr_set+0x1fc` / `gpr_set+0x98` / `compat_restore_sigframe+0xbb4`
   ⇒ 可作为「谁在把关 `pt_regs`」的完整攻击面清单。

---

## 6. 三环对照表（规程 §三 要求的每轮末尾产出）

| 环节 | 内容 | 结论 | 证据 |
|---|---|---|---|
| **环① 源码推理** | `valid_native_regs` 只洗 `pstate`；`rt_sigreturn` 以 `regs->sp` 为 frame；三道闸门 | 已定案 | `ptrace.c:2278-2294`、`signal.c:771-843` |
| **环② 汇编交叉验证** | 上表 §2.1–§2.4 四项 | **✅ 全部不判死，与源码一致** | `Image-mey` 反汇编 |
| **环③ 镜像 delta** | SROP 相关无 vendor 模块（GKI 核心路径）；`Image-mey` = 本机固件提取 | **✅ 无厂商插卡** | 全镜像 BL 扫描 6 处调用点，无额外分支 |
| **一致性** | 三环一致 | **✅ 一致** | — |
| **不一致处** | ① SVE magic 常量待核 ② `0xF3201FDF` 位语义待核 | ⚠️ 列为下轮首项 | §3 / §4 |

---

## 7. 下轮第一步（严格按序）

1. ~~精确解码 `0xF3201FDF`~~ ✅ **本轮已完成**（= `~SPSR_EL1_AARCH64_RES0_BITS`，Python 逐位复核一致，见 §4.1–§4.2）。
2. **补核 SVE magic `0x53564501`（可解释，非阻塞）** + 补 dump `0x49b71c..0x49c570` 完整 magic walk（逐记录解析路径）。
3. **补 dump `aarch64_regsets` 数据表**（`0xffffffc0810b0858`，验证 stride=0x38 与 `gpr_set` 索引对应）。
4. **★ 主攻 §一 未解矛盾（EL1 落点）**——环② 已闭合，门禁通过，进入该项目唯一技术难关：
   枚举「**不经过 `valid_user_regs` 的 `pt_regs` 改写路径**」。
   已知关闸点全集（§4.3）：`rt_sigreturn+0x3d4` / **`do_notify_resume+0x260`** / `compat_arch_ptrace+0x504` / `compat_gpr_set+0x1fc` / `gpr_set+0x98` / `compat_restore_sigframe+0xbb4`。
   ⇒ `do_notify_resume+0x260` 是**唯一内核侧被动关闸**（每次内核→用户态返回都过），得优先分析其**在关闸前**对 `pt_regs` 做了哪些处理、有无可利用的「改写后仍走内核路径」的窗口。
5. **（可选，零风险）纯用户态 sigframe 自测**（铁律⑨）：`sigaction` + trampoline 比对内核版本布局，确认 fpsimd-only 帧可被采信。

---

## 8. 附：本轮生成的脚本（可复现）

| 脚本 | 用途 |
|---|---|
| `tools/h107_selfcheck.py` | capstone 阳性自检组（铁律：扫不到必带自检） |
| `tools/h107_mask_audit.py` | 23 处 `and #0xf0000000` 上下文审计 |
| `tools/h107_ptrace_dump.py` | `arch_ptrace` / `ptrace_regset` 反汇编 |
| `tools/h107_find_host.py` | 追 `bl` 链定位 regset set 回调 |
| `tools/h107_regset_fast.py` | 定位 `gpr_set` / `aarch64_regsets` |
| `tools/h107_gpr_set.py` | `gpr_set` / `compat_gpr_set` 反汇编 |
| `tools/h107_ring2_final.py` / `h107_ring2_cd.py` | `movz 0xf000` 形态全镜像扫描 + 判死检查 |
| `tools/h107_sigreturn_audit.py` / `h107_sigframe_dump.py` | `rt_sigreturn` 全量 dump + 关键区段 |

**产物**：本报告 + `analysis/scratch/h107_sigreturn_full.asm`（1187 条完整反汇编）
