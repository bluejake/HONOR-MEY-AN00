# H111 — `ptrace` 侧 EL1 落点判定（正式裁定）+ `badframe` 链证伪

- 轮次：H111
- 日期：2026-10-05
- 设备：MEY-AN00 / MagicOS 10.0.0.175 / SM8735 / 内核 `6.6.118-android15-8` / 4K 页
- Image：`analysis/scratch/Image-mey`（`0x2368a00` B）
- 基线：`_text = 0xffffffc080000000`，`file_off = vaddr − 0xffffffc080000000`
- 任务来源：H109 §6.2 收敛结论 —— 「L3 若要继续，必须离开信号路径：`ptrace` 侧 `gpr_set` / `compat_gpr_set` 是仅剩的非信号 `valid_user_regs` 调用点」

---

## 0. 一句话结论

**`ptrace` GPR 通道（`gpr_set` / `compat_gpr_set`）不是 EL1 落点 —— 它与 `rt_sigreturn` 共用同一把 `valid_user_regs` 锁。** 但本轮在同一锁上发现 **2 处此前未记录的事实修正**，并**新证伪了一条 H107 遗留的候选链（`badframe` → `die()`）**。**信号域与 ptrace 域现已全部穷尽；EL1 落点在「上游写 `pstate`」这一层面【不存在】。**

---

## 1. 本轮穷尽链（三环闭环）

### 环① 源码推理

| 项 | 源码位置 | 结论 |
|---|---|---|
| `gpr_set` | `arch/arm64/kernel/ptrace.c:564` | 两段式：拷到局部 `newregs` → `valid_user_regs` 校验 → 才写回；**失败返回 `-EINVAL`，不写回** |
| `ptrace_regset` | `kernel/ptrace.c:908` | `pos` 恒传 `0`；`iov_len = min(iov_len, regset->n * regset->size)` = `0x110`；`(iov_len % 8) != 0 → -EINVAL` |
| `find_regset` | `kernel/ptrace.c:894` | 按 `core_note_type` 匹配；`REGSET_GPR.core_note_type = NT_PRSTATUS` ⇒ `PTRACE_SETREGSET(NT_PRSTATUS)` 是**唯一**写 `pt_regs` 的 regset |
| `aarch64_regsets[]` | `ptrace.c:1442` | `REGSET_GPR` = 唯一带 `.set = gpr_set` 且触及 `user_pt_regs` 的项 |
| `PTRACE_POKEUSER` | **全树 0 命中**（`arch/arm64/` + `kernel/ptrace.c` + `include/linux/ptrace.h`） | **arm64 从不实现该请求**（不是被厂商裁掉）；无 `MAX_REG_OFFSET` 通道 |
| `arch_ptrace` | `ptrace.c:2131` | 只特判 `PTRACE_PEEKMTETAGS`/`POKEMTETAGS`，其余转 `ptrace_request` |
| `valid_native_regs` | `ptrace.c:2278` | `pstate &= ~RES0_BITS` → 条件检验 → 非法则 `pstate &= N\|Z\|C\|V` |
| `restore_sigframe` | `signal.c:771` | **`err \|= !valid_user_regs(...)`（不是 `-EINVAL` 早退）** |
| `rt_sigreturn` | `signal.c:819` | `badframe: arm64_notify_segfault(regs->sp)` |

### 环② 设备 Image 汇编交叉验证（本轮新做）

#### ②-A `gpr_set`（`0xffffffc0808d2174`，59 条）—— 与源码逐条一致

```asm
0x8d219c  ldr  x8, [x0, #0x38]      ; x8 = task->stack
0x8d21a8  mov  w2, #0x110           ; sizeof(user_pt_regs)
0x8d21b4  bl   memcpy(&newregs, task_pt_regs(target), 0x110)   ; 拷到【局部栈】
0x8d21cc  mov  w5, wzr              ; user_regset_copyin start_pos = 0（硬编码）
0x8d21d0  mov  w6, #-1              ; end_pos = -1（无上界）
0x8d21d4  bl   user_regset_copyin   ; 用户数据 → newregs
0x8d2204  add  x0, sp, #0x18        ; &newregs
0x8d2208  mov  x1, x20              ; target
0x8d220c  bl   0x445248             ; ★ valid_user_regs
0x8d2210  cbz  w0, 0x8d2234         ; ★★ 返回 0 → -EINVAL，【不写回】
0x8d2228  bl   memcpy(task_pt_regs(target), &newregs, 0x110)   ; 写回
0x8d222c  mov  w0, wzr
0x8d2234  mov  w0, #-0x16           ; -EINVAL
```

**裁决**：`0x8d2210 cbz w0, -EINVAL` 是**硬闸门**，且**失败不写回**（与 `rt_sigreturn` 的 `err |=` 语义相反）。⇒ `gpr_set` **必须 `valid_user_regs` 返回 1** ⇒ 同锁。

#### ②-B `valid_user_regs`（`0xffffffc080445248`）内联体 —— ★ H107 表述修正

```asm
0x445260  bl     0x445ae8                 ; user_regs_reset_single_step
0x445264  ldr    x9, [x20]                ; task_thread_info(task)->flags
0x445268  ldr    x8, [x19, #0x108]        ; ★ x8 = regs->pstate
0x44526c  tbnz   w9, #0x16, 0x4452a4      ; is_compat_thread → compat 分支
;; === native (64-bit) ===
0x445270  mov    w9, #0x3df
0x445274  mov    w10, #0x1fdf
0x445278  tst    x8, x9                   ; ★★ (pstate & 0x3df) == 0 ?
0x44527c  mov    w9, #-0x10000000         ; 0xF0000000   ← H107 已记录的形态 ✅
0x445280  movk   w10, #0xf320, lsl #16    ; 0xF3201FDF
0x445284  csel   x9, x10, x9, eq          ; eq → 0xF3201FDF ; ne → 0xF0000000
0x445288  cset   w0, eq                   ; 返回值
0x44528c  and    x8, x9, x8               ; regs->pstate &= 掩码
0x445290  str    x8, [x19, #0x108]        ; ★★ 无条件写回
```

**`tst` 掩码 `0x3df` 精确解码**（Python 复核）：

| 位 | 值 | 含义 |
|---|---|---|
| bit0-3 | `1`×4 | `PSR_MODE_MASK` = `0xf` |
| bit4 | `1` | `PSR_MODE32_BIT` = `0x10` |
| bit6-9 | `1`×4 | `PSR_f` = F\|I\|A\|D = `0x3c0` |
| 合计 | — | `0xf\|0x10\|0x3c0 = 0x3df` ✅ |

⇒ `tst x8, #0x3df` **就是 `user_mode(regs) && !MODE32 && !D && !A && !I && !F` 的完全展开**。

**★ H107 表述修正（重要）**：H107 写「`valid_native_regs` 末行把 `pstate` 锁死为 EL0t」，机制描述为「**掩码洗掉 MODE**」。**镜像真相是**：返回 1 的**前提条件 `tst w/ 0x3df` 本身就包含 bit0-3**，即 **MODE≠0 直接判非法**（`csel` 选 `0xF0000000`，该掩码清掉 MODE）。两条路径最终都使 `regs->pstate` 的 MODE 位为 0：

- `ret==1` ⇔ `pstate & 0x3df == 0` ⇒ **MODE 已为 0**
- `ret==0` ⇒ 掩码 `0xF0000000` ⇒ **MODE 被清为 0**

**净结论不变（双向死锁成立），但机制从「掩码洗」更正为「检验条件含 MODE 位」。** 这影响后续任何依赖「掩码形态」的检测脚本。

#### ②-C `restore_sigframe` + `badframe`（内联于 `rt_sigreturn`，`0x49b6a4..0x49b6dc`）

```asm
0x49b6a4  str   x8, [x22, #0x3fb8]     ; ★ regs->pstate = 我们填的值（【无条件】）
0x49b6a8  mov   w8, #-1
0x49b6ac  mov   x0, x19                ; &regs->user_regs
0x49b6b0  mov   x1, x20                ; current
0x49b6b4  str   w8, [x22, #0x3fc8]     ; regs->syscallno = NO_SYSCALL  (= forget_syscall)
0x49b6b8  bl    0x445248               ; ★★ valid_user_regs
0x49b6bc  cmp   w0, #0
0x49b6c0  cset  w8, eq
0x49b6c4  orr   w8, w21, w8            ; ★★ err |= !valid_user_regs  ← 与源码一致（非 -EINVAL）
0x49b6c8  cbnz  w8, 0x49b6d8           ; err != 0 → badframe
0x49b6cc  add   x0, x23, #0x250        ; regs->sp 地址
0x49b6d0  tst   x0, #0xf               ; ★ sp & 15
0x49b6d4  b.eq  0x49b71c               ; 对齐 → 正常路径
0x49b6d8  ldr   x0, [x22, #0x3fa8]     ; ★★ badframe: x0 = regs->sp  (0x3fa8 = 0x3eb0+0xf8)
0x49b6dc  bl    0x5c38d8               ; ★★ arm64_notify_segfault(regs->sp)
```

**关键**：`0x49b6a4` 写 `pstate` **先于** `0x49b6b8` 的校验，且**无条件**。但 `valid_user_regs` 内部 `str x8, [x19, #0x108]`（`0x445290`）**原地洗过 `regs->pstate`** ⇒ 到达 `badframe` 时 `regs->pstate` **必为 MODE=0**。

#### ②-D `arm64_notify_segfault`（`0x5c38d8`）— 新证伪一条链

```asm
0x5c38f4  mov  x19, x0                 ; ★ x19 = addr = regs->sp（用户可控）
0x5c38fc  add  x0, x20, #0x90          ; mm
0x5c3900  bl   0x810773f0              ; mmap_read_lock
0x5c3908  lsl  x8, x19, #8
0x5c390c  ldr  x0, [x21, #0x5a0]       ; current->mm
0x5c3910  and  x1, x19, x8, asr #8     ; ★ untagged_addr() = sign_extend64(a,55) & a
0x5c3914  bl   0x800d145c              ; ★ find_vma(mm, untagged_addr(addr))
0x5c3918  cmp  x0, #0
0x5c392c  cinc w21, w8, ne             ; code = vma ? ACCERR : MAPERR
0x5c3930  bl   0x8006d874              ; mmap_read_unlock
0x5c3934  mov  w0, #0xb                ; SIGSEGV
0x5c393c  mov  x2, x19                 ; ★ addr 原样传
0x5c3944  bl   0x5c3800                ; force_signal_inject(SIGSEGV, code, addr, 0)
```

**源码层判定**：`find_vma` 在 6.6 已改用 **Maple Tree**（`mt_find(&mm->mm_mt, &index, ULONG_MAX)`，`mm/mmap.c:1905`），`addr` **仅作树索引键**，无回调、无对 `addr` 的解引用 ⇒ **不构成任意读/写**。`code` 进 `siginfo`（用户态本就知道 addr）⇒ **零信息量**。

#### ②-E `arm64_notify_die`（`0x5c3788`）内联 `user_mode` — 判定 `die()` 不可达

```asm
0x5c3794  ldrb  w8, [x1, #0x108]      ; ★ w8 = regs->pstate
0x5c3798  tst   w8, #0xf              ; ★ user_mode 判据
0x5c37a0  b.ne  0x5c37e4
0x5c37e4  mov  x0, x8                 ; else 分支:
0x5c37ec  bl   0x5c33ec               ; ★★★ die(str, regs, err) — 内核态异常处理
```

**`die()` 可达性判定**：
`badframe` 到达时 `regs->pstate` 已被 `valid_user_regs` 洗成 MODE=0（`0x445290` 无条件写回）⇒ `tst w8, #0xf` **恒为 0** ⇒ **恒走 `user_mode` 分支（`0x5c37a4..`，`arm64_force_sig_fault`）** ⇒ **`0x5c37e4 die()` 不可达**。

⇒ **`badframe` 链正式判死**（两条子链：`find_vma` 非写原语、`die()` 不可达）。

### 环③ 镜像 delta

- 全镜像 BL 扫描（手写 AArch64 位域解码）：`valid_user_regs` **调用点 6 处**，与 H108 完全一致：
  `0x49b6b8`(= `rt_sigreturn+0x3d4`) / `0x49c7d0`(`do_notify_resume+0x260`) / `0x8d08b8`(`compat_arch_ptrace+0x504`) / `0x8d0eb4`(`compat_gpr_set+0x1fc`) / `0x8d220c`(`gpr_set+0x98`) / `0x8d7d40`(`compat_restore_sigframe+0xbb4`)
- **64 位进程真实闸点仅 3 处**：`rt_sigreturn` / `gpr_set` / `do_notify_resume`（投递侧）⇒ **全锁在同一把 `valid_native_regs`**
- **无厂商新增 `pc`/`sp` 范围校验、无 `pstate` 保留位校验**（本轮 ②-B/②-C 逐条双证）

---

## 2. `ptrace` 侧自由度（相对 `rt_sigreturn` 的差异）—— 均**不改变** EL1 结论

| 维度 | `rt_sigreturn` | `gpr_set` | 是否突破 pstate 锁 |
|---|---|---|---|
| `pstate` 可否任意 | 可填，但被洗 | 可填，但被洗 | ❌ 同锁 |
| `pc`/`sp` | 任意（帧内） | **任意**（`iov_len<=0x100` 时不需带 `pstate`） | ❌ `eret` 仍回 EL0 |
| 部分覆盖 | 否（需完整 sigframe） | **是**（`iov_len` 可 < `0x110`，`pstate` 保原值） | ❌ |
| fpsimd 记录 | **强制**（`parse_user_sigframe` 须解出） | **不需要** | ❌ |
| 16B 帧对齐 | **强制** | **不需要** | ❌ |
| 失败语义 | `err\|=` → `badframe`（**regs 已被写**） | `-EINVAL` 早退（**不写回**） | ❌ |
| `orig_x0`(0x110)/`syscallno`(0x118) | 不可达 | **不可达**（iov 上限 `0x110`） | ❌ |
| 改后继续跑内核代码 | 否（`eret` 回用户态） | **是**（syscall 边界 stop 后继续 `invoke_syscall`） | ❌（见下） |

### 「syscall 边界窗口」判定（本轮新增结论）

`el0_svc_common`（`arch/arm64/kernel/syscall.c:75`）时序：

```c
regs->orig_x0  = regs->regs[0];
regs->syscallno = scno;                                    // ① scno 在 do_el0_svc 里已由 regs[8] 读出
if (has_syscall_work(flags)) {
    scno = syscall_trace_enter(regs);                      // ② 此处 ptrace_stop → tracer 可改 regs
    if (scno == NO_SYSCALL) goto trace_exit;
}
invoke_syscall(regs, scno, sc_nr, syscall_table);          // ③ 用 scno 调 syscall_fn(regs)
```

- `syscall_trace_enter` 的 `return regs->syscallno`（`ptrace.c:2212`）**确实读改后的值** —— 但 `syscallno` 在 `0x118`，**超出 iov 上限 `0x110`** ⇒ 改不到
- `regs->regs[8]`（x8，`scno` 的原始来源）**可改**，但 `scno` 已在 ① 定型（`do_el0_svc` 传参），**改 x8 不生效**
- ⇒ **可用窗口 = 只能改 `regs[0..30]` + `sp` + `pc`（不含 `pstate` 的非法值）**，而 syscall 实现读的是**正常参数**，内核会正常校验

**⇒ 该窗口不产生新落点。** 与 `rt_sigreturn` 殊途同归。

---

## 3. 判死清单（本轮）

| # | 候选 | 判据 | 结论 |
|---|---|---|---|
| 1 | `PTRACE_POKEUSER` 通道 | 全树 0 命中（arm64 不实现） | **判死** |
| 2 | `gpr_set` 直通 EL1 | `0x8d2210 cbz w0, -EINVAL` 硬闸门 | **判死** |
| 3 | `orig_x0` / `syscallno` 通道（64 位） | iov 上限 `0x110`，`orig_x0`@`0x110`/`syscallno`@`0x118` | **判死** |
| 4 | 其他 regset 写 `pt_regs` | `find_regset` 按 `core_note_type` 匹配，仅 `REGSET_GPR` 触及 `user_pt_regs` | **判死** |
| 5 | `badframe` → `find_vma` 任意读 | 6.6 改 Maple Tree，`addr` 仅作索引键 | **判死** |
| 6 | `badframe` → `die()` EL1 | `valid_user_regs` 先洗 `pstate` ⇒ `user_mode` 恒真 | **判死** |
| 7 | syscall 边界改 `regs` 窗口 | 可改字段均为 syscall 正常参数 | **判死** |
| 8 | `compat_gpr_set` / `compat_arch_ptrace` | `0x8d0eb4` / `0x8d08b8` 同调 `valid_user_regs` | **判死** |

---

## 4. 本轮新铁律 / 表述修正（须回填）

1. **★★★★ H111 修正 H107**：`valid_native_regs` 的双向死锁机制**不是「掩码洗掉 MODE」**，而是 **`tst x8, #0x3df`（=`user_mode && !MODE32 && !DAIF`）的检验条件本身包含 bit0-3**。`ret==1` 路径掩码 `0xF3201FDF` **保留** bit0-3；`ret==0` 路径掩码 `0xF0000000` 清之。**任何依赖「掩码 `0xF0000000` 形态」的检测脚本需按 `0x3df` 检验条件重写。**
2. **★★★★ H111**：`rt_sigreturn` 的 `restore_sigframe` 是 **`err |= !valid_user_regs(...)`**（`0x49b6c4 orr w8, w21, w8`），**失败继续写 regs**；`gpr_set` 是 **`cbz w0, -EINVAL`**，**失败不写回**。**两者语义相反**，`rt_sigreturn` 的「写后失败」不构成新原语（`pstate` 已被洗）。
3. **★★★ H111**：`pt_regs` 的编译形态有两类，判据不同 ——
   - `current_pt_regs()` 形态：**`[Xn, #0x3fb8]`**（=`task->stack + 0x3eb0 + 0x108`），全镜像 **22 处**（`rt_sigreturn` 的写点在 `0x49b6a4`）
   - 指针形态：`[Xn, #0x108]`（`regs` 在寄存器里），全镜像 **618 处（噪声大）**
   - **`add Xn, Xm, #0x3eb0` 零命中** ⇒ 编译器总是合并基址与偏移，**不能用 `0x3eb0` 作锚**
4. **★★ H111**：`PTRACE_POKEUSER` / `PEEKUSER` 在 arm64 **不存在**（全树 0 命中，非厂商裁剪）。
5. **★★ H111**：6.6 的 `find_vma` 是 **Maple Tree `mt_find`**，不是红黑树 `mm_rb` ⇒ L1 的 `rb_erase` 线（已存档）在本内核**语义需重审**。
6. **★★★★ H111（收口铁律）**：**`user_mode(regs)` 判据 `pstate & PSR_MODE_MASK(0xf) == PSR_MODE_EL0t(0)` 是 native 与 compat 两侧的【统一收口点】**。AArch32 的宽 MODE 编码（`PSR_AA32_MODE_MASK=0x1f`，含 SVC=`0x13`）**不能**逃逸，因为该检查用的是 `0xf` 而非 `0x1f`。**任何未来在 `pstate` 上找 EL1 落点的尝试，都要先过这一条 —— 已两向证伪，不必再试。**

---

## 4-bis. compat（AArch32）路径 —— 本轮最后的穷尽维度【已判死】

`valid_user_regs` 的 compat 分支（`0x4452a4`，内联 `valid_compat_regs`，源码 `ptrace.c:2246`）：

```asm
0x4452a4  mov   w9, #-0x500001          ; ~(SPSR_EL1_AARCH32_RES0_BITS)
0x4452a8  mov   w0, #0x700
0x4452ac  and   x8, x8, x9              ; pstate &= ~RES0
0x4452b0  movk  w0, #0x18, lsl #16
0x4452b4  str   x8, [x19, #0x108]
0x4452b8  bl    0x6f4ec                 ; system_supports_mixed_endian_el0
0x4452bc  and   x9, x0, #0xf00
0x4452c4  cmp   x9, #0x100
0x4452d0  cmp   x9, #0x10, lsl #12
0x4452dc  ands  w10, w10, w9            ; ★ w10 = 条件不满足标志
0x4452e0  mov   w9, #0x1df
0x4452ec  movk  w11, #0xfe0f, lsl #16
0x4452f0  and   x9, x8, x9              ; ★ x9 = pstate & 0x1df
0x4452f8  cmp   x9, #0x10               ; ★★ (pstate & 0x1df) == 0x10 ?
0x4452fc  orr   x11, x11, #0x10         ; ★★ 强制 OR PSR_MODE32_BIT = 0x10
0x445300  cset  w0, eq
0x445304  csel  x8, x8, x11, eq
0x445308  tbnz  w10, #0, 0x445290       ; 条件不满足 → 公共写回 (ret=0 路径)
0x445310  b.eq  0x445294                ; x9==0x10 → ret=1
```

**关键剖析**：`x9 = pstate & 0x1df`，`0x1df = PSR_MODE_MASK(0xf) | PSR_MODE32_BIT(0x10) | ... | F|I|A|D-ish`。

⇒ **通过条件 `(pstate & 0x1df) == 0x10` 的完整含义**：
- `pstate & PSR_MODE_MASK (0xf) == 0` ⇒ **`user_mode(regs)` 为真**
- `pstate & PSR_MODE32_BIT (0x10) == 0x10` ⇒ compat 模式
- `pstate & (A|I|F) == 0`

**★ 决定性**：源码 `user_mode(regs)` 的判据是 **`PSR_MODE_MASK = 0xf`**（`arch/arm64/include/asm/ptrace.h:227`），**不是** `PSR_AA32_MODE_MASK = 0x1f`。因此：

| AArch32 模式 | `M[4:0]` | `pstate & 0xf` | `user_mode()` | 结果 |
|---|---|---|---|---|
| USR | `0x10` | `0` | ✅ 真 | `ret=1` |
| **SVC（EL1 等价）** | `0x13` | `3` | ❌ 假 | `ret=0`，MODE 被清 |
| FIQ / IRQ / ABT / UND / SYS | `0x11/0x12/0x17/0x1b/0x1f` | 非 0 | ❌ 假 | `ret=0`，MODE 被清 |

**⇒ AArch32 宽阔的 MODE 编码空间（`PSR_AA32_MODE_MASK = 0x1f`，含 SVC=`0x13`）被 `user_mode()` 统一的 `PSR_MODE_MASK = 0xf` 检查收口，不构成逃逸。compat 路径与 native 路径【完全同构的死锁】。**

**⇒ H111 全维度闭环：信号域（H108/H109）+ ptrace 域 native（H111 §3）+ ptrace 域 compat（本节）三向均无 EL1 落点。**

---

## 5. 产物

| 文件 | 内容 |
|---|---|
| `tools/h111a_badframe.py` | `rt_sigreturn` 尾段 + `arm64_notify_segfault` + `force_signal_inject` + `arm64_notify_die` 反汇编 + BL 位域扫描 |
| `tools/h111b_regsflow.py` | 全树 `regs->pc/sp/pstate/orig_x0/syscallno` 流向扫描 |
| `tools/h111c_pstate_writers.py` | 全镜像 `disp==0x108` 写点扫描（618 处，含噪声） |
| `tools/h111d_rtsigreturn.py` | `rt_sigreturn` 全体 1187 条反汇编 + `valid_user_regs` 调用点 + `badframe` 定位 |
| `tools/h111e_fastscan.py` | 字节模式快速扫 `disp==0x108` 的 STR/STUR |
| `tools/h111f_ptregs_anchor.py` | 用 `0x3eb0` 锚点定位（**0 命中，证明锚不对**） |
| `analysis/output/h111_ptrace_el1.md` | 本报告 |

---

## 6. 后续（唯一剩余方向）

**信号域（H108/H109）+ ptrace 域 native（§3）+ ptrace 域 compat（§4-bis）三向已全部穷尽 ⇒ 「上游写 `pstate`」层面无 EL1 落点。**

按规程 §一 kill criterion，L3 已面临「连续多轮被证伪」：H108（不经过 `valid_user_regs` 路径 ❌）、H109（`setup_rt_frame` 内核态写 ❌）、H111（`ptrace` native + compat ❌）。**「控制流劫持到 EL1」这条子路线在源码/汇编两侧均已穷尽，无新变体可挖。**

**剩余可查方向（按价值排序）**：

1. **转向「非 `pstate` 的提权路径」**：放弃「控制流劫持到 EL1」，改找**「内核带着被改写的 GPR 执行既有提权逻辑」**的落点。已知可用的改写面：`regs[0..30]` + `sp` + `pc`（无需合法 `pstate`）。候选：
   - 内核中有无「从 `pt_regs` 取参数、且参数流向特权操作（mount / capability / cred）」的函数
   - `install_child_root` 类函数若从 `regs` 取参
   - `syscall_trace_enter` 的 `audit_syscall_entry(regs->syscallno, regs->orig_x0, regs->regs[1..3])`（`orig_x0` 改不到，但 `regs[1..3]` 可改）
2. **重估攻击面**（若 1 也判死）：按规程 §一，L3 挂起，收尾重估，不再无限消耗轮次。这是规程明确要求的动作。

**本轮明确不做的**：不再在「写 `pstate`」上做任何尝试（已穷尽）。
