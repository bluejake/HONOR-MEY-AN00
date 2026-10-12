# H109 · L3 主攻「`setup_rt_frame` 内核态写路径」审查（H108 §V.4 方向）

> 2026-10-05 · MEY-AN00 · 内核 6.6.118-android15-8 · 4K 页
> 设备串行、未开火（纯逆向，零真机操作）
> 上一轮：H108（EL1 落点第一次解剖，递归窗口否证 + 四 static 内联 + 6 调用点归属）

---

## §0 结论（一句话）

**H108 §V.4 提出的「`regs` 字段值 → 内核写地址」假设，在 `setup_rt_frame` 内联体（`do_notify_resume` `0x49c570..0x49d700`）内【不存在】。**
该区内全部 22 个 `sttr` 写点的写地址 **100% 由 `sigframe` 派生链产生**，经 `tbi` 剥离 + `access_ok` 双界门控，**数学上无可能落在内核 VA**。

⇒ **信号投递路径不是内核态任意写的来源。该维度已证伪，不得再挖。**

**同时修复了 H108 遗留的检测器缺陷**（上一轮「0 命中」是假阴性，检测器本身无效）。

---

## §1 本轮首要任务：修复检测器（铁律「扫不到必带自检组」）

H108 遗留问题：检测器在 `rb_erase` / `__save_altstack` / `do_notify_resume` 三处均返回 0 命中，阳性对照失败 ⇒ **阴性结论作废**。

### 1.1 三个根因（全部定位并修正）

| # | 根因 | 修正 |
|---|---|---|
| 1 | `Image-mey` 切片用 `blob[0x49c570 - 0xffffffc080000000]` ⇒ **巨大负索引**，返回空字节 ⇒ capstone 解出 **0 条** | 必须 `blob[0xffffffc08049c570 - KB : ...]`，**VA 必须整体带前缀**；加 `assert len(code) == 0x1190` |
| 2 | 解析操作数用 `op_str.split(",")` ⇒ `[x0, #8]` 被切碎，误判 | 改用 capstone `detail`：`o.type == cs_a64.ARM64_OP_MEM` / `o.mem.base` / `md.reg_name()` |
| 3 | **常量命名空间错**：capstone 5.0.7 的 `ARM64_OP_MEM` **不在 `capstone` 顶层** | 必须 `import capstone.arm64 as cs_a64`，用 `cs_a64.ARM64_OP_MEM`（顶层只有 `CS_OP_MEM`） |

另：`skipdata=True` 下 `ins.operands` 会抛 `CsError(CS_ERR_SKIPDATA)`，需 `try/except` 跳过 `data` 伪指令。

### 1.2 阳性对照（自检组）—— 通过 ✅

自造 mini 汇编（手工编码，**先解码验证再跑检测器**）：

```
0x1000: ldr x8, [x19, #0x200]     ; 编码 F9410268 -> LE 68 02 41 f9
0x1004: str w9, [x8]              ; 编码 B9000109 -> LE 09 01 00 b9
```

检测器输出：

```
[TAINT] 0x1000: ldr x8, [x19, #0x200] (base=x19)
[HIT ] 0x1004: str w9, [x8] base=x8 TAINTED
```

⇒ **检测器有效**，可对目标区下结论。**H108 的「0 命中」正式作废**（那是检测器失效导致的假阴性）。

---

## §2 自检组 2：目标区全景（不猜，直接 dump）

`do_notify_resume` = `0xffffffc08049c570..0x49d700`（H108 记录 `+0xcc0` 至 `0x49d230` 有分派）。

```
指令数 = 1124      data 伪指令 = 0      写指令 = 45
写指令 base 直方图: sp×14, x19×10, x9×9, x10×4, x8×3, x14×2, fp×1, x13×1, x12×1
```

★ **`regs` 基址寄存器自动判定 = `x19`**（独立确认 H108）：
判据 = 存在写 `[x19,#0x100]`(=pc) + `[x19,#0xf8]`(=sp) + `[x19,#0x108]`(=pstate) + `[x19,#0xe8]`(=fp)，**四折齐全**，唯一候选。

`x20` 亦确认 = `current`（`mrs x20, sp_el0` @`0x49c5c8`，`ldr x8,[x20,#0x10f8]` 等结构体访问）。
`x23` = `sigframe`（见 §3）。

---

## §3 ★ `get_sigframe()` 内联体逐条核算（独立透镜）

汇编 `0x49c7fc..0x49c8b4`（`x19` = regs）：

```
0x49c7fc  ldr   x8, [x19, #0xf8]            ; x8 = regs->sp
0x49c808  mov   w10, #0x1250                ; sizeof(struct rt_sigframe)
0x49c814  and   x10, x8, #0xfffffffffffffff0 ; sp_top = sp & ~0xf
0x49c81c  sub   x28, x10, #0x10             ; x28 = sp_top - 0x10
0x49c820  and   x10, x9, #0xfffffffffffffff0 ; -(round_up(size,16))
0x49c828  add   x23, x10, x28               ; ★ x23 = sigframe 基址
0x49c82c  sub   x8, x8, x23                 ; x8 = framesize
0x49c840  mov   x9, #0x8000000000           ; TASK_SIZE
0x49c848  cmp   x8, x9    ; b.hi -> 拒绝     ; ★ access_ok 上界
0x49c850  sub   x8, x9, x8
0x49c854  cmp   x8, x23   ; b.lo -> 拒绝     ; ★ access_ok 下界
0x49c85c  add   x14, x23, #0x80             ; x14 = &frame->uc（首个写目标）
0x49c8a4  sub   x25, x26, #4                ; x25 = 0x7ffffffff9
0x49c8a8  cmp   x8, x25   ; b.hs -> 拒绝     ; ★ 最终上界 < 0x7ffffffff9
```

对照源码 `signal.c:1048-1074` `get_sigframe()`：

```c
sp = sp_top = sigsp(regs->sp, ksig);                  /* 无 SA_ONSTACK 时 == regs->sp */
sp = round_down(sp - sizeof(struct frame_record), 16);/* x28 */
sp = round_down(sp - sigframe_size(user), 16);        /* x23 */
if (!access_ok(user->sigframe, sp_top - sp)) return -EFAULT;
```

**Python 逐条模拟（`h109g_derive.py`）**：

| 假设 `regs->sp` | `x23` sigframe | `x14` 写目标基 | access_ok |
|---|---|---|---|
| `0x7ff0000000` | `0x7fefffeda0` | `0x7fefffee20` | PASS |
| `0x7fffffe000` | `0x7fffffcda0` | `0x7fffffce20` | PASS |
| `0x4000000000` | `0x3fffffeda0` | `0x3fffffee20` | PASS |
| `0xfffffffff0000000` | — | — | **FAIL** |
| `0xffff800000000000` | — | — | **FAIL** |

★ **写目标数学上界：`x14 < 0x7ffffffff9 < 2^47`。**
内核 VA 最低 = `0xffffff8000000000`（≈ `2^64 - 2^47`），**永不满足**。

---

## §4 ★★★ 22 个 `sttr` 写点全表（带写值/写地址双向回溯）

`sttr` = arm64 `__put_user` 的实现（store-unprivileged）。区内**共 22 个**，全部前置 `and xN, xM, #0xff7fffffffffffff`（TBI 剥离，**共 22 处，一一对应**）。

| # | 地址 | 写值来源 | 写地址来源 | 对应源码 | 分类 |
|---|---|---|---|---|---|
| 1 | `0x49c8f0` | `0` | `x14=sigframe+0x80` | `__put_user_error(0,&uc_flags)` | A |
| 2 | `0x49c984` | `0` | `x9` sigframe链 | 写 0 | A |
| 3 | `0x49ca34` | **`regs[29]` fp** | `x9=x28` sigframe链 | `&user->next_frame->fp` | **B** |
| 4 | `0x49cac8` | **`regs[30]` lr** | `x9=x10` sigframe链 | `&user->next_frame->lr` | **B** |
| 5 | `0x49cb7c` | **`regs[i]`** | `x9=x13` sigframe链 | `for(31) &uc_mcontext.regs[i]` | **B** |
| 6 | `0x49cc4c` | **`regs->sp`** | `x10=x11` sigframe链 | `&uc_mcontext.sp` | **B** |
| 7 | `0x49cce4` | **`regs->pc`** | `x9=x11` sigframe链 | `&uc_mcontext.pc` | **B** |
| 8 | `0x49cd7c` | **`regs->pstate`** | `x10=x11` sigframe链 | `&uc_mcontext.pstate` | **B** |
| 9 | `0x49ce10` | `current[0x10f8]` | `x8` 残留(sigframe+0x80) | `fault_address` | C |
| 10 | `0x49cfa8` | `current[0x10c0]` | `x8=x9` sigframe链 | `__copy_to_user(uc_sigmask)` | C |
| 11 | `0x49d040` | `current[0x10c4]` | `x9=x10` sigframe链 | 同上 | C |
| 12 | `0x49d0d8` | 常量 `0x46508001` | `x8=x24` sigframe链 | `FPSIMD_MAGIC` | A |
| 13 | `0x49d170` | 常量 `0x210` | `x9` sigframe链 | fpsimd size | A |
| 14 | `0x49d324` | 常量 `0x4558_0120` | `x14=x9` sigframe链 | SVE magic | A |
| 15 | `0x49d3b8` | 常量 `0x20` | `x14=x15` sigframe链 | size | A |
| 16 | `0x49d44c` | current 派生 | `x13=x15` sigframe链 | extra_context | C |
| 17 | `0x49d4e0` | `w11<<12` | `x12=x14` sigframe链 | extra_context | C |
| 18 | `0x49d574` | `0` | `x10` sigframe链 | 写 0 | A |
| 19 | `0x49d60c` | `0` | `x9` sigframe链 | 写 0 | A |
| 20 | `0x49d6ac` | `0` | `x10` sigframe链 | 写 0 | A |

（另 2 个 `sttr` 属 `__arch_copy_to_user` 调用路径，见 §4.2）

### 4.1 分类统计

| 类 | 含义 | 数量 |
|---|---|---|
| **A** | 常量/零（无信息） | 9 |
| **B** | **`regs` → 用户内存** = ★ **信息【泄漏】方向，非内核写** | 6 |
| **C** | `current` → 用户内存（内核数据泄漏） | 5 |

★ **无一处为「`regs` 字段值 → 内核地址」**。

### 4.2 函数调用点（`bl`）佐证

| 地址 | 目标 | 符号 | 参数 |
|---|---|---|---|
| `0x49ce84` | `0xffffffc080204480` | **`__arch_copy_to_user`** | `x0 = sigframe+0xa8` (TBI 剥离后 = 用户 VA) |
| `0x49c7a8` | `0xffffffc0808d9f50` | `compat_setup_frame` | `x3 = x19 = regs`（**32 位 compat 分支**） |
| `0x49c7c0` | `0xffffffc0808d84e8` | (compat 变体) | 同上 |
| `0x49c7d0` | `0xffffffc080445248` | **`valid_user_regs`** | `x0 = regs`, `x1 = current`（**H108 的 6 调用点之一**） |
| `0x49c7ec` | `0xffffffc08027873c` | `signal_setup_done` | — |

★ `valid_user_regs` 位于 **compat/native 分派之后**（`0x49c780 cbz w0` 处 `is_compat_task()`），
与 H108 结论一致：**调用点 `0x49c7d0` = `do_notify_resume+0x260`**。

---

## §5 源码 ↔ 汇编双证对照表（自检）

`setup_sigframe()`（`signal.c:940-960`）：

| 源码 | 汇编 | ✅ |
|---|---|---|
| `__put_user_error(regs->regs[29], &user->next_frame->fp, err)` | `0x49ca34 sttr x10,[x9]`，值 `ldr x10,[x19,#0xe8]` | ✅ |
| `__put_user_error(regs->regs[30], &user->next_frame->lr, err)` | `0x49cac8 sttr x10,[x9]`，值 `ldr x10,[x19,#0xf0]` | ✅ |
| `for(i=0;i<31;i++) __put_user_error(regs->regs[i], &sf->uc.uc_mcontext.regs[i], err)` | `0x49cb7c sttr x13,[x9]`，值 `ldr x13,[x19,x8]` + `add x8,x8,#8` / `cmp x8,#0xf8` 循环 | ✅ |
| `__put_user_error(regs->sp, &sf->uc.uc_mcontext.sp, err)` | `0x49cc4c` ，值 `ldr x11,[x19,#0xf8]` | ✅ |
| `__put_user_error(regs->pc, &sf->uc.uc_mcontext.pc, err)` | `0x49cce4`，值 `ldr x11,[x19,#0x100]` | ✅ |
| `__put_user_error(regs->pstate, &sf->uc.uc_mcontext.pstate, err)` | `0x49cd7c`，值 `ldr x11,[x19,#0x108]` | ✅ |
| `err \|= __copy_to_user(&sf->uc.uc_sigmask, set, sizeof(*set))` | `0x49ce84 bl __arch_copy_to_user`，`x0=sigframe+0xa8` | ✅ |
| `preserve_fpsimd_context(fpsimd_ctx)` | `0x49d0d8` 写 `0x46508001`；`0x49d170` 写 `0x210` | ✅ |

**所有写目标都是 `__user` 指针（源码 `__put_user_error` 的第二参数）+ 汇编 TBI 剥离形态** ⇒ 双证成立。

---

## §6 净结论：H108 §V.4 假设的回答

| 问题 | 回答 |
|---|---|
| `setup_rt_frame` 内联体内是否存在「`regs` 值当写地址」？ | **不存在** |
| 是否存在「`regs` 值当【内核】写地址」？ | **不存在**（写目标恒为用户 VA） |
| 是否还有「以 `regs` 为源」的写？ | 有 6 处，但方向是 **`regs` → 用户内存（信息泄漏）**，不是内核写 |
| 该维度能否作为 EL1 落点来源？ | **不能。已证伪。** |

### 6.1 三重独立证据（每条都能单独否证假设）

1. **数据流**：22 个写地址 100% 溯源到 `x23 = regs->sp - size`（`get_sigframe` 唯一来源）。
2. **指令形态**：22 处 `and xN,xM,#0xff7fffffffffffff`（TBI 剥离）与 `sttr` 一一对应，是 `__put_user` 的编译器指纹；且 `sttr`（store-unprivileged）**对内核地址会触发 fault 而非写入**（PAN/MMU 双重保险）。
3. **数学界**：`access_ok` 双界 + `cmp x8,x25(0x7ffffffff9)` ⇒ 写目标 `< 2^47`，而内核 VA `≥ 0xffffff8000000000`，**集合无交集**。

### 6.2 ★ 对 L3 全局的影响

至此，**SROP 信号域的两个候选维度全部穷尽**：

| 维度 | 结论 | 轮次 |
|---|---|---|
| 不经过 `valid_user_regs` 的 `pt_regs` 改写路径 | ❌ 不存在（6 调用点全锁） | H108 |
| 信号投递递归放大 | ❌ 不成立（`HANDLER_SIG_DFL` 兜底） | H108 |
| **`setup_rt_frame` 内以 `regs` 为源/地址的内核态写** | ❌ 不存在（本轮） | **H109** |

⇒ **信号路径（投递 + 恢复）内，不存在任何「内核态写」落点。**
L3 若要继续，**必须离开信号路径**，回到规程 §一「未解矛盾」：
「**如何让内核自行带着被改写的 `pt_regs` 走向 EL1**」——
且必须从**信号域之外**的调用点入手（`ptrace` 的 `gpr_set`/`compat_gpr_set` 是仅剩的 3 个非信号调用点之一）。

---

## §7 ★ 本轮新增/修订铁律（建议同步 `MEY-TECH.md` §0）

1. **★★★★ `Image-mey` 切片纪律**：`va` 必须**整体带 `0xffffffc080...` 前缀**再减 `KERNEL_BASE`；
   写 `blob[0x49c570 - 0xffffffc080000000]` 得**巨大负索引 → 空切片 → capstone 0 条**，
   会被误读为「区域不可解码」。**每次切片后必须 `assert len(code) == 期望长度`。**
2. **★★★★ capstone 5.0.7 操作数常量在子模块**：`capstone.ARM64_OP_MEM` **不存在**；
   必须 `import capstone.arm64 as cs_a64` → `cs_a64.ARM64_OP_MEM` / `cs_a64.ARM64_OP_REG`。
   顶层只有 `CS_OP_MEM`。
3. **★★★★ `skipdata=True` 的 `ins.operands` 会抛 `CsError(CS_ERR_SKIPDATA)`**，
   必须 `try/except` 跳过 `data` 伪指令，否则扫描中途崩。
4. **★★★★ 自检组必须用【自造 mini 汇编】验证解码 + 检测双环**：
   只解码对不够（H108 就是解码对但检测器错）。自造样本能精确控制语义，是唯一可靠阳性对照。
5. **★★★ arm64 `sttr`（store-unprivileged）= `__put_user` 指纹**；
   其前置 `and xN,xM,#0xff7fffffffffffff`（TBI 剥离）= `access_ok` 已放行的编译器证据。
   看到 `sttr` + 该 `and` 组合 ⇒ 写目标必为用户 VA，**无需再追数据流**（快速判死手段）。
6. **★★★ `x19` = `do_notify_resume` 的 `regs`，`x20` = `current`**（本机权威）；
   `regs` 基址自动判定法 = 找「同时写 `+0x100/+0xf8/+0x108/+0xe8` 四折」的寄存器。

---

## §8 本轮产物

| 类型 | 路径 |
|---|---|
| 报告 | `analysis/output/h109_setupframe_write.md`（本文件） |
| 检测器（含自检组） | `tools/h109_taint.py` |
| 精确判定 | `tools/h109b_regs_write.py` |
| 写点探测（自检组） | `tools/h109c_probe.py` |
| 逐寄存器核验 | `tools/h109d_audit.py` |
| 窗口 dump | `tools/h109e_window.py` |
| 定义点追踪 | `tools/h109f_trace.py` |
| sigframe 派生核算 | `tools/h109g_derive.py` |
| 写点分类 | `tools/h109h_classify.py` |
| 22 sttr 回溯 | `tools/h109i_sttr.py` |
| 最终判定 | `tools/h109j_verdict.py` |

---

## §9 禁止重复

- ❌ 在 `setup_rt_frame` / `setup_sigframe` / `get_sigframe` / `__save_altstack` 内找内核态写
  （已穷尽：22 个写点全用户 VA）。
- ❌ 用 `op_str.split(",")` 解析 capstone 操作数。
- ❌ 用 `blob[小数字 - 0xffffffc080000000]` 切片。
- ❌ 在信号路径（投递 + 恢复）内继续找 EL1 落点 —— **两维度已全部穷尽**。
