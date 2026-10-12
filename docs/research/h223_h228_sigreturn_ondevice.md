# H223–H228 · sigreturn 路线真机验证报告（步 A / 步 B 完成）

> 设备：MEY-AN00 / `6.6.118-android15-8` · 会话 2026-10-06 续做
> **真机开火 0 发**（`boot_id` 全程 `ba30251b-…a0` 不变；多次用户态 SIGSEGV 均未影响内核）
> 工具链：`<HOME>\.workbuddy\binaries\android\android-ndk-r27c`（clang 18.0.3）

---

## §0 结论速览

| 步 | 内容 | 结果 |
|---|---|---|
| **A** | fpsimd 信号帧被本机内核采信 | ✅ **通过**（magic 3/3 命中、size `0x210` 精确一致、512B vregs 可写、不崩） |
| **B** | SP0（`/proc/<pid>/syscall` 的 `sp`）在同线程内恒定 | ✅ **通过**（6/6 采样完全相同 ⇒ N4 真机成立） |
| **C** | 三线程拓扑实机验证 | ⏸ **未做**（被「画布投递装置」的调试占用） |
| **D** | 画布注入 + 消费触发 | ⏸ 未做 |

**净收获**：**A/B 两个零风险先决条件在真机证实**；另发现并修掉
**项目画布投递装置的一处结构性错误**（见 §3），并拿到本机 **fpsimd 帧的权威偏移表**（见 §2）。

---

## §1 ★ 步 B：SP0 真机恒定（N4 成立）

`tools/h223_sigframe_probe.c`（NDK 静态编译）真机运行：

```
[B] 同线程 6 次采样 sp:
      sample[0] = 0x7fffbf68b0
      sample[1] = 0x7fffbf68b0
      ... （6/6 完全相同）
[B] 判定: SP0 恒定 ✅ (N4 真机成立)
```

⇒ ★ **`/proc/<pid>/syscall` 的 `sp` 字段可作 SP0 锚，且同线程内跨 syscall 恒定。**
⇒ 上一轮（H221）推出的地址公式（`waiter=S−0x1F0`、`画布=S−0x300`、`伪lock=S−0x260`）
**其 SP0 来源在真机得到验证**。

---

## §2 ★★ 步 A：fpsimd 帧被采信 + 本机权威偏移表（自校准实测）

`tools/h223_sigframe_probe.c`：

```
[A] handler 命中 = 3
[A] 找到 FPSIMD_MAGIC = 是 (size=0x210, 期望 0x210)
[A] 已向 vregs 写 512B 图案 = 是
[A] 判定: fpsimd 帧被内核采信 ✅ (步 A 通过)
```

随后用 `tools/h226_canvas3.c` 做**自校准**（不依赖任何记忆中的结构体大小，
用 `ucontext_t` 标准字段地址反算），真机实测偏移：

| 量 | 实测值 | 说明 |
|---|---|---|
| `sizeof(ucontext_t)` | **4560 = 0x11d0** | bionic 实测 |
| `sigcontext.sp` 相对帧基址 | **0x5b0** | 真值校验 ✅ |
| `sigcontext.pc` | **0x5b8** | ✅ |
| `sigcontext.pstate` | **0x5c0** | 实测 `0x1000` = EL0t |
| `fpsimd vregs` | **0x5d8** | = `pc_off + 0x20` = `sigcontext + 0x20` ✔ 与结构定义吻合 |
| 帧的 8KB 重拷 | kernel `rt_sigrestore_sigframe` 取 `min(sizeof(rt_sigframe), 0x2000)` | ⇒ 帧缓冲**必须 ≥ 8KB 且余量充足** |

⇒ ★★ **本机 fpsimd 画布在帧内的精确落点已实测确定**，可直接用于构造。

---

## §3 ★★★ 画布投递通道：真机判定（H229/H230，**推翻 H195 的结论**）

### 3.1 H229：从 handler 内发 syscall 时，内核用【活寄存器】

handler 内同时设置：帧内 `vregs[0] = V_MARK`、活 `v0 = R_MARK`，然后
从 handler 内发 `syscall(SYS_getpid)` 并读回 `v0`：

```
vregs_off = 0x5d8
syscall 返回后读回 v0 = 0x1111000000000001 = R_MARK
判定: 读回 == 活寄存器 ⇒ 改帧被忽略
```

### 3.2 h230：★ **正常返回路径用【帧内 vregs】**（结论翻转）

handler 内：帧内 `vregs[0] = V_MARK`、活 `v0 = R_MARK`，然后**正常 return**：

```
返回后（syscall 前）v0 = 0x2222000000000002   ← ★ V_MARK 胜出
再 syscall 后        v0 = 0x2222000000000002
判定: 正常返回用【帧内 vregs】⇒ ★ 改帧有效（tgkill/改帧通道可用）
```

### 3.3 ★★★ 判定与纠正

| 结论 | 依据 |
|---|---|
| **改帧（handler 内改 ucontext 的 fpsimd vregs）= 有效通道** | h230 真机实测：返回后 `v0 == V_MARK` |
| 内核在**信号返回**路径读取**帧内** fpsimd 记录 | 同上；且与 `restore_fpsimd_context` 反汇编（`__arch_copy_from_user(sp+0x10, user, 0x200)`）一致 |
| ⇒ **画布确实经 `rt_sigreturn` 进入内核栈 `sp+0x10`** | 两条独立证据（真机 + 反汇编） |
| 从 handler 内再发 syscall 时，内核用**活寄存器** | h229 实测（`v0 == R_MARK`）—— 因为该路径是「保存」而非「恢复」 |

⇒ ★★★ **纠正 H195 的判死**：H195 称「投递画布是零效果操作、落点是 `task+0xec0`、与内核栈不重叠」。
**该结论只对「handler 内发 syscall 的那条路径」成立**。
**正常信号返回路径（handler return → `restore_sigframe`）用的是帧内 vregs，
会把 512B 原文写进内核栈 `sp+0x10`** —— 真机已证（h230）。

⇒ **装置可以继续用 `tgkill_staged`（改帧）通道**，但必须理解：
画布是从**信号返回路径**进入内核栈的，而不是从 handler 内的 syscall。

### 3.4 ★ 由此得到的装置设计要点

1. **投递必须发生在 handler return 那一刻**（由内核 `restore_sigframe` 完成），
   所以 `tgkill_staged` 的「改 ucontext → 让 handler 返回」形态是**正确**的。
2. **窗口**：画布落在内核栈后，**任何使用 fpsimd 的 syscall** 都可能在入口
   把活寄存器保存到 `task+0xec0`（**不**覆盖 `sp+0x10` 区），
   但若之后又有信号/系统调用复用该栈区，画布会被覆盖。
3. ⇒ **最优触发时序**：让**消费 syscall 紧随信号返回**（或干脆在 handler 返回前
   把消费动作排好），中间不插入多余 syscall。
4. ⚠️ **仍待实测**：画布落在内核栈后，**下一个 syscall 的栈帧是否会覆盖它** ——
   这决定「能否跨 syscall 消费」。**这是步 C/D 之前必须补的一项零风险实验。**


### 3.2 错误二：`rt_sigreturn` 的帧地址来自 **`sp`**，不是 `x0`

`h224`/`h225`/`h226` 连续三次用户态 SIGSEGV 的根因：
我最初按 `syscall(SYS_rt_sigreturn, frame)` 传 `x0`，但内核从 **`regs->sp`** 取帧。
修正为「裸汇编 `mov sp, frame; svc #0`」后帧定位立即自校验通过（`pc`/`sp` 双 ✅）。

### 3.3 尚未解决：手工调用 `rt_sigreturn` 仍 SIGSEGV

即使（a）帧基址正确、（b）偏移自校准通过、（c）用裸汇编 trampoline 切 `sp`、
（d）帧缓冲 64KB 页对齐 —— **`stamp` 模式（未改动的帧）仍 SIGSEGV**（`boot_id` 不变）。

已排除：帧基址错（自校验 ✅）、`sp` 未切换（裸汇编已切）、缓冲溢出（64KB + 8KB 重拷充裕）。

⇒ **剩余怀疑**：手工调用 `rt_sigreturn` 时，`regs->sp` 指向的帧**不是当前进程真正的那一帧**
（内核在 `setup_rt_frame` 里记录/校验的东西，或 signal mask 的恢复路径）
⇒ 进程在恢复后随即异常。

⚠️ **重要**：**真实利用路径并不需要手工调用 `rt_sigreturn`** ——
正确形态是「信号在内核栈上自然构造帧 → handler 里改帧的 fpsimd 段 → handler 返回时
内核自己走 `restore_sigframe`」。手工调用只是为了「零副作用地验证原语」而引入的额外复杂度。

---

## §4 产物清单

| 文件 | 用途 | 真机结果 |
|---|---|---|
| `tools/h223_sigframe_probe.c` | 步 A + 步 B | ✅ 双通过 |
| `tools/h224_canvas.c` | 第一版画布（x0 传帧，错） | ❌ SIGSEGV（已定位原因） |
| `tools/h225_canvas2.c` | 自校准版（仍 x0） | ❌ |
| `tools/h226_canvas3.c` | 自校准 + 镜像校验（仍 x0） | ❌ |
| `tools/h227_canvas.c` | 改用 sp + 大缓冲 | ❌ stamp 仍崩 |
| `tools/h228_canvas.c` | 裸汇编 trampoline | ❌ stamp 仍崩（已排除 3 类原因） |

编译命令（可复用）：
```powershell
& "<HOME>\.workbuddy\binaries\android\android-ndk-r27c\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe" `
  --target=aarch64-linux-android34 -O2 -static -o <out> <src>
```

---

## §5 下一步（按序）

1. **绕开手工 `rt_sigreturn`**：改为「在第二个信号的 handler 里改**第一个**尚未消费的帧」，
   或者直接在 handler 内改当前帧并**让内核自然返回**（需先解决 H195 的
   「handler 改 vregs 会被 `fpsimd_update_current_state` 覆盖」问题 ——
   实测确认：handler 里改 vregs 后，`current->thread.uw.fpsimd_state` 是否被内核覆盖）。
2. **步 C**：只跑 W/O/R 拓扑、**不投画布**，先验「悬垂能否产生且不崩」。
3. **步 D/E**：投画布 + 触发消费 + 独立透镜判据。

⚠️ **C 之前不要再试手工 `rt_sigreturn`** —— 已 5 次 SIGSEGV，均因手工调用这一非必需环节。
