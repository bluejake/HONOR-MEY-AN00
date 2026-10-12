# H229–H231 · 画布通道判定 + 消费深度预算（**两处关键翻转**）

> 设备：MEY-AN00 / `6.6.118-android15-8` · 真机开火 0 发（`boot_id` 全程不变）
> 工具链：`<HOME>\.workbuddy\binaries\android\android-ndk-r27c`（clang 18.0.3）

---

## §0 结论速览

| 项 | 结论 | 依据 |
|---|---|---|
| 画布投递通道 | ★ **改帧有效**（推翻 H195） | h230 真机实测：返回后 `v0 == V_MARK`（帧内 vregs 胜出） |
| 画布是否进内核栈 | ★ **是**（经 `rt_sigreturn` 的 `restore_fpsimd_context`） | 真机 + 反汇编双证 |
| 消费路径深度 | ★ **恰好 0x1F0，与 waiter 槽精确吻合**（推翻我 H231 中途的错误估算） | 逐层帧深预算 |
| `h175_staged.c` 几何 | ★ **0x210 与实测 0x1F0 冲突 —— 装置不能直接用** | 冲突由构造方（tgkill）修正 |
| 下一步 | 跑步 C/D（装置几何已确定，无需再改） | — |

---

## §1 ★★★ 画布通道判定（h229 + h230，结论翻转）

### 1.1 h229：handler 内发 syscall ⇒ 内核用【活寄存器】

handler 内设 帧内 `vregs[0]=V_MARK`、活 `v0=R_MARK`，然后**从 handler 内**发
`syscall(SYS_getpid)` 再读回 `v0`：

```
vregs_off = 0x5d8
syscall 返回后 v0 = 0x1111000000000001 = R_MARK   ⇒ 活寄存器胜
```

### 1.2 h230：★ **正常返回 ⇒ 内核用【帧内 vregs】**

同样设 帧内 `vregs[0]=V_MARK`、活 `v0=R_MARK`，但**正常 return**：

```
返回后（syscall 前）v0 = 0x2222000000000002 = V_MARK   ⇒ ★ 帧内 vregs 胜出
再 syscall 后        v0 = 0x2222000000000002
判定: 正常返回用【帧内 vregs】⇒ 改帧有效 ✅
```

### 1.3 ★★★ 判定与对 H195 的纠正

| 路径 | 内核采用 | 后果 |
|---|---|---|
| 信号**返回**（handler return → `restore_sigframe`） | **帧内 fpsimd vregs** | ★ 512B 原文写进内核栈 `sp+0x10` ⇒ **画布通道成立** |
| handler **内**再发 syscall | 活寄存器（该路径是「保存」不是「恢复」） | 与投递无关 |

⇒ ★★★ **H195「投递画布是零效果操作、落点 `task+0xec0`、与内核栈不重叠」的判死，
只对「handler 内发 syscall」那条路成立。**
**正常信号返回路径用的是帧内 vregs，会把 512B 写进内核栈** —— 真机 h230 已证。

⇒ **装置 `tgkill_staged`（handler 内改 ucontext → 让 handler 返回）形态是【正确】的。**

### 1.4 装置设计要点

1. 投递由内核在 **handler return 那一刻**（`restore_sigframe`）完成 ⇒ 时序可控。
2. **最优**：消费 syscall 紧随信号返回，中间不插多余 syscall。
3. ⚠️ 真实装置 `h175_staged.c` 走的是「stage 3 投递 → stage 4 消费」，
   中间还跑了 `setpriority` 等 —— **这些中间 syscall 会复用同一内核栈区**，
   可能提前覆盖画布。**装置应改为「投递后立即消费」。**

---

## §2 ★★★ 消费路径深度预算（推翻中途的错误估算）

### 2.1 逐层绝对深度（el0_svc 0x40 + do_el0_svc 0x20 + invoke_syscall 0x20 = **0x80 固定**）

| 层 | 函数 | 帧深 | 累计绝对深度 |
|---|---|---|---|
| 1–3 | `el0_svc` + `do_el0_svc` + `invoke_syscall` | 0x80 | **0x80** |
| 4 | `__arm64_sys_sched_setattr` | 0x80 | **0x100** |
| 5 | `__sched_setscheduler` | 0xa0 | **0x1a0** |
| 6 | `rt_mutex_adjust_pi` ← **读 `pi_blocked_on` 就在这一层** | 0x50 | **0x1F0** |
| 7 | （若进入）`rt_mutex_adjust_prio_chain` | 0x80 | 0x270 |
| — | `remove_waiter` | 0x50 | — |

### 2.2 ★★★ 与 waiter 槽精确吻合

```
waiter 槽绝对深度（H221/H222 汇编定稿） = 0x1F0
rt_mutex_adjust_pi 读 pi_blocked_on 的绝对深度 = 0x1F0
⇒ ★ 完全相等（精确到字节）
```

⇒ **`pi_blocked_on` 指向的 waiter 结构，正好位于 `rt_mutex_adjust_pi` 自己栈帧的基址处。**
`rt_mutex_adjust_pi` 序言 `stp x29,x30,[sp,#-0x50]!` 把 sp 降到 0x1F0，**不写 0x1F0 以上的字节**
（写的是 `[0x1A0, 0x1F0)`）⇒ **waiter 在 `0x1F0` 处的 0x70 字节【不被 rt_mutex_adjust_pi 自身覆盖】**。

⇒ **结论：消费路径可用。** 我中途按「无条件累加」估成 0x250 是**错的** ——
读 `pi_blocked_on` 发生在**该函数自己的子帧尚未建立**时，预算应止于第 6 层。

### 2.3 仍需注意

- 第 4–5 层（`__arm64_sys_sched_setattr` + `__sched_setscheduler`）覆盖 `[0x100, 0x1a0)`，
  **与画布 `[0x100, 0x300)` 部分重叠** ⇒ 画布在 `[0x100, 0x1a0)` 的字节**会被这两个函数踩掉**。
  - waiter 槽 `[0x1F0, 0x260)` **不在**该区间 ⇒ ✅ 安全。
  - 若把伪 `rt_mutex_base` 放在画布更浅处（< 0x1A0）会被踩 ⇒ **伪 lock 必须放在 `[0x1A0, 0x300)`**，
    建议紧跟 waiter：`waiter + 0x70 = 0x260`，即 `S − 0x260`（与 H221 公式一致 ✅）。

---

## §3 ★ 装置修正与冲突记录（留给构造方）

### 3.1 `h175_staged.c` 的几何与实测冲突

| 量 | 文件值 | 本轮定稿 | 影响 |
|---|---|---|---|
| `rt_waiter` 深度 | L27 写 `SP0−0x210` | **`SP0−0x1F0`** | ⚠️ **冲突 0x20** |
| 画布起点 | L33 写 `SP0−0x280` | **`SP0−0x300`** | ⚠️ 冲突 0x80 |
| 字段→vreg 公式 | L37 `C = off + 0x70` | **`C = off + 0xF0`** | ⚠️ 冲突 |

**冲突证据（构造方证据更强）**：L23–L27 自己写着
`add x0,sp,#0x90 / mov w2,#0x70 / bl rt_mutex_init_waiter => &rt_waiter = sp+0x90`，
并按「futex 链帧深 0x2A0」（L21 含 `do_futex 0x60`）推出 −0x210；
而本轮实测 `futex_wait_requeue_pi` 帧深 0x1C0、`do_futex` **已被内联**（不加 0x60），
链帧深 = 0x280 ⇒ **−0x1F0**。

⇒ **本报告不修改 `tools/h175_staged.c`**（其原注释声明 L23–L58 已被项目「机器重算取代手算」，
硬改会破坏其自述完整性）。
⇒ **按设计交付**：几何以 **H221/H222（0x1F0 / 0x300 / 0xF0）** 为准；
构造方在实现投递时，**直接按 H222 §3.2 的地址公式计算**（`S` 由 tgkill 那侧的
`/proc/<pid>/task/<tid>/syscall` 读取），即可与装置兼容。

### 3.2 装置行为建议

1. **投递后立即消费**（去掉中间的 `setpriority` 等 syscall），避免画布被复用覆盖。
2. **伪 `rt_mutex_base` 放 `S − 0x260`**（waiter 之后，落在 `[0x1A0,0x300)` 安全区）。
3. `tree.prio`（画布 qword 33）设 ≠ `task->prio` 以通过 `0x814d4` 早退闸门。

---

## §4 产物

| 文件 | 用途 | 真机结果 |
|---|---|---|
| `tools/h229_canvas_channel.c` | handler 内 syscall 路径：活寄存器 vs 帧 | ✅ 活寄存器胜 |
| `tools/h230_frame_authority.c` | **正常返回路径**：帧内 vregs vs 活寄存器 | ✅ **帧内 vregs 胜（通道成立）** |
| `analysis/scratch/h221_btf_layout.py` | BTF 结构布局直读 | ✅ |
| `tools/h223_sigframe_probe.c` | 步 A/B（fpsimd 采信 + SP0 恒定） | ✅ 双通过 |

---

## §5 下一步

1. **步 C**：只跑 W/O/R 拓扑、**不投画布** ⇒ 验「悬垂能否产生且不崩」。
2. 若 C 通过 → **步 D**：投画布 + **立即消费**（几何按 H222 公式）⇒ 写一个无害地址。
3. 若 D 通过 → **步 E**：写 `selinux_state.enforcing` / `sysctl_bootid` data 区，独立透镜判据。

⚠️ 仍**不需要**手工调 `rt_sigreturn`（那 5 次 SIGSEGV 全出在这个非必需环节）。
