# H106 · CVE-2026-43499 sigreturn 载波几何（MEY-AN00）

> 轮次：H106（2026-10-05 10:3x–11:0x）· 阶段：一（复盘）+ 二（分析）· **未开火**
> 起因：用户指令「走 sigreturn 路线，利用 CVE-2026-43499 给 MEY-AN00 复现临时 root」
> 判据来源：`Image-mey` 反汇编（capstone + `skipdata=True`）+ `kallsyms_mey_an00.txt` + 本机同版本 GKI 源码
> 产物：`analysis/scratch/h106_sigreturn_geom.py`、`h106_rt_sigreturn_dump.py`、`h106_bl_resolve.py`、`h106_vregs_slot.py`、`h106_remove_waiter_callers.py`

---

## 0. 一句话结论

**sigreturn 载波在本机成立，且几何已精确测定：0x200 字节的 FPSIMD 拷贝目的地恰在 `SP0 − 0x280`，而 CVE 的 stale waiter 在 `SP0 − 0x1B0`，二者相距 `0xD0`，整个 `struct rt_mutex_waiter`（0x70）连同 0xC0 字节余量全部落在我们可控的画布内。**

这直接解除了 H105 列出的第③道关卡（pselect 只有 120 B 且错位，`waiter->lock` 恒 0）。同时本轮**修正了 H105 的第②道关卡**：EDEADLK 并非被 `brk #0x800` 堵死——那条 `brk` 只在本线程自阻塞的 `rt_mutex_slowlock` 分支上，而 CVE 真正依赖的 `rt_mutex_start_proxy_lock`（跨线程代理）有**独立的 remove_waiter 调用点**，不经 `rt_mutex_slowlock`。

**尚未解决**：不等于可以上机。剩余硬门禁见 §6。

---

## 1. 为什么换载波是正确的诊断

| 载波 | 可控窗口 | 能否覆盖整个 waiter | 判死理由 |
|---|---|---|---|
| pselect `fd_set`（H47 方案） | `3 * FDS_BYTES(nfds)` ≤ **120 B**，且相对 waiter 错位 **+0x50** | ❌ 只到 `waiter+0x28`；`task(+0x50)` / `lock(+0x58)` 全落在 `res_*` 归零区 | H47 原判「容量矛盾」已由 H105 证伪；真因是**对齐错位** |
| **rt_sigreturn fpsimd vregs（本方案）** | **0x200 B 全长，起点即 `SP0−0x280`** | ✅ 覆盖 `waiter[0x00..0x70)` 全部 14 词，另余 **0xC0 B** | 无阈值、无 kmalloc 分支、不依赖 `nfds` |

**关键结构性优势**：以前只能在 120 B 里挑 5 个词，现在可以在一块**连续且完全自主**的 512 B 画布里同时摆放

```
[ waiter 0x70 ][ 伪 struct rt_mutex ][ 伪 rt_waiter_node / 影子节点 ]
```

⇒ 任何消费路径对 `waiter->task` / `waiter->lock` / `waiter->pi_tree` 的解引用都可以被**圈养在我们自己的栈区内**，不再有必然的 NULL 解引用。

---

## 2. 环① 源码推理

源码树 = `kernel_src/Code_Opensource/kernel/`（本机同版本 `6.6.118-android15-8`）。设备实测 `/proc/cpuinfo` 的 Features **不含 `sve`** ⇒ 运行期走纯 FPSIMD 分支（`restore_fpsimd_context`）。

| 环①结论 | 出处 |
|---|---|
| `restore_fpsimd_context()` 用 `__copy_from_user(fpsimd.vregs, &user->fpsimd->vregs, sizeof(fpsimd.vregs))`，长度恒为 **0x200** | `arch/arm64/kernel/signal.c:207-218` |
| `struct user_fpsimd_state.vregs` 是该结构体**首个成员** ⇒ 拷贝目的地 = 该栈局部的**首地址** | `include/uapi/asm/sigcontext.h` |
| 入口必经三道闸门：① `regs->sp & 15` → `badframe` ② `access_ok(frame, sizeof(*frame))` ③ `restore_sigframe` 必须解出 fpsimd 记录 | `signal.c:820-848` |
| fpsimd 记录的 magic 必须 `0x46508001`、size 必须 `0x210`（`user->fpsimd_size != sizeof(struct fpsimd_context)` 直接 `-EINVAL`） | `signal.c:212-213` |
| `remove_waiter()` 的第一处 `rb_erase` 只需要 `waiter+0x00/0x08/0x10`，`lock` 是**函数实参**不由 waiter 取 | `kernel/locking/rtmutex.c` + H105 环②复核 |
| ★ **CVE 触发拓扑**：`rt_mutex_start_proxy_lock()` 在 `__rt_mutex_start_proxy_lock` 返回错误（**-EDEADLK**）时调 `remove_waiter(lock, waiter)`，此处 `current` 是**请求方线程**而 `waiter->task` 是**被 requeue 的线程**，二者不同 ⇒ `current->pi_blocked_on = NULL` 清错人 ⇒ **目标线程的 `pi_blocked_on` 悬挂** | `kernel/locking/rtmutex_api.c:344-356` |
| 该 waiter 由 requeuer 通过 `this->rt_waiter` 取得，指向**目标线程 `futex_wait_requeue_pi` 的栈局部** | `kernel/futex/requeue.c:627` |

---

## 3. 环② 汇编交叉验证（本轮核心产出）

### 3.1 两条链的深度（均以 `SP0` = `kernel_entry` 后的 SP = `pt_regs` 基址为零点）

| 链 | 入口帧 | 被调用帧 | 关键槽 | 相对 SP0 |
|---|---|---|---|---|
| futex | `__arm64_sys_futex` `sub sp,sp,#0x80` | `futex_wait_requeue_pi` `sub sp,sp,#0x1c0` | waiter = `sp+0x90` | **`SP0 − 0x1B0`** ✔（重算与 H105 独立一致） |
| select | `__arm64_sys_pselect6` `0x90` | `core_sys_select` `0x1e0` | `stack_fds` = `sp+0x70` | `SP0 − 0x200`（⇒ waiter 在 `stack_fds+0x50`，复现 H47 错位） |
| **sigreturn** | `stp x29,x30,[sp,#-0x60]!` 再 `sub sp,sp,#0x230` | `restore_sigframe`/`restore_fpsimd_context` **已内联**（无独立符号） | vregs 拷贝目的地 = `sp+0x10` | **`SP0 − 0x280`** |

**SP 调整审计**：整个 `__arm64_sys_rt_sigreturn`（符号范围 `0x49b2e4 .. 0x49c570`，4748 B / 1187 条指令）内只有两处改写 SP —— 入口 `0x49b304 sub sp,sp,#0x230` 与出口 `0x49b6f8 add sp,sp,#0x230`。函数体内 SP 恒为 `SP0 − 0x290`。

### 3.2 0x200 拷贝的决定性指令

```
; __arm64_sys_rt_sigreturn（内联了 restore_fpsimd_context）
0xffffffc08049be6c  cmp     w21, #0x210        ; fpsimd_size 必须 == sizeof(fpsimd_context)
0xffffffc08049be70  b.ne    -> badframe
0xffffffc08049beac  add     x0, sp, #0x10      ; ★ dst = SP0 - 0x290 + 0x10 = SP0 - 0x280
0xffffffc08049beb0  mov     w2, #0x200         ; ★ size = 0x200
0xffffffc08049beb4  bl      __arch_copy_from_user
```

另有第二个等价拷贝点（`0x49c228 add x0,sp,#0x10` / `mov w2,#0x200` / `0x49c230 bl`）分属另一条分流。**两条分流的目的地同为 `sp+0x10`、长度同为 0x200** ⇒ 结论对分支选择鲁棒（这是重要的健壮性证据，不必赌哪条路会被走）。

> **外部互证**：本机的帧总计 `0x60 + 0x230 = 0x290` 与 mdarcy 9.2.4 参考实现注释的 `sys_rt_sigreturn frames −0x290`、`0x200-byte FPSIMD copy destination −0x280`**逐项相同**；不同机型的 waiter 深度不同（mdarcy `0xf0`、iQOO `0x08`、本机 `0xD0`），说明**框架可继承、数值必须自算**——这条纪律再次被验证。

---

## 4. ★ 几何常数表（本机权威值）

```
画布起点（vregs 字节 0x00） = SP0 − 0x280
waiter 落点                 = SP0 − 0x1B0
SIGRETURN_WAITER_VREG_OFF   = 0x280 − 0x1B0 = 0xD0      （qword 序号 26，整除 ✔）
画布余量                    = 0x200 − (0xD0 + 0x70) = 0xC0 字节
覆盖检查                    : 0xD0 + 0x70 = 0x140 ≤ 0x200 ✔
```

`struct rt_mutex_waiter`（BTF 实测 sizeof = **0x70**，与 `futex_wait_requeue_pi` 的 `memset(sp+0x90, 0, 0x70)` 吻合）逐字段映射：

| 字段 | waiter 内偏移 | 画布偏移 | vregs qword | 作用 |
|---|---|---|---|---|
| `tree.__rb_parent_color` | +0x00 | **0xD0** | **26** | 写**目标**（`mpc = pc & ~3`）|
| `tree.rb_right` | +0x08 | **0xD8** | **27** | 写**值**；同时是写点②的地址 |
| `tree.rb_left` | +0x10 | 0xE0 | 28 | `rb_erase` 的 `csel` 条件 / Path 选择 |
| `pi_tree.__rb_parent_color` | +0x28 | 0xF8 | 31 | 第二处 rb_erase（受 leftmost 门控）|
| `pi_tree.rb_right` | +0x30 | 0x100 | 32 | 同上 |
| `pi_tree.rb_left` | +0x38 | 0x108 | 33 | 同上 |
| `task` | +0x50 | 0x120 | 36 | ★ pselect 时恒 0，现在**可控** |
| `lock` | +0x58 | 0x128 | 37 | ★ pselect 时恒 0 ⇒ adjust_prio_chain 必崩；现在**可控** |
| `wake_state` | +0x60 | 0x130 | 38 | |
| `ww_ctx` | +0x68 | 0x138 | 39 | |
| —— 自由区 —— | — | **0x140 .. 0x200** | 40 .. 63 | 192 B，可安放伪 `rt_mutex` 等 |

---

## 5. 写原语语义（沿用 MEY-TECH §3.1，`rb_erase @ 0x3a9d4`，三种写法均已汇编证）

| 写点 | 落点 | 值 | 门控 |
|---|---|---|---|
| ① `0x3aa00 str x8,[x11]` | `mpc+0x08`（默认分支）或 `mpc+0x10`（`[mpc+0x10]==node` 时） | `waiter.tree.rb_right` | `mpc != 0` |
| ② `0x3aa10 str x9,[x8]` | `*tree.rb_right` | 原始 `pc`（含低 2 位） | `tree.rb_right != 0` |
| ③ Path B | — | — | `rb_right != 0` |

**干净的「写 0 到任意地址」配方**（与 H90 同源，现改为 sigreturn 投递）：

```
tree.__rb_parent_color = TARGET − 8      ⇒ mpc = TARGET−8（TARGET 需 4 对齐）
tree.rb_right          = 0                ⇒ 写点②③ 均被跳过
tree.rb_left           = 0
⇒ 净效果：只发生一次 *(TARGET) = 0，无副作用、无重平衡（pc&3==0 ⇒ rebalance==NULL，已由 H96 证）
```

**局限性（必须记账）**：写点②使「值」与「地址」二位一体——要写**非零**值 V，就必须让 V 同时是一个可接受 `*(V) = TARGET−8` 的地址。因此**当前唯一无副作用的原语是「写 0」**，写指针类常量需要额外设计（候选：选一个可牺牲的 scratch 全局；或先把 V 指向自己可控的栈画布）。

---

## 6. ★ 剩余硬门禁（未完成前禁止真机开火）

| # | 门禁 | 现状 | 判据 |
|---|---|---|---|
| **G1** | 确认 planted waiter 会被消费（触发拓扑实测） | 源码已定位，未实测 | 见 §8 判据 E1 |
| **G2** | 重定位真 `selinux_state.enforcing` 地址 | `0x23ba418` 已被 H99 证伪；候补 `0x23e2c20` 未核 | 见 §7.1 |
| **G3** | 验证 `SP0` 两次 syscall 一致（无随机扰动） | `CONFIG_RANDOMIZE_KSTACK_OFFSET=y` 但 `_DEFAULT` 未设 ⇒ 理论确定，**未实测** | 纯用户态探针即可验证 |
| **G4** | `struct rt_mutex_base` 精确布局（伪 lock 用） | 源码给出成员顺序，偏移未定 | 需 BTF 或流式反汇编推算 |
| **G5** | 铁律⑨：先做纯用户态 sigframe 自测 | 未做 | 构造只含 fpsimd 记录的帧，`sigaction`+handler 改 ucontext，验证不被 `badframe` 拒 |

> **H104 的协同提示**：10-04 的 `h17/` 系列已证明 L1 链路能走到 `MP_SET_OK`（`modprobe_path` 改写成功），唯一失败是 helper 落在 `u:r:shell:s0` + `CapEff=0`。H104 的「下轮第一步」正是**同 boot 内先写 `enforcing=0` 再触发**。本线提供的「干净写 0」与该需求**完全吻合** ⇒ 两条线在下一步汇合，不必各自造轮子。

---

## 7. 下一步（严格按序）

### 7.1 （最高）用已有读能力回收 `enforcing` 真地址

不动 device/machinery，只用已打通的 L1 桥（`MISC_BRIDGE_RW_PASS` 已在 10-04 实测）：

1. 扫描 `.data` 区读 `0x23ba400..0x23ba460` 与 `0x23e2c00..0x23e2c50`，按 **8 字段布局指纹**判别真 `struct selinux_state`：`initialized==1`、连续 8 个小整数 `policycap[8]`、其后两个 bool。
2. **阴性对照不可省**：同法扫一块已知非该结构的 `.data`，必须**不命中**该指纹（H99 铁律）。
3. 命中后用「写 0 → `getenforce` 变 Permissive」做终局闭环（**必须同 boot 内回读**）。

### 7.2 纯用户态 sigframe 自测（零设备风险）

安装 `SIGUSR1` handler（`SA_SIGINFO`），在 handler 内定位 `fpsimd_context`（magic `0x46508001`），向 `vregs` 全长写入递增标记并返回。判据：不崩溃、不 `-EINVAL`、后续用户态行为正常 ⇒ 帧布局被本机内核采信。

### 7.3 触发拓扑（三线程）

```
W（waiter，同一进程内的线程）: futex_wait_requeue_pi(uaddr1, ...) 阻塞
R（requeuer）:                 futex(FUTEX_CMP_REQUEUE_PI, uaddr1 -> uaddr2, PI-aware uaddr2)
O（owner）:                    持有 uaddr2 的 PI 锁，构造使 __rt_mutex_start_proxy_lock 返回 -EDEADLK 的环形依赖
```
`FUTEX_CMP_REQUEUE_PI` → `requeue.c:627 rt_mutex_start_proxy_lock(pi_mutex, W_q->rt_waiter, W_task)` → `-EDEADLK` → `remove_waiter` 清错人 ⇒ `W->pi_blocked_on` 悬挂到 **W 自己的 `SP0−0x1B0`**。

W 返回后立刻在同一线程 `raise(SIGUSR1)`（或干脆让 handler 在下一个信号窗口执行），用 §4 的 qword 映射把伪造 waiter 写进去，然后 **spin 保持不退栈**，避免该槽被复用/清零。

### 7.4 消费器选择（按优先级）

1. **`remove_waiter`**（再触发一次 requeue 或让 owner 释放后另一个 waiter 进来）——它的第一处 `rb_erase` 只用 `waiter+0x00/0x08/0x10`，且 `lock` 是实参 ⇒ **最抗崩**。
2. `rt_mutex_adjust_prio_chain`——以前必崩（`waiter->lock==0`），现在可以用画布余量里的**伪 rt_mutex** 补上 `waiter->lock`，重新成为可选路径。
3. ❌ **禁止**再用不加伪 lock 的 `sched_setattr → adjust_prio_chain`（H105 已列禁止项，除非伪 lock 就位）。

---

## 8. 可证伪判据（写原语是否真的落地 —— 必须遵守）

**假设 H106-A**：按 §4 几何布置的 waiter 会被某条 `remove_waiter` 路径消费，产生一次 `*(TARGET) = 0`。

判据（**同一 boot 内立刻回读，跨重启一律判 UNKNOWN**）：

1. **独立透镜**：`TARGET` 选 `sysctl_bootid` 的 data 区。历史上 `text=90b0292a` 证明该区可被内核 8 字节写并能被用户态 `cat /proc/sys/kernel/random/boot_id` 读回 —— **这是唯一已知的、不依赖我自己组件的独立回读通道**。若 `boot_id` 出现预期形态 ⇒ H106-A 成立。
2. **不崩**：`boot_id` 未变 + `uptime` 未归零 + `history.log` 无新增 `page_request`/`null_pointer`。
3. **反证**：若 panic 且病 debut 落在 `raw_spin_lock(&lock->wait_lock)` 或 `[waiter+0x58]` ⇒ 说明走了 `adjust_prio_chain` 且伪 lock 未生效 ⇒ 回到 §7.4 第 2 项。
4. **零信息量排除**：任何「用同一 rb_erase 写再读回」的自校准**不算判据**（铁律）。

---

## 9. 三环对照表

| 环 | 内容 | 结论 |
|---|---|---|
| ① 源码 | `restore_fpsimd_context` 恒拷 0x200；`vregs` 是结构首成员；`rt_mutex_start_proxy_lock` 的失败分支调 `remove_waiter`（跨线程 ⇒ 清错 `pi_blocked_on`） | **成立** |
| ② 汇编 | `rt_sigreturn` 帧 `0x60+0x230=0x290`，目的槽 `sp+0x10` ⇒ `SP0−0x280`；waiter = `SP0−0x1B0`；`remove_waiter` 仅 3 个调用点，全在 futex PI/proxy 路径 | **成立** |
| ③ 镜像 delta | `Image-mey` 即本机固件裸镜像；`restore_sigframe`/`restore_fpsimd_context`/`do_futex` 均被**内联**（与荣耀 6.1 同源问题，6.6 上偏移不同）⇒ 静态帧深必须以汇编为准 | **成立** |
| 矛盾 | 无。**矛盾不在三环内，而在「漏洞可用」与「尚未选定消费器 + `enforcing` 地址未知」之间** | — |

---

## 10. 本轮新增 / 修正清单

**新增的事实（可直接引用）**
- `SIGRETURN_WAITER_VREG_OFF = 0xD0`（qword 26），画布余量 0xC0 B
- `__arm64_sys_rt_sigreturn` 帧 `0x290`，`Image-mey` 符号区 `0x49b2e4..0x49c570`
- `remove_waiter` 全部调用点：`rt_mutex_start_proxy_lock+0x64` / `rt_mutex_cleanup_proxy_lock+0x4c` / `rt_mutex_slowlock+0x194`
- `rt_mutex_adjust_prio_chain` 调用点：`task_blocks_on_rt_mutex+0x2c8` / `remove_waiter+0x1fc` / `rt_mutex_adjust_pi+0xf8`

**修正的旧结论**
- ❌ H105「EDEADLK 触发被 `brk #0x800` 硬化」——**部分修正**：`brk` 确在，但它 guard 的是 `rt_mutex_slowlock` 内 `cmn w22,#0x23`（ret==-EDEADLK）的**自阻塞分支**；CVE 依赖的 proxy 路径有独立 `remove_waiter` 调用点，**不经该 brk**。H105 据此给出的 ⊘ 应降级为「需按 §7.3 重新验证」。
- ❌ H47「L2 永不复活」——已被 H105 部分推翻（判据错），本轮进一步：换载波后几何错位 0x50 也不再成立。HANDOFF §3 与 §S.1 表格中「永不复活」的措辞**需要更新**。

**禁止重复**
- ❌ 再引用「容量矛盾」作为 L2 判死理由（H105 已证伪）
- ❌ 直接照抄 mdarcy 的 `0xf0` / iQOO 的 `0x08` / CGA-W00 的 `0xe8`（本机实测 `0xD0`）
- ❌ 未完成 §6 的 G1–G5 就上机开火
