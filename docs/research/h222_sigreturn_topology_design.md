# H222 · sigreturn 路线三线程拓扑设计（装置现成，几何已改）

> 设备：MEY-AN00 / `6.6.118-android15-8` · **真机开火 0 发**
> 依据：`vmlinux-mey.elf` 反汇编 + 本机 BTF + `tools/h175_staged.c`（现成装置）
> 纪律：地址一律用 **SP0 相对**；不硬编码内核绝对地址。

---

## §0 一句话结论

**装置已经现成（`tools/h175_staged.c`，887 行，含完整 W/O/R 三线程 + 分段投递 + spin 保持），
但它的几何常数是旧的、且地址是硬编码内核全局 —— 两者都必须改。
本轮把 `rt_waiter` 位置从汇编钉死为 `sp+0x90`（绝对深度 0x1F0），
并把全部地址改为 SP0 相对（SP0 可用 `/proc/<pid>/task/<tid>/syscall` 实时读取）。**

---

## §1 ★★★ `rt_waiter` 位置：汇编三重实证 → **`sp+0x90`，绝对深度 0x1F0**

### 1.1 决定性证据：proxy-lock 调用直接传 `sp+0x90`

```asm
; futex_wait_requeue_pi @0x...959060
95906c: ldr   x8, [sp, #0x50]
959070: add   x2, sp, #0x90         ; ★★ x2 = waiter 实参
959074: mov   x1, x19               ;    lock
959078: add   x21, x8, #0x10
95907c: mov   x0, x21
959080: bl    rt_mutex_wait_proxy_lock      ; ★ (lock, waiter=sp+0x90, ...)
...
959098: add   x1, sp, #0x90         ; ★★ 同一对象传给 cleanup
9590a0: bl    rt_mutex_cleanup_proxy_lock
```

⇒ **`rt_mutex_waiter` 就在 `sp+0x90`** —— 这是函数实参，不是推断。

### 1.2 交叉印证：`memset(sp+0x90, 0, 0x70)` 的长度

```asm
958ea4: add  x0, sp, #0x90
958eac: mov  w2, #0x70
958eb4: bl   __memset
```
`sizeof(struct rt_mutex_waiter) = 0x70`（本机 BTF 实测）⇒ 精确吻合。

（注：另两处 memset 为 `sp+0x00`（len 0x70，`futex_q` 本身）与
`x29-0x60`（len 0x50，`hrtimer_sleeper`）。三处各不相同，勿混。）

### 1.3 深度

```
futex 链帧深 = el0_svc 0x40 + __arm64_sys_futex 0x80 + futex_wait_requeue_pi 0x1c0 = 0x280
rt_waiter 绝对深度 = 0x280 − 0x90 = 0x1F0     占用 [0x1F0, 0x260)
```

| 来源 | 值 | 判定 |
|---|---|---|
| `h175_staged.c` L27 | `SP0 − 0x210` | ❌ 差 0x20 |
| H106 | `SP0 − 0x1B0` | ❌ 差 0x40 |
| **本轮** | **`SP0 − 0x1F0`** | ★ 定稿（实参 + memset + 帧账本 三重） |

---

## §2 装置盘点：`tools/h175_staged.c` 已实现什么（可直接复用）

| 组件 | 实现 | 位置 |
|---|---|---|
| 线程 W（waiter） | `FUTEX_LOCK_PI(f_chain)` 持链 → `FUTEX_WAIT_REQUEUE_PI(f_src, to, f_target)` | L335 `thread_W` |
| 线程 O（owner） | `FUTEX_LOCK_PI(f_target)` 持目标锁 | L624 `thread_O` |
| 主线程（requeuer） | `FUTEX_CMP_REQUEUE_PI(f_src, 1, 0, f_target)` ⇒ 预期 **EDEADLK** | L1124 |
| 分段投递 S1/S2/S3/S4 | `g_w_stage` 状态机 | L470–552 |
| 画布投递 | `tgkill_staged(pid, w_tid, SIGUSR1, T, V, TASKP, LOCKP)`（signal handler 改 ucontext fpsimd） | L434 |
| 消费触发 | `do_sched_setattr_nice(w_tid, ...)` / `do_sched_setattr(w_tid, ...)` | L540/L544 |
| 因子开关 | `g_skip_deliver` / `g_stop_after_s1` / `g_stop_before_s4` | L199–204 |
| B4 攻击线程 | 等 W 返回后由**另一线程**对 W 发 S4 | L563 `thread_B4_attacker` |

⇒ ★ **拓扑不用重写**，只需改几何与地址来源。

---

## §3 ★★★ 装置的两处必改

### 3.1 几何常数（旧值 → 新值）

| 量 | 旧（h175_staged.c） | **新** |
|---|---|---|
| `rt_waiter` 绝对深度 | `0x210` | **`0x1F0`** |
| 画布起点 | `SP0 − 0x280` | **`SP0 − 0x300`** |
| 画布内 waiter 偏移 | `0x70` | **`0xF0`** |
| waiter 字段 → vreg 槽公式 | `C = waiter_off + 0x70` | **`C = waiter_off + 0xF0`** |

**新字段映射表（照此填 `vregs[]`；qword 索引 = C/8）**：

| 字段 | waiter off | 画布 C | qword | vreg |
|---|---|---|---|---|
| `tree.entry.rb_parent_color`（写值 V） | +0x00 | **0xF0** | 30 | `v15.d[0]` |
| `tree.entry.rb_right`（须 0） | +0x08 | **0xF8** | 31 | `v15.d[1]` |
| `tree.entry.rb_left`（写地址 T） | +0x10 | **0x100** | 32 | `v16.d[0]` |
| `tree.prio` | +0x18 | **0x108** | 33 | `v16.d[1]` |
| `tree.deadline` | +0x20 | 0x110 | 34 | `v17.d[0]` |
| `pi_tree` | +0x28 | 0x118 | 35–39 | `v17.d[1]`… |
| **`task`** | +0x50 | **0x140** | **40** | `v20.d[0]` |
| **`lock`** | +0x58 | **0x148** | **41** | `v20.d[1]` |
| `wake_state` | +0x60 | 0x150 | 42 | `v21.d[0]` |
| `ww_ctx` | +0x68 | 0x158 | 43 | `v21.d[1]` |

### 3.2 ★★ 地址来源：硬编码内核全局 → **SP0 相对**

旧装置用固定绝对地址：
```c
#define MEY_LOCK      0xffffffc082136048UL   /* .data 空洞 */
#define MEY_INIT_TASK 0xffffffc08217e280UL   /* init_task */
```
**问题**：本项目已证 KASLR 每 boot 变化（slide 经 `sched_blocked_reason` 泄漏，多次实测不同值）
⇒ **硬编码必错 ⇒ 必 panic**。

**新方案（本轮引进，同时解决 N6）**：

```
S = 读 /proc/<pid>/task/<tid>/syscall 的 sp 字段   /* = 该线程 SP0 */
伪 rt_mutex_base 地址 =  S − 0x260      （画布余量内，绝对深度 [0x260,0x280)）
画布基址（vregs[0]）  =  S − 0x300
rt_waiter 槽          =  S − 0x1F0
```

★ **全部 slide 无关**（只有相对 SP0 的偏移），且不需要 KASLR 基址。
★ 伪 lock 放在**我们自己的内核栈**上 ⇒ 不再依赖 `.data` 空洞的绝对地址。

**伪 `rt_mutex_base` 内容（BTF 实测布局）**：
```c
struct rt_mutex_base {   // size 0x20
    +0x00 raw_spinlock_t  wait_lock;   // = 0  ⇒ raw_spin_trylock 成功
    +0x08 rb_root_cached  waiters;     // rb_root(0x08) + rb_leftmost(0x10)
    +0x18 struct task_struct *owner;
};
```
⇒ 四 qword 全 0 即可（`wait_lock=0` 未持锁；`owner=0` 走无 owner 分支）。

---

## §4 ★ 消费链选择（两条，需分别评估）

### 4.1 `rt_mutex_adjust_prio_chain`（经 `sched_setattr`）

```asm
; rt_mutex_adjust_pi @0x81081438 早退闸门
8146c: ldr x21, [x19, #0x938]   ; waiter = task->pi_blocked_on
81474: cbnz x21, ...            ; != NULL ⇒ 继续
814c8: ldr w9, [x21, #0x18]     ; ★ waiter->tree.prio
814c4: ldr w8, [x19, #0x84]     ; ★ task->prio
814d0: cmp w9, w8
814d4: b.ne ...                 ; ★ 不等 ⇒ 进入（我们可控 tree.prio）
```
⇒ `tree.prio`（画布 qword 33）设成 ≠ `task->prio` ⇒ 通过闸门。
⇒ 随后 `raw_spin_trylock(waiter->lock)` —— **伪 lock 必须在此就位**（`wait_lock=0` ⇒ 成功）。

### 4.2 `remove_waiter`（再走一次 requeue/cleanup）

```asm
81080e7c: ldr  x24, [x0, #0x10]   ; top_waiter = lock->waiters.rb_leftmost
81080e88: cbz  x24, ...
81080e8c: ldr  x8, [x24, #0x58]   ; ★ top_waiter->lock
81080e90: cmp  x8, x19
81080e94: b.ne #0x81080f8c        ; ★ 不等 ⇒ BUG_ON brk ⇒ panic
```
⇒ 需要 `lock->waiters.rb_leftmost` 与伪 waiter 的 `lock` 一致。
★ 好处：**不调用 `raw_spin_trylock`**（无 trylock 失败风险）。
⚠️ 但其 `lock` 是实参（内核真实锁），要让 `rb_leftmost == waiter` 需精确控制树形。

**建议先走 4.1**（伪 lock 全 0 即可，门槛更低）。

---

## §5 实验序列（严格分阶，一 boot 一发）

| 步 | 内容 | 开火 | 判据 |
|---|---|---|---|
| **A** | 纯用户态：装 SIGUSR1 handler，handler 内定位 fpsimd_context（magic `0x46508001`）、向 vregs 写递增值、返回 | ❌ 零内核写 | 不崩、不 EINVAL、行为正常 |
| **B** | 真机读 SP0 两次（同线程不同 syscall）比对 | ❌ 只读 | `S` 恒定 ⇒ N4 于真机成立 |
| **C** | 只跑 W/O/R 拓扑**不投画布**（`g_skip_deliver=1`），观察是否产生悬垂且不崩 | ✅ 1 boot | `boot_id` 不变 + 无 panic |
| **D** | 投画布 + 触发消费，**不设 T/V 为破坏性值**（先写一个无害固定地址） | ✅ 1 boot | 独立透镜回读（见 §6） |
| **E** | 正式写 `TARGET`（如 `selinux_state.enforcing` 或 `sysctl_bootid` data 区） | ✅ 1 boot | `getenforce` 变 Permissive / `boot_id` 形态变化 |

⚠️ **C 必须在 D 之前**：先把「悬垂能否产生且不崩」与「画布注入能否落地」分开验证。

---

## §6 判据（必须用独立透镜，禁用自校准）

| 判据 | 说明 |
|---|---|
| **独立透镜 A** | `sysctl_bootid` 的 data 区：`cat /proc/sys/kernel/random/boot_id` 可独立回读（历史上 `text=90b0292a` 已证可被内核写改变） |
| **独立透镜 B** | `selinux_state.enforcing` → `getenforce` 由 Enforcing 变 Permissive |
| **不崩** | `boot_id` 未变 + `uptime` 未归零 + `/data/log/reliability/faultdetect/history.log` 无新增 |
| **反证** | 若 panic 且病征落在 `raw_spin_lock/trylock(lock->wait_lock)` 或 `[waiter+0x58]` ⇒ 伪 lock 未生效（偏移/地址错） |
| ❌ 禁用 | 任何「用同一 rb_erase 写再读回」的自校准（铁律） |

---

## §7 诚实评估与风险

- ★★ **装置现成是本轮最大利好**：拓扑、状态机、投递、spin 保持都写好了，不用从零写。
- ★★★ **两处必改都会导致必 panic**：几何差 0x20/0x80 时，伪 waiter 根本没落在 `pi_blocked_on`
  指向的槽上，链会读到自然栈垃圾 ⇒ `trylock(NULL)` 或 `brk` ⇒ 重启。**这极可能就是历史失败原因。**
- ⚠️ **风险**：步 C/D 若走错会 panic 重启（设备可自恢复，`/data/local/tmp` 不清空）。
- ⚠️ **仍未验证**：`h175_staged.c` 的 stage 状态机是否与本轮几何自洽（需通读 L460–560 再定稿）。
- ★ **下一轮应先做步 A、B（零风险），再改装置常数，最后才 C/D/E。**
