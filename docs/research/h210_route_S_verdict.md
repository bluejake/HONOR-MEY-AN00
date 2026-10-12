

# H210 终局报告：路线 S（43499 悬垂 waiter → adjust_pi → prio_chain）几何判死

**日期**：2026-10-07（本轮）  
**设备**：MEY-AN00 · SM8735 · 内核 `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`  
**依据**：全程 Image-mey 反汇编（`dis_mey.py` / h210e–h210h 脚本），0 源码，0 boot  
**boot_id 基线**：`ba30251b-07f6-4bcb-8a6d-a569da07e4a0`（未消耗）

---

## 1. 结论

**路线 S 终局判死（★ 汇编已证未实测）。CVE-2026-43499 全线闭合。**

悬垂 `pi_blocked_on` 的唯一真实消费者 `rt_mutex_adjust_pi` → `rt_mutex_adjust_prio_chain` 的写原语链，  
在全部自然阻塞场景下，**waiter->lock 必然先被触发链自身的栈写破坏**，`_raw_spin_trylock`  
读到 0 或返回地址 → 对无效地址加锁必崩（写原语未落地）。且栈上无落点自由度（W0 由内核  
调用链决定，用户态不可选）。

## 2. 证据链（五步，全部汇编实读）

### 2.1 悬垂形成路径穷尽（h210e/h210f）

`task_blocks_on_rt_mutex`（设置 pi_blocked_on 的唯一函数）全镜像 bl 扫描仅 2 个调用者：

| 调用者                                                                                    | 可达性                                                                                                                                                                       |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rt_mutex_slowlock_block`（← slowlock ← rt_mutex_lock/lock_interruptible/lock_killable） | ★ **uid=2000 不可达**：`rt_mutex_lock` 24 个调用者全为内核 driver 子系统（i2c/icc/dwc3/geni/tegra/rcu_boost_kthread），`lock_interruptible`/`lock_killable` 全镜像 **0 调用者**；futex 不调 slowlock |
| `__rt_mutex_start_proxy_lock`                                                          | ← `futex_lock_pi` 与 `futex_requeue`；自阻塞等待经 `rt_mutex_wait_proxy_lock`，仅被 `futex_lock_pi+0x178` 与 `futex_wait_requeue_pi+0x264` 调用                                         |

⇒ 悬垂 waiter 只能形成于 **futex_lock_pi** 或 **futex_wait_requeue_pi** 阻塞期间。

### 2.2 waiter 栈归属（h210e PART C，汇编实读）

| 函数                                    | 证据                                                   | 归属                                  |
| ------------------------------------- | ---------------------------------------------------- | ----------------------------------- |
| `rt_mutex_start_proxy_lock`（F=0x30）   | 调用点 +0x64：`x1 = 入口x1`                                | waiter 为调用者传入，本帧不拥有                 |
| `rt_mutex_cleanup_proxy_lock`（F=0x30） | 调用点 +0x4c：`x1 = 入口x1`                                | 同上                                  |
| `rt_mutex_slowlock`（F=0xc0）           | 调用点 +0x194：`add x1, sp, #8`                          | slowlock 帧内 +8（但不可达，判死）             |
| **`futex_lock_pi`（F=0x1a0）**          | `memset(sp+0x70,0,0x70)` + 三处 `add xN, sp, #0x70` 传参 | **waiter @ 帧内 +0x70**               |
| **`futex_wait_requeue_pi`（F=0x1c0）**  | `memset(sp+0x90,0,0x70)` + `x27 = sp+0x90`           | **waiter @ 帧内 +0x90**（★ 修正旧账"帧底"说法） |

### 2.3 入口层帧深（汇编实读序言 `sub sp`）

`__arm64_sys_futex` F=0x80（直调 flpi/requeue_pi，跳表 `br x9`）；  
`__arm64_sys_futex_time32` F=0x70；`do_futex` F=0x60；前缀（el0_svc 链）= 0x80。

### 2.4 W0 全场景账本（穷尽，4 项）

W0 = 0x80 + Σ入口层帧深 + F(阻塞函数) − waiter 帧内偏移：

| 阻塞路径                           | D_entry | W0        | lock@W0−0x58 |
| ------------------------------ | ------- | --------- | ------------ |
| sys_futex 直调 → flpi            | 0x100   | **0x230** | 0x1D8        |
| sys_futex 直调 → requeue_pi      | 0x100   | **0x230** | 0x1D8        |
| time32 → do_futex → flpi       | 0x150   | **0x280** | 0x228        |
| time32 → do_futex → requeue_pi | 0x150   | **0x280** | 0x228        |

### 2.5 lock 存活性判定（h210g/h210h 写图）

触发链（sched_setscheduler → adjust_pi，帧深 0x80+0x0+0x80+0x10+0x50+0xa0+0x50）：

- `__sched_setscheduler`（帧 [0x160,0x200)）序言后早期：  
  `0xffffffc0801698d8: stp xzr, xzr, [sp, #0x20]` → 写深度 **[0x1D0,0x1E0)**，  
  **完整覆盖 0x1D8**（W0=0x230 场景的 lock 落点）→ lock 读回 0
- `rt_mutex_adjust_pi`（帧 [0x200,0x250)）FP/LR 对 @ [0x220,0x230)，  
  **完整覆盖 0x228**（W0=0x280 场景的 lock 落点）→ lock 读回 x30（返回地址）
- lock 的三个消费读点（全部要求存活）：
  - adjust_pi `0x…14ec: ldr x21,[x21,#0x58]`（锁存→x3 传 chain）
  - chain `0x…1660: ldr x8,[x25,#0x58]` + `0x…1664 cmp x27,x8; b.ne 退出`（★ chain **不**用寄存器锁存值 trylock，而是从 `task->pi_blocked_on` 重载 x25（`0x…1648`）后栈上重读）
  - chain `0x…16c0: ldr x24,[x25,#0x58]` → `0x…16c8 bl _raw_spin_trylock(x24)`

⇒ W0=0x230：trylock(0)（NULL 解引用）；W0=0x280：trylock(返回地址)（只读段写）。  
**两场景均崩在写原语落地之前。**

### 2.6 可行带推导（若 W0 可选的话）

lock 唯一 8B 无写洞 = adjust_pi 帧内 [0x248,0x250)（该帧写图：x20/x19@[0x200,0x210)、  
x22/x21@[0x210,0x220)、FP/LR@[0x220,0x230)、canary@[0x230,0x238)、wzr@[0x238,0x23C)、  
x1@[0x240,0x248)）→ W0 ∈ [0x2A0,0x2A8]。  
chain 帧 [0x250,0x2d0) 写满（6 对 callee-saved+FP/LR+局部，8B 对齐无洞），prio(W0−0x18)  
在该带内落 [0x288,0x290) 被 chain 序言踩——但 prio 被踩读回 callee-saved 确定值，  
`b.ne` 放行分支可过，非死路。  
**然而 W0 由内核调用链决定 ∈ {0x230, 0x280}，无用户可控自由度，可行带无对应场景 → 落空。**

## 3. 43499 全线闭合

| 环节                  | 判定                                                 | 依据类型                     |
| ------------------- | -------------------------------------------------- | ------------------------ |
| sigreturn 512B 栈写原语 | 成立                                                 | ★ 汇编已证（H209）             |
| 跨 syscall 残留消费者     | 0 幸存                                               | ★ 汇编已证（H209 五层仲裁，四重阳性对照） |
| 悬垂 waiter 真实消费者     | `rt_mutex_adjust_pi`（唯一调用点 `__sched_setscheduler`） | ★ 汇编已证                   |
| 悬垂形成路径              | 仅 flpi/requeue_pi（slowlock 线 uid=2000 不可达）         | ★ 汇编已证                   |
| waiter 栈落点 W0       | ∈ {0x230, 0x280}，4 场景穷尽                            | ★ 汇编已证                   |
| lock 存活             | 必被触发链写踩 → trylock 必崩                               | ★ 汇编已证                   |
| **路线 S 总判定**        | **几何判死**                                           | ★ 汇编已证未实测                |

**遗留降级项**（不影响判定）：prio_chain 循环体（0x…1630–0x1a00）全量语义、  
`__sched_setscheduler` 调用点 `tbz w21,#0` 门条件——判死依据是 chain 早期读点 lock 已被踩，  
与循环体/门参数无关。若未来出现绕过 2.6 可行带的新机制（如能改变触发链帧深的新入口），  
需重开此账。

## 4. 攻击线全景（更新）

| 线              | 状态                                                             |
| -------------- | -------------------------------------------------------------- |
| CVE-2026-43499 | **全线闭合**（sigreturn 写原语成立但无消费者；悬垂消费线几何判死）                       |
| CVE-2026-64560 | 拓扑已实测跑通；竞态层未完成（`release_task@0x…baac` 可抢占窗口，首选 P2-a execve 路径） |

## 5. 脚本与输出落盘

| 文件                                                                | 内容                                                       |
| ----------------------------------------------------------------- | -------------------------------------------------------- |
| `analysis/scratch/h210e_slowlock_w0.py` / `h210e_out.txt`         | 三调用点上下文 + 全镜像 BL 调用图                                     |
| `analysis/scratch/h210f_futex_depth.py` / `h210f_out.txt`         | sys_futex/do_futex/requeue_pi/rt_mutex_lock 系反汇编 + 可达性递归 |
| `analysis/scratch/h210g_adjp_write_map.py` / `h210g_out.txt`      | adjust_pi 全量写图 + chain 入口回读 + requeue_pi waiter 偏移       |
| `analysis/scratch/h210h_trigchain_write_map.py` / `h210h_out.txt` | 触发链五层帧写图 + 悬案 [0x1D8,0x1E0) 判定                           |

工具链：`firmware/boot.img → magiskboot unpack → Image-mey → vmlinux-to-elf → mey_vmlinux_symbols.txt`，  
反汇编 `dis_mey.py`（TEXT=0xffffffc080000000，FOFF=0x0）。
