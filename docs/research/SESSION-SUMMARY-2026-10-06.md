# MEY-AN00 sigreturn 路线 · 会话总结（2026-10-06）

> 本文件是本会话（H218–H245）的**一页总览**，便于下轮开工。
> 全部结论均以 **本机 BTF + vmlinux 汇编 + dc15 参考实现 + 真机行为** 四重交叉。

---

## 0. 结论

**步 A/B/C 全部真机通过；写原语未落地，但已把缺口收敛到【唯一一个机制性动作】。**

| 里程碑 | 状态 |
|---|---|
| 技能 `magicpad3-root-handoff` 安装 + 加载 | ✅ |
| sigreturn 帧被内核采信（fpsimd magic/size 0x210） | ✅ 真机 |
| SP0 可读（`/proc/<pid>/task/<tid>/syscall` 的 `sp`）且同线程恒定 | ✅ 真机 6/6 |
| 画布 512B 进入内核栈（`restore_fpsimd_context`） | ✅ 反汇编 + 真机 h230 |
| 步 C：EDEADLK 回滚拓扑可触发且不崩 | ✅ 真机 |
| 消费器 frame 与 waiter 槽不重叠（`remove_waiter`） | ✅ 反汇编 + 真机零 panic |
| 写原语几何（第二次 `rb_erase` / `pi_tree` 三字段） | ✅ dc15 参考 + 本机汇编 |
| 上游 `waiter` 实参 = `futex_q.rt_waiter` = 画布槽 | ✅ `futex_requeue` 汇编 |
| **写原语在真机落地** | ❌ **未达成** |

---

## 1. 关键几何（本机定稿，全部有证据）

```
SP0 锚 S = /proc/<pid>/task/<tid>/syscall 的 sp 字段
rt_waiter  绝对深度 0x1F0   占用 [0x1F0, 0x260)
sigreturn 画布            [0x300−0x200, 0x300) = 深度 [0x100, 0x300)
  画布字节 C ↔ 绝对地址 S − 0x300 + C
  字段画布偏移 = 0x110 + 字段off      （0x110 = 0x300 − 0x1F0）
伪 rt_mutex_base 绝对深度 0x260

futex 链帧深 = el0_svc 0x40 + __arm64_sys_futex 0x80 + futex_wait_requeue_pi 0x1c0 = 0x280
sigreturn 链帧深 = 0x40 + 0x20 + 0x20 + 0x290 = 0x310
```

**KASLR：本机 slide 恒为 0**（项目 H196 实测；数十 boot 同值）
⇒ 所有内核地址 = 编译期常量，**不需要地址泄漏**。

---

## 2. 写原语配方（dc15 参考，已按本机 0x70 布局换算）

```
第一次 rb_erase（擦 lock->waiters 树）必须 no-op:
   waiter+0x00 = 1     (tree.rb_parent_color sentinel)
   waiter+0x08 = 0     (tree.rb_right)
   waiter+0x10 = 0     (tree.rb_left)

第二次 rb_erase（擦 pi_tree）= 写原语:
   waiter+0x28 = 写值   (pi_tree.rb_parent_color)
   waiter+0x30 = 0      (pi_tree.rb_right  必须 0)
   waiter+0x38 = 写目标 (pi_tree.rb_left)

其余:
   waiter+0x18 = tree.prio（≠ task->prio）
   waiter+0x58 = 伪 lock 地址（非 0）
   伪lock+0x18 = 合法 task_struct（如 init_task）  ← remove_waiter 把 owner 当 task 用
```

⚠️ **`rb_erase` Case2 会算 `parent = 写值 & ~3` 并读 `[parent+0x10]`**
⇒ 写值的 parent 字段**必须指向已映射地址**。

---

## 3. ❌ 唯一剩余缺口（H247/H248 后**定论**）

### 3.1 消费器全枚举（本会话最重要的离线成果）

判据：真消费者必须**同时**访问 `pi_lock(+0x90c)` 与 `pi_blocked_on(+0x938)`。
**全树真实消费者只有 3 个**：

| 函数 | frame | 判定 |
|---|---|---|
| `remove_waiter` | **0x50** | 不覆盖 waiter 槽；需 `EDEADLK` 触发 |
| `rt_mutex_adjust_pi` | **0x50** | 不覆盖；读点 `0x8146c` |
| `rt_mutex_adjust_prio_chain` | **0x80** | ❌ 覆盖 waiter 槽（**内联**调用，读点更浅） |

### 3.2 ★★★ 顺序矛盾的定论（三发实证）

| 顺序 | 结果 |
|---|---|
| fire **先**，requeue 后 | `rc=0`（成功）⇒ **无 `remove_waiter`** ⇒ 不写 |
| requeue 先，**延迟** fire | **panic** `20261006105103` |
| requeue 先，fire **紧跟** | **panic** `20261006105243`（同签名） |

⇒ **`fire-after-EDEADLK` 是结构性失败点**：`remove_waiter` 改动 W 的 futex 状态后，
定向信号落帧 + pc 劫持会踩到不一致状态。

⇒ ★★★ **本装置下「画布就位」与「`remove_waiter` 被调用」无法在同一线程/同一栈槽共存。**

### 3.3 下一轮唯一深入方向（纯离线）

从 `futex_requeue` 的**失败分支**逐条读出：`-EDEADLK` 回滚是否**唤醒** W。
- 会唤醒 ⇒ 需让 W 保持阻塞（`to=NULL` 且不被唤醒）再 fire；
- 不会 ⇒ 崩因在别处，需读 `futex_requeue` 收尾序列。

### 3.4 已排除项（14 发累计）

几何 · 画布通道 · SP0 · 偏移公式 · 消费器 frame 重叠 · 写 recipe · 写值耦合 ·
上游 waiter 来源 · pc 劫持 pinning · 消费器枚举 · 顺序两向 —— **全部有本机证据。**



---

## 4. 真机开火总账（11 发）

| 类别 | 发数 | 说明 |
|---|---|---|
| **panic** | 7 | 全 `page_request`；根因 = `adjust_prio_chain` 的 frame 覆盖 waiter 槽（已解决） |
| **零 panic** | 4 | H239/H240/H241/H242/H243/H244/H245 中的验证发 |
| 设备 | — | 全程自动恢复，最终健康（`024088a8-…`、uid 2000、Enforcing） |

---

## 5. 工具链与产物

**编译器**：`<HOME>\.workbuddy\binaries\android\android-ndk-r27c\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe`
```
clang --target=aarch64-linux-android34 -O2 -static -o <out> <src>
```

**本会话新增装置**（`tools/`）：
`h223_sigframe_probe.c`（步 A/B）· `h226_canvas3.c`（帧自校准）· `h229/h230`（通道判定）·
`h232_stepc.c`（步 C）· `h233/h234/h235`（写路径尝试）· `h237/h238`（偏移修正）·
`h239_stepD4.c`（remove_waiter 消费器）· `h240_stepD4b.c` · `h241_stepE.c` ·
`h242_stepD5.c`（dc15 配方）· `h243_stepD6.c`（参考时序）· `h244_final.c` · `h245_final2.c`

**报告**（`analysis/output/`）：
`h218_h219_sigreturn_route_reevaluation.md` · `h221_sigreturn_geometry_final.md` ·
`h222_sigreturn_topology_design.md` · `h223_h228_sigreturn_ondevice.md` ·
`h229_h231_canvas_channel_and_depth.md` · `h232_h234_stepC_D_and_root_cause.md` ·
`h236_chain_readthrough.md` · `h237_h238_canvas_offset_fix.md` ·
`h239_h240_remove_waiter_breakthrough.md` · `h242_dc15_reference_crosscheck.md` ·
`h243_h244_write_parameter_coupling.md`

**参考源**：`<HOME>\WorkBuddy\2026-09-26-09-04-37\dc15_repro\src`（已解压）
