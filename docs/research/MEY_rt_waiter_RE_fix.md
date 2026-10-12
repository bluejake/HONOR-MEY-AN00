# MEY-AN00 系统性 panic 根因 — rt_mutex_waiter 布局错位（BTF 反汇编 RE）

> 结论先行：MEY 上 3/3 boot 都在「consumer firing sched_setattr」后 panic、root 从未落地，
> 根因**不是** fmps shift 范围、也不是 pselect 路径、更不是随机 miss —— 而是 exploit 写死的
> `rt_mutex_waiter` 字段偏移与 MEY 6.6.118 内核 BTF 的真实布局**不符**。

## 1. 真因：fake waiter 几何错位

exploit 假设（参考旧内核的 OLD `rt_mutex_waiter`，带 `prio`+`deadline`，size 0x58）：

| 字段 | exploit 旧偏移 | MEY BTF 真实偏移 |
|------|---------------|------------------|
| tree (rb_node) | 0x00 / 0x08 / 0x10 | 0x00 / 0x08 / 0x10（一致） |
| pi_tree (rb_node) | **0x18** / 0x20 / 0x28 | **0x28** / 0x30 / 0x38 |
| task | **0x30** | **0x50** |
| lock | **0x38** | **0x58** |
| wake_state(+prio) | **0x40**(+0x44) | **0x60**（无 prio） |
| deadline | 0x48（存在） | **不存在** |
| ww_ctx | **0x50** | **0x68** |
| 结构体大小 | 0x58 | 0x70 |

MEY 的 `rt_mutex_waiter`（BTF，`dump_btf.py` 直接读出，size=0x70，6 个成员）：
`tree@0x00, pi_tree@0x28, task@0x50, lock@0x58, wake_state@0x60, ww_ctx@0x68`，**没有 prio/deadline**。

**偏差后果**：假 waiter 的 pi_tree / task / lock 字段整体错位 +0x10~+0x20，落到 MEY 的 padding 间隙
（0x18-0x28、0x40-0x50）；真正被内核 `rt_mutex_adjust_prio_chain` → `rb_erase` 读取的 pi_tree 区
（0x28/0x30/0x38）根本没被写对 → PI walk 读垃圾 → 必然 panic。这正好解释了「干净 miss 不该 panic、
却每次都 panic」的怪象：不是随机 miss，是几何错位。

> 注：09:09 那版日志仅用 `ikconfig` 的 `CONFIG_DEBUG_RT_MUTEXES is not set` 推出「compact 布局 =
旧偏移一致」，这是错的 —— compact 只表示无 DEBUG 字段，**不代表字段偏移与参考内核相同**。

## 2. 已应用修复（已编译验证通过）

- **`exploit-src/dc15/target.h:581-591`**：`FAKE_WAITER_*` 宏全部改到 MEY BTF 偏移
  （pi_tree@0x28 / task@0x50 / lock@0x58 / wake_state@0x60 / ww_ctx@0x68 / LAYOUT_SIZE 0x70）；
  旧 prio/deadline/tree_prio 等“不存在字段”改为指向 MEY 的 padding 间隙，写之无害。
- **`exploit-src/dc15/slide_app.c`（fmps 路径 1660-1669）** 与 **`exploit-src/dc15/fops.c`（352-360）**：
  把硬编码旧偏移改为 MEY 偏移。Path A / Path B 写原语语义不变
  （pi_parent=fake_fops 写值；pi_right/pi_left=slide_oracle_target 写目标）。
- **`slide_app.c:1628` / `fops.c:332`**：`param[256]` → `param[1024]`（MEY waiter 0x70，大 shift 下不越界）。
- **`exploit-src/target_mey_an00.h:270`**：启用 `rt_sigreturn` 载波（`#define SLIDE_STACK_WRITER SLIDE_STACK_WRITER_SIGRETURN`）。

## 3. 为什么同时切到 sigreturn 载波（回答「可以走 sigreturn 路线吗」：**可以，且推荐**）

- MEY 有 `CONFIG_RANDOMIZE_KSTACK_OFFSET=y`（虽 DEFAULT 未开，机制存在）。源码注释明确指出：
  fmps/pselect 依赖「两次 syscall 的栈偏移对齐」，该随机化会**破坏确定性穿地**；而 `rt_sigreturn`
  把假 waiter 放进**同一次 syscall** 的信号帧 `fpsimd vregs`，**免疫**该随机化。
- `aak-an00` 同是 6.6.118，已用 sigreturn 成功提权。
- MEY 的 `futex_wait_requeue_pi` 帧 = **0x1c0**（capstone 反汇编 `sub sp, sp, #0x1c0` 证实），与 cga 一致，
  故 `SIGRETURN_FPSIMD_WAITER_OFF=0xe8` 就是正确起点。
- **fmps 读原语（leak / base / oracle，即 `slide_leak_*` + P0 `kernel_read64`）与 `SLIDE_STACK_WRITER` 无关，
  启用 sigreturn 仅替换“写原语喷洒”机制，读原语保持活跃，无退化。**

## 4. 验证状态与下一步

- ✅ `build_ndk.sh preload` 编译通过（`preload.so` 171KB，仅 benign warning）。
- ⏳ 真机实跑 / 落 root 需用户在设备上验证（本机无设备）。建议顺序：
  1. 先跑 `slide_sigreturn_preflight()`（零写、不 panic）确认 fpsimd 定位成功（日志 `fpsimd=1`）；
  2. 再 FULL FIRE；
  3. 若写原语仍 miss，按帧深差微调 `SIGRETURN_FPSIMD_WAITER_OFF`（或用 `slide_sigreturn_runtime_off` 运行时覆盖）。
- 回退方案：若 sigreturn 在 MEY 上另有问题，注释掉 `target_mey_an00.h:270` 一行即回到 fmps 写喷洒
  （此时 fake_waiter 几何已修正，fmps 路径本身也修好了）。
