# MEY rb_erase 写原语 / 崩点 反汇编定论（2026-09-28）

## 背景
设备：Honor MEY-AN00 · Android 16 · kernel 6.6.118。
开火实锤崩点：consumer `sched_setattr` → `rt_mutex_adjust_prio_chain` 解引用我们伪造的
rt_mutex_waiter 时崩（裸 data abort，无 pstore/ramoops，无 backtrace）。本文件用
`analysis/scripts/disasm_mey.py` 反汇编内核，定位写原语指令并澄清崩点机制。

## 反汇编目标（kallsyms）
- `rt_mutex_adjust_pi`      @ 0xffffffc081081438（consumer walk 入口，内联 dequeue/augment）
- `rt_mutex_adjust_prio_chain` @ 0xffffffc0810815d4（真正 PI 链 walk）
- `rb_erase`               @ 0xffffffc08003a9d4（非 augmented，用于 lock->waiters tree_entry）
- `__rb_erase_augmented`   @ 0xffffffc08003a860（augmented，用于 task->pi_waiters pi_tree_entry）
- `__rb_erase_color`       @ 0xffffffc08003a58c（重平衡；含 augment 回调 canary `0x20ff58b5`）

产物：`analysis/output/disasm_walk.txt`（adjust_pi/adjust_prio_chain/rb_erase）、
`analysis/output/rb_erase_color_mey.txt`（__rb_erase_color + __rb_erase_augmented）。

## 写原语指令（★ 定位成功）
MEY `rb_erase` @ `0x3ab04`–`0x3ab24`，对伪造节点（`rb_left=0`、`rb_right=target≠0`、
`rb_parent_color = value|1`）走「单子节点」删除路径，末尾：

```
0x3ab04: ldr x9, [x0]              ; x9 = node->rb_parent_color (= value|1)
0x3ab08: ands x8, x9, #-4         ; x8 = parent = value (mask 掉颜色位)
0x3ab0c: str x9, [x10]            ; ★ [x10]=[rb_right]=target  ← 写原语：把 写值 写入 写目标
0x3ab10: b.eq 0x3ac0c             ; parent==0 ?
0x3ab14: ldr x9, [x8, #0x10]      ; 读 parent->rb_right（parent=mapped → 安全）
0x3ab18: cmp x9, x0
0x3ab1c: b.ne 0x3ac8c
0x3ab20: str x10, [x8, #0x10]
0x3ab24: ret                      ; 直接返回，不进 __rb_erase_color
```

即：`[target] = value`（target = misc_fops 地址，value = 写值 fake_fops / nfulnl_logger）。
**这与 CGA 参考内核的 `0x8040230 str x9,[x10]` 机制一致。** 写原语本身成立。

## ★ 关键修正：此前「重平衡 walk 野指针」假设作废
此前交接文档假设崩点在 `__rb_erase_color` 重平衡时把假 parent 当 rb 节点向上回溯。
**反汇编证明：本几何（rb_left=0、rb_right=target≠0）走「单子节点」删除路径，在
0x3ab24 直接 ret，根本不调用 `__rb_erase_color`**。rb_erase 全程只读取一次 parent->rb_right
（parent = value，是内核映射地址，不崩），随后写 parent->rb_left 后返回。
结论：**rb_erase / __rb_erase_augmented 的单子节点路径本身不会崩，也不会向上 walk 野指针。**

## ★ 新发现的根因（高置信）：RED 颜色位污染了写值
`slide_build_fake_waiter`（L1728/1731 等）为了让节点「染红跳过重平衡」做了：
`tree_parent = slide_oracle_parent | 1`。
但 `0x3ab0c` 写入的是 **完整** `rb_parent_color`（含颜色位），所以实际写入：
`[misc_fops] = value | 1`（奇数的、PAC 破坏的指针）。
- 写值被污染：本该劫持成干净的 fake_fops/nfulnl_logger，结果末尾多了 `|1`。
- 系统持续使用 misc 设备（logcat、binder 等），一旦内核解引用被污染的
  `misc_fops`（奇数/PAC 校验失败）→ data abort → panic，时间线上即表现为
  「每次到这里（写完 misc_fops 后）就重启」。

而「染红」的初衷（跳过重平衡）对当前几何是**多余的**：单子节点路径本就不重平衡。
因此去掉 `|1`（节点变 BLACK，但仍是单子节点路径）既修复写值、又不引重平衡崩。

> 注：早期注释（L1719）称「去掉 |1（BLACK）会非确定 data abort」——那是在 rb_right=0
> （无子节点 BLACK → 真进 __rb_erase_color）的旧几何下成立的。当前几何显式令
> rb_right=target≠0，已避开无子节点重平衡分支，故去 |1 对当前几何安全。

## 真正的崩点（待真机日志确认）
由于 rb_erase 写原语路径安全，崩点必在以下之一（需真机 logcat 内核日志确认）：
1. **被污染的 misc_fops 延时解引用**（最可能，如上）。
2. `rt_mutex_adjust_prio_chain` 的 PI 链 walk 解引用伪造 waiter 的其它字段
   （`waiter->task`=init_task 真、但 `waiter->lock`=fake_lock 若字段不全 → 读 garbage）。

## 本次已落地的修改
1. **APK 日志不再遗漏**（slide_app.c）：
   - L2929 原 `#if defined(APP_CLOSED_FOPS_ROUTE) && APP_CLOSED_FOPS_ROUTE` 守卫在
     MEY（`CLOSED=0`）上把最关键的 `CP: addr base=...oracle_parent=...oracle_target=...`
     几何自检整段裁掉 → 已改为 `#if 1`，恒编译（cp_note 已 fsync，panic 也保留）。
   - 在 SIGRETURN writer 设置处（L2563 后）新增 `cp_note("CP: waiter tree=...pi=...")`，
     把 fake waiter 几何同时落 cp.log（pr_info 只进 logcat，重启会丢）。
2. 重新编译 `preload.so` + APK（app-debug.apk），已确认两个新日志串进包。

## 下一步建议（需真机验证）
- **修复写值污染（首选）**：把 `slide_build_fake_waiter` 里 `| 1` 去掉，或在写目标路径
  单独 mask。待设备上确认 misc_fops 是否被正确劫持（cfi replaced / 后续 su 落地）。
- 真机开火前 `adb logcat` 抓内核日志（排除无关行），崩点 backtrace / 最近内核打印
  能最终坐实崩点（1 or 2）。
- 若去 |1 后写原语稳定但未提权，再用 gradient（`SLIDE_SIGRETURN_GRADIENT`）逐 word
  定位 walk 读哪个字段崩。
