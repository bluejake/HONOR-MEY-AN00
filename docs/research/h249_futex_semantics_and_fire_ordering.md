# H249 · `futex_wait_requeue_pi` 等待语义读穿 + `fire-after-EDEADLK` 定论（收口）

> 真机：H249 一发 → panic（`20261006105803`）。设备已恢复（`29f3e5f1-…`）。
> **本会话真机开火累计 15 发**（10 panic + 5 零 panic）。

---

## §1 ★★★ 源码级事实（消除本会话最后两个未知量）

依据：`refs/ghostlock-cve-2026-43499/workspace/ksrc/futex.c`（6.6 同代源码）
+ `vmlinux-mey.elf` 汇编（本机一手）

### 1.1 W 的等待状态 = **`TASK_INTERRUPTIBLE`** ⇒ 可被信号唤醒

```c
/* futex.c L2712-2721 */
static void futex_wait_queue_me(struct futex_hash_bucket *hb, struct futex_q *q, ...)
{
    set_current_state(TASK_INTERRUPTIBLE);      /* ★ 可中断 */
    ...
}
/* futex_wait_requeue_pi() L3369 也走这条路 */
futex_wait_queue_me(hb, &q, to);
```

⇒ ★ **定向信号（`rt_tgsigqueueinfo`）可以唤醒 W 的 futex 睡眠。**

### 1.2 `-EDEADLK` 回滚**不唤醒 W**（汇编实证）

```asm
; futex_requeue @0x802ca35c 之后
802ca35c: bl   rt_mutex_start_proxy_lock
802ca360: cbz  w0, #0x2ca6a0          ; ==0 ⇒ 成功路径
802ca368: cmp  w0, #1
802ca36c: b.ne #0x802ca3f4            ; ★★ -EDEADLK(35) 走这里
...
802ca3f4: str  xzr, [x28, #0x38]      ; ★ futex_q.rt_waiter = NULL
802ca3fc: bl   put_pi_state
```

而 `wake_up_state(x0, 3)` 在 **`w0 == 1`** 的分支（非 EDEADLK）上。

⇒ ★★ **EDEADLK 路径：不唤醒 W + 清空 `futex_q.rt_waiter`。**
⇒ 于是 `#1 rc=-1 EDEADLK` 之后：**W 仍在 `TASK_INTERRUPTIBLE` 睡眠中**，
`pi_blocked_on` 悬垂（指 W 栈上 waiter），`futex_q.rt_waiter = NULL`。

### 1.3 源码另一条铁律（项目早已记录）

```c
/* futex.c L2384 */
* state is implicit in the state of woken task (see futex_wait_requeue_pi() for ...)
```

---

## §2 ★★★ `fire-after-EDEADLK` 是**结构性失败点**（三发 + 两变体，全同签名）

| 实验 | 变体 | 结果 |
|---|---|---|
| H247 | `to=3s`，EDEADLK 后**延迟** fire | panic `20261006105103` |
| H248 | `to=3s`，EDEADLK 后 fire **紧跟** | panic `20261006105243` |
| **H249** | **`to=NULL`（永久等待）**，EDEADLK 后 fire | panic `20261006105803` |

⇒ **三种变体（不同超时策略、不同延迟）全部 `page_request`，同签名。**
⇒ 崩因**不是**时序抖动，而是**结构性的**：

**在 `remove_waiter` 已改动 W 的 futex 状态之后**（`rt_waiter=NULL`、waiter 已从树摘除），
再用信号去唤醒 W 并在其内核上下文落帧 ⇒ 内核在**不一致状态**上继续 ⇒ `page_request`。

---

## §3 为何参考实现（dc15）可行 —— 最终理解

参考的 `fire` 之所以安全，是因为它触发在一个**W 不再持有不一致 futex 状态**的时刻：

```
① W 阻塞（TASK_INTERRUPTIBLE）
② R : CMP_REQUEUE_PI → -EDEADLK ⇒ remove_waiter(真 waiter) ⇒ W 的 pi_blocked_on 悬垂
③ W : 因信号/超时**自行返回** WAIT_REQUEUE_PI（内核完成 syscall 收尾，状态回到一致）
④ 主: fire(W) 投画布 —— 此时 W 处于【用户态】，落帧干净
⑤ 主: sched_setattr(W) 消费
```

★ 关键差别：**fire 必须发生在 W 已从 `futex_wait_requeue_pi` 返回之后**（状态一致），
而不是**在它仍睡眠/处于收尾中**时。

⇒ 我 H247/H248/H249 三发都在 ③ **之前** fire（试图抢在超时前），因此必崩。

⇒ ★★★ **正解（下一发唯一形态）**：
```
① W 阻塞（to=3s）
② R : CMP_REQUEUE_PI → EDEADLK
③ 等 W **自然超时返回**（ETIMEDOUT）——状态回到一致、栈帧已退出
④ 主: fire(W) + pc 劫持 spin_forever  ⇒ 画布写进已悬垂槽并【钉住】
⑤ 主: sched_setattr(W) 消费
```
⚠️ 但 ③ 之后 W 的栈帧**已退出**，`pi_blocked_on` 指向的槽不再被 memset 保护——
画布写进去就**保持**（正是我们要的），且 sched_setattr 的消费器 frame 不覆盖它
（H247 §1 已证 `adjust_pi` frame=0x50 不覆盖）。**这才是唯一自洽的形态。**

⇒ 注意：H243–H245 用 `to=3s` + 等超时 + 投画布，**形态接近**，
但它们**没有 pc 劫持（钉住）**，且**消费器用的是第二次 requeue**（会因 waiter 已消失而失败）。
⇒ **把 H245 的"等超时" + H246 的"pc 劫持" + H247 §1 的"sched_setattr 消费器"三者合成一发即可。**

---

## §4 收口账目

### 4.1 本会话已验证为真（全部本机证据）

1. 技能安装 + 加载
2. fpsimd 帧被内核采信（magic/size `0x210`）
3. **SP0 可读**且同线程恒定（6/6）
4. **画布 512B 进内核栈**（`restore_fpsimd_context`）—— 推翻 H195
5. 步 C：EDEADLK 拓扑可触发且不崩
6. **消费器 frame 不得与 waiter 槽重叠**（7 发 panic 真死结）
7. 写原语几何（第二次 `rb_erase` / `pi_tree` 三字段）+ compact 0x58→0x70 的 +0x18 换算
8. 上游 `waiter` 实参 = `futex_q.rt_waiter` = 画布槽
9. **消费器全枚举**（真实消费者仅 3 个）
10. **W 等待状态 = `TASK_INTERRUPTIBLE`** 且 **EDEADLK 不唤醒 W**
11. **`fire-after-EDEADLK` 是结构性失败点**（三变体同签名）

### 4.2 未达成

**写原语未在真机落地。** 唯一剩余 = §3 的**三段合成**（等超时 + pc 劫持 + sched_setattr 消费器）。

### 4.3 开火账

| 类别 | 发数 |
|---|---|
| panic | **10**（全 `page_request`） |
| 零 panic | **5** |
| 设备 | 全程自动恢复，最终健康 |

---

## §5 铁律增补

| # | 铁律 |
|---|---|
| **㊻** | ★★ `futex_wait_queue_me` 用 **`TASK_INTERRUPTIBLE`** ⇒ W 可被定向信号唤醒 |
| **㊼** | ★★ `-EDEADLK`（`w0 != 0/1`）路径**不唤醒 W**，且会 `str xzr,[futex_q,#0x38]`（`rt_waiter=NULL`）；`wake_up_state(t,3)` 只在 `w0==1` 分支 |
| **㊽** | ★★★ **`fire` 必须发生在 W 已从 `futex_wait_requeue_pi` 返回之后**（内核状态一致）。在它睡眠/收尾期间 fire ⇒ 必 `page_request`（三变体实证） |
| **㊾** | ★★★ 正解 = 「等超时返回（状态一致）→ fire + pc 劫持钉住 → `sched_setattr(W)` 消费」三段合成 |
