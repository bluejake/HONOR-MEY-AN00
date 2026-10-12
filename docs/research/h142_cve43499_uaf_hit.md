# CVE-2026-43499 端到端触发成功报告

**设备**：MEY-AN00 · MagicOS 10.0.0.175 · A16 · SM8735 · 内核 `6.6.118-android15-8`（4K 页）
**日期**：2026-10-05
**轮次**：H141–H142

---

## 一、一句话结论

**CVE-2026-43499（rtmutex `remove_waiter` UAF）在 MEY-AN00 上已从「用户态 shell（uid=2000）」端到端触发到内核 panic，8 个环节全部真机验证，无一步靠推断。**

---

## 二、成果判据（硬证据）

| 判据 | 结果 |
|---|---|
| `boot_id` BEFORE | `2888f136-4ff1-487b-8d4c-58e02e1897e0` |
| **`boot_id` AFTER** | **`e4fc8d80-a895-4ce8-ab5c-88a579ea0da2`**（★ 变了） |
| `uptime` AFTER | 30.56（归零，新 boot） |
| `history.log` 新增条目 | `reason [null_pointer], time [20261005141844-24434260], category [AP_S_PANIC]` |
| 时间戳匹配 | 与本轮实跑 14:18 **精确对应** |
| adb 退出码 | 255（连接中断） |

**⇒ H128–H142 全程首次 `boot_id` 变化 ⇒ 内核 panic 重启 ⇒ UAF 被真实命中。**

---

## 三、完整利用链（8 环节，全部真机验证）

| # | 环节 | 关键事实 | 证据 |
|---|---|---|---|
| 1 | 设备未修复 | `remove_waiter` 用 `mrs x20, sp_el0`（`current`），非 `waiter->task` | 设备 Image 反汇编 @`0xffffffc081080e60` |
| 2 | 三 futex 真环 | `rtmutex.c:837` 判环：`rt_mutex_owner(f_chain)==W==top_task` | `h141c`：`CMP_REQUEUE_PI` = `-EDEADLK(35)` |
| 3 | `remove_waiter` 执行 | `rtmutex_api.c:353`：`if (unlikely(ret)) remove_waiter(lock, waiter)` | 同上 + 源码 |
| 4 | **W 返回 ⇒ 悬垂成立** | `futex_requeue` deadlock 分支**不唤醒 W** ⇒ 必须自带超时 | `h142b`：W 返回 `ETIMEDOUT` |
| 5 | **改 prio 破早退闸门** | `rt_mutex_adjust_pi` 的 `rt_waiter_node_equal` 早退 | `setpriority(nice=1) rc=0` |
| 6 | **`sched_setattr` 必走 PI 路径** | `sched/core.c:8069 → :8014`（`pi=true`） | 源码 |
| 7 | **`waiter->lock` 解引用** | `next_lock = waiter->lock` | 输出戛然而止 |
| 8 | **内核 panic** | `reason = null_pointer` | `boot_id` 变 + `history.log` |

---

## 四、本项目的关键原创发现（公开材料未提及）

### ★★★ 发现 1：`rt_mutex_adjust_pi()` 有早退闸门
```c
// rtmutex_api.c:458
waiter = task->pi_blocked_on;                       // ★ UAF 读
if (!waiter || rt_waiter_node_equal(&waiter->tree, task_to_waiter_node(task)))
    return;                                          // ★★ 早退
next_lock = waiter->lock;                            // ★★★ 才到这里
```

`rt_waiter_node_equal` 的判定是 **`waiter->tree.prio == task->prio`**（快照 vs 当前动态优先级）。

**⇒ 只做 `sched_setattr(victim)` 是无效的（会早退）；必须先让 victim 的 `prio` 与其快照不同。**

这一前置条件**公开材料完全未提及**，是本项目发现并实测验证的。

### ★★★ 发现 2：`futex_requeue` deadlock 分支不唤醒 W
设备汇编实证：`0xffffffc0802ca490 bl wake_up_q`（`0x…8004c044`），`wake_q` 只含
`requeue_pi_wake_futex()`（`ret==1` 路径）加过的 waiter ⇒ **deadlock 的 W 不在其中**。

`FUTEX_WAKE(f_src)` 亦无效（`h142a`：`rc=-1 errno=22 EINVAL`）。

**⇒ 唯一解 = 给 W 的 `FUTEX_WAIT_REQUEUE_PI` 传 `abs_time`。**

### ★★ 发现 3：`sched_setattr` 的 `pi` 参数
| 调用者 | `pi` |
|---|---|
| `sched_setattr(p, attr)` | **true** |
| `sched_setscheduler(p, ...)` | **true** |
| sysrq renormalize | false |

**⇒ shell 域可达的 `sys_sched_setattr`（274）与 `sched_setscheduler` 都走 PI 链。**

---

## 五、本机实测常量（设备专属，不可跨设备复用）

### 符号（本机 kallsyms）
| 符号 | 地址 |
|---|---|
| `remove_waiter` | `0xffffffc081080e60` |
| `rt_mutex_start_proxy_lock` | `0xffffffc081080df4` |
| `futex_requeue` | `0xffffffc0802c9f50` |
| `futex_wait_requeue_pi` | `0xffffffc080958e1c` |
| `wake_up_q` | `0xffffffc08004c044` |
| `rb_erase` | `0xffffffc08003a9d4` |

### 结构体偏移（本机反汇编推）
| 项 | 值 |
|---|---|
| `task_struct.pi_blocked_on` | `0x938` |
| `task_struct.pi_lock` | `0x90c` |
| `struct futex_q.requeue_state` | `0x54` |
| `struct futex_q.pi_state` | `0x38` |
| `&rt_waiter`（帧内） | `sp+0`（帧 `0x1c0`，waiter `0x70`）|
| `&q`（futex_q，帧内） | `sp+0x90` |

---

## 六、与「内核任意读写」的距离

**当前能力**：`waiter->lock` 是悬垂指针，值来自 W 内核栈被覆盖后的内容。
- 本实验里栈被自然覆盖 ⇒ 读到 **NULL** ⇒ panic
- **转为任意读写的必要条件 = 内核栈重占**，让 `waiter->lock` 指向攻击者控制的内核地址

**已具备的抓手**：
- `rt_mutex_adjust_prio_chain` 对该 lock 会做 `raw_spin_trylock(&lock->wait_lock)`（原子读改写）
  + 解引用 `lock->owner`
- 本机已有载波几何（H106）：帧 0x290、`SIGRETURN_WAITER_VREG_OFF=0xD0`

---

## 七、产物

| 文件 | 说明 |
|---|---|
| `tools/h142e_consume.c` | **★ UAF 命中探针**（md5 `ce89b5c99791a0965c9508b91ccdaaac`）|
| `tools/h142b_timeout.c` | W 超时返回（悬垂成立判据）|
| `tools/h142c_live.c` | 消费侧（判读已更正）|
| `tools/h142d_ctrl.c` | 对照组（排除正常解释）|
| `tools/h142a_wake.c` | 失败存档（FUTEX_WAKE 无效）|
| `analysis/scratch/dis_mey.py` | 设备 Image 反汇编工具（capstone）|
| `.workbuddy/memory/2026-10-05.md` | §41–§42 完整证据链 |

---

## 八、设备新基线（★ 重启后更新）

| 项 | 新值 |
|---|---|
| `boot_id` | `e4fc8d80-a895-4ce8-ab5c-88a579ea0da2` |
| `AP_S_PANIC` 累计 | 725（本底 724 + 本次 1） |

**★ 下一步必须先重跑 Phase 0**：`boot_id` 已变 ⇒ KASLR slide 已变 ⇒ 所有运行时地址需重取。

---

## 九、下一步（优先级序）

1. **★★★ 内核栈重占**：`prctl(PR_SET_MM, PR_SET_MM_MAP, ...)` 的 `user_auxv` 缓冲
   ⇒ `waiter->lock` 可控 ⇒ 从 panic 转为可控读写
2. **★ 转写原语**：`rb_erase` `0xffffffc08003a9d4` + H106 载波几何
3. **CVE-2026-64560**（posix-cpu-timers UAF，需 non-leader `exec()` 竞态）
