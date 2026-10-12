# GhostLock / CVE-2026-43499 情报整理（来源：Matrix 安全情报，2026-08-27）

> 用途：与本项目 H191 已实测结论交叉校验，并补齐「写原语如何落地」的缺失环节。
> 注意：文章以 x86 为主链，**数值与地址一律不得直接搬到本机 arm64**。

## 1. 漏洞机理（与本项目 H191 实测吻合）

- 根因函数：`kernel/locking/rtmutex.c` 的 `remove_waiter()`
- 错误假设：假定调用者就是被清理的 waiter 任务，于是操作 `current->pi_blocked_on`
- 实际：`remove_waiter()` 被 `rt_mutex_start_proxy_lock()` 用于代理锁回滚时，
  `current` 是执行 `FUTEX_CMP_REQUEUE_PI` 的**重排队请求者**，不是 waiter 任务
- 后果：waiter 的 `pi_blocked_on` 仍指向其**已弹出的内核栈帧** ⇒ 悬挂指针
- 引入 commit：`8161239a8bcc`（2011-05 rtmutex 重构）

```c
static void __sched_remove_waiter(struct rt_mutex_base *lock,
                                  struct rt_mutex_waiter *waiter) {
    raw_spin_lock(&current->pi_lock);        /* BUG: 应为 waiter->task */
    rt_mutex_dequeue(lock, waiter);
    current->pi_blocked_on = NULL;           /* BUG: 应清 waiter->task->pi_blocked_on */
    raw_spin_unlock(&current->pi_lock);
}
```

**本项目对应**：`pi_blocked_on` 在 `task_struct` 内偏移 `+0x938`（本机 BTF/汇编实测）。

## 2. ★ 本机受影响判定（关键）

| 项 | 值 |
|---|---|
| 6.6 分支修复版本 | **6.6.140** |
| 本机内核 | **6.6.118** |
| 判定 | ★ **118 < 140 ⇒ 在 affected 区间内，漏洞成立** |

其他分支上界（供未来换机参考）：

| 分支 | 修复于 |
|---|---|
| 2.6.39 ~ 6.1 | 6.1.175 |
| 6.2 ~ 6.6 | **6.6.140** |
| 6.7 ~ 6.12 | 6.12.86 |
| 6.13 ~ 6.18 | 6.18.27 |
| 6.19 ~ 7.0 | 7.0.4 |
| 7.1+ | 已修 |

前置条件：`CONFIG_FUTEX_PI=y`（默认值）＋ 非特权本地用户进程。

## 3. ★★ 触发拓扑（三线程 + 三 futex）

1. **waiter 线程**：持有 `f_pi_chain`，阻塞在 `FUTEX_WAIT_REQUEUE_PI(f_wait → f_pi_target)`；
   其 `rt_mutex_waiter` 在**该线程内核栈**上
2. **owner 线程**：持有 `f_pi_target`，阻塞在 `f_pi_chain` 上等 waiter 释放
3. **main 线程**：`FUTEX_CMP_REQUEUE_PI(f_wait → f_pi_target)` ⇒ 遍历发现闭环 ⇒ 返回 `-EDEADLK` ⇒ 触发回滚

⇒ 与本项目 W / O / main 三线程拓扑**完全一致**（H187/H191 已实测）。

## 4. ★★★ 官方利用链阶段（缺的就是第 2 阶段）

| 阶段 | 内容 | 对本项目的意义 |
|---|---|---|
| 1 | Prefetch ASLR 泄漏（x86，9 bit 熵） | ★ arm64 不适用；Android 改用 KernelSnitch 侧信道 |
| **2** | **Stack UAF 回收：把受控字节喷回 waiter 已释放的栈帧** | ★★★ **本项目一直缺这一步** |
| 3 | 受控指针写：`rt_mutex_dequeue()` → `rb_erase` ⇒ 覆写 `inet6_protos[IPPROTO_UDP]` | 与本项目 `rb_erase` 机制假设一致 |
| 4 | CET/CEA 条目区喷溅（120 字节连续可控内存） | ★ x86 专属 |
| 5 | DirtyMode 提权：改 `core_pattern` | — |

### 4.1 阶段 2 的喷溅原语（Android）

- `PR_SET_MM_MAP`
- **`pselect()` / `select()`**
- `TCP_ZEROCOPY_RECEIVE` 路由

★ 本项目 H191 已实测前提成立：`logx()` 的栈复用把该区域**清零**，
panic 从 `page_request` 变 `null_pointer` ⇒ 说明窗口真实存在且可控。

### 4.2 阶段 3 的 Android 变体（IonStack Part III）

- 受限 R/W：覆写 `ashmem_miscs[0].fops` 为伪造 `file_operations`（满足 CFI 前向边约束）
  ⇒ 经 ashmem fd 的 `read`/`write`/`splice` 获得受限内核读写
- 任意 R/W：伪造 `pipe_buffer` 结构（`vmemmap` ↔ direct-map 地址转换）
- KASLR：Phase A 经 `/proc/sys/kernel/random/boot_id` 泄漏 + 损坏 `ctl_table.data`
  推导 KASLR 基址（每 boot 一次，可能 panic）；Phase B 固定 `KASLR_BASE` 重放
- Root 补丁：管道原语置 `cred`（uid/gid=0）、SELinux `osid`/`sid` = `SECINITSID_KERNEL`、
  清 seccomp、关 `selinux_state.enforcing`

## 5. ★ 修复补丁（判断本机是否已打）

- 主补丁 `3bfdc63936dd4773109b7b8c280c0f3b5ae7d349` —— 用 `waiter->task` 替代 `current`
- 后续：`3fb7394a837740770f0d6b4b30567e60786a63f2`、`6d52dfcb2a5db86e346cf51f8fcf2071b8085166`、
  `88614876370aac8ad1050ad785a4c095ba17ac11`、`8a1fc8d698ac5e5916e3082a0f74450d71f9611f`、
  `d8cce4773c2b23d819baf5abedc62f7b430e8745`
- ⚠️ **补丁本身引入新竞态 CVE-2026-53163**（`remove_waiter()` 未入队时需跳过）

## 6. 缓解措施与本机现状

| 缓解 | 说明 | 本机 |
|---|---|---|
| `randomize_kstack_offset` | 增加利用难度但不阻止 | ★ 文件不存在（`cat` rc=1）⇒ **未启用/未暴露** |
| seccomp 过滤两个 futex syscall | 影响合法应用 | uid 2000 无 seccomp 限制 |
| kernelCare livepatch | 需重启 | 不可用 |

## 7. 与本项目已实测结论的交叉校验

| 本项目结论 | 文章 | 一致性 |
|---|---|---|
| P1 悬垂机制（H191 实测） | `remove_waiter()` 误用 `current` | ✅ 完全吻合 |
| `pi_blocked_on` 偏移 `+0x938` | `waiter->task->pi_blocked_on` | ✅ |
| 三线程 EDEADLK 拓扑 | 章节 3 | ✅ |
| 写原语走 `rb_erase`（Path A/B） | 阶段 3 `rt_mutex_dequeue` | ✅ |
| 「崩在 `rb_erase` 之前」 | dequeue 才触发 erase | ✅ 解释 J9 写未落地 |
| **栈重占可做**（曾被我判死） | ★ 阶段 2 | ★★ **推翻我先前的判死，H191 已证窗口存在** |

## 8. 公开资源

- 官方：`github.com/NebuSec/CyberMeowfia`（Apache-2.0，IonStack Part II + Part III Android）
- Android 适配：`github.com/CakesTwix/Android-CVE-2026-43499`（检测）
- KernelSU 工程化：`github.com/JingMatrix/pixel-ksu-root`（19 台 Pixel，GKI 6.1/6.6）
- Red Hat：RHSB-2026-010（43499 + 53163 须同时修）
