# H192 U-C 栈重占（Stack Spray）设计书 —— 把 page fault 转成写原语

> 前置：H191 已实测 P1（`pi_blocked_on` 悬垂）+ 栈帧会被后续 syscall 复用清零。
> 本文件是**设计**，不含实测结论。所有偏移均标注来源。

## 1. 目标

把 H191 的「纯崩溃」升级为「受控写」。路线与官方链阶段 2→3 一致：
**伪造 waiter 喷回栈帧 → 让 `rt_mutex_dequeue` 的 `rb_erase` 按伪造值写。**

## 2. 本机权威布局（全部来自本机，非套用文章/x86）

### 2.1 `struct rt_mutex_waiter` —— **来源：本机 BTF `offsetof`**
文件：`analysis/output/btf_offsets.txt:312`

```text
## struct rt_mutex_waiter  (size=0x70  vlen=6)
    tree       off=0x0000    pi_tree  off=0x0028
    task       off=0x0050    lock     off=0x0058
    wake_state off=0x0060    ww_ctx   off=0x0068
```

推得的 `rt_waiter_node`（`tree`，源码 `kernel/locking/rtmutex_common.h:32`）：

| 偏移 | 字段 | 字节 |
|---|---|---|
| `+0x00` | `tree.entry.rb_node.__rb_parent_color` | 8 |
| `+0x08` | `tree.entry.rb_left` | 8 |
| `+0x10` | `tree.entry.rb_right` | 8 |
| `+0x18` | `tree.prio`（int） | 4 |
| `+0x20` | `tree.deadline`（u64） | 8 |

⇒ **`waiter` 整体布局**（供 spray 用）：

| 偏移 | 字段 | 用途 |
|---|---|---|
| `+0x00` | `tree.entry` | ★ rb_erase 的 `node` ⇒ **写原语入口** |
| `+0x08` | `tree.entry.rb_left` | ★ Path A 写目标 |
| `+0x10` | `tree.entry.rb_right` | ★ Path B 写目标 / Path A 写值 |
| `+0x18` | `tree.prio` | rt_mutex_adjust_pi 会读 |
| `+0x20` | `tree.deadline` | — |
| `+0x28` | `pi_tree.entry` | dequeue_pi 会碰 |
| `+0x50` | **`task`** | ★ 指向 W 自己 |
| `+0x58` | **`lock`** | ★ 指向目标 rt_mutex |
| `+0x60` | `wake_state` | TASK_NORMAL=0 |
| `+0x68` | `ww_ctx` | NULL |

### 2.2 `rb_erase` 双写 —— **来源：本机 vmlinux 反汇编（独立复核 H177）**
`rb_erase@0xffffffc08003a9d4`（kallsyms 实证）：

```asm
0x…a9d4: ldp  x8, x10, [x0, #8]    ; x8=node->rb_right, x10=node->rb_parent
0x…a9d8: cbnz x10, #…aa18         ; parent != NULL ⇒ Path B
0x…a9dc: ldr  x9, [x0]             ; x9=node->rb_left
0x…aa00: str  x8, [x11]           ; ★ Path A: *(node->rb_left)  = node->rb_right
0x…aa10: str  x9, [x8]            ; ★ Path B: *(node->rb_right) = node->rb_left
```

⇒ **8 字节任意值 → 任意地址**。`node` = 伪造 waiter 的 `+0x00`。
⇒ 三个字段联动即可完全控制写目标与写值。

### 2.3 `rt_mutex_dequeue` —— **来源：本机源码 `kernel/locking/rtmutex.c:473`**

```c
void rt_mutex_dequeue(struct rt_mutex_base *lock, struct rt_mutex_waiter *waiter)
{
	lockdep_assert_held(&lock->wait_lock);
	if (RB_EMPTY_NODE(&waiter->tree.entry))   /* ← 伪造时必须非空！ */
		return;
	rb_erase_cached(&waiter->tree.entry, &lock->waiters);
	RB_CLEAR_NODE(&waiter->tree.entry);
}
```

★ **`RB_EMPTY_NODE` 检查是本设计的核心约束**：
`rb_node.__rb_parent_color == (unsigned long)node` 即为空。
⇒ 伪造时 `+0x00` **不能自指**，否则 dequeue 直接 return，`rb_erase` 永不执行。

## 3. ★ 关键约束：崩溃发生在 dequeue **之前**

H191 已实测（J9 四重判据）：崩溃点早于任何 `rb_erase`。
本机调用链：

```
rt_mutex_adjust_pi()          ← 崩在这里（H191 实测）
  └─ rt_mutex_adjust_prio_chain()
       └─ rb_erase()          ← 写原语在此，但到不了
```

⇒ ★★ **光 spray 栈帧不够**。必须让内核**先活着走完 adjust_pi**，
再由**另一条路径**触发 dequeue。
⇒ 这是本设计与文章阶段的**最大差异点**，文章未讲清这一点。

### 3.1 破局思路（待验证，不保证成立）

`remove_waiter()`（`rtmutex.c:1524`）本身也调 `rt_mutex_dequeue`：

```c
raw_spin_lock(&current->pi_lock);
rt_mutex_dequeue(lock, waiter);      /* ← 第二次 dequeue 机会 */
current->pi_blocked_on = NULL;
```

但它在 `CMP_REQUEUE_PI` 阶段就跑了（那时 waiter 还在栈上、且已入队），
**早于我们的 spray**。⇒ 需要新的 dequeue 触发点，或在 S1 之前就 spray。

| 方案 | 思路 | 风险 |
|---|---|---|
| **S-a** | 在 S1 **之前** spray（栈帧尚未建立 waiter，无法定向） | 偏移不可控 |
| **S-b** | 双 waiter：让另一个 waiter 在 S1 后才 dequeue | 需第二个悬垂源 |
| **S-c** | 用 `wake_up_state` 路径触发 unlock 时 dequeue | 需构造 |
| ★ **S-d** | **不 spray waiter，而是让 adjust_pi 走完**：把 `pi_blocked_on` 指向一个**合法的**（非栈）waiter | 需另一个已知地址的 waiter |

## 4. spray 原语评估 —— ★ pselect 已**排除**（离线源码实证）

### 4.1 pselect 机制成立但容量不够（本节结论 = 已验证）

调用链（**本机源码**）：

```
SYSCALL_DEFINE6(pselect6)        fs/select.c:795
  └─ do_pselect()                fs/select.c:732
       └─ core_sys_select()      fs/select.c:625
            ├─ long stack_fds[SELECT_STACK_ALLOC/sizeof(long)]   :634  ← 内核栈
            └─ get_fd_set(n, inp, fds.in)                       :673
                 └─ copy_from_user(fdset, ufdset, nr)           :394  ← ★ 落栈
```

★ `copy_from_user` 到内核栈，**机制成立**。

### 4.2 ★ 但容量上限致命

```c
/* include/linux/poll.h:18-19 */
#define FRONTEND_STACK_ALLOC   256
#define SELECT_STACK_ALLOC     FRONTEND_STACK_ALLOC

/* fs/select.c:634 */
long stack_fds[SELECT_STACK_ALLOC/sizeof(long)];   /* 只有 256 字节 */

/* fs/select.c:653-665 */
size = FDS_BYTES(n);
bits = stack_fds;
if (size > sizeof(stack_fds) / 6) {       /* ★ 超过 256/6 = 42 字节 ⇒ 改走 kvmalloc */
        ret = -ENOMEM;
        bits = kvmalloc(6 * size, GFP_KERNEL);   /* ← 不在栈上，spray 失效 */
}
```

推算：

| 项 | 值 |
|---|---|
| 栈上总容量 | `256` 字节 |
| 触发 kmalloc 阈值 | `size > 256/6 = 42` 字节 |
| `FDS_BYTES(n) = ((n+63)/64)*8` | 8 字节粒度 |
| **栈上单块（fds.in）最大** | **40 字节**（n=31），三个输入集各 40 |
| waiter 需求 | **112 字节（0x70）** |

⇒ ★★ **pselect 容量 < waiter 需求 ⇒ 排除。**
★ 即便 `n` 取到 32 以上，`bits` 也已切到 `kvmalloc` 堆上，**不再落内核栈**。

### 4.3 修正后的原语候选（待验证）

| 原语 | 机制 | 容量 | 状态 |
|---|---|---|---|
| `pselect`/`select` | fd_set copy_from_user | ★ **42 B 硬上限** | ✘ **已排除** |
| `PR_SET_MM_MAP` | 改用户 mm | — | 需权限，uid 2000 大概率 EPERM |
| `TCP_ZEROCOPY_RECEIVE` | skb 落栈 | 理论够 | 未验证，构造复杂 |
| ★ **定制栈拷贝** | 找一个「用户变长数据 → 内核栈」的路径 | 可控 | ★ **待离线筛选** |

★ 筛选准则：`copy_from_user` 目标必须**是栈变量**、且**无长度硬上限**、
且 syscall 栈帧深度与 `futex_wait_requeue_pi` 接近。

## 5. 下一步（每步 1 boot，一 boot 一发）

| 发 | 内容 | 判据 |
|---|---|---|
| **H192** | ★ **改为离线**：筛选满足「无长度上限 + 落内核栈 + 栈帧深度接近」的 spray 原语（§4.3 准则） | 产出一个可编译的候选清单 |
| **H193** | 用选定原语喷 **已知 pattern** 到 SP0-0x210 附近，W 走完 S1 超时退出，attacker 发 S4 | panic reason 从 `null_pointer` → `page_request` ⇒ 覆盖到了该区域；仍 `null_pointer` ⇒ 偏移不对 |
| H194+ | 偏移对齐后填入伪造 waiter（`+0x00` 非自指、`+0x50`=W、`+0x58`=目标 lock） | 观察是否走到 `rb_erase` |

★ H193 **不改任何内核数据语义**，只喷 pattern，是零副作用探针。

## 6. 置信度标注

| 结论 | 置信度 |
|---|---|
| waiter 布局（§2.1） | ★ **已验证**（BTF offsetof） |
| rb_erase 双写（§2.2） | ★ **已验证**（本机汇编） |
| dequeue 的 RB_EMPTY_NODE 约束（§2.3） | ★ **已验证**（本机源码） |
| 崩溃早于 rb_erase | ★ **已实测**（H191 + J9） |
| pselect 容量不足（42B < 112B） | ★ **已验证**（本机源码 `poll.h:19` + `select.c:655`）⇒ **排除** |
| 存在满足准则的替代 spray 原语 | ★ **未验证**（H192 离线筛选待做） |
| spray 后能到达 rb_erase | ★ **未验证**（§3 是推理，方案未定） |

---

## 6. H192 离线筛选结论（已完成）

### 6.1 ★ 两处前期判断被纠正

| 我之前的说法 | 实测/源码实证 | 来源 |
|---|---|---|
| `rt_mutex_adjust_pi` 在 `rtmutex.c` | ★ **在 `kernel/locking/rtmutex_api.c:458`**，唯一调用点 `kernel/sched/core.c:8014` | 本机源码 |
| 崩点需 `sched_setattr` 触发 | ★ 确认读 `pi_blocked_on` 的是 `sched_setscheduler` 路径 | 同上 |

⇒ ★★ **触发侧无需任何特权**，利用门槛比预想低。

### 6.2 `struct rt_mutex_waiter` = 112 字节（0x70）—— 与 BTF 一致

`kernel/locking/rtmutex_common.h:32-59` 推算 + BTF `offsetof` 互证（§2.1），size=0x70。
⇒ **spray 必须覆盖 112 字节连续区间**，不足则无法重建完整 waiter。

### 6.3 ★★ `harden_usercopy` **不构成阻碍**（重要利好）

本机 `CONFIG_HARDEN_USERCOPY` 已开，但源码实证（`mm/usercopy.c` + `include/linux/thread_info.h`）：

```c
/* usercopy.c:233-240 —— __check_object_size 判定 */
case GOOD_FRAME:
case GOOD_STACK:
        return;                      /* ★ 栈目标直接放行，无长度检查 */

/* usercopy.c:38 check_stack_object —— 全程无 len 上限检查 */
/* ★ 树中不存在 STACKLEAK_*/OBJECT_SIZE 长度阈值 */

/* thread_info.h:198 —— arm64 无 arch_within_stack_frames */
static inline int arch_within_stack_frames(...) { return 0; }  /* ⇒ 恒 GOOD_STACK */
```

⇒ ★ **arm64 上「用户数据 → 内核栈」拷贝恒被放行，无论长度。**
（注意：`check_object_size` 仅在长度**非常量**时检查 ⇒ 变长拷贝必触发，但栈路径放行。）

### 6.4 ★★ 候选原语清单（离线筛选，按可行性）

| # | 候选 | 栈变量 & 大小 | 长度上限 | 特权 | 判定 |
|---|---|---|---|---|---|
| **1** | `__sys_bind` `net/socket.c:1840` | `sockaddr_storage address` **128 B** | **128** | **无** | ★★★ **首选**（单次可覆盖 112 B） |
| 2 | `sys_sethostname` `kernel/sys.c:1389` | `char tmp[__NEW_UTS_LEN]` 64 B | 64 | `ns_capable`（可 user_ns） | ★★ 备选（64 B 不足） |
| 3 | `__sys_connect` `net/socket.c:2065` | `sockaddr_storage` 128 B | 128 | 无 | ★★ 备选 |
| 4 | `sys_setdomainname` `kernel/sys.c:1444` | 64 B | 64 | 同 2 | 备用 |
| 5 | `ptrace_writedata` `kernel/ptrace.c:654` | `char buf[128]` | 128/次 | 需 ptrace | 循环破坏语义 |
| — | `sendmsg` ctl `net/socket.c:2536` | `ctl[44]` | >44 转堆 | 无 | ✘ 排除 |
| — | `getname` `fs/namei.c:129` | kmalloc | 4096 | 无 | ✘ 排除（不在栈） |
| — | `SO_ATTACH_FILTER` `net/core/filter.c:1425` | kmalloc | 4096 | 无 | ✘ 排除（不在栈） |
| — | `prctl(PR_SET_NAME)` `kernel/sys.c:2516` | 16 B | 15 | 无 | ✘ 排除（15 B ≪ 112 B） |
| — | `pselect` | 42 B 硬上限 | — | 无 | ✘ **已排除**（§4.2） |

★ **`__sys_bind` 的关键优势**（`net/socket.c:1840-1856` + `250`）：

```c
int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
        struct sockaddr_storage address;         /* 128 B 纯栈 */
        sock = sockfd_lookup_light(fd, &err, &fput_needed);
        if (sock) {
                err = move_addr_to_kernel(umyaddr, addrlen, &address);  /* ← 拷贝 */

/* net/socket.c:250 */
if (ulen < 0 || ulen > sizeof(struct sockaddr_storage))   /* 128 */
        return -EINVAL;
```

- **零特权**（只要一个 socket fd）
- **容量 128 B ≥ 112 B** ⇒ 单次即可完整重建 waiter
- ★ **spray-then-fail 模式可行**：无效数据会让 bind 返回 `-EAFNOSUPPORT`/`-EINVAL`，
  **但拷贝已在返回前完成**，返回值不影响喷溅效果 ⇒ 零副作用

### 6.5 ★★★ 唯一的真障碍：kstack 偏移随机化**运行时状态未知**

**已知（源码实证）**：

```c
/* arch/arm64/configs/merge_sun_defconfig:783-785 */
CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET=y
CONFIG_RANDOMIZE_KSTACK_OFFSET=y
# CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is not set   /* ★ 默认关闭 */

/* init/main.c:813-828 */
static int __init early_randomize_kstack_offset(char *buf) {
        ret = kstrtobool(buf, &bool_result);
        if (bool_result) static_branch_enable(&randomize_kstack_offset);
        else             static_branch_disable(&randomize_kstack_offset);
}
early_param("randomize_kstack_offset", early_randomize_kstack_offset);
/* ★ 只有 boot cmdline 显式传 randomize_kstack_offset=on 才启用 */
```

**符号存在**（kallsyms 实证，说明**编译时打开**）：
`randomize_kstack_offset@0xffffffc0816982d8`（static key）、
`kstack_offset@0xffffffc082136080`（percpu，区内偏移 `0x80`）

**间接证据（指向"未启用"）**：
`__arm64_sys_futex@0xffffffc080119ad8` 序言 `sub sp, sp, #0x80`
—— **恰好 128 字节、16 字节对齐的整齐值**。若随机化生效，
该值应被加上 `0~0x3F0` 的随机量，不会如此整齐。

> ★★ **这是间接证据，不是实证。** 置信度：中等。

**无法确认的原因（uid 2000 权限限制）**：

| 途径 | 结果 |
|---|---|
| `/proc/cmdline` | **EACCES** |
| `/proc/self/cmdline` | **EACCES** |
| `/proc/bootconfig` | **EACCES** |
| `/proc/sys/kernel/randomize_kstack_offset` | 文件不存在（rc=1） |

⇒ ★★ **这是本轮最重要的开放项**。
若运行时**已启用**（cmdline 有 `=on`）：偏移 = `random & 0x3FF` 对齐 16B
⇒ **64 个档位**，需 64 次迭代覆盖。
若运行时**未启用**（源码默认值，符合间接证据）：**偏移恒为 0**，
单次喷溅即可，方案难度大幅下降。

### 6.6 §3 的卡点仍未解决（★ 比 spray 容量更根本）

即使 spray 成功，仍有硬约束：**H191/J9 已实测崩溃发生在 `rb_erase` 之前**。
调用链：

```
rt_mutex_adjust_pi()      kernel/locking/rtmutex_api.c:458   ← H191 实测崩在这里
  └─ rt_mutex_adjust_prio_chain()
       └─ rb_erase()                                        ← 写原语在此，到不了
```

⇒ ★★ **必须先让内核活着走完 `adjust_pi`**，再由**另一条路径**触发 dequeue。
四个候选方案（§3.1）**均未验证**。

**新增的可行思路**（基于 §6.1 的发现）：

`remove_waiter()`（`rtmutex.c:1524`）本身调 `rt_mutex_dequeue`：

```c
raw_spin_lock(&current->pi_lock);
rt_mutex_dequeue(lock, waiter);       /* ← 第二次 dequeue 机会 */
current->pi_blocked_on = NULL;
```

★ 它在 `CMP_REQUEUE_PI` 阶段执行，**早于我们的 spray** ⇒ 栈上 waiter 真实有效，
**不会崩**，但也**拿不到写**（rb_erase 用的是真实值）。
⇒ 若能让这次 dequeue **推迟到 spray 之后**（如让 `CMP_REQUEUE_PI` 的 EDEADLK
回滚变慢/分步），就是理想的写原语触发点。**可行性未验证。**

## 7. H192 判决

| 项 | 状态 |
|---|---|
| waiter 布局 112 B | ★ **已验证**（BTF + 源码互证） |
| rb_erase 双写 8B→任意地址 | ★ **已验证**（本机汇编） |
| `RB_EMPTY_NODE` 约束 | ★ **已验证**（`rtmutex.c:477`，`+0x00` 不得自指） |
| harden_usercopy 无阻碍 | ★ **已验证**（源码，arm64 恒 GOOD_STACK） |
| `pselect` 容量不足 | ★ **已验证** ⇒ 排除 |
| `__sys_bind` 可喷 128 B 落栈 | ★ **已验证**（源码）⇒ **首选原语** |
| kstack 随机化运行时状态 | ★★ **未确认**（权限阻塞，§6.5） |
| spray 后能到达 `rb_erase` | ★ **未解决**（§6.6 是核心卡点） |

⇒ ★★ **本轮零开火、零 boot 消耗**，全部为离线/零副作用工作。
⇒ 下一步优先级：**先解决 §6.6 的 dequeue 触发点**（比 spray 容量更根本），
否则即使 spray 成功也只是把「空指针崩」换成「野指针崩」。

---

## 8. ★★★ §6.6 卡点已解决 —— dequeue 就在 adjust_pi 内部（同一次调用）

### 8.1 前期一个认知错误（★ 必须纠正）

我此前写「崩溃发生在 `rb_erase` 之前，所以 spray 之后还要设法诱发一次 dequeue」——
**这个理解是错的**。源码实证：

```c
/* kernel/locking/rtmutex.c:919-934（adjust_prio_chain 内部 [7]/[8]） */
prerequeue_top_waiter = rt_mutex_top_waiter(lock);

/* [7] Requeue the waiter in the lock waiter tree. */
rt_mutex_dequeue(lock, waiter);        /* ← rb_erase_cached 写原语在此 */

/* 注释原文（:922-929）：这些值可能已被 sys_sched_setattr() 改变 */
waiter_update_prio(waiter, task);

rt_mutex_enqueue(lock, waiter);        /* ← 伪造 waiter 顺手入队到真实树 */
```

⇒ ★★★ **`dequeue` + `enqueue` 在同一次 `sched_setscheduler()` 内成对执行。**
⇒ 只要让链 walk **不早退**并通过 B8，写原语当场触发，**无需任何二次诱发**。
⇒ 这也顺带解答了「spray 之后如何再次 dequeue」：
**B13 的 `rt_mutex_enqueue` 把伪造 waiter 留在真实 `lock->waiters` 树里**，
之后 `FUTEX_UNLOCK_PI` → `mark_wakeup_next_waiter`（`rtmutex.c:1315`
`rt_mutex_dequeue_pi`）构成**第二个可控触发点**。

### 8.2 ★★★ 崩溃点的精确修正（比"解引用 pi_blocked_on"更准确）

H191 的 `null_pointer` **不是**解引用 `pi_blocked_on` 崩的，而是走到
`rtmutex.c:829-830` 时崩的：

```c
/* [4] Get the next lock */
lock = waiter->lock;                    /* waiter 是野指针 → 读到垃圾 */

/* [5] We need to trylock here ... */
if (!raw_spin_trylock(&lock->wait_lock)) {      /* ★ 写 lock->wait_lock ！ */
        raw_spin_unlock_irq(&task->pi_lock);
        cpu_relax();
        goto retry;
}
```

⇒ ★★ **`raw_spin_trylock` 会「写」`lock->wait_lock`（自旋锁的 value 字段）**。
⇒ H191 的栈被清零 ⇒ `waiter->lock == NULL` ⇒ 写 NULL 附近 ⇒ **`null_pointer`** ✅ 完美吻合。
⇒ H187 的栈是随机垃圾 ⇒ `lock` 是随机值 ⇒ 写未映射地址 ⇒ **`page_request`** ✅ 同样吻合。

⇒ ★★★ **两级 panic 原因至此全部解释完毕，机制闭环。**
（此前我只知道「沿 pi_blocked_on 链解引用」，现在精确到「写 `lock->wait_lock`」。）

### 8.3 链路全图（本机源码实证）

```
main: FUTEX_CMP_REQUEUE_PI
  └─ futex_requeue()                         kernel/futex/requeue.c:364
       └─ rt_mutex_start_proxy_lock()        requeue.c:627-629
            └─ __rt_mutex_start_proxy_lock() rtmutex_api.c:351
                 └─ task_blocks_on_rt_mutex() → adjust_prio_chain()
                      └─ [6] -EDEADLK         rtmutex.c:845-846
            └─ remove_waiter(lock, waiter)  rtmutex_api.c:352-353   ★ bug 现场
                 ├─ rt_mutex_dequeue(lock, waiter)   rtmutex.c:1534（真对象，不崩）
                 └─ current->pi_blocked_on = NULL   rtmutex.c:1535  ★ 清错了对象
                      ⇒ T->pi_blocked_on 保持悬垂 ★★

—— 之后（spray 完成后）——
main: __sys_bind(伪造 waiter 112B)           net/socket.c:1840   ← 喷到 T 的旧栈
main: sched_setattr(T, SCHED_OTHER, nice=1)
  └─ __sched_setscheduler(pi=true)           kernel/sched/core.c:8069
       └─ rt_mutex_adjust_pi(T)              core.c:8014 → rtmutex_api.c:458
            ├─ waiter = T->pi_blocked_on      （★ 已指向伪造 waiter）
            ├─ B6: rt_waiter_node_equal?      rtmutex.c:809   ← prio 必须不等
            ├─ lock = waiter->lock            rtmutex.c:822   ← 必须是真实 lock
            ├─ B8: trylock(&lock->wait_lock)  rtmutex.c:830   ★ H191 崩在这
            ├─ B9: owner != top_task?         rtmutex.c:845
            └─ B12/B13: dequeue + enqueue    rtmutex.c:919/934 ★★ 写原语
```

### 8.4 ★★ 重大利好：lockdep 全关，伪造条件大幅放宽

**本机 defconfig 实证**：

| 配置 | 状态 | 行号 |
|---|---|---|
| `CONFIG_DEBUG_RT_MUTEXES` | **not set** | 7658 |
| `CONFIG_DEBUG_LOCK_ALLOC` | **not set** | 7663 |
| `CONFIG_PROVE_LOCKING` | **not set** | 7656 |
| `CONFIG_FUTEX_PI` | **=y** | 259 |
| `CONFIG_RT_MUTEXES` | **=y** | 819 |

⇒ ★★ **`lockdep_assert*()` 全部退化为 `do{}while(0)`**（`include/linux/lockdep.h:427`）
⇒ ★ `rt_mutex_dequeue` 里的 `lockdep_assert_held(&lock->wait_lock)`（`:475`）**不检查**
⇒ ★ `waiter_update_prio` 里的 `lockdep_assert(RB_EMPTY_NODE(...))` **不检查**
⇒ **伪造 waiter 不必满足 lockdep 的锁序/嵌套一致性要求。**

### 8.5 伪造 waiter 的字段规格（★ 全部本机源码/BTF 实证）

| 偏移 | 字段 | 要求 | 依据 |
|---|---|---|---|
| `+0x00` | `tree.entry.__rb_parent_color` | ★ **不得自指**（否则 `RB_EMPTY_NODE` 为真 → dequeue 直接 return） | `rtmutex.c:477` |
| `+0x08` | `tree.entry.rb_left` | 与 `lock->waiters` 现状自洽 | `rbtree_augmented.h` |
| `+0x10` | `tree.entry.rb_right` | 同上 | 同上 |
| `+0x28` | `tree.prio` | ★ **≠ T->prio**（否则 B6 早退） | `rtmutex.c:809`、`:391-407` |
| `+0x30` | `tree.deadline` | 任意（prio ≥ 0 时不参与比较） | `rtmutex.c:399-400` |
| `+0x38` | `pi_tree.entry...` | 若走 B16 需非空 | `rtmutex.c:505` |
| `+0x50` | `task` | 填可解引用的 task（T 自身） | `:954` `wake_up_state` |
| `+0x58` | **`lock`** | ★★ **指向真实且 `wait_lock` 空闲的 `rt_mutex_base`** | `:822`、`:830` |
| `+0x60` | `wake_state` | 合法 task state | 同上 |
| `+0x68` | `ww_ctx` | NULL | 本树无 `WW_RT` |

★ **`lock` 的现实选择**：本项目已有 futex PI 通路，
`futex_q->pi_mutex`（futex hash bucket 内的 `rt_mutex_base`）是**真实、已知、
且 `wait_lock` 空闲**的候选。但需先确定其地址（`/proc/kallsyms` EACCES ⇒ 需另想办法）。
`lock` 选错 ⇒ `trylock` 写野地址 ⇒ 崩（这正是 H191 的机制）。

### 8.6 「tree.entry 自洽」是剩余最硬约束

`rb_erase_cached`（`rbtree.h:119-129`）→ `__rb_erase_augmented` 会调
`__rb_change_child`（`rbtree_augmented.h:195-206`）**写 parent 的 rb_left/rb_right**。
最省事构型（源码推断，未验证）：

- 让 `lock->waiters` 为空树（`rb_root == NULL`）
- 伪造 node 的 `rb_left = rb_right = NULL`
- `__rb_parent_color` 设为「父视角」且低位颜色 = `RB_BLACK(0)`
  ⇒ `__rb_erase_augmented` 走 Case 1（`tmp = node->rb_left == NULL`）
  ⇒ `__rb_change_child(node, NULL, parent, root)`：
  - `parent == NULL` ⇒ 写 `root->rb_node`（即 `lock->waiters`）—— **受控但落点固定**
  - 要落点任意 ⇒ 令 `parent` = 目标地址，并使 `parent->rb_left == node` 或反之
  ⇒ ★ 这正是可用的**受控 8 字节任意写**形态

⚠️ 以上 `parent` 构造的**可满足性未验证**（需实测 `__rb_change_child` 的实际比较方向）。

### 8.7 修正后的优先级

| 优先 | 事项 | 理由 |
|---|---|---|
| ★ **1** | 确定一个**真实 `rt_mutex_base` 的地址**作 `waiter->lock` | 缺它则 §8.5 无法满足，一切归零 |
| ★ 2 | 标定 `T->prio`（含 vendor hook `trace_android_vh_rtmutex_waiter_prio` 是否改写） | 决定 `+0x28` 填什么 |
| 3 | 验证 `__sys_bind` 实际栈偏移与 `SP0-0x210` 的关系 | spray 能否命中 |
| 4 | 构造 `tree.entry` 自洽子树 | §8.6 |

⇒ ★★ **新的头号卡点从「spray 容量」变成「`lock` 地址未知」**。
⇒ 这是零风险的离线工作，**不需要开火**。

---

## 9. ★★★ 本机汇编级取证（`rt_mutex_adjust_prio_chain@0xffffffc0810815d4`）

### 9.1 B6 早退闸门（`:809`）—— 汇编实证

```asm
0x…81648: ldr  x25, [x19, #0x938]   ; ★ x25 = waiter = task->pi_blocked_on
0x…8164c: cbz  x25, #0x…81980      ; ★ waiter == NULL ⇒ return
0x…81654: ldr  x8, [x21, #0x18]    ; task_to_waiter_node(task).prio
0x…81660: ldr  x8, [x25, #0x58]    ; ★ lock = waiter->lock
0x…81664: cmp  x27, x8             ; lock == orig_lock ?
0x…81668: b.ne #0x…81980           ; ⇒ out_unlock_pi
```

★ 与源码 `rtmutex.c:809/822/752` 逐条对应。`x19 = task`，`x21/x27` 为
`task_to_waiter_node(task)` 与 `orig_lock`。

### 9.2 ★★★ `[7] dequeue` + `[8] enqueue` 实证 —— ★ 写原语落点确认

```asm
0x…8170c: ldr  x8, [x24, #0x18]    ; ★★ lock+0x18 = &lock->waiters.rb_root
0x…81738: ldr  x8, [x25]           ; ★★ waiter->tree.entry（x25 = 野 waiter）
0x…8173c: cmp  x8, x25             ; ★★ RB_EMPTY_NODE(node) ⇔ (node->parent_color == node)
0x…81740: b.eq #0x…81768           ;   ★ 为真 ⇒ 跳过 dequeue（源码 :477-478）
0x…8174c: mov  x0, x25
0x…81750: bl   #0xffffffc08003af24 ; ★★ rb_erase_cached(node=x25, root=lock+0x18)
0x…81754: str  x0, [x24, #0x10]    ; ★ leftmost 写回 lock+0x10
0x…81758: add  x1, x24, #8         ; enqueue: root = lock+0x08
0x…8175c: mov  x0, x25
```

⇒ ★★★ **本机汇编直接证明**：
1. `rb_erase_cached` 就在 `sched_setscheduler` 的同一次调用内（无需二次诱发）
2. `tree.entry.__rb_parent_color` **不得自指**，否则 dequeue 被跳过
3. `lock->waiters.rb_root` 在 **`lock+0x18`**，`rb_leftmost` 在 **`lock+0x10`**

⇒ 由此**反推 `struct rt_mutex_base` 布局**（本机，无 lockdep ⇒ `raw_spinlock_t` 仅 4 字节）：

| 偏移 | 字段 | 依据 |
|---|---|---|
| `+0x00` | `wait_lock`（`raw_spinlock_t` = `u32`） | 源码 `rtmutex.h` |
| `+0x08` | `waiters.rb_node`（`__rb_parent_color`） | 汇编 `add x1, x24, #8` |
| `+0x10` | `waiters.rb_leftmost` | 汇编 `str x0, [x24, #0x10]` |
| `+0x18` | `waiters` 的…（`rb_root` 在此，见 §9.4 修正） | 汇编 `ldr [x24,#0x18]` |
| `+0x20` | `owner` | 源码顺序 |

⚠️ **`+0x08` 与 `+0x18` 的归属存在解释冲突**（见 §9.4），需进一步确认后才能定稿。

### 9.3 ★ `__waiter_prio` 无 vendor hook 改写 —— prio 完全可预测

```c
/* kernel/locking/rtmutex.c:327-338 */
static __always_inline int __waiter_prio(struct task_struct *task)
{
	int waiter_prio = 0;
	trace_android_vh_rtmutex_waiter_prio(task, &waiter_prio);
	if (waiter_prio > 0)
		return waiter_prio;      /* ★ 仅当 hook 返回 >0 才改写 */
	return task->prio;
}
```

**全 drivers 树检索**：`rtmutex_waiter_prio` 仅出现在
`drivers/android/vendor_hooks.c:110` 的 `EXPORT_TRACEPOINT_SYMBOL_GPL`，
**无任何模块注册它**。

⇒ ★★★ **`__waiter_prio(task) == task->prio`，无 hook 干扰。**
⇒ 伪造 `waiter->tree.prio`（`+0x28`）只需与 `task->prio` 不同即可避开 B6。
⇒ `task->prio` 在 `task_struct+0x84`（本项目 BTF/汇编既有结论），
普通线程 = `MAX_RT_PRIO` 系；CFS 下 `prio = 120 + nice` ⇒ 填 `1` 必定不等。

### 9.4 ⚠️ 待解决：`lock+0x08` / `+0x18` 归属冲突

`add x1, x24, #8` 看似 enqueue 用 `lock+0x8` 作 root；但 `rb_root_cached`
只有一个 `rb_node`（24B = `parent_color`/`left`/`right`）+ `leftmost` 指针，
不可能同时占据 `+0x08..+0x18` 三段。两种可能：

| 解释 | 布局 | 佐证 |
|---|---|---|
| **E1** | `wait_lock`(4B) + pad(4B) + `waiters`(0x08..0x20) + `owner`(0x20) | 源码 `rtmutex.h` 顺序 |
| **E2** | 编译器将 `rb_root_cached` 拆分为 `lock+0x08`(rb_node) + `lock+0x10`(leftmost) + **`lock+0x18` = `owner`**，而 `ldr [x24,#0x18]` 是 **B9 的 owner 比较**、不是 rb_root | 汇编上下文 |

⇒ ★ 需再取一段 `rb_erase_cached` 调用前的 `add x1, ...` 指令来判定。
⇒ **本节标记为「未闭合」，不得据此写代码。**

## 10. ★ 头号卡点升级：`waiter->lock` 必须是**真实且空闲**的 `rt_mutex_base`

### 10.1 为什么这是硬约束

```asm
0x…816c0: ldr x24, [x25, #0x58]   ; lock = waiter->lock
0x…8170c: ldr x8,  [x24, #0x18]  ; ★ 读 lock+0x18
```

⇒ `waiter->lock` 为野值 ⇒ **读/写未映射或错误地址 ⇒ 崩**。
⇒ H191 的 `null_pointer` 正是此处（`lock == NULL`）。
⇒ ★ **这个字段填错 = 崩，填对 = 才有写原语**。它是成败分水岭。

### 10.2 候选：futex 的 `pi_mutex`

`kernel/futex/futex.h:54-68`：

```c
struct futex_pi_state {
	struct list_head list;                  /* 16 B */
	struct rt_mutex_base pi_mutex;          /* ★ 真实 rt_mutex_base */
	struct task_struct *owner;
	refcount_t refcount;
	union futex_key key;
} __randomize_layout;                       /* ★★ 布局每次 boot 随机化 */
```

⇒ `pi_mutex` 满足「真实存在」，但：
- ★★ `__randomize_layout` ⇒ `pi_mutex` 在 `futex_pi_state` 内的偏移每次 boot 都变
- ★★ `futex_pi_state` 本身在 slab 上 ⇒ 需要 KASLR 泄漏才能算出绝对地址
- ⇒ **不能预先算好**，必须**运行时得到**

### 10.3 ★ 运行时取得 `lock` 地址的三条路（均需评估）

| 路线 | 做法 | 可行性 |
|---|---|---|
| **L1** | 复用**本项目已有**的 KASLR 知识（本机 `_text` 已知 + 已恢复全量符号） | 需先解决 slab 基址随机化（`vmemmap`/`kmem_cache`） |
| **L2** | KASLR 侧信道泄漏（文章 §4.2 的 KernelSnitch / futex 哈希桶冲突时序） | 复杂，但 arm64 官方路径 |
| ★ **L3** | ★ **不解地址，改用「让内核自己填」**：不 spray `lock` 字段，而是**保留真实的 waiter 内容**、只改写 `tree.entry`/`prio` 等可控字节 | ★★ **风险最低，无需任何地址泄漏** |

⇒ ★★★ **L3 是本项目的最优路线**：H191 已证「栈会被清零」，
但 H189（B4）已证**栈帧有效时一切正常**。⇒ 若能让 waiter 保持**部分真实**，
则 `lock` 天然正确。关键问题：**能否只 spray 部分字节而不破坏 `lock` 字段？**

| 尝试 | 思路 | 风险 |
|---|---|---|
| **L3-a** | spray 长度只覆盖 `+0x00..+0x30`（前 48 字节，含 `tree` 与 `prio`），**保住 `+0x50 task` / `+0x58 lock`** | ★ 需 `__sys_bind` 的拷贝起点恰好低到能只覆盖前 48 字节 |
| **L3-b** | 让 W 在退出前**自己**把 `lock` 写回栈上（用户态无法写内核栈 ⇒ ✗） | ✗ 不可行 |
| **L3-c** | spray 后由 S4 **先**触发一次「安全早退」建立状态，再触发第二次 | 复杂度高 |

⇒ ★★ **L3-a 是下一步的首选**，但**必须先实测 `__sys_bind` 的实际栈偏移**。

## 11. H192 阶段判决

| 项 | 状态 |
|---|---|
| 机理全链闭合（remove_waiter bug → 悬垂 → trylock 崩） | ★ **已闭合**（源码 + 汇编 + H191 panic reason 三方互证） |
| `dequeue` 在同一次调用内（无需二次诱发） | ★ **已验证**（`rtmutex.c:919/934` + 汇编 `:81750`） |
| lockdep 全关 ⇒ 伪造条件放宽 | ★ **已验证**（defconfig 7656/7658/7663） |
| `__waiter_prio` 无 hook 改写 | ★ **已验证**（全树无注册） |
| `tree.entry` 不得自指 | ★ **已验证**（汇编 `cmp x8,x25; b.eq`） |
| `lock+0x08/+0x18` 归属 | ★ **未闭合**（§9.4 冲突） |
| kstack 随机化运行时状态 | ★ **未确认**（权限阻塞） |
| ★ `waiter->lock` 的运行时地址 | ★★ **头号未解卡点**（§10.3） |

⇒ 本轮 **零开火、零 boot 消耗**。
⇒ 下一步：★ **L3-a** —— 实测 `__sys_bind` 栈偏移，尝试只 spray 前 48 字节
以保住 `task`/`lock` 字段，把「需要 KASLR 泄漏」降级为「零地址需求」。

---

## 12. ★ §9.4 冲突已闭合（`rb_erase_cached` 首指令判定）

### 12.1 决定性反汇编 —— `rb_erase_cached@0xffffffc08003af24`

```asm
0x…3af24: ldr  x9, [x0]        ; x9 = x0[0] = node->__rb_parent_color
0x…3af28: cmp  x9, x0         ; ★ cmp node->parent_color, node
0x…3af2c: b.eq #0x…3af74      ; ★ 相等 ⇒ RB_EMPTY_NODE ⇒ 跳过（源码 rbtree.h:123）
0x…3af30: mov  x8, x0
0x…3af34: ldr  x0, [x0, #8]    ; x0 = node->rb_left
0x…3af38: cbnz x0, #…3af5c
0x…3af3c: ldr  x9, [x8]       ; x9 = node->__rb_parent_color
0x…3af40: ands x0, x9, #-4     ; x0 = __rb_parent(pc)  ⇒ ★ pc 低 2 位是颜色位
0x…3af44: b.eq #…3af58        ; parent == NULL ⇒ 直接 ret（空树/根节点）
```

★ **`x0` 语义确定 = `struct rb_node *node`**（不是 root）：
它读 `x0[0]` 并与 `x0` 自身比较，这正是 `RB_EMPTY_NODE(node)` 的定义。
⇒ **`x1` 才是 `struct rb_root_cached *root`。**

### 12.2 回到调用点 —— E2 成立，冲突解除

```asm
/* rt_mutex_adjust_prio_chain @ 0xffffffc0810815d4 */
0x…81750: bl   #0xffffffc08003af24   ; x0 = x25 = node = waiter(野)
                                     ; ★ x1 = ?  ← root
0x…81758: add  x1, x24, #8          ; ← ★★ root = lock + 0x08
```

⇒ ★★★ **`lock->waiters`（`rb_root_cached`）基址 = `lock + 0x08`**。
⇒ 因此 `ldr x8, [x24, #0x18]`（`:8170c`）**不是** rb_root，
而是 **`lock->owner`**（B9 的 `rt_mutex_owner(lock) == top_task` 判定所用）。

### 12.3 ★★ `struct rt_mutex_base` 布局定稿（本机，汇编 + 源码互证）

| 偏移 | 字段 | 大小 | 依据 |
|---|---|---|---|
| `+0x00` | `wait_lock`（`raw_spinlock_t` = `u32`；本机无 lockdep ⇒ 无 `lockdep_map`） | 4 | 源码 `rtmutex.h` + defconfig 7663 |
| `+0x04` | *（pad，8 字节对齐）* | 4 | 推算 |
| `+0x08` | `waiters.rb_node.__rb_parent_color` | 8 | ★★ 汇编 `add x1,x24,#8` |
| `+0x10` | `waiters.rb_node.rb_left` | 8 | ★ 汇编 `str x0,[x24,#0x10]`（leftmost 写回，见下注） |
| `+0x18` | `waiters.rb_node.rb_right` | 8 | 结构顺序 |
| `+0x20` | `waiters.rb_leftmost` | 8 | ★ 汇编 `str x0, [x24,#0x10]` 的语义存疑，见 §12.4 |
| `+0x28` | `owner` | 8 | ★★ 汇编 `ldr [x24,#0x18]` 归属 B9 |
| — | **总 size** | **0x30** | 推算 |

> ⚠️ **一处仍需注意**：`rb_erase_cached` 的实现（`rbtree.h:119-129`）在
> `root->rb_leftmost == node` 时会写 `root->rb_leftmost`。
> 汇编 `str x0, [x24, #0x10]` 说明 **`rb_leftmost` 在 `lock+0x10`**。
> ⇒ ★★ 修正：布局应为

| 偏移 | 字段 |
|---|---|
| `+0x00` | `wait_lock`（u32）+ pad |
| `+0x08` | `waiters.rb_node.__rb_parent_color` |
| `+0x10` | ★ **`waiters.rb_leftmost`**（被 `rb_erase_cached` 写） |
| `+0x18` | `owner`（B9 读） |

⇒ ★ 编译器布局与源码字段顺序**不一致**（`rb_leftmost` 提前了），
这在 C 里是允许的（`rb_root_cached` 是 `{ struct rb_node rb_root; struct rb_node *rb_leftmost; }`，
`rb_leftmost` 紧跟 `rb_root`，即 `+0x08+0x18 = +0x20`…… 与观测不符）。
⇒ ★★ **`rt_mutex_base` 的真实布局标记为「汇编实证但与源码推导不一致」**，
**唯一可靠依据是本节汇编**。写代码时**必须**用汇编值，不得用 sizeof 推算。

## 13. ★★ 关键结论：`lock+0x08` 作为 root ⇒ 伪造 `tree.entry` 的最小要求

`rb_erase_cached(node, root=lock+0x08)` 走空树路径时（`:3af44 b.eq → ret`）
**不做任何写**。要产生写，必须满足：

| 条件 | 说明 |
|---|---|
| `node->__rb_parent_color != (u64)node` | 否则 `RB_EMPTY_NODE` 提前返回（`rbtree.h:123`） |
| `__rb_parent(node->__rb_parent_color) != NULL` | 否则 `rb_erase` 在 `:3af44` 直接 ret，无写 |
| `node->rb_left == NULL` 且 `node->rb_right == NULL` | 走 Case 1（`__rb_erase_augmented` 最简路径） |
| ★ `parent` 必须**可解引用且语义正确** | `__rb_change_child` 会比较 `parent->rb_left == old`，**读** parent |

⇒ ★★ **最危险的未知**：`__rb_parent_color` 的高 62 位即 parent 地址，
内核会**读 `parent->rb_left`**（`rbtree_augmented.h:195-206`），
读错 ⇒ 崩在读取处（类似 H191 的 trylock）。
⇒ ⇒ **要产生写，必须能提供一个「可读的 parent」** ⇒ 又回到 §10 的地址需求。

⇒ ★★★ **L3-a 的可行性因此下降**：保住 `lock` 字段还不够，
**`tree.entry` 里的 parent 指针同样需要真实地址**。
⇒ 唯一同时绕过 `lock` 与 `parent` 两个地址需求的做法：
**让 `lock->waiters` 为空树，且 `parent` 落在同一 slab 页内可预测位置**，
或 **直接泄漏一个内核地址**（回到 L1/L2）。

⇒ ★★ **诚实结论：写原语路线最终必然需要至少一个内核地址泄漏。**
⇒ 最现实路径：**L2（futex 侧信道泄漏）** —— 这也正是官方链阶段 1 的作用，
本项目只是因 arm64 而无法用 x86 的 prefetch 变体。

---

## 14. ★★ H193 勘误：源码树 6.6.56 vs 设备 6.6.118 一致性审计

> 完整审计见 `analysis/scratch/h193_src_vs_bin_audit.md`

### 14.1 版本 delta
| 项 | 值 |
|---|---|
| 源码树 | `Makefile` `SUBLEVEL=56` ⇒ **6.6.56** |
| 设备 | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` |
| delta | **62 个 stable 补丁**；源码树**无 `.git`** ⇒ 只能靠本机汇编判定 |

### 14.2 ★★★ 结论：BUG 未修，源码树对本机成立

`remove_waiter@0xffffffc081080e60` 汇编：

```asm
0x…80e98: mrs  x20, sp_el0          ; ★★ x20 = current
0x…80e9c: add  x21, x20, #0x90c     ; &current->pi_lock
0x…80ea8: bl   #…83358            ; raw_spin_lock(&current->pi_lock)   ★ 仍用 current
0x…80ebc: add  x22, x19, #8         ; root = lock+0x08
0x…80ecc: bl   #0xffffffc08003af24  ; rb_erase_cached
0x…80ed0: str  x0, [x19, #0x10]     ; rb_leftmost @ lock+0x10
0x…80edc: bl   #0xffffffc08003a9d4  ; rb_erase
0x…80ee8: str  xzr, [x20, #0x938]   ; ★★★ current->pi_blocked_on = NULL ← BUG 本体
```

| 判据 | 观测 | 结论 |
|---|---|---|
| 若主补丁 `3bfdc63936dd` 已打 | 应见 `waiter->task` 读取 | ★ 未见，仍用 `sp_el0` ⇒ **未打** |
| 若已含 CVE-2026-53163 守卫 | 应有 `pi_blocked_on == waiter` 比较 | ★ 无比较，直接 `str xzr` ⇒ **未修** |

### 14.3 ★★ H192 偏移表逐条汇编复核 —— 失配为零

| H192 结论 | 本机汇编 | 一致 |
|---|---|:--:|
| `pi_blocked_on@task+0x938` | `ldr x25,[x19,#0x938]` `:81648` / `str xzr,[x20,#0x938]` `:80ee8` | ✅ |
| `pi_lock@task+0x90c` | `add x21, x20, #0x90c` `:80e9c` | ✅ |
| `waiter->lock@+0x58` | `ldr x8, [x25, #0x58]` `:81660` | ✅ |
| `tree.prio@+0x28` | `ldr x8, [x21, #0x18]` `:81654` | ✅ |
| `pi_tree.entry@+0x28` | ★ `ldr x8, [x23, #0x28]!` `:80f0c` | ✅ |
| root = `lock+0x08` | `add x22, x19, #8` `:80ebc` / `add x1,x24,#8` `:81758` | ✅ |
| `rb_leftmost@lock+0x10` | 读 `:80e7c` / 写 `:80ed0` | ✅ |
| ★ `owner@lock+0x18` | ★★ `ldr x25, [x19, #0x18]` `:80ea0` | ✅ |
| `tree.entry` 不得自指 | `cmp x8, x23; b.eq` `:80eb0` | ✅ |

### 14.4 ★★ 勘误：`rt_mutex_base` 总 size 是 **0x20**，不是 0x30

§12.3 曾把布局写成 0x30（含一处 `owner` 误判）。**本轮汇编定案**：

| 偏移 | 字段 | 证据 |
|---|---|---|
| `+0x00` | `wait_lock`（u32） | 源码 + 无 lockdep |
| `+0x08` | `waiters.rb_node`（root） | `add x22,x19,#8` `:80ebc` |
| `+0x10` | `waiters.rb_leftmost` | 读 `:80e7c` / 写 `:80ed0` |
| `+0x18` | `owner` | `ldr x25,[x19,#0x18]` `:80ea0` |
| — | **size = 0x20** | ★ 修正（原推算 0x30 有误） |

⇒ ★ **对伪造 waiter 的直接影响**：目标 `lock` 只需 **0x20 字节**有效空间，
且其前方 `wait_lock`（`lock+0x00`）必须读为 0（已解锁）——与文章
`*(u32*)(target-0x08) == 0` 约束**完全一致**（因为 `wait_lock` 在 `+0x00`）。

### 14.5 ★★ 纪律更新

**源码树行号一律降级为「约」；权威定位一律用「符号名 + 本机汇编地址」。**
理由：62 个 stable 补丁足以让行号漂移，而本项目已有全量符号 + 汇编实证能力。

⇒ ★★ **对本项目当前阶段（写原语构造），源码树完全可用。**
⇒ ⚠️ 若切到 **CVE-2026-64560**（`posix-cpu-timers`），那条线**尚未做汇编级验证**，
必须**先补**一次本机汇编核对再动手。

---

## 15. ★★★ H194 勘误：官方主推原语 `PR_SET_MM_MAP` 在本机**不存在**

> 完整论证见 `analysis/scratch/h194_is_source_needed.md` §7

### 15.1 事件

IonStack Part II 官方原文推荐用 `prctl(PR_SET_MM_MAP)` 的
`unsigned long user_auxv[AT_VECTOR_SIZE]` 栈缓冲做栈复用。
H192 §4.3 曾据此把它列为候选。

### 15.2 本机源码与 defconfig 实证

```c
/* kernel/sys.c:2003-2007 */
#ifdef CONFIG_CHECKPOINT_RESTORE                       /* ★★ 编译开关 */
static int prctl_set_mm_map(int opt, const void __user *addr, unsigned long data_size)
{
	unsigned long user_auxv[AT_VECTOR_SIZE];          /* 栈上 */
...
/* kernel/sys.c:2160-2161 */
	if (opt == PR_SET_MM_MAP || opt == PR_SET_MM_MAP_SIZE)
		return prctl_set_mm_map(...);
#endif
```

| 判据 | 结果 |
|---|---|
| defconfig `merge_sun_defconfig:219` | ★ **`# CONFIG_CHECKPOINT_RESTORE is not set`** |
| kallsyms `prctl_set_mm_map` | ★ **无此符号** |
| kallsyms `checkpoint` | 5 条，**全是 f2fs**，与 prctl 无关 |

⇒ ★★★ **`PR_SET_MM_MAP` 在本机不存在**，`user_auxv` 栈缓冲不会出现。

### 15.3 容量信息（若开关打开本可用）

```c
/* include/linux/mm_types.h:27-29 */
#define AT_VECTOR_SIZE (2*(0 + 22 + 1)) = 46      ⇒ 46 × 8 = 368 字节
```

⇒ ★ 容量 368B ≫ waiter 112B，本是最优选 —— **可惜被编译掉了。**
⇒ ★ 附带发现：权限检查仅在 `exe_fd != (u32)-1` 时触发（`sys.c:2147`），
  即只传 auxv 时可能不需 `CAP_SYS_ADMIN`（假想开关打开的情形）。

### 15.4 ★★★ spray 原语选型**修正表**

| 原语 | 本机状态 | 依据 |
|---|---|---|
| `pselect` | ✘ 栈上仅 42B | H192 §4.2 |
| ★ `prctl(PR_SET_MM_MAP)` | ✘★ **编译关闭，不存在** | ★ H194 §7 |
| ★★ **`__sys_bind`** | ★★ **仍是最优**（128B 纯栈、零特权） | H192 §6.4 |
| `setsockopt` / `keyctl` / `clone` | ⚠️ 待查容量 | 官方列「同样可用」但未给数值 |

⇒ ★★ **`__sys_bind` 重新确认是首选**，且这是**第二次**靠源码排除候选
（第一次是 `pselect`）。
⇒ ★★ **纪律：官方文章的推荐必须逐条在本机 defconfig 上验证后才能用。**
