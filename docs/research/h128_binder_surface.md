# H128–H137 · binder / binderfs 攻击面测绘报告

> 设备：MEY-AN00 · MagicOS 10.0.0.175 · A16 · SM8735 · 内核 `6.6.118-android15-8`（4K 页）
> shell 域 `uid=2000(shell)` · `context=u:r:shell:s0` · `getenforce=Enforcing`
> `boot_id = 2888f136-4ff1-487b-8d4c-58e02e1897e0`（**全程未变，10 轮探针零 panic**）
> 触发：用户选「深挖 B. binder/binderfs」（SROP 判死后唯一未投入且 shell 域 RDWR 可达的标准 IPC 面）

---

## 零、结论（一句话）

**binder 面对 shell 域开放了「驱动命令协议」的绝大部分写侧命令，路径可实测触达 `binder_alloc` 的红黑树（`allocated_buffers`/`free_buffers`）查找与遍历；但所有能真正驱动 `rb_erase`（数据变更）的命令都被上游/厂商的**前置条件**卡死：**

| 关键能力 | 状态 |
|---|---|
| `BC_ENTER_LOOPER` / `REGISTER` / `EXIT` | ✅ 可达（SUCCESS） |
| **`BC_FREE_BUFFER`（→ `binder_alloc_prepare_to_free` 红黑树查找）** | ✅ **可达（SUCCESS, wc=12）** |
| `BC_INCREFS` / `ACQUIRE` / `RELEASE` / `DECREFS` | ✅ 可达 |
| 死亡通知类（`REQUEST/CLEAR_DEATH_NOTIFICATION`, `DEAD_BINDER_DONE`） | ✅ 可达 |
| freeze 通知类（`REQUEST/CLEAR_FREEZE_NOTIFICATION`） | ✅ 可达 |
| `BINDER_SET_MAX_THREADS` | ✅ 可达 |
| `BINDER_VERSION` | ✅ 可达（protocol=8） |
| `BINDER_GET_EXTENDED_ERROR` | ✅ 可达 |
| `BINDER_ENABLE_ONEWAY_SPAM_DETECTION` | ✅ 可达 |
| **`BC_TRANSACTION` / `BC_REPLY`（唯一能「分配 buffer」从而让 `rb_erase` 有对象可删）** | ❌ **EINVAL**（无合法 handle / 无 pending transaction） |
| `BINDER_SET_CONTEXT_MGR` | ❌ `/dev/binder`=`EBUSY(16)`（system_server 已占）｜`/dev/hwbinder`=`EACCES(13)`｜`/dev/vndbinder`=open `EACCES(13)` |
| `mmap` binder 缓冲区 | ⚠️ **只读可映射（PROT_READ OK），带 `VM_WRITE` 恒 `EPERM(1)`**；映射后**全页 SIGBUS**（无物理页） |
| `BINDER_FREEZE` / `GET_FROZEN_INFO` / `GET_NODE_DEBUG_INFO` | ❌ `EACCES(13)` / `EINVAL` |
| `/dev/binderfs` 目录操作（`mkdir`/`BINDER_CTL_ADD`/`binder-control`） | ❌ `EACCES(13)`（SELinux 域） |
| 荣耀新增 procfs（`binder_logs/*`, `honor_binder_logs/*`） | ❌ 挂在 binderfs 内，shell 域不可达 |

**⇒ 关键结论：能触达红黑树遍历，但无法触达红黑树的【变更】路径。判死依据见 §五。**

---

## 一、攻击面测绘（H128/H129/H137）

### 1.1 节点与挂载

```
/dev/binder    -> /dev/binderfs/binder    crw-rw-rw-  u:object_r:binder_device:s0   507,1
/dev/hwbinder  -> /dev/binderfs/hwbinder  (同上结构)  u:object_r:hwbinder_device:s0
/dev/vndbinder -> /dev/binderfs/vndbinder (同上结构)  u:object_r:vndbinder_device:s0
/dev/binderfs  drwxr-xr-x root root        u:object_r:binderfs:s0
挂载: binder /dev/binderfs binder rw,relatime,max=1048576,stats=global
```

### 1.2 shell 域可达性（H128/H137 实测 `open()` errno）

| 节点 | open 结果 |
|---|---|
| `/dev/binder` | ✅ OK |
| `/dev/binderfs/binder` | ✅ OK |
| `/dev/vndbinder` | ❌ `EACCES(13)` |
| `/dev/hwbinder` | ✅ open OK（但 `SET_CONTEXT_MGR` = `EACCES(13)`） |
| `/dev/binderfs`（目录） | ❌ `EACCES(13)` |

---

## 二、ioctl 命令可达性（H128/H129/H137 真机）

| ioctl | 结果 | 说明 |
|---|---|---|
| `BINDER_VERSION` | ✅ ret=0 `protocol=8` | 协议版本 8（上游标准） |
| `BINDER_SET_MAX_THREADS` | ✅ ret=0（0/4/1000 全 SUCCESS） | **无上限检查**（上游一致） |
| `BINDER_SET_CONTEXT_MGR` | ❌ `EBUSY(16)` / `EACCES(13)` | 已占用 / 域策略拒 |
| `BINDER_SET_CONTEXT_MGR_EXT` | ❌ `EBUSY(16)` | 同上 |
| `BINDER_THREAD_EXIT` | ✅ ret=0 | — |
| `BINDER_GET_EXTENDED_ERROR` | ✅ ret=0 | — |
| `BINDER_ENABLE_ONEWAY_SPAM_DETECTION` | ✅ ret=0 | — |
| `BINDER_GET_NODE_DEBUG_INFO` | ❌ `EINVAL(22)` | 参数不合法（ptr=0x1000） |
| `BINDER_GET_FROZEN_INFO` | ❌ `EACCES(13)` | 域策略拒 |
| `BINDER_FREEZE` | ❌ `EACCES(13)` | 域策略拒 |
| `BINDER_SET_IDLE_TIMEOUT` | ❌ `EINVAL(22)` | — |
| 未知 ioctl（`0xdeadbeef` / `_IOWR('b',99)`） | ❌ `EACCES(13)` | **★ 与合法命令的 error 不同 ⇒ 有域策略过滤层** |

**★ 关键**：未知 ioctl 返回 `EACCES(13)` 而非上游的 `ENOTTY(25)` ⇒ **SELinux/厂商在 ioctl 分发前有统一拦截层**（与 H121 cdev 面的「全量 fallback」同类现象）。

---

## 三、★★★ BC 命令协议（真值修正 —— 本轮最重要的方法论突破）

### 3.1 教训：BC 值必须从 enum 精确计算，不能凭记忆

**第一轮（H134/H135）全部误判**：我用了 `BC_ENTER_LOOPER=0x630c` 这类「剥离 `_IOC` 头」的值，导致：
- `BC_ENTER_LOOPER` **侥幸正确**（`_IO` 无方向位/无 size ⇒ 就是 `0x630c`）
- `BC_INCREFS/ACQUIRE/RELEASE/FREE_BUFFER/TRANSACTION` **全部错误** ⇒ 走 `default: return -EINVAL` ⇒ 我误判为「权限拒绝」

**根因**（`include/uapi/linux/android/binder.h:535`）：
```c
enum binder_driver_command_protocol {
    BC_TRANSACTION = _IOW('c', 0, struct binder_transaction_data),   /* 有方向+size! */
    ...
    BC_ENTER_LOOPER = _IO('c', 12),                                   /* 裸值 */
```

**真值表**（`_IOC(dir,0x63,nr,size)`，Python 精确计算）：

| BC 命令 | 真值 | 我的错误值 |
|---|---|---|
| `BC_TRANSACTION` | **`0x40286300`** | `0x6300` ✗ |
| `BC_REPLY` | `0x40286301` | `0x6301` ✗ |
| `BC_FREE_BUFFER` | **`0x40086303`** | `0x6304` ✗ |
| `BC_INCREFS` | **`0x40046304`** | `0x6308` ✗ |
| `BC_ACQUIRE` | `0x40046305` | `0x6309` ✗ |
| `BC_RELEASE` | `0x40046306` | `0x630a` ✗ |
| `BC_DECREFS` | `0x40046307` | — |
| `BC_ENTER_LOOPER` | `0x0000630c` ✓ | `0x630c` ✓ |
| `BC_REGISTER_LOOPER` | `0x0000630b` ✓ | — |
| `BC_EXIT_LOOPER` | `0x0000630d` ✓ | — |
| `BC_REQUEST_DEATH_NOTIFICATION` | `0x400c630e` | — |
| `BC_CLEAR_DEATH_NOTIFICATION` | `0x400c630f` | — |
| `BC_DEAD_BINDER_DONE` | `0x40086310` | — |
| `BC_TRANSACTION_SG` | `0x40306311` | — |
| `BC_REPLY_SG` | `0x40306312` | — |
| `BC_REQUEST_FREEZE_NOTIFICATION` | `0x400c6313` | — |
| `BC_CLEAR_FREEZE_NOTIFICATION` | `0x400c6314` | — |
| `BC_FREEZE_NOTIFICATION_DONE` | `0x40086315` | — |

### 3.2 ★ 真机结果（H136，正确真值）

| BC 命令 | ret | errno | write_consumed |
|---|---|---|---|
| `BC_ENTER_LOOPER` | 0 | 0 | 4 ✅ |
| `BC_REGISTER_LOOPER` | 0 | 0 | 4 ✅ |
| `BC_EXIT_LOOPER` | 0 | 0 | 4 ✅ |
| **`BC_FREE_BUFFER(任何值)`** | **0** | **0** | **12 ✅** |
| `BC_INCREFS(0/1)` | 0 | 0 | 8 ✅ |
| `BC_ACQUIRE(1)` | 0 | 0 | 8 ✅ |
| `BC_RELEASE(1)` | 0 | 0 | 8 ✅ |
| `BC_DECREFS(1)` | 0 | 0 | 8 ✅ |
| `BC_REQUEST_DEATH_NOTIF(h0)` | 0 | 0 | 16 ✅ |
| `BC_CLEAR_DEATH_NOTIF(h0)` | 0 | 0 | 16 ✅ |
| `BC_DEAD_BINDER_DONE` | 0 | 0 | 12 ✅ |
| `BC_REQUEST_FREEZE_NOTIF(h0)` | 0 | 0 | 16 ✅ |
| `BC_CLEAR_FREEZE_NOTIF(h0)` | 0 | 0 | 16 ✅ |
| **`BC_TRANSACTION(h0)`** | **-1** | **22 (EINVAL)** | **0 ❌** |
| `BC_REPLY`（无 pending） | -1 | 22 | 0 ❌ |
| `BC_FREEZE_NOTIF_DONE`（无 pending） | -1 | 22 | 0 ❌ |
| 未知 BC（`0x631f` / `0x1234`） | -1 | 22 | 0（对照锚点） |

**★ 判据锚点**：未知命令 = `EINVAL` + `wc=0`；`BC_FREE_BUFFER` = `SUCCESS` + `wc=12` ⇒ **两者语义清晰分离，判据可靠**。

---

## 四、mmap 缓冲区测绘（H129/H130/H132/H133）

### 4.1 flag 矩阵（H130 实测，8 组合各独立进程）

| prot | `MAP_SHARED` | `MAP_PRIVATE` | `MAP_SHARED\|NORESERVE` | `MAP_PRIVATE\|NORESERVE` |
|---|---|---|---|---|
| `PROT_READ` | ✅ OK | ✅ OK | ✅ OK | ✅ OK |
| `PROT_READ\|PROT_WRITE` | ❌ `EPERM(1)` | ❌ `EPERM(1)` | ❌ `EPERM(1)` | ❌ `EPERM(1)` |

**⇒ 由 `prot` 决定，与 `flags` 无关。**

### 4.2 源码 + 汇编双证（根因）

**源码**（`binder.c:125`）：
```c
#define FORBIDDEN_MMAP_FLAGS (VM_WRITE)
```

**设备镜像汇编**（`binder_mmap` @ `0xffffffc0802c00d8`）：
```
0x2c013c  ldr   x8, [x19, #0x20]      ; x8 = vma->vm_flags
0x2c0140  tbnz  w8, #1, 0x2c01c4      ; ★ bit1 = VM_WRITE ⇒ 跳 EPERM 分支
...
0x2c01c4  ...  mov w19, #-1           ; ret = -EPERM
0x2c0170  and   x8, x8, #~0x20        ; vm_flags_mod: 清 VM_MAYWRITE
0x2c0180  orr   x8, x8, #0x10020000   ; 设 VM_DONTCOPY | VM_MIXEDMAP
```

**⇒ 逐条对上源码。这是上游 binder 标准行为（非厂商插卡），任何 uid 都一样。**

### 4.3 只读映射后的内容（H132/H133 实测）

| 项 | 结果 |
|---|---|
| `mmap(PROT_READ)` 1 页 | ✅ 成功 |
| 读 offset 0 | **SIGBUS**（`si_addr` = 映射基址，`si_addr - base = 0`） |
| 页粒度扫描 | **全部 SIGBUS** |
| VMA 权限 | `r--p` |
| `boot_id` | **未变**（用户进程收 SIGBUS，内核完好） |

**⇒ binder 用 `VM_MIXEDMAP` + `vm_fault` 按需供页；未分配 buffer 的区域无物理页 ⇒ 读即 SIGBUS。无信息泄露价值。**

---

## 五、判死依据（B1–B10）

| 编号 | 判死对象 | 依据 |
|---|---|---|
| **B1** | `BC_TRANSACTION` 分配 buffer 路径 | `EINVAL` + `wc=0`；需要合法 handle，而 shell 域拿不到任何 handle（context mgr 被 system_server 占，`SELinux` 拒 binderfs 目录） |
| **B2** | `BC_FREE_BUFFER` 触发 `rb_erase` | 命令可达（`wc=12`），但**必须先有成功分配过的 buffer**（`allow_user_free=1` 只在 `binder_thread_read` 投递 `BR_TRANSACTION` 时置位，binder.c:5390）。无分配 ⇒ 红黑树查找恒空 ⇒ `break`，`rb_erase` 不可达 |
| **B3** | `BINDER_SET_CONTEXT_MGR` 抢占 | `/dev/binder`=`EBUSY`（已占）；`/dev/hwbinder`=`EACCES`（域拒）；无第 4 个 binder 节点 |
| **B4** | binderfs 目录创建控制节点 | `mkdir`/`open(O_DIRECTORY)`/`binder-control` 全 `EACCES(13)`（`binderfs:s0` 域策略） |
| **B5** | 荣耀新增 procfs（`binder_logs/*`, `honor_binder_logs/*`） | 挂在 binderfs 内 ⇒ 与 B4 同门；`/sys/kernel/debug` 未挂载 |
| **B6** | `mmap` 可写 | `FORBIDDEN_MMAP_FLAGS=VM_WRITE` 硬闸门（源码+汇编双证） |
| **B7** | 只读 mmap 泄露内核数据 | `VM_MIXEDMAP` + 按需供页 ⇒ 未分配区全 SIGBUS，VMA `r--p` |
| **B8** | `BC_INCREFS/ACQUIRE/RELEASE` 引用计数操纵 | 命令可达，但 handle 恒 `EINVAL`（`binder_get_ref_olocked` 找不到 ref）⇒ 无 ref 可操纵 |
| **B9** | 未知 ioctl 信息泄露 | 未知 ioctl 恒 `EACCES(13)`（统一拦截层）⇒ 无差异信道 |
| **B10** | freeze 类命令 | `BINDER_FREEZE`/`GET_FROZEN_INFO` = `EACCES`；`BC_REQUEST_FREEZE_NOTIF` 可达但需合法 handle |

---

## 六、★★ 厂商 delta 记账（重要）

源码树 `6.6.56` vs 设备 `6.6.118`（**62 个补丁版本差**），且荣耀有**私有 binder 改动**：

| 项 | 内容 |
|---|---|
| `CONFIG_HONOR_BINDER_TRANSACTION_BRIEF` | 新增；在 `binder.c`/`binder_alloc.c`/`binderfs.c`/`binder_alloc.h` 共 20+ 处 `#ifdef` |
| `struct hn_binder_transinfo` | `binder.c:279` 新增；挂 `t->android_oem_data1`（`kzalloc(sizeof(*t)+sizeof(hn_transinfo))`） |
| `binder_alloc_get_free_space()` | `binder_alloc.c:1316` 新增；遍历 `free_buffers` 红黑树求总空闲 |
| `honor_binder_transaction_proc_fops` | `binderfs.c` 新增 procfs 文件（`binder_logs/transaction_proc`、`honor_binder_logs/{transaction_proc,state}`） |
| `CONFIG_HONOR_BINDER_TRANSACTION_DESCRIPTOR` | 依赖上者，新增 descriptor 功能 |
| `trace_android_vh_binder_alloc_new_buf_locked` | 厂商 vendor hook，挂在 `binder_alloc_new_buf_locked` 入口（`&should_fail` 出参可被 vendor 置真 → 直接 `-EPERM`） |

**★ 注意**：`vendor/honor` 树中**搜不到**这些 hook 的实现 ⇒ **厂商 binder 改动的实现不在开源源码范围**，只能靠设备镜像反汇编验证。这是**未验证基线**，必须标注。

---

## 七、方法学副产品（跨设备可继承，5 条）

1. **★★★ `_IOC()` 编码必须精确计算**：`_IOW('c',4,__u32)` = `0x40046304`，**不是** `nr|(type<<8)`。凭记忆填值 ⇒ 全部命令走 `default: return -EINVAL`，**误判为「权限拒绝」**（本轮 H134/H135 因此浪费 2 轮）。
   - **判据分离**：真·权限拒 = `EACCES(13)`/`EPERM(1)`；协议错 = `EINVAL(22)` + `wc=0`。**必须同时看 ret/errno/write_consumed 三元组。**
2. **★ `write_consumed` 是命令「是否被处理」的独立透镜**：`wc=0` = 未被处理（协议层拒），`wc=4/8/12` = 已消费（业务层处理）。**比 errno 更可靠。**
3. **★ binder mmap 的 EPERM 不是权限**：`FORBIDDEN_MMAP_FLAGS=VM_WRITE` 是**协议设计**，任何 uid 都一样。遇到 binder mmap `EPERM` 不要当权限问题。
4. **binder 映射区读 = SIGBUS 是正常设计**：`VM_MIXEDMAP` + 按需供页。**「读不到」不等于「有洞」。**
5. **阻塞读必须 alarm 兜底**：`BC_ENTER_LOOPER` 后带 `read_size>0` 会**永久阻塞**（等事务）。H134 因此被工具 SIGTERM 打断（`boot_id` 未变，无残留）。

---

## 八、产物清单

| 文件 | 内容 |
|---|---|
| `tools/h128_binder_probe.c` | ioctl 全命令 + mmap 初测 |
| `tools/h129_binder_mmap_bfs.c` | mmap 单进程 + binderfs 管理面 |
| `tools/h130_binder_mmap_matrix.c` | mmap prot×flags 矩阵 |
| `tools/h131_binder_asm.py` | 设备镜像 binder 函数反汇编器 |
| `tools/h132_binder_ro_read.c` | 只读映射内容测绘 |
| `tools/h133_binder_fault_probe.c` | SIGBUS 精确触发点 |
| `tools/h134_binder_looper_probe.c` | 写侧命令（错误值，存档） |
| `tools/h135_binder_bc_reach.c` | BC 可达性（错误值，存档） |
| `tools/h136_binder_bc_real.c` | **BC 命令真值重测（决定性）** |
| `tools/h137_binder_selfloop.c` | 自环流程 + context mgr + 真值 transaction |

---

## 九、剩余未穷尽面（更新）

| 面 | 状态 |
|---|---|
| **B. binder / binderfs** | ⚠️ **本轮测穿命令层与 mmap 层 ⇒ 判死 B1–B10**；**唯一残余**：若未来能拿到**任意一个合法 handle**（需要另一个进程协助或域提升），B2 会被激活 —— 但那是**循环依赖**（需先提权） |
| D. `dma_heap/system`（RDONLY 可达） | ⚠️ 未测（`DMA_HEAP_IOCTL_ALLOC` 需 RDWR） |
| **E. L1(`rb_erase`) / L2(`rt_mutex`) 存档原语** | ⚠️ 冻结中 —— **唯一已构造出「任意写」几何的线** |
| F. SROP / 信号域 | ❌ 判死（H111/H113–H120） |
| G. 非 pstate 控制流落点 | ❌ 判死（H115 全树零命中） |
| A. 厂商 cdev ioctl | ❌ 判死（H121–H127） |
