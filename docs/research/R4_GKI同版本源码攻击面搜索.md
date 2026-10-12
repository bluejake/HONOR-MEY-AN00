# R4 GKI 同版本源码攻击面搜索

> 对象：`refs/google_kernel_GKI-6.6.118-android15.8/`
> 模式：纯案头静态检索

## 结论先行

| # | 结论 |
|---|---|
| 1 | **该树未通过版本校验 ⇒ 本报告未产出任何可用于设备结论的漏洞候选** |
| 2 | 检索陷阱已确认：工作树未 checkout（`git status` 全 `D`），`git grep <pat>`（不带 `HEAD`）**静默返回空且不报错** |
| 3 | ★ **版本自相矛盾**：Makefile 声明 6.6.118，但代码是 folio 化的 shmem（6.9+），真实基线 **≥6.10**（很可能 6.12/6.13） |
| 4 | 来源不可信：第三方个人账号（`Kernels-by-ravindu644`）、**单 commit**、经 `ghfast.top` 镜像（非 android.googlesource.com） |
| 5 | **唯一有正面价值的旁证**：`mm/shmem.c` 中完全不存在 `write_protect` / `pte_marker` / `vmf_insert_pte`，`fs/userfaultfd.c` 只做编译期掩码 ⇒ 若设备侧同样缺 shmem 上的 `PTE_MARKER_UFFD_WP` 处理，则 **uffd write-protect 在 shmem/memfd 上不成立** |
| 6 | 权限门控：`sysctl_perf_event_paranoid=2` ⇒ uid=2000 无 CAP_PERFMON 时被拒；`sysctl_unprivileged_userfaultfd` 默认 0 ⇒ uid=2000 默认被拒；`io_uring` 通常可达 |

---

## 一、版本自相矛盾的证据

### 声明 vs 实际

| 项 | 值 |
|---|---|
| 目录名 | `google_kernel_GKI-6.6.118-android15.8` |
| Makefile | `VERSION=6 PATCHLEVEL=6 SUBLEVEL=118` |
| 真实基线 | **≥6.10**（很可能 6.12/6.13） |

### 指纹（6.9+/6.10+ 特征，却出现在自称 6.6.118 的树里）

| 指纹 | 命中 | 说明 |
|---|---|---|
| `shmem_get_folio`（6.9+） | **17 处** | 应为 `shmem_getpage`（6.6） |
| `mnt_idmap`（6.8+） | `fs/namei.c` **73 处** | — |
| `shmem_mfill_atomic_pte`（6.10+） | 存在 | — |
| `ipc/msgutil.c` 用 `load_msg`/`store_msg` | 存在 | 6.13 前后 |
| `IORING_OP_SENDMSG_ZC`（6.10+） | 存在 | — |
| `MAPLE_TREE` | **全树缺失**，但 `CONFIG_DEBUG_MAPLE_TREE` 选项被引用 | 自相矛盾 |

### 来源

- 第三方个人账号 `Kernels-by-ravindu644`
- **单 commit**
- 经 `ghfast.top` 镜像（非官方 `android.googlesource.com`）

> ⇒ **第三方单 commit 伪装成 6.6.118 的较新内核树，不可作为设备结论的依据。**

---

## 二、★ 正确的裁决方法（比结论本身更重要）

**★ 用 blob 哈希比对，而不是版本特征法。**

R8 独立验证发现：版本特征法**在 Android GKI 上不可用**，因为 GKI 把 6.9/6.10 特性**回移**进了 6.6。正确方法是与官方树逐字节比对：

```
refs/kernel_nothing_sm8735/ (6.6.127)
  vs
analysis/src_refs/code-linaro-full/ (CodeLinaro 官方 6.6.139)

include/linux/fs.h          6065d6d85e18  ≡  6065d6d85e18   IDENTICAL
mm/shmem.c                  d2d08ee11ccb  ≡  d2d08ee11ccb   IDENTICAL
kernel/futex/core.c         0a1745d76c25  ≡  0a1745d76c25   IDENTICAL
include/linux/maple_tree.h  a452dd8a1e5c  ≡  a452dd8a1e5c   IDENTICAL
kernel/locking/rtmutex.c    10521605e30e  ≠  6d4942bcec7d   DIFF ★
```

⇒ 同一组「6.9+ 特征」在两棵**可信**树上同时出现 ⇒ **特征不能区分版本，只能用 blob 哈希**。
⇒ 这也解释了 `google_kernel_GKI-6.6.118` 为何是伪装树：**应当用同一方法（与官方 6.6.139 比 blob）复验**。

**该裁决已让 `kernel_nothing_sm8735` 成为可信的 6.6 偏移仲裁器，并直接产出 R9 的决定级发现（见 `R9_remove_waiter补丁状态裁决.md`）。**

---

## 三、检索陷阱（已确认）

| 陷阱 | 表现 | 正确做法 |
|---|---|---|
| 工作树未 checkout | `git status` 全是 `D` | `git show HEAD:<path>` 读文件 |
| `git grep` 不带 `HEAD` | **静默返回空且不报错** | `git grep <pat> HEAD -- <path>` |

⇒ 后果：**任何用「不确定符号名」得到的 0 命中都不可直接采信。**

### 本轮自我证伪记录（两处）

| 我一度判定 | 实际 |
|---|---|
| `ipc/msgqueue.c` 不存在 | 实际文件名是 `ipc/mqueue.c` |
| `do_mq_sendmsg` / `do_msgxfer` 缺失 | 实际 `do_mq_timedsend` 有 3 处命中 |

⇒ **凡是用「不确定符号名」得到的 0 命中，都必须先用阳性对照复验。**

---

## 四、权限门控

| 机制 | 门控 | 对 uid=2000 的后果 |
|---|---|---|
| perf_event | `sysctl_perf_event_paranoid=2` | 无 CAP_PERFMON 时被拒 |
| userfaultfd | `sysctl_unprivileged_userfaultfd` 默认 0 | **默认被拒** |
| `uffd write-protect`（PTE_MARKER_UFFD_WP） | `mm/shmem.c` 中**完全不存在** `write_protect`/`pte_marker`/`vmf_insert_pte`；`fs/userfaultfd.c` 只做编译期掩码 | 若设备侧同样缺 shmem 上的处理 ⇒ **该原语在 shmem/memfd 上不成立** |
| io_uring | 通常可达 | — |

---

## 五、明确没找到的

因前提校验失败，**未产出任何可用于设备结论的漏洞候选**。以下是检索过但**在可信树上确认缺失/存在**的项：

| 项 | 状态 |
|---|---|
| `mm/shmem.c` 的 `write_protect` / `pte_marker` / `vmf_insert_pte` | 全无 |
| `fs/userfaultfd.c` 的运行时 PTE_MARKER 处理 | 只有编译期掩码 |

---

## 六、下一步建议

1. **不要在这棵树上继续投入**。若要读 6.6 源码，用 `refs/kernel_nothing_sm8735/`（6.6.127，已通过 blob 裁决）或 `analysis/src_refs/code-linaro-full/`（6.6.139 官方）
2. **所有版本裁决改用 blob 哈希比对**，不用版本特征法
3. `uffd write-protect in shmem` 这条线值得**用本机 Image 反汇编独立验证**：查本机 `shmem` / `userfaultfd` 相关符号里是否有 `pte_marker` / `vmf_insert_pte` 调用 —— 这是唯一从本报告继承下去的开放项