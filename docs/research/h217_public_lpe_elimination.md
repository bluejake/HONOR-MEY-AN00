# H217 · 公开 LPE 逐条淘汰 —— 为什么本机"没得打"

> 设备：MEY-AN00（荣耀 500 / SM8735 / `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` / A16 / MagicOS 10.0.0.175）
> 会话：2026-10-06 续做（binder 方向验证）
> 纪律：**真机开火 = 0 发**（`boot_id` 全程 `ba30251b-…a0` 不变）；结论全部来自
> 设备实测（`open()` / 内核配置 / SELinux 策略）+ 公开漏洞资料。
> 零内核源码引用。

---

## §0 一句话结论

**本轮把 2026 年所有有公开 PoC 的主流内核 LPE 逐条对本机做了先决条件检验，
全部【白名单式淘汰】。** 本机不是因为"难打"而打不下来，而是
**漏洞所依赖的内核子系统被厂商成体系地关闭了**（见 §3 配置实证）。

---

## §1 ★★★ 决定性发现：厂商关掉了一整批 LPE 依赖的子系统

从设备 `/proc/config.gz` 实测（7787 行全量）：

| 配置项 | 值 | 被它封死的漏洞类别 |
|---|---|---|
| **`CONFIG_USER_NS`** | **NOT SET** | ★ 所有 **userns 提权**（overlayfs、netfilter-in-userns 等一大批） |
| **`CONFIG_SYSVIPC`** | **NOT SET** | ★ **System V msg_msg heap spray** —— 即几乎所有现代内核 UAF 的"泵" |
| **`CONFIG_POSIX_MQUEUE`** | **NOT SET** | POSIX mqueue spray |
| **`CONFIG_NF_TABLES`** | **NOT SET** | ★ nftables 系列（近年最高产的 LPE 面之一） |
| **`CONFIG_CRYPTO_USER_API_*`（全部 4 项）** | **NOT SET** | ★ **AF_ALG 整个用户态 crypto API**（含 `algif_aead`） |
| `CONFIG_MPTCP` | NOT SET | MPTCP 系列 |
| `CONFIG_NFS_FS` / `CONFIG_CIFS` / `CONFIG_9P_FS` | NOT SET | 网络文件系统系列 |
| `CONFIG_AF_KCM` / `CONFIG_BATMAN_ADV` | NOT SET | 对应协议栈系列 |

> ★★ **`CONFIG_SYSVIPC` NOT SET + `CONFIG_USER_NS` NOT SET** 这两条的杀伤力最大：
> 它们分别是**堆喷泵**与**权限跳跃底座**。少了它们，绝大多数公开 LPE 的
> **第二阶段直接无法搭建**，与第一阶段的 bug 是否存在无关。

---

## §2 逐条淘汰表（2026 有公开 PoC 的主流 LPE）

| 漏洞 | 性质 | 本机先决条件检验 | 判决 |
|---|---|---|---|
| **CVE-2026-64468** | binder `binder_free_transaction()` UAF → root（[公开 PoC](https://raw.githubusercontent.com/aramosf/cve-2026-64468/main/exploit.c)，作者 A. Ramos；发现者 Alice Ryhl, Google；修复 f223d27a546c） | ① 需 `CONFIG_SYSVIPC=y` 做 msg_msg 堆喷 → 本机 **NOT SET**；② 需 `BINDER_SET_CONTEXT_MGR (0x6307)` → **本机 SELinux 拒绝**（策略只授 `servicemanager`）；③ PoC 仅 x86_64（依赖 `prefetch` 侧信道做 KASLR/direct-map 泄漏），本机 **aarch64** | ❌ **三重封死** |
| **CVE-2026-31431「Copy Fail」** | kernel crypto API（**AF_ALG**）逻辑缺陷 → 页缓存破坏 → root；引入于 4.14，仅在 6.18.22/6.19.12/7.0 修复（[oss-sec 原始通告](https://seclists.org/oss-sec/2026/q2/290)，[PoC](https://github.com/theori-io/copy-fail-CVE-2026-31431/blob/main/copy_fail_exp.py)）⇒ **6.6.118 理论上未修复** | 需 `AF_ALG` socket（`CONFIG_CRYPTO_USER_API_AEAD`）→ 本机 **NOT SET**（全部 4 项 crypto user API 均关） | ❌ **入口被编译期移除** |
| **CVE-2026-46225** | `spi: rspi` 控制器注销顺序缺陷（[Ubuntu CVE](https://ubuntu.com/security/CVE-2026-46225)） | 依赖 **Renesas RSPI** 驱动 + driver-unbind 路径；本机为 Qualcomm 平台，无 rspi，且 unbind 需特权 | ❌ **不适用** |
| **CVE-2026-43499** | `rt_mutex` 栈 UAF 写原语（项目主线） | 唯一 112/112 完整覆盖的内核栈喷溅原语 `prctl(PR_SET_VMA_ANON_NAME)` 需 **`CAP_SYS_RESOURCE`** → 实测 `CapEff=0`、`CapBnd` 不含 bit24 | ❌ **能力墙**（见 H206/H216） |
| **CVE-2026-64560** | `sighand` UAF（项目副线） | 触发者必然与受害者**同生命周期**；`timer_settime` 不经过 `posix_c_timer_set` | ❌ **永不可达**（H207 穷举判死） |

---

## §3 加固配置实证（本机为什么"硬"）

从 `/proc/config.gz` 实测：

```
CONFIG_ARM64_PTR_AUTH=y            CONFIG_ARM64_PTR_AUTH_KERNEL=y
CONFIG_CFI_CLANG=y                 CONFIG_SHADOW_CALL_STACK=y
CONFIG_STACKPROTECTOR_STRONG=y     CONFIG_HARDENED_USERCOPY=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y  CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y    CONFIG_RANDOMIZE_KSTACK_OFFSET=y (DEFAULT off)
CONFIG_BPF_JIT_ALWAYS_ON=y         CONFIG_BPF_LSM=y
```

⇒ **PAC + kCFI + SCS + 栈保护 + usercopy 加固 + alloc 清零 + freelist 随机化/加固** 全开。
⇒ 未开的两项（`CONFIG_RANDOM_KMALLOC_CACHES`、`CONFIG_SLAB_BUCKETS`）是仅有的一点空间，
但**没有已知可用原语**（见 §4）。

---

## §4 仍然存在的理论空间（诚实清单，均无已知可用原语）

| 面 | 状态 | 说明 |
|---|---|---|
| `CONFIG_BPF_SYSCALL=y` | 配置为开 | 但 **`kernel.unprivileged_bpf_disabled` 对本 shell 域 0400 不可读**，Android 常规设为 `2` ⇒ **未能证实可达**。即便可达也需新漏洞 |
| `CONFIG_IO_URING=y` | 配置为开 | `kernel.io_uring_disabled` 同样不可读；Android 常规设为 `2` |
| `CONFIG_XFRM_USER=y` | 配置为开 | 需网络相关新漏洞 |
| `CONFIG_KEYS=y` | 配置为开 | 同上 |
| `/dev/binder`（shell 可达 11 个服务） | 可达已证 | 但 `SET_CONTEXT_MGR` 被拒 ⇒ 无法自建 binder 上下文；只能打那 11 个系统/vendor 服务 |
| `RANDOM_KMALLOC_CACHES` 未开 | 空间存在 | 无已知原语 |

> ⚠️ 上表**不是"有希望"**，而是"没有被编译期完全关掉"。要利用仍必须**发现新漏洞**。

---

## §5 本轮方法学（可复用）

1. **先决条件矩阵法**：对每个公开 LPE，抽取它的**必要子系统/权限**（不是"内核版本"），
   再拿设备实测的 `config.gz` / SELinux 策略 / `CapEff` 逐条对撞。
   → 一条 `# CONFIG_X is not set` 就能在**零开火**下淘汰一个漏洞，成本极低、结论极硬。
2. **公开 PoC 的 `qfail()` 分支往往自带先决条件自检**（本例 `msg_pump_init()` 直接报
   "CONFIG_SYSVIPC is required"）→ 读 PoC 的失败路径比读它的利用路径更省时间。
3. **不把"内核版本未修复"等同于"可利用"**：CVE-2026-31431 在 6.6.118 确实未修复，
   但 `CONFIG_CRYPTO_USER_API_AEAD is not set` 使其**从入口就不存在**。
   ★ 这是本轮最关键的一课。

---

## §6 最终判决

**本机不存在可由公开已知漏洞直接达成的本地提权路径。**
所有 2026 年有公开 PoC 的主流内核 LPE，在本机均被
**配置裁剪（USER_NS/SYSVIPC/AF_ALG/nf_tables）、SELinux 策略、能力墙或架构差异**之一封死。

⇒ 要取得 uid 0，必须**发现一个全新的、且落在本机剩余开放子系统内、且能从
`u:r:shell:s0`（零能力）触达的内核漏洞**。这是独立研究工作，不是参数调优。
