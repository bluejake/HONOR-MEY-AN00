# H209 · sigreturn 深度攻坚报告

> 设备：MEY-AN00（荣耀 500 / SM8735 / `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`）
> 唯一依据：`analysis/vmlinux/vmlinux-mey.elf`（由 `boot.img` 经 `magiskboot unpack` →
> `kernel` → `vmlinux-to-elf` 重建，107605 符号）
> 禁止参考内核源码。本报告全部数据来自本机反汇编。

---

## 0. 结论速览

| 路线 | 状态 | 依据 |
|---|---|---|
| **sigreturn 写栈原语** | ★ **成立（本项目首个 512 字节用户可控内核栈写）** | 汇编已证 |
| sigreturn 覆盖 43499 waiter | ✗ **判死** | `init_waiter` 的 `memset(0x70)` 覆盖全部 112 字节 |
| 跨 syscall 残留复用 | ⚠️ 31 个 syscall 存在未被 memset 的干净区间，但需逐个确认语义 | 汇编已证（区间），语义未验 |

---

## 1. 本轮修掉的 4 个扫描器缺陷（方法论层面比结论更重要）

| # | 缺陷 | 现象 | 修法 |
|---|---|---|---|
| **D1** | 流式 `md.disasm()` 遇数据区断链 | sigreturn 只解出 97/1187 条，`ldtr` 计 0（实为 4） | 逐 4 字节独立解码 → 1175 条 |
| **D2** | `va2off` 双重偏移 | `CODE` 已按 section 切过又加 `off`，阳性对照全 FAIL | `va2off = va - section_addr` |
| **D3** | 扫描窗口 `0x600` 太窄 | sigreturn 的 cfu 在 `+0xBD0`，被截断 ⇒ 误报「零命中」 | 窗口改 `0x1400` |
| **D4** | 帧深统计遇分支不停止 / 窗口 20 条 | sigreturn 报成 `push=0x60 sub=0x0`（实为 `0x60+0x230`） | 窗口 64 + 遇分支即停 |

**D1+D3 是本轮真正的转折点**：H209 初版「sigreturn 只有 sp+8 一个写点、零重叠」这个**错误结论**，根因就是这两条。若不修，会错判整条路线。

---

## 2. 核心发现：sigreturn 的 512 字节内核栈写

### 2.1 两条 cfu 站点（本机汇编）

```asm
; 路径 A
0xffffffc08049bea8: and  x1, x8, #0xff7fffffffffffff
0xffffffc08049beac: add  x0, sp, #0x10
0xffffffc08049beb0: mov  w2, #0x200
0xffffffc08049beb4: bl   __arch_copy_from_user      ; ★ 512 字节用户数据 → 内核栈

; 路径 B
0xffffffc08049c224: and  x1, x8, #0xff7fffffffffffff
0xffffffc08049c228: add  x0, sp, #0x10
0xffffffc08049c22c: mov  w2, #0x200
0xffffffc08049c230: bl   __arch_copy_from_user      ; ★ 同上
```

### 2.2 栈帧几何（全部实测）

| 项 | 值 | 来源 |
|---|---|---|
| sigreturn 帧深 | `0x60 + 0x230 = 0x290` | 序言汇编 |
| cfu 落点 | `[sp+0x10, sp+0x210)` | `add x0,sp,#0x10` + `mov w2,#0x200` |
| **绝对深度** | **`[0x100, 0x300)`** | 见 §3 账本 |

**这是本项目首次在 uid=2000 无任何特权下找到单条 syscall 把 512 字节任意用户数据连续写入内核栈。**

### 2.3 可达性

两条路径各只有 **1 条无条件 `b`** 跳入：
- A：`0xffffffc08049c0dc: b 0xffffffc08049bea8`
- B：`0xffffffc08049c4c4: b 0xffffffc08049c224`

唯一前置门是 `tbz xN, #0x26`，其中 `xN` 来自 `[adrp 0xffffffc082374000 + #0xa60]` —— **一个全局单例的 lazy-init 标志位**，全函数 40 处检查同一地址。**不受用户数据控制 ⇒ 路径必然可达。**

### 2.4 无清零（残留可存活）

```asm
; el0_svc（syscall 入口）序言
0xffffffc08106f708: paciasp
0xffffffc08106f70c: sub  sp, sp, #0x40
0xffffffc08106f710: stp  x29, x30, [sp, #0x20]
                    ; ← 无任何 memset / 栈清零
```

`CONFIG_INIT_STACK_ALL_ZERO=y` 确实存在于 `analysis/output/mey_config.txt:7030`，但其实现**不在 syscall 入口路径**上（镜像中 `keystack` 相关符号为 0，全部已内联）。这一点以 `el0_svc` 序言汇编为判据，而非配置语义推断。

全函数唯一 `msr` 均为 `ttbr0_el1/ttbr1_el1/daif`，**无 `msr sp_el0`** ⇒ 内核不改栈基址，几何叠加前提成立。

---

## 3. 绝对坐标账本（这是 H206 判死的一个方法论漏洞）

H206 只筛了帧深 ∈ `[0xb8,0x1c0]` 的 syscall，等价于假设「spray 缓冲区与 waiter 区间在同一帧底」。**这是错的** —— 不同 syscall 帧底不同。

正确定判据（`x = SP0 - depth`，depth 越小越浅）：

| 路径 | 逐跳 sp 变化 | 累计 |
|---|---|---|
| sigreturn | `el0_svc 0x40` + `invoke_syscall 0x20` + `do_el0_svc 0x20` + `sigreturn 0x290` | `0x310` |
| futex | `el0_svc 0x40` + `__arm64_sys_futex 0x80` + `futex_wait_requeue_pi 0x1c0` | `0x280` |

已排除的重复累加风险：
- `do_el0_svc@0x46544` 与 `invoke_syscall@0x46704` 是**不同函数**（前者区间 `[0x46544,0x46624)` 不含后者），各有 `push 0x20` ⇒ 账本正确。
- `do_futex@0x1edfc0` 已内联进 `__arm64_sys_futex@0x119ad8`（后者 `0x119dd4` 直调 `futex_wait_requeue_pi`）⇒ futex 路径**不加** `do_futex` 的 `0x60`。

**全树重扫结果（462 个 syscall 入口，窗口 0x1400）：**

```
已识别 (帧深, cfu 栈缓冲) 组合 = 43
★ 能覆盖 waiter 全部 112 字节的组合 = 2      ← 全是 sigreturn
★ 部分覆盖的组合 = 0
```

sigreturn 是**全树唯一**的 FULL 覆盖者。

---

## 4. 但 waiter 路线仍然判死

几何 FULL 覆盖 ≠ 可利用。内核在 waiter 落地后**立即整体清零**：

```asm
0xffffffc080958e50: mov  x23, x0
0xffffffc080958e54: mov  x0, sp        ; ← waiter
0xffffffc080958e58: mov  w1, wzr       ; ← 0
0xffffffc080958e5c: mov  w2, #0x70     ; ← 112，恰为 waiter 大小
   ...（x0/x1/x2 未被改）
0xffffffc080958e78: bl   __memset      ; memset(waiter, 0, 0x70)
```

**waiter 存活率 = 0/112。** sigreturn 写进去的用户数据在 `init_waiter` 那一刻全部消失。

⇒ **「sigreturn spray 覆盖 43499 waiter」路线判死。** 这也解释了为什么 H206 穷举 spray 原语时始终找不到能完整覆盖 112 字节的组合 —— 内核本来就不允许它存活。

---

## 5. 残留的跨 syscall 复用（未判死，需继续）

前提全部成立：sigreturn 写 `[0x100,0x300)` → eret 回用户态 → 栈不销毁（VMAP_STACK 一次性分配 16KB）→ `el0_svc` 不清零 ⇒ 残留存活。

全树扫描「深度 `[0x100,0x300)` 内被 `str` 写过但未被 `memset` 覆盖」的干净区间，命中 **31 个 syscall**，其中有价值的：

| syscall | 帧深 | 部分写未覆盖高 4 字节的槽（深度） |
|---|---|---|
| `__arm64_sys_newfstatat` | 0x1a0 | 槽 `0x190`、`0x160` |
| `__arm64_sys_newfstat` | 0x180 | 槽 `0x148`、`0x178` |
| `__arm64_sys_finit_module` | 0x140 | 槽 `0x130`、`0x120` |
| `__arm64_sys_mprotect` | 0x140 | 槽 `0x138`、`0x130` |
| `__arm64_sys_io_getevents` | 0x110 | 槽 `0x108` |
| `__arm64_sys_adjtimex` | 0x120 | 槽 `0x110`、`0x118` |
| `__arm64_sys_clone3` | 0x140 | 槽 `0x130` |

**判定条件（4 条全部满足才算命中）：**
1. 该 8 字节槽的高 4 字节在内核读它之前从未被写过
2. 该槽被当作指针/长度等敏感类型使用
3. 该 syscall 在 uid=2000 下可达且不需 `CAP_*`
4. `CONFIG_HARDENED_USERCOPY` / `FORTIFY_SOURCE` 不拦截

**注意 3 的初筛结果**：`finit_module` 需要 `CAP_SYS_MODULE`（uid 2000 不可达）；`clone3`、`perf_event_open`、`reboot`、`swapoff` 同理不可达。剩下真正可达的是 `newfstatat` / `newfstat` / `mprotect` / `io_getevents` / `adjtimex` / `epoll_pwait` / `writev` / `sendto` / `recvfrom` / `recvmsg` / `mremap` / `prctl` / `cachestat`。

---

## 6. 可证伪判据（每条结论的失败信号）

| 结论 | 若成立应观测到 | 若观测不到说明 |
|---|---|---|
| sigreturn 写栈 `0x200` | 两次 sigreturn 后内核栈 `[0x100,0x300)` 仍是用户 sigcontext 内容 | 帧深账本错（查 `el0_svc`/`invoke_syscall`/`do_el0_svc` 是否被漏） |
| 路径可达 | 任意 sigreturn 都走到 `0x49beb4`/`0x49c230` | `tbz #0x26` 的全局标志语义未清 |
| 栈不销毁 | sigreturn 后跑任意 syscall，`[0x100,0x300)` 不被自动清零 | 存在未发现的入口清零路径 |
| waiter 判死 | 无论如何构造，`waiter->task` 必为内核 `current` | `memset` 的 `x0/x1/x2` 在 bl 前被改（已逐条核对，未改） |

---

## 7. 置信度标注

| 项 | 置信度 |
|---|---|
| sigreturn 帧深 `0x290`、cfu `sp+0x10`/`0x200` | ★ 已汇编实证（三重阳性对照） |
| 绝对深度 `[0x100,0x300)` | ★ 已汇编实证（逐跳 sp 账本，重复累加已排除） |
| 全树唯一 FULL 覆盖 | ★ 已汇编实证（462 入口全扫） |
| `init_waiter` memset 判死 waiter 路线 | ★ 已汇编实证 |
| `el0_svc` 无清零 | ★ 已汇编实证 |
| `tbz #0x26` 为全局 lazy-init 标志 | ★ 汇编已证未实测（未追踪置位点） |
| 31 个候选的残留可利用性 | ★ **待验证**（区间已证，语义未验） |
| `CONFIG_INIT_STACK_ALL_ZERO` 不在入口路径 | ★ 汇编已证未实测（符号为 0，无法直接定位实现） |

---

## 8. 工具与脚本

| 脚本 | 用途 |
|---|---|
| `analysis/scratch/h209b_sigreturn_full.py` | 修正版 sigreturn 扫描器（含阳性对照 + 流式/独立解码对比） |
| `analysis/scratch/h209c_canvas.py` | 栈画布 vs waiter 判定（SCAN1/2/3） |
| `analysis/scratch/h209d_reach.py` | 可达性分析 + 分支图 + memset 位置 |
| `analysis/scratch/h209e_abs.py` | 绝对坐标全树重扫（**修正 H206 方法论漏洞**） |
| `analysis/scratch/h209g_chain.py` | 调用链 sp 基准核实 |
| `analysis/scratch/h209h_ledger.py` | 完整 sp 账本（最终判定） |
| `analysis/scratch/h209j_survival.py` | waiter 存活率（含决定性 memset 证据） |
| `analysis/scratch/h209k_cross.py` | 跨 syscall 残留复用扫描 |
| `analysis/scratch/h209l_partial.py` | 部分写（4 字节 store）存活分析 |

---

## 9. 下一步

1. **对 5 节中可达的 syscall 逐个做「读前写」确认** —— 查 `newfstatat` / `mprotect` / `adjtimex` / `io_getevents` 的槽 `0x190`/`0x148`/`0x178`/`0x138`/`0x130`/`0x110`/`0x118`/`0x108`，看高 4 字节是否真的在被读前未写。
2. **追踪 `tbz #0x26` 全局标志的置位点**（`[0xffffffc082374000+0xa60]`），确认它不是用户可影响的。
3. **本轮不消耗 boot** —— 离线几何已闭合，真机实验需等到有明确的、可证伪的假设后再开火。
---

# ★★★ H209 终局修订（2026-10-06，o→w 系列）

> 本节**推翻**上文 §5「31 个候选」与 §7「待验证」、§9「下一步 1/2」。
> 原因：后续五轮扫描（h209o→h209w）发现并修正了**五层扫描器缺陷**，
> 逐层假阳性均被具体汇编证据解释，终局**全树 0 幸存**。

## W1. 五层缺陷与修正链（每层都有汇编实证）

| 版本 | 缺陷 | 后果 | 修正证据 |
|---|---|---|---|
| h209n | `tag()` 用 `(0x[0-9a-f]+)$` 匹配，但 `bl` 目标写法 `0xADDR <name>` 以 `>` 结尾，**永不匹配** | 所有 `bl __memset`/`bl copy_from_user` 未建模 ⇒ memset 区间排除完全失效 ⇒ 36 个假阳性 | 修正后 sigreturn 内 `bl` 带符号命中 22 条、`__memset` 3 条 |
| h209n | `parse_mem` 系列解析缺陷（stp 双源寄存器、pre/post-index） | mprotect/io_getevents 假阳性 | `parse_sp` 阳性对照三态全过 |
| h209r | **pre-index push 深度记账错误**：`stp x29,x30,[sp,#-N]!` 被记到 `[F+N-16,F+N)`（帧外），实际 AABI 保证 FP/LR 对在帧顶 `[F-16,F)` | 73 个假阳性 = 全部是尾声 `ldp x29,x30,[sp],#N` 的帧恢复读 | `__arm64_sys_close` F=0x30：尾声读 [F-16,F) 必须由序言 push 覆盖 |
| h209s | **bulk 参数一级推导**：`add x26,sp,#0x18` + `add x0,x26,#8` 的二级链看不到 | recvfrom 3 个假阳性（[sp+0x20]/[sp+0x40] 实际被 `memset(sp+0x20,0,0x60)` 覆盖） | 反汇编实读：`0x...26f0 bl __memset`，推导出 dst=sp+0x20 len=0x60 |
| h209w | **字节级边界口径差一**：w 字节 @imm 覆盖深度 `[F-imm-w+1, F-imm]`（闭），v3 用半开区间丢端点 | recvfrom [sp+0x20]（深度恰为 memset 端点 0x150）被漏判 | 统一口径后对照 PASS |

另有：函数窗口出血（sendto/recvfrom 同址读点在两个 F 下重复）→ 用「下一符号地址」精确切割后重叠 = 0。

## W2. 终局扫描（h209w_arbiter_v4.py）

模型：**any-write-kills**（全函数无序）：
```
命中 ⟺ 读点 w 字节全部 ∉ (显式 store ∪ memset/copy 类 bulk 区间)
       且读点落在 (0,F] 帧内（帧外字节会被被调帧覆盖）
       且读之前无任何支配写
```

结果：
```
syscall 入口       = 462（参与扫描 366，其余帧深 0 无栈访问）
bulk 调用建模       = 203
原始命中（帧内+无任何覆盖写） = 0
读前支配写仲裁后幸存          = 0
```

阳性对照（全部 PASS 才允许出结论）：
1. sigreturn 帧深 = 0x290
2. recvfrom 二级 memset 推导覆盖 [sp+0x20]/[sp+0x40] 全部字节
3. `__arm64_sys_close` 尾声 ldp 由序言 push 覆盖（h209r 73 假阳性的反证）
4. 历史 36/73/3 假阳性在修正模型下全部消失

## W3. 终局结论（sigreturn 线完整闭合）

| 路线 | 状态 | 依据 |
|---|---|---|
| sigreturn 512B 内核栈写原语 | ★ **成立**（汇编实证） | 两条 cfu `dst=sp+0x10 len=0x200`，绝对深度 [0x100,0x300) |
| waiter 覆盖（43499 主线） | ★ **判死** | `init_waiter` 入口 `memset(waiter,0,0x70)`，存活率 0/112 |
| 跨 syscall 残留消费 | ★ **判死（终局）** | 462 入口 any-write-kills + 支配写三重筛选，0 幸存；每层假阳性有汇编级解释 |
| CVE-2026-64560 | ★ 永久归档（不变） | 三重封死（H207） |

**结论**：sigreturn 512B 写原语在本机内核上是一个「有武器、无目标」的原语——
全树不存在任何「读本函数未写字节」的 syscall 消费点。sigreturn 利用线**完全闭合**。

## W4. 项目攻击线全景（截至本轮）

| 线 | 状态 |
|---|---|
| CVE-2026-43499 写原语（rb_erase / sigreturn 画布 / 栈重占） | 全部判死（R 系 + H209 系列） |
| CVE-2026-43499 waiter 覆盖 | 判死（本报告） |
| CVE-2026-43499 内核地址泄漏 | 非卡点（slide 恒 0，多 boot 投票） |
| CVE-2026-64560 | 永久归档 |
| sigreturn 跨 syscall 残留 | 判死（本报告 W2） |

⇒ **当前无活线**。下一步是重新做攻击面测绘（新 CVE 候选 / 厂商私有驱动审计），
而不是在已闭合的线上继续消耗。

## W5. 本轮脚本与产物

| 文件 | 用途 |
|---|---|
| `analysis/scratch/h209o_residual_final.py` | tag() 修正 + any-write-kills 首版（0 命中但对照不完整） |
| `analysis/scratch/h209p_terminal.py` | 判据①帧内 + sigreturn 残留区交叉（暴露对照 A 不足） |
| `analysis/scratch/h209q_diag.py` | 诊断：16 命中 + 出血发现 |
| `analysis/scratch/h209r_final_arbiter.py` | 精确边界 + 支配写（73 假阳性 → 发现 push 记账 bug） |
| `analysis/scratch/h209s_arbiter_v2.py` | pre-index push 修正（3 幸存 → 发现二级推导缺失） |
| `analysis/scratch/h209t_callees.py` | recvfrom 被调函数解剖（security_socket_recvmsg 薄壳实读） |
| `analysis/scratch/h209u_recvfrom.py` | recvfrom 全函数解剖（**决定性 memset 实读**） |
| `analysis/scratch/h209v_arbiter_v3.py` | 二级推导（暴露边界口径差一） |
| `analysis/scratch/h209w_arbiter_v4.py` | **终局版**：全修正 + 四重阳性对照，0 幸存 |

本轮消耗 boot：**0**（全程离线）。
