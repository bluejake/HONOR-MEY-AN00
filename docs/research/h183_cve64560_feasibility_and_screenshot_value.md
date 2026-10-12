# H183 —— CVE-2026-64560 评估：截图参考价值 + 本机可行性裁定

> 轮次：**H183**｜日期：2026-10-06｜设备：MEY-AN00（**未开火，boot `5176c1fc` 零消耗**）
> 触发：用户提供一张截图（另一台设备 **HNPPG** 声称 64560 全链 root 成功）
> 裁定级别：**漏洞状态 = 已实测（汇编级）**｜**利用可行性 = 源码/文档推断，未实测**

---

## 0. 一句话结论

★★ **截图本身参考价值有限（它是另一台机器的成功记录），但它指向的 `refs/op13-cve-2026-64560` 是本项目目前最有价值的第二攻击面。**

**本机 64560 漏洞状态：成立（汇编级实证）。** 且本机 `WARN_ON_ONCE` 被编译成 `brk #0x800` 硬 trap，
⇒ 命中 UAF 窗口时**同步 trap、判据比 panic 强得多**。
**但绝对地址与 op13 差最大 3MB，二进制不可直接移植，必须重定位。**

---

## 1. 截图可信度审查

### 1.1 截图内容（逐项转录）

```
BOOTID_WRITE_PASS → STAGE0_GATE_PASS → CROSSCACHE_RECLAIM → MISC_BRIDGE_OPEN_PASS
→ MISC_BRIDGE_RW_PASS → PIPE_RECLAIM_PASS → PHYS_READ_PASS → PHYS_WRITE_PASS
→ (STAGE8) → 弹 root shell: `HNPPG:/data/local/tmp/cve64560-ppg #`
getenforce = Permissive（SELinux 已被打成宽容）
```

### 1.2 ★ 关键发现：截图**不是**官方 PoC 的产物

`refs/cve-2026-64560-analysis/README.md` 明确声明：

> 本仓库…**不包含** heap spray、对象占位、RIP 控制等任何利用原语。
> 将其变成提权 exploit 需要额外的大量工作…

⇒ 官方 PoC **只是触发验证器**，产不出 `PHYS_WRITE_PASS` 这种 gate。
⇒ 截图的 gate 链（`CROSSCACHE` / `MISC_BRIDGE` / `PIPE_RECLAIM` / `PHYS_RW`）必然来自
**第三方完整提权实现**。

### 1.3 ★ gate 链逐项对上了 `op13`

`refs/op13-cve-2026-64560/docs/TECHNICAL.md` 原文：

| 截图 gate | op13 TECHNICAL.md 对应句 |
|---|---|
| `BOOTID_WRITE_PASS` | "Re-derived the **boot-ID cycle**"、"stable **boot-ID** reads" |
| `STAGE0_GATE_PASS` | "Added hard gates for the full **fingerprint**… **boot ID**… slab visibility" |
| `CROSSCACHE_RECLAIM` | "**cross-cache page**" |
| `MISC_BRIDGE_OPEN/RW_PASS` | "**misc-list bridge**" |
| `PIPE_RECLAIM_PASS` | "**pipe-buffer** layout" |
| `PHYS_READ/WRITE_PASS` | "Re-derived… **physical-memory**… and **credential** offsets" |
| `STAGE8` → root shell | "Starts a **current-boot helper**"、"`uid=0(root)`" |

**结论：截图是 `op13` 类实现（及其移植/衍生）的成功实例。**
⇒ 它的**技术路线可信且已被文档化**，但**那台机器的所有绝对地址/参数对本机无效**。

### 1.4 截图的疑点（不影响技术路线参考价值）

1. `HNPPG:/data/local/tmp/cve64560-ppg #` —— 提示符里**不含 `shell@`**，
   正常 adb shell 是 `shell@HNPPG:/... $`。⇒ 该输出可能是 helper 进程自设的 `$0`，
   也可能是**伪造/改写的日志**。不可作为判据。
2. 截图末尾自述「Device went offline again（possibly the root-child process state destabilized
   adb, or a late crash）」⇒ **root 未稳定留存**。
   ★ 但 **SELinux permissive 的状态是否留存未验证** ⇒ 不能排除「拿到 root 但没坐稳」。
3. 「冷却到 33°C 的干净 boot 一发即中」——暗示**发数极少即命中**。
   op13 文档记录的是多轮/多策略（`fanout` / `rotate`），两者难度差异大，
   **不应据此推断本机一发就能中**。

---

## 2. ★★★ 本机 64560 漏洞状态裁定：**成立**（汇编级，非版本号推断）

### 2.1 版本与 SPL

| 项 | 本机 | 64560 修复版本 | 结论 |
|---|---|---|---|
| `linux_banner` | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` | **6.6 LTS ≤ 6.6.146 受影响** | ★ 受影响 |
| SPL | `2026-08-01` | 公开日 `2026-07-29` | ★ 卡在边界，**必须汇编实证** |

★ SPL 恰好等于公开日 ⇒ **不能用版本号下结论**。以下全部用本机 vmlinux 实证。

### 2.2 kallsyms 证据

```text
$ grep -i timer_lock_sighand analysis/output/mey_6.6.118.kallsyms.txt
（无输出）  ★★ timer_lock_sighand 是修复补丁新引入的 helper ⇒ 本机不存在 ⇒ 未修复

ffffffc080880088 T posix_cpu_timer_del
ffffffc0800b9488 T __lock_task_sighand      ← 注意：本机是 __lock_（6.6 早期命名）
ffffffc08016ef58 T posix_cpu_timers_exit
ffffffc08016f128 T run_posix_cpu_timers
ffffffc08007fb0c T pid_task
```

### 2.3 ★★ 漏洞模式在本机汇编中精确坐实

`posix_cpu_timer_del@0xffffffc080880088`：

```asm
0x8800b4: bl   __rcu_read_lock
0x8800b8: ldr  w8, [x19, #0x30]           ; it->cpu.clock
0x8800bc: mov  w9, #1
0x8800c0: ldr  x0, [x19, #0xa0]           ; ★ it->cpu.pid
0x8800c4: bic  w1, w9, w8, lsr #2         ; pid_type
0x8800c8: bl   pid_task@0x07fb0c          ; ★★ 唯一一次 pid_task 查找
0x8800cc: cbz  x0, #0x880174               ; 查不到 ⇒ 走出口
0x8800d8: add  x21, x19, #0x78             ; ★ it->timerqueue_node
0x8800dc: bl   __lock_task_sighand@0x0b9488
0x8800e0: cbz  x0, #0x8801b0               ; ★★★ sighand == NULL ⇒ 分支到独立 WARN 块
0x8800e4: ldr  w8, [x19, #0xb8]            ; timer_queued 检查
```

`__lock_task_sighand@0xffffffc0800b9488`：

```asm
0x0b94a8: ldr  x21, [x20, #0x880]          ; ★★ task->sighand @ 0x880
0x0b94ac: cbz  x21, #0x0b94e8              ; ★ NULL ⇒ 返回 NULL（无 smp_acquire 屏障）
```

`sighand == NULL` 分支的出口 `0xffffffc080880174`：

```asm
0x880174: bl   __rcu_read_unlock
0x880178: ldr  x0, [x19, #0xa0]
0x88017c: bl   pid_task                   ; 收尾
0x880180: mov  w0, wzr                    ; ★★ return 0
0x880184: mrs  x8, sp_el0                 ; canary
           ...
```

★ **全程无任何摘链操作** ⇒ 与 README 描述的 `if (!sighand) return 0;` **完全一致**。
★ 修复补丁要求此处改为 `timer_lock_sighand()` **重试查找**，本机**没有**这个 helper。

### 2.4 ★★★ 本机独有优势：`WARN_ON_ONCE` = 硬 trap

`0x8801b0` 分支（sighand==NULL 后的处理）：

```asm
0x8801b0: ldr  x8, [x19, #0x98]           ; it->[0x98]
0x8801b4: cbz  x8, #0x8801c0
0x8801b8: brk  #0x800                     ; ★★ WARN_ON_ONCE ⇒ 硬 trap（brk，非 panic）
0x8801bc: b    #0x880174
0x8801c0: ldr  x8, [x21]                  ; x21 = it + 0x78 = timerqueue_node
0x8801c4: cmp  x8, x21                    ; timerqueue 为空？
0x8801c8: b.eq  #0x880174                 ;   空 ⇒ 安全退出
0x8801cc: b    #0x8801b8                  ; ★ 非空 ⇒ 直接 brk #0x800
```

★ **`WARN_ON_ONCE` 在本机被编译为 `brk #0x800`（同步 trap，不走 panic 流程）。**

⇒ **本项目独有的判据优势**：
- 命中 UAF 窗口且已释放的 `k_itimer` **仍挂在** `signal->cpu_timers` 上 ⇒ **立刻 `brk #0x800`**；
- **无需等 tick**（不必等 `run_posix_cpu_timers`），`timer_delete()` 当场命中当场 trap；
- 判据是**同步确定性 trap**，比等 panic 更快、更无歧义（`page_request` 需要内核异步取页才发生）。

★ 这解释了为什么本项目的 43499 线要靠 `boot_id` 变化做二值判断，而 64560 线可以做到「当场判成败」。

### 2.5 与 op13 文档的交叉验证

`op13/docs/OP13.md` 对同款机型的描述：

> `posix_cpu_timer_del` … performs **one** `pid_task()` lookup followed by **one**
> `__lock_task_sighand()` call, and on `sighand == NULL` branches **forward**
> (`cbz x0, 0x…a72fc`) into a separate `WARN_ON_ONCE` block **past the function epilogue**.

★ 与本机结构**逐条吻合**（一次 pid_task、一次 lock_task_sighand、cbz 前进到独立 WARN 块）。
⇒ 该形态是 **6.6.118 GKI 的通用形态**，不是某一机型的巧合。

---

## 3. ★★ 跨设备隔离：op13 二进制**不可**直接用于本机

### 3.1 关键符号地址对照

| 符号 | op13 (OnePlus 13) | 本机 (MEY-AN00) | 差值 |
|---|---|---|---|
| `posix_cpu_timer_del` | `0xffffffc0801a71c8` | `0xffffffc080880088` | ★ **0x2E7140** |
| `__lock_task_sighand` | `0xffffffc0800c43c0` | `0xffffffc0800b9488` | ★ **0xAF38** |
| `pid_task` | op13 未单列（`0x0dbaf4` 为 `__rcu_read_lock`） | `0xffffffc08007fb0c` | — |

★ 同一 `6.6.118` GKI、同一 4K 页、同一 39-bit VA，**但绝对地址差最大 3MB**。
⇒ **op13 的 `bin/cve-2026-64560-fanout` 等产物在本机必然失效。**

### 3.2 op13 自己的移植文档已明令禁止

`op13/docs/PORTING.md`：

> The **default physical layout values belong to the documented Xiaomi 15 target**.
> For another platform, supply independently verified `--phys-offset`, `--kernel-phys-load`,
> `--page-offset`, and `--random-table-data-offset` values.
> ★ **Do not copy them based only on a matching kernel version string.**

> a different kernel Image is **not a drop-in build target**. Static offsets, allocator
> behavior, race parameters, and the **complete restoration path** must be validated
> on the exact build.

★ 与本项目铁律「跨设备数值隔离」完全一致。**这条禁令对本项目同样适用。**

### 3.3 可继承 vs 必须重算

| 项 | 可否继承 | 依据 |
|---|---|---|
| ★ 漏洞模式（`pid_task` 一次 + `lock_task_sighand` 一次 + cbz→WARN） | ✔ **完全可继承** | 本机汇编逐条吻合（§2.3） |
| ★ 竞态构造（`CLOCK_PROCESS_CPUTIME_ID` + 非 leader `execve`） | ✔ **可继承** | 纯用户态逻辑，与机型无关 |
| ★ 利用阶段划分（Stage0 reclaim → misc bridge → cross-cache → pipe → phys R/W → cred） | ✔ **架构可继承** | op13 TECHNICAL.md |
| ★ `timer_lock_sighand` 不存在 ⇒ 未修复 | ✔ **已本机实证** | §2.2 |
| ★ **`k_itimer` 结构偏移** | ✔ **已本机重算** | 见 §3.4 |
| ★ **`task->sighand` 偏移** | ✔ **已本机重算** | `0x880` |
| 静态地址（`phys-offset` / `kernel-phys-load` / `page-offset` / `random-table-data-offset`） | ✘ **必须重算** | PORTING.md 明令 |
| slab cache 名 / 分配器行为 / 竞态参数 / CPU 角色 | ✘ **必须重新标定** | TECHNICAL.md "Calibrate timer ceilings, CPU roles, reclaim size" |
| 完整 restoration path | ✘ **必须重验** | PORTING.md |

### 3.4 ★ 本机 `k_itimer` 偏移（从本机汇编反推，已机器化）

| 字段 | 偏移 | 汇编实证 |
|---|---|---|
| `it->cpu.pid` | `+0xa0` | `0x8800c0: ldr x0,[x19,#0xa0]` |
| `it->[0x98]`（WARN 分支检查位） | `+0x98` | `0x8801b0: ldr x8,[x19,#0x98]` |
| `it->timer_queued` 状态位 | `+0xb8` | `0x8800e4: ldr w8,[x19,#0xb8]` |
| ★ `it->timerqueue_node` | `+0x78` | `0x8800d8: add x21,x19,#0x78` |
| ★ `task->sighand` | `+0x880` | `0x0b94a8: ldr x21,[x20,#0x880]` |

★ 这些是**相对偏移**，与机型无关 ⇒ 属「可继承」类，且**本机已独立重算**（未抄 op13）。

---

## 4. 64560 vs 43499（当前主线）对比 —— 战略定位

| 维度 | CVE-2026-43499（rt_mutex/sigreturn，当前主线） | CVE-2026-64560（posix-cpu-timers） |
|---|---|---|
| 本机漏洞状态 | **已实测存在** | ★ **已实测存在**（§2.3 汇编） |
| 利用成熟度 | 本项目自研，几何复杂（H175/178 大量踩坑） | ★ **有第三方完整实现**（op13 等 7 个 ref） |
| 所需内核能力 | sigreturn fpsimd 画布 + `rt_mutex_adjust_pi` 链 | UAF（k_itimer 释放后仍挂 timerqueue） |
| 确定性 | 低（日志全封，只能差分） | ★ **高**（`brk #0x800` 硬 trap 当场判定） |
| 设备绑定 | 偏移自算（本机 vmlinux） | ★ 偏移可继承 + 需重定位静态地址 |
| 报 | H179-H182 连续 4 发 `page_request` | 未开火 |
| 目标 | 同一条 | 同一条：uid 0 + permissive + 受保护写 |

★ **战略判断**：
64560 具备**成型的第三方利用链**与**确定性判据**，而 43499 主线在 H182 才刚完成因子分离
（`S4 必需 + S1 前提`），离可用的写原语仍有距离。
⇒ **建议把 64560 提升为并行的第一优先级**，43499 降为「机理研究/备选」。

---

## 5. 下一步（B5，1 boot，低风险零内核写）

### 5.1 目标：**只验证竞态能否命中**，不做任何提权

`refs/cve-2026-64560-analysis/poc/cve_2026_64560_poc.c`（237 行）已是现成触发器：

- 线程 A：`timer_create(CLOCK_PROCESS_CPUTIME_ID)` → arm → 忙等 → `timer_delete()`
- 线程 B：`fork()` → 子进程建**非 leader 线程** → 该线程 `execve("/bin/true")` → 父 `waitpid()`

### 5.2 判据链

| 现象 | 解读 |
|---|---|
| ★ `brk #0x800`（设备立即挂，`reason` 非 `page_request`） | ★★★ **UAF 命中，Stage0 成功** |
| 数分钟无事件 | 未命中 ⇒ 需标定 CPU 角色 / timer 数量 / reclaim 策略（op13 用 56,000 timer 上限） |
| `history.log` 无新增 | 未命中（**这是本发的主要失败模式**） |

★ op13 报告「一发即中」但也记录了多策略；本机**不应假设一发命中**。

### 5.3 纪律

- 官方 PoC 是 `static, pie`；NDK r27c 编译时**不加 `-lpthread`**（r27c 已并入 libc）
- 崩溃类实验**前台跑、抓 stdout**（`__sched_setscheduler` 类的 stdout 会被 panic 截断）
- 判 panic 读 `boot_id` + `history.log`，**不信 stdout 尾部**
- 一 boot 一发

---

## 6. 置信度标注

| 结论 | 等级 |
|---|---|
| 截图不是官方 PoC 产物（官方无提权原语） | **文档已证**（README 明文） |
| 截图 gate 链来自 `op13` 类实现 | **文档已证**（TECHNICAL.md 逐项对应） |
| 截图提示符格式异常、root 未稳定留存 | **已实测判读**（截图自述 offline） |
| ★ **本机 6.6.118 未打 64560 补丁** | ★ **已实测**（kallsyms 无 `timer_lock_sighand`） |
| ★ **本机漏洞模式与源码/文档逐条吻合** | ★ **已实测**（`posix_cpu_timer_del` / `__lock_task_sighand` / 出口反汇编） |
| ★ **本机 `WARN_ON_ONCE` = `brk #0x800` 硬 trap** | ★ **已实测**（`0x8801b8` / `0x8801cc`） |
| ★ 本机 `k_itimer`/`task->sighand` 偏移 | ★ **已实测**（本机汇编反推） |
| 绝对地址与 op13 差 3MB、二进制不可移植 | **已实测**（kallsyms 对照 + PORTING.md） |
| 竞态在本机可命中 | **未验证基线**（B5 待做） |
| Stage0 之后的提权链在本机可复现 | **未验证基线**（需重定位全部静态地址 + 重新标定） |
| 报告可用于 root | **未验证基线**（当前 uid 2000 / Enforcing） |

---

## 7. 设备状态

| 项 | 值 |
|---|---|
| serial | `A22C026319001339` |
| boot_id | `5176c1fc-654f-4150-b4b0-943962f09ff1`（**H183 零开火，未消耗**） |
| SPL | `2026-08-01` |
| `getenforce` | **Enforcing**（未 root） |
| `id -u` | **2000** |
| `timer_lock_sighand` | **不存在**（⇒ 未打 64560 补丁） |

---

## 8. 文件清单

**新建**
- `analysis/output/h183_cve64560_feasibility_and_screenshot_value.md`（本文件）

**未修改**：H183 阶段只做离线评估，**未改动 `tools/` 任何文件、未 push、未开火**。
