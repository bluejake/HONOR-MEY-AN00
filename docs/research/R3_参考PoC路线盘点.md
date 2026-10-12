# R3 参考 PoC 路线盘点（refs/ 精选）

> 目的：从 `refs/` 下已验证 PoC 中找出可迁移到 MEY-AN00（6.6.118-android15-8，BL锁，uid=2000）的机制
> 模式：纯案头静态审计

## 一、可移植性分级

### 同基线兄弟（内核串逐字一致）

`refs/opace6-cve-2026-64560/` — OnePlus Ace 6 / PLQ110

| 参数 | 值 | 与本机对齐 |
|---|---|---|
| kernelRelease | `6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k` | 内核串一致 |
| imageBase | `0xffffffc080000000` | ✅ 一致 |
| imagePhys | `0xa8000000` | ✅ 一致 |
| memstartAddr | `0x80000000` | ✅ 一致 |
| physicalDelta | `0x28000000` | ✅ 一致 |
| pageSize / CPU | 4096 / 8 | ✅ 一致 |

**交叉验证**：f77.c 与 opace6 的 `imageBase` / `imagePhys` / `memstartAddr` / `physDelta` / `pageSize` **全部一致**；`LINK_SELINUX_STATE` 不同（各自 Image，正常）。

> ★ 详细差异分析见 **R7 报告**（结论：opace6 的成功路径**同样经过 stageB**，不能解释本机 W1 卡点；移植价值≈0）。

### 推翻既有判死的案例

`refs/galaxy-a37-root/` — 三星 A37

**★ 关键**：用 `FUTEX_CMP_REQUEUE_PI` 把 `rt_mutex_waiter` **重排到堆上**，**推翻了「43499 在本机机制性死亡」的判断**。

| 文件 | 内容 |
|---|---|
| `exploit/src/main.c:21-72` | 三线程编排 |
| `exploit/src/main.c:41` | `FUTEX_WAIT_REQUEUE_PI` |
| `exploit/src/main.c:161` | `FUTEX_CMP_REQUEUE_PI`（★ 堆重排） |
| `exploit/src/fops.c:73-180` | pselect 假锁路由 |
| `exploit/src/pipe.c:66` | `resize_pipe_slots` |
| `exploit/src/pipe.c:468` | `find_pipe_buffer` |
| `exploit/src/pipe.c:545` | `forge_pipe_buffers_on_page` |
| `exploit/src/slide.c:287` | `slide_pselect_stack_copy` |
| `exploit/src/slide.c:405-456` | `slide_leak_kernel_base` |
| `exploit/src/root.c:363-371` | `patch_cred_object`（**两次写**） |

### 空仓库（已复核）

`refs/honor300-amm-an00-kernel/` — **确认为空**：全库仅 3 个 git 对象（1 commit + 1 tree + 1 blob），blob 就是那 3 行 README，**无任何外部链接**，无 exploit 代码。内核 5.15.180 与本机 6.6 差两个世代。**不构成同厂可移植性依据。**

---

## 二、f77.c 相比 opace6 缺失的机制（★ 已被 R7 裁决为不可移植）

| 机制 | opace6 位置 | f77.c | R7 裁决 |
|---|---|---|---|
| kprobe + perf ring buffer 直取 task | `exploit-fanout.c:3750-3900` | ❌ 0 命中 | ☠️ 双重 EACCES 阻断 |
| `transition_enforcing_for_direct_probe`（窄窗口 enforcing 切换 + 读回校验） | `:4628-4657` | ❌ | 零增量价值（f77.c `:6993-7024` 已有等价物） |
| `renew_identical_cred` | `:4104-4118` | ✅ `:4719` | 已有 |
| `write_cred_fields` | `:4234-4244` | ✅ `:4915` | 已有 |
| `validate_direct_task_match` | `:4325-4358` | ❌ | f77.c 有等价自洽校验 |
| child 分离 | `:5012-5050` | ✅ | 已有 |
| `selinux_state=0` | `:5186-5199` | ✅ | 已有 |

**方法论**：opace6 的 8 个 `direct_*` 函数在 f77.c 中不存在（`grep kprobe|perf_event|tracing|TRACEPOINT|PERF_SAMPLE` 在 f77.c 中 0 命中，阳性对照成立）。但**它们是「加速器 + 有 fallback」，不是必需品** —— opace6 自己三处 `STAGE8_TASK_DIRECT_FALLBACK` 会自动回落到全表扫描。

---

## 三、可复用资产清单

### 判据方法学

| 资产 | 说明 |
|---|---|
| **fault 通道** | `adb pull /data/log/log.db` → `event_info.extra` 的 `F1NAME`/`F2NAME`/`F3NAME`/`REASON` |
| random_table boot_id 劫持读原语 | 写配对 `{镜像地址, data 槽}` → 读 boot_id 文本 |
| A/D 二元判据（dc15） | 对 owner 开火，nice 使闸门必不匹配 ⇒ 存活=链健康 / panic=链坏 |
| 扫描式探针（dc15 §3.4） | 一次启动连打 40 发（nice −20..19），**「没崩的那个 nice 就是悬垂槽里那 32 位值」** |

### 判据教训（★ 比成功经验更重要）

| 教训 | 内容 |
|---|---|
| `cfi_step` 不可信 | — |
| `sched_pi_setprio` 单向判据 | 合法 walk 也是静默的（`pi_baseline` 正控跑完整条链仍 0 条）⇒ 「0 条」不能推出「walk 死在某处」 |
| `/proc/tid/syscall` 尾两字段 | 是**用户态 SP/PC**，不是内核栈 |
| rb_erase 写值须「+8 良性」 | — |
| `Grep` 工具假 0 命中 | 对 `base_typeattr_880` 报 0，Python 同条件报存在（R5） |
| `git grep` 不带 `HEAD` 静默返回空 | GKI 树工作树未 checkout 时（R2/R4） |
| **plant 后的任何诊断都是攻击面** | route 线程自己的 syscall 会覆写 waiter（dc15 §3.4h 根因） |
| **tracefs 会被 exploit 自己重设事件集** | 导致「0 条」假阴性（dc15 §3.4n），修好后同窗口抓到 648 条 |

---

## 四、完整参考目录索引

见 **R8 报告** `R8_refs盘点与sm8735裁决.md` 的 129 项全量清点表（R8 按「同内核 / 荣耀系 / SoC 系 / 其他」分组，并逐项评了可移植性）。

**第一梯队结论**（详见 R8）：

| 目录 | 评级理由 |
|---|---|
| `GhostLock-MEP-AN00-App` | ★ 与 dc15 同型号 MEP-AN00、内核串逐字相同 → 提供已知可用的 `target.h` 骨架 |
| `kernel_nothing_sm8735` | ★ 唯一同 SoC（sun/SM8735）源码树，已通过 blob 哈希裁决 → 6.6 偏移仲裁器 |
| `cve-2026-64560-a16` | ★ 明示 6.6.118 未修 + 纯 Go 工具链 + 不依赖栈几何 → 正交第二条腿 |
| `ghostlock-h80gt` | ★ MCAST 载体参考实现 + 实机验证 |
| `cve-2026-43499-honor` | 荣耀私有 waiter 偏移表 + 载体穷尽表 |
| `cve-2026-43499-aak-an00` | 荣耀同代 6.6.89，10 篇复盘 docs |

---

## 五、下一步建议

1. **★ 立即：移植 `GhostLock-MEP-AN00-App` 的 `target.h`（48 偏移 + 32 行指纹表）**，用本机 kallsyms 重算，与 dc15 实测值**交叉验证**。两套独立来源一致 ⇒ 偏移可信度直接拉满
2. **`cve-2026-64560-a16` 的 profile 换指纹**：3 个 6.6.118 profile 可直接改；注意其自标 rmx5010「完整提权尚未实机验证」
3. **不要投**：kprobe+perf 直取 task（R7 已裁决双重阻断）、`honor300-amm-an00-kernel`（空仓库）、`google_kernel_GKI-6.6.118`（伪装树）