# R7 opace6 → f77.c 差异分析：移植价值裁决

> 目标：MEY-AN00（6.6.118-android15-8，BL锁，uid=2000）
> 模式：**纯离线**差异分析（未连 adb、未编译）
> 对比对象：`refs/opace6-cve-2026-64560/` vs `c64560/f77.c`（7973 行）
> 标注：`[汇编已证]` / `[源码推断未验证]` / `[已实测]` / `[未验证]`

## 结论摘要

1. **opace6 的成功路径 100% 经过 stageB/misc 桥**（`exploit-fanout-opace6.c:5712-5799`）。它**没有**绕过 stageB，**没有** alternative privilege path ⇒ 「opace6 成功而本机卡 stageB W1」**不能**用 direct-probe 缺失解释。
2. **前提修正**：`direct_*` 全套存在于全部 4 个 opace6 文件（与 `exploit-fanout.c` diff 仅 146 行，全是 `#define LINK_*` 与 profile 字符串）。opace6 只是**参数覆盖层**，不是「更优机制」。
3. **「同基线兄弟」在符号层被证伪**：profile 记 `kallsymsNumSyms=110445`，本机实测 **110,992**；且 opace6 的**每一个** `LINK_*` 与本机 kallsyms 同名符号**全部不同**，差值**非均匀**（`+0xc88` / `+0x1fb00` / `+0x1ddf8` / `-0x7ee0` / `-0x828ec8`）⇒ **不同厂商内核 build**，非同一 build 的 slide 差异。
4. **kprobe 路线被双重 EACCES 阻断**：`kprobe_events` 写入被 SELinux 拒，**且** `perf_event_open()` 在 `selinux_perf_event_open()` LSM hook 即返 EACCES(13)（sysctl 从未被求值，H112 曾撤回过一次误判）。`open_direct_task_probe()` **两者缺一不可** ⇒ 本机 100% 不可用。
5. **`transition_enforcing_for_direct_probe` 零增量价值**：f77.c `:6993-7024` 已有逐字等价的「读1→写0→读回验0→写回1→读回验1」窄窗口。opace6 额外的 `parent-abort` 回滚分支只在「必须写 tracefs」时才有意义。
6. **direct-probe 是「加速器 + 有 fallback」**：三处 `STAGE8_TASK_DIRECT_FALLBACK`（`:4873/:4895/:5094`）表明失败自动回落全表扫描。第三方 `k80pro-miro` 文档也把它标为「✅ 可放弃」。
7. **移植价值 ≈ 0**。唯一值得做的是 `run_direct_probe_self_test`，但目的是**反向证伪**（预期必然 EACCES）。

---

## R7.1 opace6 机制全景表

> 判据 = 子串在 f77.c 中是否存在（已双向对照，见本节末）

### 组① 写原语构造 — f77.c **全部已有且更完备**

`prepare_spray_pairs`(1359/✅1566)、`close_spray_pairs`(1382/✅1589)、`spray_worker`(1410/✅1631)、`run_spray_phase`(1465/✅1682)、`fake_misc_record_offset`(1501/✅1729)、`fake_misc_child`(1505/✅1733)、`build_fake_fragment`(1511/✅1739)、`build_misc_fragments`(1529/✅1758)、`run_race`/`race_timing_slot`(1175/1155/✅1392/787)、`delete_worker`/`prime_worker`/`rcu_flush_worker`(1008/1056/1071/✅1250/1293/1308)、`force_rcu_callbacks`(1089/✅1326)、`wait_timer_slab_drain`(2067/✅2765)、`restore_misc_list`(1717/✅2390)、`confirm_stage0_cycle`(1852/✅2525)、`restore_stage0_state`(1888/✅2561)、`verify_real_uhid`(1938/✅2611)

### 组② 直取 task / cred（kprobe + perf）— f77.c **9 个函数全缺**

| 函数 | 行号 | 用途 | f77.c |
|---|---|---|---|
| `direct_trace_command` | 3757 | 写 `kprobe_events` | ❌ 0命中 |
| `direct_perf_event_open` | 3771 | `SYS_perf_event_open` | ❌ 0命中 |
| `direct_ring_copy` | 3775 | perf ring 环绕拷贝 | ❌ 0命中 |
| `open_direct_task_probe` | 3801 | kprobe→读 id→perf→mmap ring | ❌ 0命中 |
| `read_direct_task_snapshot` | 3862 | 解析 task/real_cred/cred | ❌ 0命中 |
| `close_direct_task_probe` | 3787 | 关 perf + 删事件 | ❌ 0命中 |
| `validate_direct_task_match` | 4332 | 交叉校验全表扫描结果 | ❌ 0命中 |
| `transition_enforcing_for_direct_probe` | 4635 | 窄窗口 enforcing 1→0→1 | ❌ 0命中 |
| `run_direct_probe_self_test` | 5519 | `--probe-task` 自检 | ❌ 0命中 |

### 组④ 提权落地 — f77.c **全部已有**

`validate_kernel_root_cred`(4534/✅5589)、`validate_init_task_layout`(4511/✅5564)、`read_stable_cred_bytes`(4189/✅4863)、`write_cred_fields`/`verify_`/`restore_`(4241/4255/4266/✅4915/4929/4940)、`verify_task_cred_pair`(4275/✅4949)、`renew_identical_cred`(4111/✅4719)、`crosscache_*`(2643-2774/✅3340-3471)、`pipe_*` 12 个(2914-3319/✅3611-4071)、`load_physical_layout`(3319/✅4073)、`kernel_virtual_to_physical`(3348/✅4102)、`pipe_physical_read/write`(3481/3503/✅4234/4256)、`run_stage8_root_probe`(4732/✅6486)

### 组⑥ **f77.c 独有**（opace6 没有，本项目自研增量）

`stageb_observation_probe`(2164)、`h74_probe_fake_fops`/`h74_ioctl_gate_on`/`h74_report_ioctl_gate`(2089/2079/2106)、`h68_fops_hijack_probe`(2008)、`bootid_geometry_probe`(1933)、`probe_text_write`(6173)、`refresh_direct_ram_limit`(3672)、`attempt_thermal_gate`/`read_max_thermal_mC`(892/858)、`try_pin_physical_cpu`(1617)

> **★ 关键**：`h74_probe_fake_fops` 明确设计为「**不依赖 bridge 读、不依赖预先知道 slide**」的 W1 命中判据 —— **这恰好是 opace6 没有、而本机更需要的**。

**阳性/阴性对照**：`kprobe|perf_event|tracing|TRACEPOINT|PERF_SAMPLE` 在 f77.c 全 0，opace6 分别 1/7/2/1/1（阳性成立）；反向对照 f77.c 上 `selinux_state=25`/`enforcing=31`/`LINK_CAP_CAPABLE=4` 均 >0（证明 grep 正常）。Python 全量函数集比对：opace6 定义 171 函数中**恰好 9 个**不在 f77.c。

---

## R7.2 f77.c 缺失机制逐条拆解

### 缺失 #1：direct-probe 全套（6 函数，opace6 L3757-3907）

**解决什么问题（精确化）**：把 f77.c 唯一通道「全表遍历 `init_task.tasks`」降级为两条路之一。f77.c 现状的具体受限：

1. **成本**：`scan_task_once`(`:5322`) 单向沿 `tasks.next`，最多 `DP_TASK_SCAN_LIMIT=32768` 节点、3 pass × 8 retries，每节点读走 `pipe_physical_read`。opace6 direct 路径是 O(1)（`:3893-3895`）。
2. **对 `tasks.prev` 写坏的鲁棒性**：f77.c 自建 `validate_tasks_head_once`(`:5164`)/`candidate_tasks_head_ok`(`:5121`) 兜底 prev 损坏，并加 `calibrate_tasks_offset`(`:5218`) 扫 8..0x1000 标定 `g_tasks_off` —— **opace6 完全没有这三函数**，反证其设备 `tasks=0x550` 直接可用。
3. **无法证明「找到的就是我」**：全表扫描靠 pid/tgid/group_leader/comm **间接**证明；direct 是内核主动交出 `%x0`，是**第一人称证据**。

**依赖符号逐个查本机 kallsyms**：

| 符号 | 本机 | 判据 |
|---|---|---|
| `__set_task_comm`（kprobe 挂钩点） | `ffffffc0801e7b64 T` | ✅ **存在，且与 opace6 用的完全相同** |
| `register_kprobe` / `tracepoint_probe_register` | 各 1 命中 | ✅ |
| `DP_TASK_REAL_CRED_OFF=0x818` / `DP_TASK_CRED_OFF=0x820` | 偏移 | ✅ 与 opace6 **逐字相同** |

⇒ ★ **符号层不是障碍：内核前提在本机是满足的**。

**★ 本机双重硬阻断** `[已实测]`：

| 条件 | 本机实测 | 出处 |
|---|---|---|
| 写 `kprobe_events` | **SELinux 拒** | H53/H54 精确定界「不能 enable 事件」；R2 L319/L517 复述 |
| `perf_event_open()` | **EACCES(13)** ×4 变体 | HANDOFF Y.5 实测表 |
| `/dev/perf`、`/dev/bpf` | **ENOENT(2)**（节点不存在） | HANDOFF L3332 |
| `perf_event_paranoid=-1` | **假象，作废** | uid=2000 在 **LSM hook** 即被拒，sysctl 根本没被求值 |
| tracefs 可读 | ✅ group3012 可读 | 但**可读≠可写**，写仍拒 |

**判定**：**双重且互不补偿**的阻断。①被 SELinux 域策略拒，②被 SELinux LSM hook 拒，两者都是**域策略层而非 capability 层** —— 即使绕过①，②依然拒。

**无法用现有资产绕过**：`/proc/kallsyms` EACCES 已被**离线静态** kallsyms 绕过（110,992 符号，20/20 关键地址逐位相同），但 kprobe 是**运行时动态捕获**，离线化不了。

**移植难度：不可移植（阻断），不是「高」。**

### 缺失 #2：`validate_direct_task_match`（L4332-4363）

不是定位机制，是**交叉校验器**（双通道一致性证明）。f77.c 走单通道，若 `g_tasks_off` 标定错就没有独立第二意见去发现它。

**缓解**：f77.c 已有 `verify_task_cred_pair`(`:4949`) + `read_stable_task_snapshot`(`:5246`，3 次一致读) + `remember_task`(`:5265`) + `TASKS_CALIBRATE_HIT` 回指校验(`:5140-5143`)，在**可获得性**上等价于 direct 的自洽性证明，只缺「独立第二通道」维度。**不建议移植。**

### 缺失 #3：`run_direct_probe_self_test`（L5519-5558）— ★ 唯一推荐

`--probe-task` 独立模式：打开探针 → `prctl(PR_SET_NAME)` 触发 `__set_task_comm` → 读 ring → 校验。**纯能力探针，零副作用（会还原 comm）。**

**为什么推荐**：把「本机 direct 通道不可用」从**推断**（基于历史实测）升级为**本项目自己的、可复现的、针对当前 build 的实测**。成本极低（自包含约 150 行），**且它是一条「几乎肯定失败但失败即证实」的实验**。

| 输出 | 判读 |
|---|---|
| `DIRECT_TASK_PROBE_FAIL stage=open errno=13` | 预期。证实 tracefs 写被拒 ⇒ 固化「direct-probe 不可用」 |
| `stage=open errno=2` | tracefs 未挂载 |
| `DIRECT_TASK_PROBE_PASS` | **重大意外发现**，需重评（但仍非 stageB 瓶颈） |

### 缺失 #4：`transition_enforcing_for_direct_probe`（L4635-4664）

**完整逻辑**：读 enforcing 校验 ==expected → 写 desired → **★ 读回校验**（防 pipe_buffer 竞态/静默失败）→ 失败返回 −1（调用方 `selinux_relaxed=0`，静默跳过 direct）。

**三处调用点与窄窗口边界**：`:4796` parent-open（1→0，包住写 tracefs + perf_event_open）；`:4819` parent-close（0→1）；`:5067/:5082` child 侧。

**★ 真正的答案 —— 根因不是「安全优势」而是硬前置依赖**：opace6 `open_direct_task_probe` 第一步是 `open("/sys/kernel/tracing/kprobe_events", O_WRONLY|O_APPEND)`（L3758），**写 tracefs 受 SELinux `security_tracefs_write` 检查**。opace6 设备（OnePlus/Ace6）域策略**允许** shell 写 kprobe_events（否则整套 300 行代码永不生效）⇒ 为能写它必须把 enforcing 临时置 0。

**f77.c 完全不需要写 tracefs** ⇒ 不需要 enforcing=0 的让步、不需要承担暴露窗口、没有 `parent-abort` 回滚分支。

**f77.c 已有逐字等价物**（`:6993-7024`）：读 enforcing 必须==1 → cred 改写 → 写 0 → 读回必须==0（否则 `hold_cred_unknown()`）→ `ROOT_CHILD_HOLD_PASS` 后写回 1。

**维度对比**：窗口粒度 opace6 更窄（只包 kprobe 开关）；中断回滚 opace6 更周全（`parent-abort`）；**能否在本机生效 f77.c 胜**（依赖 pipe桥已通 vs tracefs 被拒）；**对本机功能增益 = 零**。

> **副产品事实**：opace6 与 f77.c 最终**都**把 `selinux_state.enforcing` 写 0 才拿到 uid=0，且都用 `ROOT_CHILD_HOLD_PASS` 判定 —— 提权落地部分完全一致，与 direct 通道无关。

---

## R7.3 kallsyms / tracefs 阻断分析

### opace6 靠什么拿 task 地址？—— **两条通道，且从不读 `/proc/kallsyms`**

`grep -c kallsyms` 在 opace6 四个 .c 中**全部为 0**（阳性对照：f77.c 有 1 命中，是注释）。它的通道：

| 通道 | 机制 | 位置 |
|---|---|---|
| **①（主）静态常量** | 编译期硬编码 `LINK_INIT_TASK`/`LINK_INIT_CRED`/`DP_TASK_*_OFF` + 运行时 `kernel_slide`（slide 由 stage0 的 boot_id 环回读出） | `:315-347`, `:4404` |
| **②（辅）kprobe+perf** | `p:<grp>/task __set_task_comm task=%x0 real=+0x818(%x0):x64 cred=+0x820(%x0):x64` | `:3815-3819` |

**①才是成功路径真正依赖的**。依据：opace6 三处 direct 调用（`:4866/:4889/:5088`）全部包在 fallback 保护下，`:4873/:4895/:5094` 打印 `STAGE8_TASK_DIRECT_FALLBACK` 后调用 `find_task_stable`（opace6 自己版本的全表扫描，与 f77.c `:5489` 同源）。

⇒ **在 OP13/Ace6 那次真机成功中，direct 通道很可能压根没生效**，成功完全由通道①完成。

### `/proc/kallsyms` 对本机不是阻断

**不需要读** —— 已实现离线 kallsyms 提取（boot.img 直喂 + 预解 Image 两路径），产出 **110,992 符号**，20/20 关键地址逐位相同。**`kptr_restrict` 的封锁已被离线化绕开。**

> 用户设想的「opace6 依赖读 `/proc/kallsyms` ⇒ `kptr_restrict` 阻断 ⇒ 此路不可用」分支，**在本案中不成立**。

### tracefs 阻断才是致命点

| 权限项 | 需要 | 本机实测 | 判死 |
|---|---|---|---|
| 写 `kprobe_events` | ✅ 必须 | **SELinux 拒** | ❌ |
| 读 `events/*/id` | ✅ 必须 | 父节点写被拒，子节点不可达 | ❌ |
| `perf_event_open()` | ✅ 必须 | **EACCES(13)**（LSM hook，sysctl 无关） | ❌ |
| `mmap(perf_fd, MAP_SHARED)` | ✅ 必须 | 依赖上条 | ❌ |
| tracefs 只读 | — | ✅ 可读（group 3012） | 有用但无用 |

**横向参照（同族攻击面全判死 ⇒ 域策略层系统性封锁）**：`perf_event_open` EACCES / `bpf()` EACCES（H112）/ `io_uring_setup` EACCES / `unshare(CLONE_NEWUSER)` EINVAL（USER_NS 未编译）/ `dmesg` EACCES。

**第三方独立佐证**：`refs/k80pro-miro-cve-2026-64560/docs/05-technical.md:352` 把 `perf_event_open` 和 `写 kprobe_events` 两项标为 **「✅ STAGE8_TASK_DIRECT_FALLBACK」** —— 独立第三方认定可放弃。

---

## R7.4 参数逐项对账

### profile JSON（`profiles/opace6/ee5ee448d2985.json`）关键项

OnePlus PLQ110 / OP6113L1 · `kernelRelease=6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k` · pageSize 4096 · 8 CPU · `uhid=a:ef` · **`kallsymsNumSyms=110445`** · `imageBase=0xffffffc080000000` · `imagePhys=0xa8000000` · `memstartAddr=0x80000000` · **`physicalDelta=0x28000000`** · `btfOffset=0x172b214` · `randomTableDataOffset=0x227a160` · `bootidParent=0xffffff802a27a160` · `cycleC=0xffffff802a15dad0` · `timerGoal=40000` · **`kernelIdenticalTo: op13-bca736de6db3`**（OnePlus OP13）

`vulnerabilityEvidence`: `timerLockSighand` NOT_FOUND / `cpuTimerTaskRcu` NOT_FOUND / **`posixCpuTimerDel` FOUND @`0xffffffc0801a71c8`** / `lockTaskSighand` FOUND

### `LINK_*` 三方对账

| 常量 | opace6 | f77.c | 本机 kallsyms | 差值 | 判定 |
|---|---|---|---|---|---|
| `LINK_IMAGE_BASE` | `0xffffffc080000000` | 同 | `_text` 同 | **0** | ✅ 一致 |
| `DIRECT_MAP_BEGIN` | `0xffffff8000000000` | 同 | — | — | ✅ 一致 |
| `MEY_PHYS_DELTA` | `0x28000000` | 同 | 反推一致 | — | ✅ 一致 |
| `LINK_INIT_TASK` | `0xffffffc08215e780` | `0xffffffc08217e280` | `0xffffffc08217e280` | **`+0x1fb00`** | ⚠️ 不同 |
| `LINK_INIT_CRED` | `0xffffffc082170c48` | `0xffffffc082190790` | `0xffffffc082190790` | `+0x1fb48` | ⚠️ |
| `LINK_SELINUX_STATE` | `0xffffffc08239c620` | `0xffffffc0823ba418` | `0xffffffc0823ba418` | `+0x1ddf8` | ⚠️ |
| `LINK_MISC_LIST` | `0xffffffc08227a260` | `0xffffffc08229b190` | — | `+0x20f30` | ⚠️ |
| `LINK_SYSCTL_BOOTID` | `0xffffffc0823bd618` | `0xffffffc0823db420` | — | `+0x1de08` | ⚠️ |
| `LINK_UHID_FOPS` | `0xffffffc0812f9378` | `0xffffffc0812f1498` | `0xffffffc0812f1498` | **`-0x7ee0`** | ⚠️ |
| `LINK_ASHMEM_IOCTL` | `0xffffffc080c9d1b0` | `0xffffffc0804742e8` | `0xffffffc0804742e8` | **`-0x828ec8`** | ⚠️ |
| `LINK_ASHMEM_OPEN` | `0xffffffc080c9dae0` | `0xffffffc080474f34` | `0xffffffc080474f34` | `-0x828bac` | ⚠️ |
| `LINK_CONFIGFS_READ_ITER` | `0xffffffc0804a12fc` | `0xffffffc080a310e0` | `0xffffffc080a310e0` | **`+0x58fde4`** | ⚠️ |
| `LINK_MODULE_DIRECT_BASE` | `0xffffffc081697da0` | `0xffffffc081698a28` | `0xffffffc081698a28` | **`+0xc88`** | ⚠️ |
| `LINK_MEMSTART_ADDR` | `0xffffffc081697dc0` | `0xffffffc081698a48` | `0xffffffc081698a48` | `+0xc88` | ⚠️ |
| `LINK_ANON_PIPE_BUF_OPS` | `0xffffffc081187348` | `0xffffffc081183cc8` | `0xffffffc081183cc8` | `-0x3680` | ⚠️ |
| `LINK_SDATA` / `LINK_END` | `0xffffffc082140000` / `0xffffffc0823f0000` | `...2160000` / `...2410000` | — | `+0x20000` | ⚠️ |
| `bootidParent`（direct） | `0xffffff802a27a160` | `0xffffff802a29b090` | 反查 off `0x229b090` | `+0x1ef30` | ⚠️ 不同但**同公式** |

**`DP_TASK_*` / `DP_CRED_*` 结构偏移**：`tasks=0x550`、pid/tgid/group_leader=`0x618/0x61c/0x658`、real_cred/cred=`0x818/0x820`、comm=`0x830`(16)、`DP_CRED_SIZE` + 13 个字段偏移、扫描参数 3/3/8/32768 ⇒ **13/13 逐字一致**。

### ★ 裁决：「哪些不同 = 错误」这一前提**不成立**

1. `LINK_IMAGE_BASE`/`DIRECT_MAP_BEGIN`/`MEY_PHYS_DELTA`/pageSize/8CPU **完全一致** ⇒ GKI 同底
2. `DP_TASK_*`/`DP_CRED_*` **全部逐字一致** ⇒ 同 GKI ABI
3. `kallsymsNumSyms` **110445 vs 110992**（差 547），且**每个数据符号差值非均匀** ⇒ **vendor 树不同 ⇒ 不同 build**
4. profile 自写 `kernelIdenticalTo: op13`（OnePlus）
5. **f77.c 每个 `LINK_*` 都与本机 kallsyms 逐位吻合** ⇒ **f77.c 是对的**

**⇒ 明确结论：f77.c 的 `LINK_*` 不要动。opace6 的 `LINK_*` 是它自己那台机器的。**

opace6 CHANGELOG 里正有这类错误的真实教训：「**`OPACE6_DIRECT_BOOTID_PARENT` 地址错误（致命）**… 移植时误用了 dada（小米 15，**不同内核**）的 `0xffffff802a259e50`」。反向搬运会重演同一 bug 且更隐蔽。

### opace6 有而 f77.c 没有的（潜在新能力）

| 项 | 价值 | 可用性 |
|---|---|---|
| `DP_PERF_DATA_PAGES=8` | perf ring 大小 | ❌ 随 direct 阻断 |
| `kallsymsLayout.*`（7 项）+ `btfOffset` | 离线从 Image 提取全部符号 | ⚠️ **本项目已有等价物**（110,992 符号）。**方法可复用，数值不适用** |
| `twoNodeCycles=1` / `randomTableDataOffset` | boot_id 环回圈数 | ⚠️ H50 已用 boot_id 环回独立证过写原语 |
| `vulnerabilityEvidence.posixCpuTimerDel` | 漏洞触发点符号 | ✅ 可查本机交叉验证 |
| **`tools/port_target.py` + profile JSON schema** | ★ **参数化移植流水线**（设备参数与逻辑分离） | ✅ **最值得借鉴的工程资产** |
| `DADA_SUCCESS_SCHEDULE` | `stage0=two-rounds-of-1-16` | ⚠️ 自述「inherited, may need calibration」 |

---

## R7.6 核心判断：opace6 成功路径是否经过 stageB？

### 判定 1：**必然经过 stageB/misc 桥** `[源码已证]`

`exploit-fanout-opace6.c:5680-5799` 的 `main()` 是**硬编码两阶段串行**：

```
① BOOT_VALIDATE_KASLR (:5681)
   forged_parent = direct_bootid_parent; forged_child = direct_cycle_c
   for attempt in 1..max: exploit_attempt(...)
   if (!stage0_pass) return 1;                      ← 唯一出口是失败
   kernel_slide = stage0_result.slide;               ← ★ slide 只能由 stage0 取得

② BOOT_VALIDATE_MISC_BRIDGE (:5712)
   forged_parent = LINK_MISC_LIST + kernel_slide - 8;  ← ★ 桥写原语
   forged_child  = fake_misc_child(...)
   for attempt in 1..controlled_max: exploit_attempt(...)
       └─ if (result > 0):
            bridge_fd = open_verified_bridge(&observed);  ← ★ 必须
            restore_misc_list(bridge_fd);                  ← ★ 必须
            restore_stage0_state(bridge_fd, ...);          ← ★ 必须
            bridge_read64/bridge_write64 自检
            prepare_pipe_reclaim(bridge_fd, &pipe_probe);
            run_physical_rw_probe(bridge_fd, &page, &pipe_probe);
            run_stage8_root_probe(bridge_fd, &pipe_probe);  ← ★ 提权
   MISC_BRIDGE_MISS_PRESERVE → hold_corrupted_state();
```

**三重强制**：`kernel_slide` 只能来自 stage0；`bridge_fd` 只能来自 `open_verified_bridge()`；两个失败分支**无绕过路径**。

**CHANGELOG 独立佐证**：「bridge 任意读写建立」是**必经步骤**，不是可选旁路。

### 判定 2：direct-probe **不在**成功路径上

三条证据：三处 fallback 保护；第三方 `k80pro-miro` 独立判定可放弃；`__set_task_comm` 符号齐备却仍写带 fallback 的代码。

### 判定 3：对本机的含义

| 问题 | 回答 |
|---|---|
| opace6 是否证明「不经 stageB 也能 root」？ | **否**。成功路径与 f77.c 完全同构：stage0(KASLR)→stageB(misc bridge)→pipe reclaim→physmap 读写→stage8 cred 覆写→enforcing=0→root child |
| opace6 成功靠什么？ | 靠 **stageB W1 命中 + `open_verified_bridge()` 成功** |
| 本机卡 stageB W1，opace6 能解释吗？ | **不能**。两者在同一关卡，opace6 过了、本机没过。差异必然在 **W1 命中概率 / 落点语义 / 时序参数**，不在 stageB 之后的 direct 机制 |
| direct 缺失是本机瓶颈吗？ | **不是**。它在 stage8（stageB 之后），本机根本没走到那里 |

> **opace6 不是本机的答案，而是一把「排除法」的尺。**
> 1. **证明 stageB 路线本身可通**（同 exploit 同 CVE，同代 GKI 上过）⇒ 本机 W1 未命中**不是** exploit 原理问题，是**参数标定/时序/落点**问题
> 2. **证明 direct 机制可放弃** ⇒ 不必投入 kprobe/perf 移植（何况双重 EACCES 阻断）
> 3. **提供 `port_target.py` + profile JSON 参数化流水线** ← 才是真正遗产

---

## R7.7 建议顺序

| 优先级 | 项 | 理由 |
|---|---|---|
| **1** | 移植 `run_direct_probe_self_test`（+ 6 个 direct 函数，约 150 行） | 把「不可用」从推断升级为实测。**预期失败，但失败即证实** |
| **2** | 移植 `tools/port_target.py` + profile JSON 参数化流水线 | 纯 Python+JSON，无内核交互。防再现「误用他人常量」致命坑 |
| **3** | ❌ 其余 8 个 direct 函数 + `transition_enforcing` | 已实测双重 EACCES 阻断 |
| **4** | ❌❌ **明确禁止**：移植任何 opace6 的 `LINK_*` 到 f77.c | 非均匀差值 + 符号数不同 + opace6 自家已踩过此坑 |

**若 W1 仍无突破，更值得投的方向（基于本项目自有资产）**：

1. **调 W1 命中概率**：`race_timing_slot` 调度（opace6 的 `two-rounds-of-1-16` 自述是继承值需重标）；f77.c 已有 `attempt_thermal_gate`(`:892`) 可继续挖
2. **换 W1 落点**：f77.c 已实现 4 种（`:756-780` V-e 系列 + H163b 独立透镜 + H97 方案A）；opace6 用的是标准 `alias(misc_list)-8`，与 f77.c 默认一致 ⇒ **无差异化信息**
3. **★ 加 `--probe-bridge` 独立自检**：用 `h74_probe_fake_fops`(`:2089`) 的 ENOTTY(25) 判据做**不依赖 bridge 读**的 W1 命中探针，**在 stageB 开火前**就能判定 W1 落点是否正确 —— **当前 1/127 命中窗口太 precious，每次 boot 的信息量要最大化**