# 设备基线与 CVE-2026-98260 标识说明

> 本文件是 **MagicOS 11 / CVE-2026-98260 路线**的单一基线入口。
> 所有数值均为本机（MEY-AN00 / MagicOS 11）实测或从本机固件提取，**不是从其他机型继承**。
> 证据等级沿用固定四级划分：
> `已实测` / `汇编已证未实测` / `源码推断未验证` / `未验证基线`。

## 0. 项目范围（先读）

**本项目的提权研究与全部数值只针对荣耀 500（MEY-AN00）。**
其他 SoC 与其他内核 build 的偏移、符号地址、结构体布局**一律不可复用**；
本项目基线只以本机 vmlinux / BTF / 反汇编为准。

| 项 | 判定 |
|---|---|
| 唯一目标 | 荣耀 500 / **MEY-AN00** |
| 主攻平台 | **SM8735**（`sun` / 第四代骁龙 8s 移动平台 / Snapdragon 8s Gen 4） |
| 内核唯一主线 | **6.6.118 / android15-6.6**，两个 build：MagicOS 10 `gf17133276a57`、MagicOS 11 `g554929766a0d` |
| 不纳入 | 6.1 线、其他 SoC 的机型、任何非本机 vmlinux 推出的数值 |

---

## 1. 设备与系统版本基线

| 项 | 值 | 来源 | 置信度 |
|---|---|---|---|
| 市场名 | 荣耀 500 | 设备设置界面 | 已实测 |
| 型号代号 | **MEY-AN00** | `ro.product.device` | 已实测 |
| SoC 平台 | Qualcomm **SM8735**（Snapdragon 8s Gen 4 / 第四代骁龙 8s；平台代号 `ro.board.platform=sun`） | 本机 logcat `CPU_INFO=第四代骁龙8s移动平台`、`/proc/cpuinfo` CPU 拓扑 1+3+2+2、厂商规格三方一致 | 已实测（型号属规格信息，**不进任何 exploit 常量链**） |
| 系统版本（设备实装） | **MagicOS 11.0.0.110** | 设置 → 关于手机 | 已实测 |
| OTA 包版本标识 | `MEY-LGRP1-CHN 11.0.0.109(SP8)` | 离线增量包 `SOFTWARE_VER.mbn` 实读 | 已实测（离线包） |
| 完整构建号 | `SP5C00E110R102P2` | 上游 payload 文件头注释，**目标为 AAK-AN00** | ⚠ 跨设备，**不作本机依据** |
| 内核 release | **`6.6.118-android15-8-g554929766a0d-abogki544555896-4k`** | 本机拆包 vmlinux / `uname -r` | 已实测 |
| GKI KMI | `android15-6.6` | 内核版本串 | 已实测 |
| 内核镜像 sha256 | `ebb5bd6e70c9a19d9fb536694201f471cb4c237f77bf028fad7b6abf8e6b3409` | 本机 `kernel_11.img` | 已实测 |
| 恢复符号数 | 111,074 | `kernel_11.elf`（vmlinux-to-elf） | 已实测 |
| BTF 结构体数 | 10,692 | 设备自带 `vmlinux.btf` | 已实测 |
| 页大小 | 4 KiB | 内核配置 `-4k` | 已实测 |
| Bootloader | **锁定** | 设备状态 | 已实测 |
| SELinux（常态） | Enforcing | `getenforce` | 已实测 |
| 执行域 | **shell(uid=2000)**，经 Shizuku | `id` | 已实测 |
| root 形态 | **临时 root**（重启失效，不写分区） | 成功案例 | 已实测 |

### 1.1 三处容易混淆的版本标识（务必区分）

| 容易误读的点 | 正确解释 |
|---|---|
| **109 与 110 不一致** | `11.0.0.109(SP8)` 是**离线 OTA 增量包内** `SOFTWARE_VER.mbn` 的包标识；`11.0.0.110` 是**设备设置界面**显示的已安装系统版本。二者是「包标识」与「实装版本」，不是矛盾。`offsets_11.h` 头注释沿用前者，交付包 README 沿用后者，**指向同一份内核二进制**（sha256 相同），不影响任何偏移。 |
| **`android15-8` ≠ Android 15** | 这是 **GKI KMI 分支名**（`android15-6.6`），只描述内核基线，不代表 userspace Android 大版本。不要据此推断 Android 16/17。 |
| **`SP5C00E110R102P2` 不是本机事实** | 该串来自上游 `nisu123f/dada-cve-AN00` 的 payload 头注释，其目标机型是 **Honor AAK-AN00**。它与本机「内核 build 相同」是有用的线索，但**构建号本身未经本机核实**，故在本仓库中只作为上游来源说明出现，不进入任何判定链。 |

**关于 `h212` 报告里「记忆中 SM8735 作废」**：该行是 D5「平台身份」探针，原文
`ro.board.platform=sun`、Android 16 —— 记忆中「SM8735」作废。
作废的是**「把 SM8735 当作设备侧可直接读到的平台身份字符串」这条证据链**：
`getprop ro.board.platform` 返回的是内核平台代号 `sun`，不会返回 `SM8735` 这个市场型号。
**不是**作废 SoC 型号本身——本机 logcat `CPU_INFO=第四代骁龙8s移动平台`、
`/proc/cpuinfo` 的 1+3+2+2 拓扑与厂商规格三方一致 ⇒ MEY-AN00 = SM8735 成立。
「平台代号」与「SoC 型号」是两个层级，不冲突。
> 置信度：本机实测交叉 + 文档解读（原报告未展开该措辞，此澄清属推断性）。
> 可证伪判据：若 `getprop ro.board.platform` 现场返回 `SM8735` 字符串，则上述解读错误。

### 1.2 跨设备数值隔离（硬纪律）

同一内核版本下，厂商裁剪与编译器差异会造成结构体布局、符号地址、fops 槽位完全不同。本仓库遵守：

1. **任何偏移/符号地址/常量必须来自本机 vmlinux 符号表、本机 BTF `offsetof` 或本机反汇编实读三者之一**，并标注是哪一种。
2. 上游 payload 的 11 项常量之所以可用，是因为**逐条与本机符号表/BTF 对账后 11/11 一致**（见 §5），而不是因为「上游说它适配」。
3. 从其他 SoC / 其他内核 build 继承的**只有方法论**，不继承任何数值。
4. 可安全继承的方法论：一 boot 一发；判据必须用独立透镜（禁止循环自证）；`pr_info` 重定向是块缓冲、panic 会丢尾部日志；追加写日志前先 `rm -f`；`rb_erase` 双路径是 8 字节任意值写任意地址。

---

## 2. 「98260」在本项目中的标识含义（分层）

`98260` 不是单一标识符，在本仓库不同语境中指向不同层级的东西。完整映射如下：

| 层级 | 标识字面 | 精确含义 |
|---|---|---|
| **CVE 编号** | `CVE-2026-98260` | Linux 内核 **POSIX CPU timer 子系统**（`kernel/time/posix-cpu-timers.c`）与 **`fs/exec.c` exec 清理路径**之间的 use-after-free。多线程进程中非 leader 线程持有 `CLOCK_THREAD_CPUTIME_ID` / `CLOCK_PROCESS_CPUTIME_ID` 定时器后调用 `execve()`：exec 释放旧 `signal_struct`，定时器已脱离 timerqueue 却仍作为 `rb_node` 参与红黑树操作；`k_itimer`（`posix_timers_cache`，本机 264 B / order-1 / 31 对象每页）被 `kfree` 归还 slab 后，页内 `rb_node` 仍被 `rb_erase()` 读写。堆喷占回该页者同时控制写入目标与写入值。 |
| **上游修复标识** | commit **`acb03d388181`** | 引入 `posixtimer_exec()`，把定时器清理提前到 `begin_new_exec` 之前。已修版本：6.6.158 / 6.12.112 / 6.18.54 / 7.2.8 及之后的 stable。 |
| **补丁判定标识** | `posixtimer_exec` 符号存在性 | **唯一权威判据是二进制符号，不是版本号算术**（厂商会 cherry-pick）。符号存在 → 已修；符号缺失且 `exit_itimers()` / `posix_cpu_timers_exit()` 仍在 → 未修补。本机 111,074 个符号中 `posixtimer_exec` **0 命中** ⇒ 未修补。 |
| **profile 字段** | `vuln_type = "cve-2026-98260"` | GhostKey 系 App 的 profile 字段，决定加载哪一套 exploit。profile 按 `uname -r` **精确匹配**，不做 KMI 前缀回退（同 KMI 不同 build 的符号地址不稳定，回退会套错偏移导致 `exit=2`）。 |
| **上游项目 A** | `Again1996-bit/CVE-2026-98260-GhostKey` | Android App（Kotlin + Compose + NDK），`uaf_plant.c` / `calib.c` / `timer_probe.c` / `pc98260_rootd.c` / `ksu.c`。**profile 表驱动**，内置 13 个 profile，其中 6.6.118 系列 4 个，**不含本机 `g554929766a0d-abogki544555896`** ⇒ 需导入 boot.img 生成 profile 或灌入本仓库 [`src/magicos11-98260/profile/`](../src/magicos11-98260/profile/) 的本机 profile。 |
| **上游项目 B** | `nisu123f/dada-cve-AN00` | 单文件 C payload `kernel/cve-2026-98260.c`（1962 行）+ GhostLock App 工程。**源码内硬编码** AAK-AN00 常量；App 不做机型门控，恒跑该 payload。本仓库的 11 项常量对账即以此源码为对照物。 |
| **交付目录** | `magicOS11-98260-kit/` / [`src/magicos11-98260/`](../src/magicos11-98260/) | 本机适配交付包（工作区）与其公开文本部分（本仓库）。 |
| **payload 文件** | `cve-2026-98260-uid0` | 静态非 PIE arm64 可执行文件。md5 `3e68cb01fba10447b0a34361b1326fac`，sha256 `7842ea6a96285f4ca3275776a9306f08b8c9404fb1eb99dd4cafcf362537ec80`。**二进制不入库**，仅给校验值与可复现编译命令（§6）。 |
| **常量组** | `STATIC_TIMER_SITE` 等 11 项 | 从本机 vmlinux 符号表 / BTF 逐条对账的地址与偏移，见 §5。 |
| **与 64560 的关系** | 同子系统、不同 CVE | `CVE-2026-64560` 也是 `posix-cpu-timers` UAF（timerfd/fanout 路线），但触发路径与 98260 的 **exec 清理路径**不同；两者都依赖 tracefs 可读性，但**不是同一个洞**，补丁判定与常量组不可互换。 |

---

## 3. 漏洞机理与写原语

| 步骤 | 内容 |
|---|---|
| 1 | 多线程进程，非 leader 线程创建 CPU timer，随后 `execve()` |
| 2 | exec 释放旧 `signal_struct` → `posix_cpu_timer_del()`；定时器已脱离 timerqueue 却仍被当 `rb_node` 操作 |
| 3 | `k_itimer` 被 `kfree` 归还 `posix_timers_cache` 的 order-1 页 |
| 4 | 堆喷占回该页 → 控制页内伪造的 `rb_node` 字段 |
| 5 | `rb_erase()` 走 **case-1-left**：`__rb_parent_color = 节点自身地址 A`（使 `RB_EMPTY_NODE()` 为真）、`rb_right = NULL`（强制左分支）、`rb_left = S`（目标地址） |
| 6 | 结果：**`*(u64*)S = 0`，一次 8 字节清零写** |

**两条变现路径**

| 路径 | 做法 | 特点 |
|---|---|---|
| A. 零写 uid | `S = 子进程 cred + 8`，清掉 uid/gid | 不动 SELinux、不伪造 cred，子进程 SELinux blob 真实合法；上游 dada 主推 |
| B. fake cred | 页上铺伪造 `struct cred`（cap 全量、euid=0、security→sid=1），`S = task->cred` | 同时需把 `selinux_state.enforcing` 与 `panic_on_warn` 置 0 才能 insmod |

拿到 uid=0 且具备 `CAP_SYS_MODULE` 后，由 `ksud late-load --kmi android15-6.6` 载入 KernelSU 模块，`/proc/modules` 出现 `kernelsu` 即成功。

> ⚠️ 写原语会**连带损伤同页邻居**（8 字节写覆盖目标 ± 偏移内的相邻字段），写值与写目标必须同时设计。
> ⚠️ `struct cred` 的 `cred` 与 `real_cred` 是两个独立 qword，严格需要两次写 = 两个 boot。

---

## 4. 本机补丁状态与 CVE 裁决

| 判定项 | 本机观测 | 结论 | 置信度 |
|---|---|---|---|
| `posixtimer_exec` | 111,074 符号中 **不存在** | 修复 commit 未合入 | 已实测（符号层） |
| `exit_itimers` | 存在 @ `0xffffffc0803afad4` | 老清理路径仍在 | 已实测 |
| `posix_cpu_timers_exit` | 存在 @ `0xffffffc08016e30c` | 老清理路径仍在 | 已实测 |
| `begin_new_exec` 调用序 | 清理位于 `exec_task_namespaces` 之后（修复前形态） | 佐证未修补 | 汇编已证 |
| 内核版本 6.6.118 < 6.6.158 | 版本侧未跨过修复点 | 佐证（**不作主判据**） | 已实测 |

| CVE | 本机状态 | 判据 |
|---|---|---|
| CVE-2026-43284（DirtyFrag） | **已修补** | `esp_input` 指令数 203 → 205，新增 `cbnz/ldrb/tbz` COW 检查 |
| CVE-2026-46242（Bad Epoll） | **已修补** | `ep_remove` 内出现 `bl fput` |
| CVE-2026-43499（GhostLock） | **已修补** | 镜像 sha256 与已验证的 PPG 构建逐字节相同 |
| CVE-2026-64560 | **未修补**，但本机未跑通 | `posix_cpu_timer_set/del` 指令数与修复前构建一致 |
| **CVE-2026-98260** | **未修补，且已实测成功** | §4 符号判据 + [`research/MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_success-case.md`](research/MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_success-case.md) |

**已排除的攻击面**：`USER_NS` 与 `NF_TABLES` 均 `not set`（unshare/CLONE_NEWUSER 与 nf_tables 类路线不可用）。若 tracefs 被封，98260 与 64560 双堵，候选退路为 BPF（本机 `BPF_UNPRIV_DEFAULT_OFF` 未开）→ perf（`perf_event_paranoid=-1`）→ io_uring，**均未在本机验证**。

---

## 5. 11 项常量对账（全部来自本机固件，零推断）

来源：本机 `kernel_11.elf`（`llvm-nm`，111,074 符号）+ 本机 `vmlinux.btf`（`offsetof`）+ 反汇编实读。
对照物：上游 `nisu123f/dada-cve-AN00` 的 `kernel/cve-2026-98260.c` 硬编码宏。

| 常量 | 值 | 来源类型 |
|---|---|---|
| `do_timer_create + 0x94`（`STATIC_TIMER_SITE`） | `0xffffffc0803afcec` | 符号表：`do_timer_create=0xffffffc0803afc58` + 0x94 |
| `selinux_state` | `0xffffffc0823ba418` | 符号表 |
| `panic_on_warn` | `0xffffffc08216ae0c` | 符号表 |
| `root_user` | `0xffffffc08218f228` | 符号表 |
| `init_user_ns` | `0xffffffc08218ef98` | 符号表 |
| `init_ucounts` | `0xffffffc082190cf8` | 符号表 |
| `init_groups` | `0xffffffc082190788` | 符号表 |
| `prepare_creds + 0x20` low21 | `0x38458` | 符号表 + 地址推算 |
| `copy_process + 0x144` low21 | `0x1cb240` | 符号表 + 地址推算 |
| `task_struct.cred` / `sizeof(task_struct)` | `0x820` / `0x12c0` | **BTF `offsetof`** |
| `k_itimer` / `it` / `cpu_timer.node` | `0x108` / `0x78` / `0x0` | **BTF `offsetof`** |

**11/11 一致。** 另附本机 BTF 结构布局（与 MagicOS 10 的 `0x838/0x840/0x850` **不同**，旧偏移表不可复用）：

| 结构 | 关键偏移 |
|---|---|
| `task_struct`（0x12c0） | `real_cred 0x818` · `cred 0x820` · `comm 0x830` · `pid 0x618` · `tgid 0x61c` · `tasks 0x550` · `mm 0x5a0` · `nsproxy 0x870` · `posix_cputimers 0x778` |
| `cred`（0xb8） | `usage 0x0` · `uid 0x8` · `gid 0xc` · `cap_inheritable 0x30` · `cap_permitted 0x38` · `cap_effective 0x40` · `cap_bset 0x48` · `cap_ambient 0x50` · `security 0x80` · `user 0x88` · `user_ns 0x90` · `ucounts 0x98` · `group_info 0xa0` |
| `k_itimer`（0x108） | `list 0x0` · `it_lock 0x20` · `sigq 0x70` · **`it (cpu_timer) 0x78`** · `rcu 0xf8` |
| `cpu_timer`（0x50） | `node 0x0` · `head 0x20` · `pid 0x28` · `elist 0x30` · `firing 0x40` · `handling 0x48` |
| `file_operations`（0x108） | `unlocked_ioctl 0x48` · `open 0x68` · `release 0x78` |

---

## 6. 可复现路径

### 6.1 基线重建（换设备/换 OTA 时必做）

```bash
# 1. 设备身份与内核版本
cat /proc/version; cat /proc/sys/kernel/random/boot_id; uname -m

# 2. 从本机固件拆内核：magiskboot unpack -> extract-vmlinux -> vmlinux-to-elf
#    产物：kernel_11.img / kernel_11.elf / vmlinux.btf

# 3. 符号表（对账 11 项常量）
llvm-nm -n kernel_11.elf > symbols_11.txt
grep -c posixtimer_exec symbols_11.txt      # 期望 0 => 未修补

# 4. BTF 结构偏移（pahole / bpftool btf dump / ctypes offsetof）
#    注意本机解析坑：BTF 头 hdr_len@4、type_off@8；段偏移相对 hdr_len(24)；
#    btf_member 步长 12 字节（不是 8）。
```

产物对照：本仓库 [`src/magicos11-98260/offsets_11.h`](../src/magicos11-98260/offsets_11.h)、
[`btf_offsets_11.json`](../src/magicos11-98260/btf_offsets_11.json)、
[`key_symbols_11.txt`](../src/magicos11-98260/key_symbols_11.txt)、
[`profile/`](../src/magicos11-98260/profile/)。

### 6.2 payload 复现编译（2026-11-07 已实测）

上游源码已收录于 [`src/magicos11-98260/upstream/`](../src/magicos11-98260/upstream/SOURCE-NOTICE.txt)，
封装脚本为 [`build.sh`](../src/magicos11-98260/build.sh)。**必须锁定 NDK 27.0.12077973（r27）**：

```bash
ANDROID_NDK_HOME=/path/to/ndk/27.0.12077973 sh build.sh
```

脚本内是与上游 `build.sh` 逐项相同的 flags：
`-std=gnu11 -O2 -g -static -pthread -D_GNU_SOURCE` + `-Wno-*` + `llvm-strip --strip-all`。

| 工具链 | 产物 | md5 | 与现役 payload |
|---|---|---|---|
| **NDK 27.0.12077973 (r27)** | 462,584 B | `3e68cb01…` / sha256 `7842ea6a…` | ✅ **逐字节相同** |
| NDK 27.2.12479018 (r27c) | 462,584 B | `4a5849d4…` | ❌ 仅 6 字节差异 |

6 字节差异全部位于偏移 **652–720** 的 `.note.android.ident`，内容是 NDK 版本串
（`r27/12077973` ↔ `r27c/12479018`），**代码体零差异**。
可证伪判据：`cmp -l` 两份产物，差异计数应恰好为 6，且全部落在该区间。

⚠️ 早期文档写的简化命令（`-O2 -static`，无 `-std/-g/-pthread/-D_GNU_SOURCE`）**不足以复现**，已废弃。
哈希一致即证明二进制里的常量就是源码里那批（已与本机符号表/BTF 对账过的 11 项），**字节级可复现**。

### 6.3 部署与命中判据

见 [`onefire.sh`](../src/magicos11-98260/onefire.sh)（PC 侧投放）、
[`run.sh`](../src/magicos11-98260/run.sh)（设备侧）与
[`README`](../src/magicos11-98260/README.md)。硬门槛：

> **置信度**：payload 本身**已实测成功**（2026-11-02，走 GhostLock APK / Shizuku UserService 投放）；
> `onefire.sh` + `run.sh` 这条编排路径**未真机验证**，属 `[源码推断未验证]`。
> 仓库当前状态为**半开箱**：可执行主体已入库，设备侧环境仍需自备。

| 门槛 | 期望值 | 失败含义 |
|---|---|---|
| `id -u` | `2000`（shell 域，经 Shizuku） | app 域执行必然 Permission denied，结果无意义 |
| `uname -r` | `6.6.118-android15-8-g554929766a0d-abogki544555896-4k` | 换 OTA 内核必须重新标定全部常量 |
| `trace_pipe_raw` | 可读 | 98260 与 64560 双堵，需改走其他攻击面 |
| `check` / `leak` | 只读自检通过 | `leak` 零写入，安全；不通过则停在只读取阶段 |

**成功判据必须是独立透镜**（不看 payload 自报）：

```bash
id                              # uid=0(root)
getenforce                      # Permissive
grep -w kernelsu /proc/modules  # 出现 kernelsu 行
su -c id                        # uid=0(root) ... u:r:ksu:s0
```

### 6.4 风险与回滚

- **不改任何分区** → 不会变砖；最坏是注入阶段 panic 重启。判断重启读 `boot_id` 变化，**不要只看 uptime**。
- **回滚 = 重启**。root 临时，重启失效。
- BL 锁定 + `verifiedbootstate=green` ⇒ **持久化 root 物理上不可能**。
- 成功后进程驻留是**故意的**：该页承载活着的 `task->cred`，进程退出会把页还给 slab，随后 `cleanup_timerqueue()` 在陈旧 `rb_node` 上操作会 panic。**不要 kill，清理只能重启。**
- **一 boot 一发**：同 boot 反复打会累积破坏内核数据结构甚至 hang。

---

## 7. 未验证项（明确留白）

| 项 | 为什么不能离线定 | 现场怎么定 |
|---|---|---|
| `profile.page_offset` | `memstart_addr` 开机才赋值，镜像中静态值为 `0xffffffffffffffff` | `calibrate-b` 现场解算；日志出现 `[calib_b] warn: fallback to profile default` 表示解算失败、用了候选值，成功率下降 |
| tracefs 可读性（shell 域） | SELinux 策略厂商定制，AAK-AN00 能读不代表 MEY-AN00 能读 | `ls -l /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw`；跑 `check` |
| 直接映射基址 | 运行时值 | `check` / `calibrate-b` |
| 注入阶段重启概率 | 竞争型利用，与当时 slab 状态相关 | 一 boot 一发，失败换 boot 重来 |
| CFI / MTP / MTE 加固状态 | 未逐项核对 | 反汇编核对间接调用点 |

---

## 8. 引用

- 设备与版本基线：本文件 §1
- 路线裁决全文：[`research/MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_implementation.md`](research/MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_implementation.md)
- 偏移清单：[`research/MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_kernel-offsets.md`](research/MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_kernel-offsets.md)
- 成功记录：[`research/MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_success-case.md`](research/MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_success-case.md)
- 上游署名：[`../REFERENCES.md`](../REFERENCES.md)
