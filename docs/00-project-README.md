# MEY-AN00 临时 Root 复现工程（离线部分）

> 设备：Honor MEY-AN00 · MagicOS 10.0.0.175(C00E170R404P2) · Android 16 · BL 锁定  
> 内核：`6.6.118-android15-8-gf17133276a57-abogki518694926-4k`（`#1 SMP PREEMPT Sun May 31 12:01:53 UTC 2026`）  
> 目标漏洞：**CVE-2026-43499**（`rt_mutex` stack-UAF 写原语）→ 配合 **CVE-2026-64560**（misc-bridge 读原语）提权  
> 本工程只做**离线分析 + 组装**：从固件推导出 MEY-AN00 专属内核偏移，不接触真机。

---

## 0. 本工程产出（一眼看全）

| 路径                                      | 内容                                            |
| --------------------------------------- | --------------------------------------------- |
| `firmware/boot.img`                     | 从固件包解出的 boot 分区（100 MB）                       |
| `firmware/vendor_boot.img`              | vendor_boot 分区                                |
| `analysis/output/kernel_mey_an00.raw`   | **裸内核 Image**（37,128,704 B，未压缩）               |
| `analysis/output/kallsyms_mey_an00.txt` | **全量符号表**（110,992 条，`addr type name`）         |
| `analysis/output/kallsyms_key_syms.txt` | 关键利用符号（vaddr + 镜像偏移）                          |
| `analysis/output/btf_offsets.txt`       | 关键结构体字段偏移（BTF 解析）                             |
| `analysis/output/btf_structs_all.txt`   | BTF 全部结构体名（10,692 个）                          |
| `analysis/output/ikconfig_mey_an00.txt` | 内核配置（IKCFG，213 KB）                            |
| `exploit-src/target_mey_an00.h`         | **MEY-AN00 的 exploit `target.h`（自动生成，可直接接编）** |
| `exploit-src/offset_mey_an00.h`         | 符号 + 结构体偏移速查（人读版）                             |
| `exploit-src/dc15/`                     | dc15 参考实现源码（CGA-W00 6.1.157 版）                |
| `exploit-src/dc15-exploit-src.zip`      | 上述源码原始压缩包                                     |
| `exploit-src/build_ndk.sh`              | **NDK 一键编译脚本**（自动带 `-DTARGET_HEADER`）         |
| `tools/mey_online_check.sh`             | **手机端在线验证脚本**（指纹 + 分阶段 + 日志回收）                |
| `android/ShizukuVerifier/`              | **Shizuku 验证 APK 工程**（Android Studio 直接打开构建）  |
| `docs/在线验证SOP-真机.md`                    | **真机在线验证 SOP**（接线 / 无线 / 顺序 / 回传）             |
| `docs/`                                 | 其余 4 份交接/思路/SOP 文档                            |
| `analysis/scripts/`                     | 全部离线工具脚本                                      |

---

## 1. 目录结构

```
D:/MEY-AN00-root-repro/
├── README.md                        ← 本文件
├── firmware/                        boot.img / vendor_boot.img
├── analysis/
│   ├── output/                      内核 Image + kallsyms + BTF + IKCONFIG
│   └── scripts/                     恢复/解析/生成脚本
├── exploit-src/
│   ├── target_mey_an00.h            ★ MEY-AN00 target.h（本工程核心产物）
│   ├── offset_mey_an00.h            速查版偏移
│   ├── dc15/                        dc15 参考源码
│   ├── dc15-exploit-src.zip
│   └── build_ndk.sh                 ★ NDK 编译（产物 build-mey/cve43499）
├── tools/
│   └── mey_online_check.sh          ★ 手机端在线验证脚本（env/leak/slide/p0/full/logs）
├── android/
│   └── ShizukuVerifier/             ★ Shizuku 验证 APK 工程（AS 打开即编）
└── docs/
    ├── 在线验证SOP-真机.md            ★ 真机接线/无线/验证顺序/日志回传
    ├── 流程SOP-从boot分析到提权.md     端到端流水线（BVL-AN16 蓝本）
    ├── 交接-临仵root-MEP-AN00.md      MEY/MEP-AN00 攻关状态交接（最重要）
    ├── 交接文档-临仵Root复现.md
    └── pselect_plant_无root校验_思路.md
```

---

## 2. 离线复现流水线

### 步骤 1 · 固件 → boot.img

源包：`D:/BaiduNetdiskDownload/MEY-AN00 10.0.0.175(C00E170R404P2)_Firmware_MagicOS 10.0_0501AJAB.zip`

从 11.4 GB 固件包中定位并抽取 `boot.img` / `vendor_boot.img`（Honor 固件为稀疏/打包格式，需按页对齐解析）。

### 步骤 2 · boot.img → 裸内核 Image

- 内核体位于 `boot.img` 内 **偏移 0x1000（4096 页对齐，不是 header_size=1584）**；
- 校验魔数：文件头 `MZ`（`4d5a40fa`）+ 偏移 0x40 处 `ARMd` ⇒ arm64 裸 Image（**未压缩**）；
- 产物：`analysis/output/kernel_mey_an00.raw`（37,128,704 B，sha256 与设备 `/proc/version` 构建一致）。

### 步骤 3 · 内核配置 IKCFG

从 Image 中搜 `IKCFG_ST` .. `IKCFG_ED` 段并解压 → `ikconfig_mey_an00.txt`（213 KB）。  
关键配置（影响利用路线）：

| 配置                               | 值            | 影响                     |
| -------------------------------- | ------------ | ---------------------- |
| `CONFIG_KALLSYMS_ALL`            | y            | local 符号也在符号表 → 可改名/解析 |
| `CONFIG_DEBUG_INFO_BTF`          | y            | 内嵌 BTF → 可取结构体布局       |
| `CONFIG_MODULE_SIG_FORCE`        | （见 ikconfig） | 模块签名是否需运行时翻位           |
| `CONFIG_RANDOMIZE_KSTACK_OFFSET` | 未设           | 逐 syscall 栈偏移随机化**关闭** |

### 步骤 4 · 恢复 kallsyms ★（无源码时最关键）

```sh
python analysis/scripts/recover_kallsyms.py
```

**编解码方案（本内核确认为旧版 pre-5.2 方案，非 v6.6 的 2-字符 token）**：

- 每个符号首字节 = 压缩后字节数 `L`（**直接单字节**，非 ULEB128）；
- 其后 `L` 字节，每一字节都是 `kallsyms_token_index` 的**直接下标 0..255**（**没有 0x80 字面/引用位**）；
- **skipped_first**：每个符号首个 token 的首字符是类型字符（`T`/`t`/`D`…），解码时丢弃，运行时再据地址段推导类型。

**关键定位参数**（本 Image）：

| 量                              | 值                                           |
| ------------------------------ | ------------------------------------------- |
| `relative_base`（=`_text` 链接地址） | `0xffffffc080000000`（Image off `0x153d020`） |
| `names` 起点 `ns`                | `0x13522c0`                                 |
| `markers` 起点 `ms`              | `0x14cfd88`（u32 × 434）                      |
| `token_table` `ts`             | `0x14d0450`                                 |
| `token_index` `p`              | `0x14d07e0`（u16 × 256）                      |
| `offsets` 起点                   | `0x14d09e0`（s32 × N）                        |
| 符号数 `N`                        | **110992**                                  |

**验收判据（全部通过）**：

- 434 个 256-符号块 checkpoint 的累计偏移 == `markers[b]` ✔（`markers consistent: True`）
- 解码到 `final_pos = 0x14cfd84` ≈ `ms`（差 4 字节尾部填充）✔
- 110992 条符号 **100% 可打印 ASCII**（`non-printable: 0`）✔
- 首符号依次 `_text`/`_stext`/`__irqentry_text_start`/`gic_handle_irq`… 完全符合 arm64 顺序 ✔

> ⚠ **踩坑记录**：最初误用 v6.6 的“2 字符 token + `(idx|0x80)` + ULEB128 + 跳首字符”方案，得到  
> `sym[0]=T_tcon`、关键符号全 NOT FOUND。真因是①token 字节应作**直接下标**（`0x93`→条目 147→`ext`，  
> 而 `0x93&0x7f`=19→`con`）；②长度字节非 ULEB128。**`diag32.py` 的决定性实验**：旧方案 100% ASCII，  
> 新方案仅 55.172%。见 `analysis/scripts/diag30~32.py`。

### 步骤 5 · 解析 BTF → 结构体布局

```sh
python analysis/scripts/dump_btf.py
```

**解析器关键点（原 `parse_btf.py` 有错位 bug）**：BTF 每种 kind 的尾随字节必须**严格按 libbpf `btf_type_size()`** 计算，否则首个写错就导致其后全部类型错位：

| kind                 | 尾随字节           |
| -------------------- | -------------- |
| `INT(1)`             | +4             |
| `ARRAY(3)`           | **+12**（不是 +8） |
| `STRUCT(4)/UNION(5)` | +vlen×12       |
| `ENUM(6)`            | +vlen×8        |
| `FUNC_PROTO(13)`     | +vlen×8        |
| `VAR(14)`            | +4             |
| `DATASEC(15)`        | +vlen×12       |
| `DECL_TAG(17)`       | **+4**         |
| `ENUM64(19)`         | +vlen×12       |

**验收判据**：`final_pos == type_len`（3,688,944 字节精确吻合）✔，共解析 144,042 个类型 / 10,692 个结构体；  
已知结构体尺寸与 arm64 6.6 完全一致（`task_struct`=0x12c0、`cred`=0xb8、`inode`=0x2c0、`file`=0x108、  
`super_block`=0x600、`selinux_state`=0x80、`miscdevice`=0x50、`rt_mutex_waiter`=0x70）✔

> ⚠ **厂商自定义布局**：本设备 `struct selinux_state` 的 `enforcing` 在**偏移 0x0**（mainline 6.6 是 1），  
> 绝不能照抄 mainline —— 必须用设备 BTF。

### 步骤 6 · 生成 MEY-AN00 `target.h`

```sh
python analysis/scripts/make_target_h.py     # -> exploit-src/target_mey_an00.h
```

---

## 3. 关键结论数据

### 3.1 关键全局符号（off = vaddr − `_text`，KASLR 无关）

| 符号                                             | 镜像偏移         | 用途                                         |
| ---------------------------------------------- | ------------ | ------------------------------------------ |
| `_text`                                        | `0x00000000` | 链接基址                                       |
| `init_task`                                    | `0x0217E280` | 进程遍历根 / 静态 task_struct                     |
| `init_cred`                                    | `0x02190790` | 提权目标 cred                                  |
| `selinux_state`                                | `0x023BA418` | 写 `enforcing(+0)=0` → Permissive           |
| `misc_list`                                    | `0x0229B190` | CVE-2026-64560 读原语遍历入口                     |
| `ashmem_misc`                                  | `0x022DE218` | → `ASHMEM_MISC_FOPS = +0x10 = 0x022DE228`  |
| `ashmem_fops`                                  | `0x012FF898` | 写原语写值前身 / fops 表                           |
| `init_cred` / `__per_cpu_offset` / `runqueues` | 见上表          | `current` 推导                               |
| `kallsyms_lookup_name`                         | `0x007E011C` | 运行时解析任意符号                                  |
| `random_table`                                 | `0x0229AF90` | 任意读：`boot_id` 槽 `+0x108`，`uuid` 槽 `+0x148` |
| `sysctl_bootid`                                | `0x023DB420` | `random_table[4].data` 指向它                 |

**交叉校验（与 `docs/交接-临仵root-MEP-AN00.md` 独立给出的值逐字一致）** ✔

| 量                 | 交接文档                  | 本工程恢复          |
| ----------------- | --------------------- | -------------- |
| `init_task` 运行地址锚 | `base + 0x217e280`    | `0x0217E280` ✔ |
| `random_table`    | image off `0x229af90` | `0x0229AF90` ✔ |
| `sysctl_bootid`   | `0xffffffc0823db420`  | `0x023DB420` ✔ |

> 📌 **符号数说明**：交接文档写“符号表 116,605”，但本内核 `markers` 数组仅 **434** 项 ⇒ 符号数上限 ≈ 434×256 = 111,104，  
> 故 **110,992 才是本内核真值**；文档的 116,605 系从 BVL/aak 文档抄来的陈旧值。

### 3.2 关键结构体字段（BTF 实测）

| 结构体                           | 关键字段                                                                                                   |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ |
| `task_struct` (0x12c0)        | `real_cred 0x818` `cred 0x820` `comm 0x830` `pid 0x618` `tgid 0x61c` `tasks 0x550` `sched_class 0x340` |
| `cred` (0xb8)                 | `uid 0x8` `euid 0x18` `securebits 0x28` `cap_effective 0x40` `security 0x80`                           |
| `selinux_state` (0x80)        | `enforcing 0x0`（厂商自定义！）                                                                                |
| `miscdevice` (0x50)           | `list 0x18` `name 0x8` `fops 0x10`                                                                     |
| `rt_mutex_waiter` (0x70, 非紧凑) | `tree 0x0` `pi_tree 0x28` `task 0x50` `lock 0x58` `wake_state 0x60` `ww_ctx 0x68`                      |
| `file_operations` (0x108)     | `unlocked_ioctl 0x48` `mmap 0x58` `open 0x68` `release 0x78` `splice_read 0xb8` `show_fdinfo 0xd8`     |
| `struct rq` (0xf00)           | `curr 0x0aa8` ⚠ CGA 是 `0x0aa0`，**差 8 字节**                                                              |
| `task_security_struct` (0x18) | `osid 0x0` `sid 0x4`（与 mainline 一致）                                                                    |

另外 CGA/MEY 的 `task_struct` 布局**整体差 0x18**（CGA `real_cred 0x830` vs MEY `0x818`），  
但 `rt_mutex_waiter` 的 tree/prio/deadline/pi_tree 四组偏移两机型**完全一致**（`0x18/0x20/0x40/0x48`）。

> `rt_mutex_waiter` 布局与交接文档 §2.3 独立反汇编结果**逐字节一致**（非紧凑）⇒ `COMPACT_RT_MUTEX_WAITER=0`。

---

## 4. 在线部分（需真机，本工程不执行）

离线只做完“推导偏移”。**真机执行需用户自备设备 + NDK + adb**，流程见 `docs/流程SOP-从boot分析到提权.md`：

```
每 boot 一发（铁律）：
  adb reboot → 等 sys.boot_completed=1 → 轮询 /proc/uptime 进 95~300s 窗口
  → tracefs 泄漏 KASLR base（MEY: sched_blocked_reason event id=109, 锚 worker_thread+0x17c=0x185864）
  → 打 exploit（pselect/MCAST/sigreturn 载波之一）→ 写原语 rb_erase
  → 读 init_task.cred / per_cpu_offset / current / comm
  → 写 cred/real_cred = init_cred；写 selinux_state.enforcing=0
  → uid 0 + Permissive
```

`docs/交接-临仵root-MEP-AN00.md` 详载 MEY 攻关现场：KASLR 泄漏**已通**、载体（MCAST/sigreturn）**落点已定**、  
**唯一未决 = `rb_erase` 写原语尚未在无 panic 前提下被证明**（单发命中率 25–30%，需多轮重启）。

### 4.1 已补齐的在线验证工具链

| 环节     | 工具                          | 说明                                                        |
| ------ | --------------------------- | --------------------------------------------------------- |
| 编译     | `exploit-src/build_ndk.sh`  | 自动 `-DTARGET_HEADER='"target_mey_an00.h"'`（漏了会编到 CGA 偏移上） |
| 手机端脚本  | `tools/mey_online_check.sh` | POSIX sh，指纹 / leak / slide / p0 / full / logs 分阶段，结构化输出   |
| APK 外壳 | `android/ShizukuVerifier/`  | Shizuku 授权 → 部署 + 抓内核日志；**app 域 exec 二进制**                |
| 操作手册   | `docs/在线验证SOP-真机.md`        | 接线与无线两条路线、验证顺序、失败对照表                                      |

> **为什么利用阶段必须用 APK 而不是 adb shell**：`/dev/fmps` 的 open 必须在  
> `untrusted_app` 域完成；adb / Shizuku 给的是 `u:r:shell:s0`，open 会被 EPERM 拒绝。  
> APK 用 `ProcessBuilder` 在自身进程域 exec 二进制，域才对得上。

---

## 5. 待办 / 未决项（诚实清单）

| # | 项                                                                                                 | 状态                                                                                                              |
| - | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| 1 | `sig_enforce`                                                                                     | 本内核未导出 kallsyms ⇒ `SIG_ENFORCE_OFF` **故意留 0（=`_text`，不可写）**。加载 .ko 前必须先 `kallsyms_lookup_name` 运行时解析，或出 ELF 后回填 |
| 2 | `SLIDE_PSELECT_WORD_SHIFT`                                                                        | 沿用 CGA 的 13；真值需对本机 Image 反汇编 `__arm64_sys_futex`/`core_sys_select` 栈深确定（交接文档：MEY 的 pselect 路线尚未落地）              |
| 3 | `SLIDE_NFULNL_LOGGER_NAME_OFF`                                                                    | 填 `0x015B66CC`（本机 `"nfnetlink_log"` 首现地址），语义未确认；MEY 未用此路径                                                       |
| 4 | `MM_STRUCT_SZ`(0x400) / `SLIDE_BANK_*` / `FOPS_OFF` / `SKB_DATA_DELTA` / `P0_ORACLE_*` 等 **行为调参** | 沿用 CGA 6.1.157 实测值；非符号偏移，需本机试跑按 log 微调。注意本机 BTF 的 `mm_struct` size 是 `0x4c0` 与 `MM_STRUCT_SZ=0x400` 不同口径        |
| 5 | `P0_KERNEL_PHYS_LOAD`/`P0_PAGE_OFFSET`/`P0_PHYS_OFFSET`                                           | 沿用 CGA `0xa8000000`（同 SM8750 平台），需一次 KASLR 实测确认 direct-map                                                      |
| 6 | 写原语端到端证明                                                                                          | 见交接文档 §3.4，**未完成**（在线环节；单发命中率 25–30%）                                                                           |
| 7 | `p0_fingerprint.h`                                                                                | 需用本机 Image 重新生成 32 行指纹表（在线环节）                                                                                   |

---

## 5b. `target.h` 的生成方式与接入

**不是**从零手写，而是以 dc15 参考实现的 `exploit-src/dc15/target.h`（CGA-W00 6.1.157）**为底稿**，  
只替换设备相关项，行为调参（`APP_*`/`SLIDE_*`/`KERNELSNITCH_*` 等）原样保留。  
这样可保证源码引用的宏**一个都不缺**。

```sh
python analysis/scripts/make_target_h.py       # -> exploit-src/target_mey_an00.h
```

**完整性已核验**（脚本比对“参考 target.h 定义的宏” vs “dc15 源码实际引用的宏”）：

```
reference macros: 278    used by dc15 sources: 230
MISSING-but-USED: 0        # ← 全部覆盖，不存在未定义宏导致编译失败
```


顺带解决的两个“BTF 里找不到”的项（实为未加入提取列表，并非厂商剥离）：

- `struct rq` **在** BTF 中 ⇒ `curr @ 0x0aa8`（size 0xf00）。CGA 是 `0x0aa0`，**差 8 字节**。
- `struct task_security_struct` **在** BTF 中 ⇒ `osid@0, sid@4`（size 0x18），与 mainline 一致。

`dump_btf.py` 现支持按名查询任意结构体：

```sh
python analysis/scripts/dump_btf.py rq cred task_struct      # 覆盖写 btf_offsets.txt
python analysis/scripts/dump_btf.py                           # 不带参数=恢复完整导出
```

**编译接入**（ userspace exploit 无顶层 Makefile，靠 `-D` 指定 target）：

```sh
# 把 target_mey_an00.h 放到 include 路径后：
aarch64-linux-android34-clang ... -DTARGET_HEADER='"target_mey_an00.h"'  \
      -o cve-2026-43499-bin-mey  *.c
```

> `offset.h` 的默认是 `"targets/cga-w00-6.1.157/target.h"`，**必须用 `-DTARGET_HEADER` 覆盖**，  
> 否则会编译到 CGA 的偏移上。

---

## 6. 复现脚本清单（`analysis/scripts/`）

| 脚本                    | 作用                                              |
| --------------------- | ----------------------------------------------- |
| `recover_kallsyms.py` | ★ 从裸 Image 恢复全量符号表（旧版 token 方案）                 |
| `dump_btf.py`         | ★ 解析 BTF（严格 libbpf 语义），导出结构体字段                  |
| `make_target_h.py`    | ★ 由 kallsyms+BTF 生成 `target_mey_an00.h`         |
| `parse_btf.py`        | 早期 BTF 解析（仅 7 结构体，已被 `dump_btf.py` 取代）          |
| `diag30/31/32.py`     | kallsyms 方案定位与决定性验证                             |
| `diag33/34.py`        | BTF 类型枚举与批量结构体导出                                |
| `diag6~28.py`         | 早期定位探测（banner / kallsyms 段 / token 表 / markers） |

---

## 7. 真机在线验证（adb / Shizuku）

| 产物                          | 作用                                                      |
| --------------------------- | ------------------------------------------------------- |
| `tools/mey_online_check.sh` | ★ 手机端分阶段验证器：`env / pre / leak / fire / logs`，结构化日志      |
| `tools/kaslr_leak`          | KASLR 泄露工具（取自参考 APK，通用）                                 |
| `exploit-src/build_ndk.sh`  | ★ NDK 一键编译，强制注入 `-DTARGET_HEADER='"target_mey_an00.h"'` |
| `android/ShizukuVerifier/`  | ★ 完整 Android Studio 工程：Shizuku 授权 + 部署 + 分阶段验证 + 日志导出   |
| `docs/在线验证SOP-真机.md`        | ★ 真机操作步骤（免接线 / 接线两条路线）                                  |
| `reference/ksu-cga-1.2.13/` | 参考 APK 解包产物（`mep_run.sh`、`dc_ksu_run.sh` 等配方基准）         |

**执行路线分工**（决定成败的关键）：

| 动作                       | 执行域                     | 说明                                |
| ------------------------ | ----------------------- | --------------------------------- |
| 部署二进制 / chmod / 抓内核日志    | Shizuku（shell uid 2000） | 需要写 `/data/local/tmp` 与读 kmsg     |
| exploit · LD_PRELOAD 载体  | shell 域即可               | 上游 `mep_run.sh` 配方，adb 直跑可用       |
| exploit · standalone PIE | **untrusted_app 域**     | 须由 APK 在自身进程 exec（二进制打包成 jniLibs） |

**铁律**：一个 boot 只打一发（`run.lock` = boot_id 强制拦截）、uptime ≥ 90s 才开火。

```sh
# 接线快速跑法
adb push exploit-src/build/{preload.so,cve43499} tools/{kaslr_leak,mey_online_check.sh} /data/local/tmp/mey/
adb shell chmod 755 /data/local/tmp/mey/{cve43499,kaslr_leak,mey_online_check.sh}
adb shell sh /data/local/tmp/mey/mey_online_check.sh env     # 先看指纹
adb shell sh /data/local/tmp/mey/mey_online_check.sh fire --yes
```

详见 `docs/在线验证SOP-真机.md`。

---

## 8. 参考

- `docs/交接-临仵root-MEP-AN00.md` —— **MEY/MEP-AN00 攻关现场交接（最重要）**
- `docs/流程SOP-从boot分析到提权.md` —— BVL-AN16 端到端流水线蓝本
- `docs/在线验证SOP-真机.md` —— 真机在线验证操作步骤
- `docs/pselect_plant_无root校验_思路.md` —— pselect 载波无 root 校验思路
- `docs/交接文档-临仵Root复现.md`

外部实现（同 CVE，多机型）：`YuKongA/ghostlock-app`、`yakidango-official/GhostLock-H80GT`（MCAST 载波）、  
`xrzcc/s26-m1q-ghostlock-selinux`（tracefs KASLR）、`oopnv70-lab/ghostlock-honor-aak`（6.6.89）、  
`knowlily/cve-2026-43499-honor`。
