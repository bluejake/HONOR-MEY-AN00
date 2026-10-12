# BVL-AN16 临时 Root 复现 — 交接文档

> 交付对象：接手继续跑 / 想在同类设备复现的人
> 日期：2026-09-21 · 交付包：`ksu_root_bvl-an16-su/`
> 结果一句话：**BL 锁定、不写任何分区，靠漏洞打进 KernelSU root，命中率约 1/3~1/10，命中后 root 长期稳定可用。**

---

## 1. 目标与环境

| 项 | 值 |
|---|---|
| 设备 | Honor Magic6 Pro（BVL-AN16） |
| 固件 | MagicOS 10.0.0.170（C00E170R202P8）· Android 16 |
| 内核 | 6.1.157-android14-11-g7d3922fade43（aarch64，GKI） |
| Bootloader | **锁定**（未解锁，全程未刷写任何分区） |
| 产物 | 每 boot 一次漏洞提权 → 加载 KernelSU 内核模块 → su / 管理器可用 |

**原理概述**（三段拼接）：
1. **漏洞提权**：用 CVE-2026-43499 的 DC14 利用程序完成 KASLR 泄漏（`kaslr_leak`）→
   物理读写原语（physrw）→ 从 `/proc/kallsyms` 解析全部内核符号（219/219）；
2. **KernelSU 模块**：借用的模块本体是 CGA-W00（MagicPad3，同代 Honor 内核）的
   KernelSU v3.2.5 (32525)，与原版**只差 23 个字节**（两个符号改名以便在 BVL 的
   kallsyms 里解析到），适配细节见 `KO_SYMBOL_NOTES.txt`；
3. **加载器**（`ksu_loader.sh`）：以漏洞给的 uid 0 上下文跑 —— 关 Honor 的两道
   复位门控（bootfail 检测器 + `ro.sys.ping_bf_dorecovery`）、`hung_task_panic=0`、
   注入 SELinux 规则 → Permissive、`load_ko` 装载模块、部署 `/system/bin/su`、拉起 `ksud`。

---

## 2. 交付包内容（都在 `ksu_root_bvl-an16-su/`）

```
一键root.bat            ← Windows 双击入口（默认完整 KSU；参数 noload = 稳定模式）
run_ksu_bvl.py          ← PC 端驱动：自动重启→等窗口→打一发→判定，循环 N 轮
ksu_loader.sh           ← 设备端加载器（uid 0 上下文执行的核心逻辑）
kernelsu_bvl.ko         ← 适配后的 KernelSU 内核模块（5,459,384 B）
kernelsu_bvl.orig.ko    ← 未打 faccessat 补丁的原版（回滚用）
cve-2026-43499-bin-dc14 ← 漏洞利用程序
kaslr_leak              ← KASLR 泄漏步骤
load_ko                 ← 模块装载器（支持传模块参数）
ksud / magiskpolicy / ksu_rules / dc_ksu_run.sh
KernelSU_manager.apk    ← 管理器 v3.2.5 (32525)，与模块同包配套
go.sh                   ← 设备端一键脚本（不接 PC 时的入口）
tools/                  ← post_root.sh（root 窗口任务脚本）、noload_round.sh、lifetime.sh 等
_参考-成功日志/          ← 成功那次的原始日志 + 命中证据（对照用）
使用说明.txt / MANIFEST.txt（全部文件 SHA256）/ KO_SYMBOL_NOTES.txt
BVL-AN16-最终报告.md 等多份分析报告（技术细节参考）
```

依赖：Windows + adb（包内自带 adb.exe）；驱动用 Python 3.13 跑（也可用设备端 go.sh 独立于 PC）。

---

## 3. 快速开始（两条命令）

```
双击 一键root.bat              → 完整 KSU 模式（自动重启循环打，命中即止）
双击 一键root.bat noload       → NO_LOAD 稳定模式（见 §6）
```

命令行等价：`python run_ksu_bvl.py --rounds 6`（或 `--noload` / `--check` 只校验载荷）。

驱动每轮自动做：
```
① adb reboot（取干净内核态）→ ② 等 boot_completed → ③ 等 uptime 进入 95~300s 窗口
→ ④ 打一发（KASLR 泄漏 attempt≤8 → 物理读写 → 后台拉起 ksu_loader.sh）
→ ⑤ 判定（/proc/modules 出现 kernelsu Live + ksud 进程 + Permissive）
→ 命中即停；未命中无副作用，自动重启进下一轮
```

命中后验证（adb shell）：
```
grep -c kernelsu /proc/modules      # ≥1 = 模块在
pidof ksud                          # 守护进程在
getenforce                          # Permissive
ls -l /system/bin/su                # 已部署
```

---

## 4. 关键规律（血泪经验，照做少走弯路）

| 规律 | 说明 |
|---|---|
| **一发制** | 每个 boot 只打一发。失败必须重启再打；连打两次必失败 |
| **先重启再打** | 命中点在 uptime≈168s；拖到 460s/873s 都没中过。驱动已锁 95~300s 窗口 |
| **命中率** | 干净命中实测约 1/3（状态好时）~1/10（低谷），波动大；通常 1~3 轮出结果，别灰心 |
| **失败无副作用** | 未命中/半命中 panic 都不写分区，设备自动重启，驱动自动接续 |
| **不要拔线** | 整轮流程 adb 会瞬断多次（正常），驱动有重连逻辑 |
| **别开 KSU 管理器** | ⚠️ 管理器打开约 10 秒会触发整机挂死→自动重启复位（模块的 faccessat kprobe 在本机有缺陷）。**不打开它 root 就长期稳定**（实测数小时无复位）。授权 app 暂用 post_root.sh 窗口替代 |
| **root 存活** | 完整 KSU 模式命中后，只要不开管理器，root 与本 boot 同寿命（实测 26 分钟~1 小时+，无自动复位） |

失败模式分类（看 `_logs/rN/dc_ksu.log` 末行）：
- `LEAK_FAIL` —— KASLR 泄漏没成，重来即可；
- 干净 miss（无 panic）—— 重来即可；
- `CP main: before-slide-route` 后复位 —— "半命中"，写原语阶段没落地，属漏洞自身概率；
- adb `error: closed` —— 多为瞬断，驱动自动重连。

---

## 5. NO_LOAD 稳定模式（只要 uid 0 干活、不要 su 框架时用）

```
双击 一键root.bat noload
（或：python run_ksu_bvl.py --noload --rounds 3）
```

- 打到提权 + 注入策略为止，**不加载内核模块** → 绕开模块相关的一切不稳定；
- 代价：没有 su / 管理器框架；
- 换来：**uid 0 操作窗口长期稳定**（实测 430s+ 连续采样无复位，SELinux 保持 Permissive）；
- 想在窗口里跑自己的 root 任务：写进 `tools/post_root.sh` 推到
  `/data/local/tmp/ksu/post_root.sh`，loader 末尾的 hook 会以 **uid 0 (u:r:kernel:s0)**
  自动执行它（hook 为纯追加，无该文件时完全空转）；
- 判定证据：`/data/local/tmp/ksu/ksu_load.log` 出现 `module NOT loaded`。

---

## 6. 常用命令速查

```
python run_ksu_bvl.py --check           # 只校验 9 个必需载荷（含 SHA256），不碰手机
python run_ksu_bvl.py --rounds 6        # 完整 KSU 模式，最多 6 轮
python run_ksu_bvl.py --noload --rounds 3
一键root.bat / 一键root.bat noload      # Windows 双击入口
```

root 窗口里能干什么（每 boot 一次，`post_root.sh` 已内置）：
- 以 root 读 root-only 数据（`/sys/module/*/parameters/*`、kallsyms、vendor 模块）；
- `cp` 任意 root-only 文件到 `/data/local/tmp/ksu/`（/data 跨复位保留）；
- 起常驻采样进程（`setsid` 脱离会话，防 adb 断连误杀）。

---

## 7. 红线（务必遵守）

1. **不写任何分区** —— 全套流程只读内核、写 `/data/local/tmp`，BL 保持锁定；
2. **失败不要慌** —— 半命中 panic 是漏洞自身概率，自动恢复后重来即可；
3. **`kernelsu_bvl.orig.ko` 是回滚锚点** —— 现役 `kernelsu_bvl.ko` 已打 faccessat 补丁
   （仅 8 字节差异，`movz x0,#0; ret`，目的：摘除"app 探测 su 路径即挂死"的雷）。
   ⚠️ 该补丁版尚在验证中；若命中后出现模块异常，直接用 `.orig.ko` 覆盖回去即回滚；
4. **每 boot 重新打** —— 临时 root 不持久，重启即失，一切 root 级服务（含 Shizuku
   这类）都要在命中后的窗口内重新部署。

---

## 8. 深入阅读（按需）

| 文档 | 内容 |
|---|---|
| `使用说明.txt` | 参数、实验标记、两种模式对照 |
| `MANIFEST.txt` | 全部文件 SHA256（核对交付完整性） |
| `KO_SYMBOL_NOTES.txt` | 模块 23 字节适配与符号改名细节 |
| `BVL-AN16-最终报告.md` | 成果、病灶定位、适配清单 |
| `BVL-AN16-崩溃定位-第二轮.md` | kmsg 取证、复位路径分析 |
| `差分对照-关闭荣耀检测措施.md` | 与上游包的生存措施逐条对照（结论：无漏项） |
| `BVL-AN16-真凶定位-第三轮.md` | vendor 模块分析、core_hang_detect 证据链 |
| `管理器挂死-复现与定位.md` | 管理器挂死根因与补丁点（含 `kernelsu_bvl.ko` 现役补丁说明） |
| `_logs/` | 每轮原始日志（dc_ksu.log / ksu_load.log / rootdump.txt） |

技术要点备查：KASLR 泄漏 → physrw 写原语 → `pselect` 时序 shift → fops SKIP 旁路 →
`kptr_restrict` 清零 → 219 符号解析 → `load_ko`（vermagic flags-only 比对）→
sepolicy 注入（Permissive）→ `ksud` 拉起。
