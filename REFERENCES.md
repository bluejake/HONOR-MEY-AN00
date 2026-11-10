# 参考仓库与署名

> **范围说明**：本清单收录两条主线的上游署名 —— DirtyFrag（CVE-2026-43284）血统链，
> 以及 MagicOS 11 路线的 CVE-2026-98260 上游项目。
> 工作区中曾下载的其他第三方仓库（含大量 CVE-2026-43499 / GhostLock 设备适配仓库）**不在本清单内，也不 vendored 入库** —— 它们属于各自作者的独立作品，未经授权不应随本仓库再分发。
> 本文件以**来源说明与链接署名**为主；唯一例外是 `dada-cve-AN00` 的一份独立 C 源码
> （已按 MIT 血统声明附许可证全文原样收录于 `src/magicos11-98260/upstream/`，见下「署名边界」）。
> 其余上游 App 工程、native 库、APK 均不入库。

---

## 一、DirtyFrag 血统链（CVE-2026-43284）

本项目 `src/dirtyfrag/` 的工作副本源自以下公开上游，血统方向为**自左向右**：

```
mitschud/DirtyFrag （原始项目）
   └─ diabl0w/DFRoot （中间 fork，README 自述 "base of this fork"）
        └─ woshigenm/DirtyFrag （本项目工作副本的基底）
             └─ src/dirtyfrag/ （本仓库：新增激活校验 / 资产加密 / 防逆向加固）
```

| 上游 | 仓库地址 | 快照 HEAD | 版本标记 |
|---|---|---|---|
| mitschud/DirtyFrag | https://github.com/mitschud/DirtyFrag | `e44c7b4` | v1.05 ~ v1.08 |
| diabl0w/DFRoot | https://github.com/diabl0w/DFRoot | `568f804` | v3.0、v3.1 |
| woshigenm/DirtyFrag | https://github.com/woshigenm/DirtyFrag | `81fdab0` | release tag `3203db9` |

工作副本基线 = `3203db9`，即 woshigenm 上游**自行发布的 release tag**。

### 上游自述的致谢（转引自 mitschud/DirtyFrag README）

这些是 DirtyFrag 主线所依赖/借鉴的作品，署名在此保留：

- 原始 PoC 及部分代码 —— https://github.com/lsposed/lspromise
- SELinux Permissive 内核模块及部分代码 —— https://github.com/polygraphene/DFReroot
- 非特权 XFRM socket 方法 —— https://github.com/combeng6th/DirtyInit
- DFRoot（本 fork 的基底）—— https://github.com/diabl0w/DFRoot

---

## 二、CVE-2026-98260 上游（2026-11 新增）

| 上游 | 仓库地址 | 形态 | 与本项目的关系 |
|---|---|---|---|
| `Again1996-bit/CVE-2026-98260-GhostKey` | https://github.com/Again1996-bit/CVE-2026-98260-GhostKey | Android App（Kotlin + Compose + NDK），`uaf_plant.c` / `calib.c` / `timer_probe.c` / `pc98260_rootd.c` / `ksu.c` | **profile 表驱动**，按 `uname -r` 精确匹配、不做 KMI 回退；内置 13 个 profile，其中 6.6.118 系列 4 个，**不含本机 `g554929766a0d-abogki544555896`**。本仓库提供本机自生成 profile（[`src/magicos11-98260/profile/`](src/magicos11-98260/profile/)）以补此缺口 |
| `nisu123f/dada-cve-AN00` | https://github.com/nisu123f/dada-cve-AN00 | 单文件 C payload `kernel/cve-2026-98260.c`（1962 行）+ GhostLock App 工程 | **源码内硬编码** AAK-AN00 常量。本项目用本机 vmlinux 符号表 / BTF 对其 **11 项常量逐条对账，11/11 一致**，据此确认可用于本机；源码已原样收录于 `upstream/`，payload 由该源码用 NDK 27.0.12077973 字节级复现编译（md5 一致） |

**署名边界（2026-11-07 修订）**：

| 类别 | 是否入库 | 依据 |
|---|---|---|
| `dada-cve-AN00` 的 `kernel/cve-2026-98260.c`（58,110 B，逐字节原样） | ✅ 已收录 | 见 [`upstream/SOURCE-NOTICE.txt`](src/magicos11-98260/upstream/SOURCE-NOTICE.txt) |
| 由该源码编译的 `cve-2026-98260-uid0`（462,584 B，静态非 PIE） | ✅ 已收录 | NDK 27.0.12077973 实测字节级可复现，见 [`build.sh`](src/magicos11-98260/build.sh) |
| 本项目自行生成的文本产物（偏移头 / BTF 偏移 / profile / 关键符号表 / `run.sh` / `onefire.sh`） | ✅ 已收录 | 本项目原创 |
| 两个上游的 Android App 工程、native `.so`、任何 `.apk` | ❌ 不入库 | `.gitignore` 排除 `*.apk` |

**许可证状态不冒充确定**：该 C 文件自身**没有** SPDX / Copyright / 独立许可证头，
唯一依据是其头注「ported from `woshigenm/CVE-2026-98260 uid0.c`, MIT」。
据此附上 MIT 全文与归属说明（`LICENSE-MIT.txt`），以满足保留许可声明的要求；
上游仓库根目录无 LICENSE，只有 `app/LICENSE`（Apache-2.0，仅覆盖 App 工程，不覆盖该内核源码）。
因此这仍是**授权灰区**。若权利人主张不同条款，请通过 `SECURITY.md` 私有渠道联系，核实后移除或重新授权。
MIT 与本仓库 GPL-3.0 兼容。

上游修复 commit：`acb03d388181`（引入 `posixtimer_exec()`）。补丁状态以**目标内核二进制符号**判定，不做版本算术。

---

## 三、构建依赖（非参考仓库）

`src/dirtyfrag/` 运行时需要 KernelSU 生态组件。这些是**独立的上游项目**，需自行构建或获取，本仓库不包含其代码或二进制：

| 组件 | 地址 | 用途 |
|---|---|---|
| KernelSU（官方） | https://github.com/tiann/KernelSU | 内核态 root 框架 |
| KernelSU-Next | https://github.com/KernelSU-Next/KernelSU-Next | 常见衍生分支 |
| diabl0w/KernelSU | https://github.com/diabl0w/KernelSU | DFRoot 推荐的 Samsung 适配分支 |
| KowSU | https://github.com/KOWX712/KernelSU | DFRoot 列出的可选分支 |

> 内核模块（`.ko`）必须与目标设备内核的 **KMI** 匹配（`android15-6.6` / `android14-6.1` 等）。本仓库不含预编译模块。

---

## 四、本仓库的原创部分

以下内容为本项目的独立工作，**不属于**任何上游：

- `src/dirtyfrag/` —— CVE-2026-43284 工具工程（Android App + JNI）
- `src/magicos11-98260/` —— 本机固件提取的偏移头 / BTF 偏移 / 关键符号表 / GhostKey 格式 profile / 部署脚本
- `docs/DEVICE_BASELINE.md` —— 设备基线、98260 标识分层含义、11 项常量对账与可复现路径
- `docs/research/` —— 成功提权数据（按漏洞归类，4 份）：
  - `MEY-AN00__CVE-2026-43284_DirtyFrag__ROOT-SUCCESS/…evidence-and-criteria.md`
  - `MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/…implementation.md`
  - `MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/…kernel-offsets.md`
  - `MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/…success-case.md`
- DirtyFrag 工作副本中新增的激活校验、资产加密与防逆向加固层（**其签发私钥与口令不在本仓库**）


---

## 五、许可证兼容性

- 本仓库整体以 **GPL-3.0** 发布。
- 上游 DirtyFrag 系列仓库亦为 GPL 系许可证；若你打算以其他许可证再分发，请先确认与上游条款兼容。
- 第三方组件的许可证以其各自仓库声明为准；本仓库通过链接引用而非代码复制的方式使用。
