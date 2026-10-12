# 参考仓库与署名

> **范围说明**：本仓库的「参考仓库」清单**仅限 DirtyFrag（CVE-2026-43284）血统链**。
> 工作区中曾下载的其他第三方仓库（含大量 CVE-2026-43499 / GhostLock 设备适配仓库）**不在本清单内，也不 vendored 入库** —— 它们属于各自作者的独立作品，未经授权不应随本仓库再分发。
> 本文件只做**来源说明与链接署名**，不复制任何上游代码。

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

## 二、构建依赖（非参考仓库）

`src/dirtyfrag/` 与 `src/bvl-root/` 运行时需要 KernelSU 生态组件。这些是**独立的上游项目**，需自行构建或获取，本仓库不包含其代码或二进制：

| 组件 | 地址 | 用途 |
|---|---|---|
| KernelSU（官方） | https://github.com/tiann/KernelSU | 内核态 root 框架 |
| KernelSU-Next | https://github.com/KernelSU-Next/KernelSU-Next | 常见衍生分支 |
| diabl0w/KernelSU | https://github.com/diabl0w/KernelSU | DFRoot 推荐的 Samsung 适配分支 |
| KowSU | https://github.com/KOWX712/KernelSU | DFRoot 列出的可选分支 |

> 内核模块（`.ko`）必须与目标设备内核的 **KMI** 匹配（`android15-6.6` / `android14-6.1` 等）。本仓库不含预编译模块。

---

## 三、本仓库的原创部分

以下内容为本项目的独立工作，**不属于**任何上游：

- `src/exploit-src/` —— 早期 exploit 源码与 SM8735 目标偏移定义
- `src/bvl-root/` —— BVL-AN16（6.1.157）独立工程与 CVE-2026-43499 触发脚手架

> **暂缓发布**：CVE-2026-43499 的完整触发链源码（含 `kernelsnitch` 等组件）源自第三方参考实现，
> 其上游许可证尚未确认，因此**未随本仓库发布**，等待确认后再补充。
> 43499 的研究结论与偏移适配保留在 `src/bvl-root/` 与 `docs/research/` 中。
- `tools/analysis/` —— 固件/内核分析脚本
- `docs/research/` —— 100 份研究报告（路线探寻 R0–R11、裁决 H25x 系列）
- DirtyFrag 工作副本中新增的激活校验、资产加密与防逆向加固层（**其签发私钥与口令不在本仓库**）

---

## 四、许可证兼容性

- 本仓库整体以 **GPL-3.0** 发布。
- 上游 DirtyFrag 系列仓库亦为 GPL 系许可证；若你打算以其他许可证再分发，请先确认与上游条款兼容。
- 第三方组件的许可证以其各自仓库声明为准；本仓库通过链接引用而非代码复制的方式使用。
