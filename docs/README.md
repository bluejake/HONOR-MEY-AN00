# 文档索引

MEY-AN00（荣耀 500）临时 root 研究的文档与数据索引。

| 路径 | 内容 |
|---|---|
| [`../README.md`](../README.md) | 项目总览、两条成功路线、成功数据索引、构建方式 |
| [`../CHANGELOG.md`](../CHANGELOG.md) | 版本变更记录 |
| [`../REFERENCES.md`](../REFERENCES.md) | 上游参考与署名（DirtyFrag 血统链 + 98260 上游） |
| [`../NOTICE`](../NOTICE) | 第三方声明与「不包含内容」清单 |
| [`../SECURITY.md`](../SECURITY.md) | 安全研究说明、脱敏策略、负责任披露 |
| [`DEVICE_BASELINE.md`](DEVICE_BASELINE.md) | ★ **设备基线 + CVE-2026-98260 标识含义**（结构化入口） |
| [`research/`](research/) | ★ **成功提权数据**（按漏洞归类，共 4 份，见下） |

---

## research/ —— 成功提权数据

目录名与文件名均含 `MEY-AN00` + CVE 编号 + `ROOT-SUCCESS`，可脱离正文核对「设备 / 漏洞 / 成功提权数据」：

| 目录 | 文件 | 内容 |
|---|---|---|
| `MEY-AN00__CVE-2026-43284_DirtyFrag__ROOT-SUCCESS/` | `MEY-AN00_CVE-2026-43284_DirtyFrag_ROOT-SUCCESS_evidence-and-criteria.md` | 实机成功证据与判据（`uid=0(root)`、LKM 已装载、boot 与 root-VERIFIED commit 吻合）、完整 UMH 链、成功判据逐条核对 |
| `MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/` | `MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_implementation.md` | 实施方案：上游仓库核实、11 项常量逐项对账、本机适用性判定、Phase A–H 步骤 |
| `MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/` | `MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_kernel-offsets.md` | 内核偏移基线：镜像 sha256 交叉核对、111,074 符号、`k_itimer`/`task_struct` BTF 布局、补丁状态二进制判定 |
| `MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/` | `MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_success-case.md` | 2026-11-02 实机成功：脱敏里程碑序列、三阶段写原语、判据分级（独立透镜 vs payload 自报） |

**建议阅读顺序**（98260 线）：
`DEVICE_BASELINE.md` → `…_kernel-offsets.md` → `…_implementation.md` → `…_success-case.md`

**建议阅读顺序**（43284 线）：
`DEVICE_BASELINE.md` → `…_evidence-and-criteria.md`

---

## 源码入口

| 路径 | 内容 |
|---|---|
| [`../src/dirtyfrag/`](../src/dirtyfrag/) | CVE-2026-43284 工具工程（Android App + JNI） |
| [`../src/magicos11-98260/`](../src/magicos11-98260/) | CVE-2026-98260 文本基线：偏移头、BTF 偏移、profile、关键符号表、部署脚本 |

---

> 当前有效的结构化基线以 [`DEVICE_BASELINE.md`](DEVICE_BASELINE.md) 为准。
