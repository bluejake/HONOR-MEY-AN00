# MEY-AN00 临时 Root 研究

> 在 **BootLoader 锁定** 的荣耀设备上，通过内核漏洞实现**运行时临时 root** 的研究记录与工程实现。

| 项 | 值 |
|---|---|
| **目标机型** | **荣耀 500 / MEY-AN00**（本仓库基线与全部数值的唯一来源） |
| SoC | Qualcomm **SM8735**（Snapdragon 8s Gen 4），平台代号 `sun` |
| 内核 | Linux **6.6.118**（GKI `android15-6.6`），覆盖 MagicOS 10 / MagicOS 11 两个 build |
| 许可证 | **GPL-3.0**（见 [LICENSE](LICENSE)） |
| 核心成果 | **2 条漏洞路线在本机实机提权成功**，数据见 [`docs/research/`](docs/research/) |

> **范围纪律**：不同 SoC / 不同内核 build 的偏移、符号地址与结构体布局**一律不可复用**。
> 本仓库一切数值只取自 MEY-AN00 本机 vmlinux / BTF / 反汇编。见 [`docs/DEVICE_BASELINE.md`](docs/DEVICE_BASELINE.md)。

---

## ⚠️ 使用前必读

本项目是**安全研究**成果，发布目的是内核漏洞机理研究、防护评估与可复现的学术记录。

- 请仅在**你拥有合法所有权**的设备上运行；勿用于他人设备、未经授权的设备或任何违法用途。
- root 会削弱设备安全模型（SELinux、验证启动、沙箱隔离），由此产生的数据泄露、变砖、失去保修等后果**由使用者自行承担**。
- 本项目**不含**任何固件镜像、厂商私有代码、签名密钥或授权签发系统（见 [NOTICE](NOTICE) 与 [SECURITY.md](SECURITY.md)）。
- 所涉漏洞均已在上游/厂商处有对应修复讨论；本仓库仅作机理记录，不提供绕过厂商更新的方法。

---

## 两条成功路线

| 漏洞 | 适用固件 | 机理 | 状态 |
|---|---|---|---|
| **CVE-2026-43284**（DirtyFrag） | MagicOS 10.0.0.175 | `esp_input` 页缓存投毒 → 动态加载 KernelSU LKM | ✅ **实机成功** |
| **CVE-2026-98260** | **MagicOS 11.0.0.110** | POSIX CPU timer `exec()` 清理路径 UAF → `rb_erase` 8 字节清零写 → fake cred / 零写 uid → `ksud late-load` | ✅ **实机成功（2026-11-02）** |

> **为何是两条而不是一条**：MagicOS 11 升级后 43284 已被修补（`esp_input`/`esp6_input` 增加 `!skb_has_shared_frag(skb)` 守卫），
> 98260 成为该内核上唯一已知可用路线。**两条路线对应两个不同的内核 build，偏移不通用。**

**root 是易失的**：两条路线均为运行时内存投毒 / 动态加载，不写持久化分区，**重启即失效、需重新运行**。

**成功判据（必须用独立透镜，禁止用同一读写原语回读自证）**：

1. `/proc/modules` 中出现 `kernelsu`
2. `su -c id` 返回 `uid=0`

---

## 成功提权数据索引

`docs/research/` 按漏洞归类，文件名含设备 / CVE / `ROOT-SUCCESS` 标识，可脱离正文核对：

| 漏洞 | 文件 | 内容 |
|---|---|---|
| 43284 | [`…DirtyFrag_ROOT-SUCCESS_evidence-and-criteria.md`](docs/research/MEY-AN00__CVE-2026-43284_DirtyFrag__ROOT-SUCCESS/MEY-AN00_CVE-2026-43284_DirtyFrag_ROOT-SUCCESS_evidence-and-criteria.md) | 实机成功证据（`uid=0(root)`、LKM 已装载、boot 与 root-VERIFIED commit 吻合）、完整 UMH 链、成功判据 |
| 98260 | [`…ROOT-SUCCESS_implementation.md`](docs/research/MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_implementation.md) | 实施方案：11 项常量逐项对账、本机适用性判定、Phase A–H 步骤 |
| 98260 | [`…ROOT-SUCCESS_kernel-offsets.md`](docs/research/MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_kernel-offsets.md) | 内核偏移基线：镜像 sha256 交叉核对、符号表、BTF 结构偏移、补丁状态二进制判定 |
| 98260 | [`…ROOT-SUCCESS_success-case.md`](docs/research/MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/MEY-AN00_CVE-2026-98260_ROOT-SUCCESS_success-case.md) | 2026-11-02 实机成功：脱敏里程碑序列、三阶段写原语、判据分级 |

设备与版本结构化基线（机型 / 系统版本 / 构建版本 / 98260 标识分层含义 / 11 项常量对账 / 未验证项）见
[`docs/DEVICE_BASELINE.md`](docs/DEVICE_BASELINE.md)。

---

## 仓库结构

```
.
├── LICENSE                 GPL-3.0
├── README.md               本文件
├── CHANGELOG.md            版本变更记录
├── REFERENCES.md           上游参考与署名
├── NOTICE                  第三方代码声明与「不包含内容」
├── SECURITY.md             安全研究说明、脱敏策略与负责任披露
├── docs/
│   ├── DEVICE_BASELINE.md  ★ 设备基线 + 98260 标识含义（结构化入口）
│   ├── README.md           文档索引
│   └── research/           ★ 成功提权数据（按漏洞归类，共 4 份）
│       ├── MEY-AN00__CVE-2026-43284_DirtyFrag__ROOT-SUCCESS/
│       └── MEY-AN00__CVE-2026-98260__ROOT-SUCCESS/
└── src/
    ├── dirtyfrag/          CVE-2026-43284 工具工程（Android App + JNI）
    └── magicos11-98260/    CVE-2026-98260 文本基线：偏移头、BTF 偏移、profile、关键符号表、部署脚本
```

---

## 构建

**环境**：Android NDK r27（或 r29）+ CMake 3.22+ + Gradle。

```bash
# CVE-2026-43284 工具（MagicOS 10 路线）
cd src/dirtyfrag && ./gradlew assembleDebug
```

原生层（`app/src/main/jni`）由 CMake 构建。**禁止 `-static-pie`**（在目标设备上会 SIGSEGV），只做动态链接。

编译所需的 KernelSU 内核模块需自行按目标内核 KMI 构建；本仓库不含预编译 `.ko`。

---

## 署名与许可

- 本仓库代码：**GPL-3.0**。
- 上游与第三方贡献：见 [REFERENCES.md](REFERENCES.md) 与 [NOTICE](NOTICE)。
- DirtyFrag 路线源自公开上游（mitschud → diabl0w → woshigenm 血统链），本项目工作副本在其基础上增加了激活校验、资产加密与防逆向加固；**签发私钥与口令不在本仓库中**。

## 免责声明

本软件按「原样」提供，不含任何明示或暗示的担保。作者不对使用本仓库内容造成的任何设备损坏、数据丢失、保修失效或法律后果负责。请遵守所在地法律法规。
