# MEY-AN00 临时 Root 研究

> 在 **BootLoader 锁定** 的荣耀/Honor 设备上，通过内核漏洞实现**运行时临时 root** 的完整研究记录与工程实现。

- 主攻平台：Qualcomm **SM8735**（荣耀 500 / 400 / Magic6 Pro 同源 SoC）
- 内核：Linux 6.6.118（android15-8）与 6.1.157（android14-11）两条线
- 许可证：**GPL-3.0**（见 [LICENSE](LICENSE)）

---

## ⚠️ 使用前必读

本项目是**安全研究**成果，发布目的是内核漏洞机理研究、防护评估与可复现的学术记录。

- 请仅在**你拥有合法所有权**的设备上运行；勿用于他人设备、未经授权的设备或任何违法用途。
- root 会削弱设备安全模型（SELinux、验证启动、沙箱隔离），由此产生的数据泄露、变砖、失去保修等后果**由使用者自行承担**。
- 本项目**不含**任何固件镜像、厂商私有代码、签名密钥或授权签发系统（见「未包含的内容」）。
- 所涉漏洞均已在上游/厂商处有对应修复讨论；本仓库仅作机理记录，不提供绕过厂商更新的方法。

---

## 技术路线与裁决

| 漏洞                            | 机理                                                        | 在本项目中的结论                                                                                            |
| ----------------------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **CVE-2026-43284**（DirtyFrag） | `esp_input` 页缓存投毒 → 动态加载 KernelSU LKM                     | ✅ **主力路线，已在 6.6.118 实机成功**（荣耀 500 / 400）                                                            |
| **CVE-2026-43499**（GhostLock） | `rt_mutex` waiter 栈喷射 + pselect6 画布 + `remove_waiter` 写原语 | 🔶 **6.1.157 线主路线**；同 SoC 6.6.118 已实证，BVL 目标为**安全触发脚手架**，实际写原语待接线                                   |
| **CVE-2026-64560**            | posix-cpu-timers UAF                                      | ❌ **架构性判死**：`flush_signal_handlers` / `do_cpu_nanosleep` / `timer_settime` 三者均硬绑定 `current`，无跨进程可达性 |
| **CVE-2026-43500**            | RxRPC                                                     | ❌ 目标内核 `CONFIG_AF_RXRPC is not set`，未编译                                                             |

关键结论：**root 是易失的**——漏洞为运行时内存投毒/动态加载，不涉及持久化分区写入，**重启即失效，需重新运行**。成功判据为 `/proc/modules` 出现 `kernelsu` 且 `su -c id` 返回 `uid=0`。

详细的路线裁决、反汇编证据与补丁状态分析见 [`docs/research/`](docs/research/)（100 份报告，含 R0–R11 路线探寻与 H25x 系列裁决）。

---

## 设备矩阵（成功案例）

完整矩阵见 [`docs/success-cases/README.md`](docs/success-cases/README.md)。摘要：

| 机型                   | 固件            | 内核                         | 路线    | 状态                  |
| -------------------- | ------------- | -------------------------- | ----- | ------------------- |
| MEY-AN00（荣耀 500）     | 10.0.0.175    | `6.6.118-android15-8-...`  | 43284 | ✅ 已成功               |
| DNN-AN00（荣耀 400）     | 同 build       | `6.6.118-android15-8-...`  | 43284 | ✅ 已成功               |
| BVL-AN16（Magic6 Pro） | 10.0.0.175    | `6.1.157-android14-11-...` | 43499 | 🔶 偏移已校准，写原语待接线     |
| PPG-AN00             | 已升 MagicOS 11 | 内核变更                       | —     | ❌ 判死（漏洞已修，BL 锁无法回退） |

> 注：设备矩阵仅记录**机型 / 固件版本 / 内核版本**等公开可查信息，**不含**序列号、IMEI、设备指纹等任何个体标识。

---

## 仓库结构

```
.
├── LICENSE                 GPL-3.0
├── README.md               本文件
├── REFERENCES.md           上游参考与署名（仅 DirtyFrag 血统）
├── NOTICE                  第三方代码声明
├── SECURITY.md             安全研究说明与负责任披露
├── docs/
│   ├── 00-project-README.md    原始项目说明
│   ├── 01-HANDOFF.md           完整研究交接记录
│   ├── handover/               方法论文档（SOP / 分析路径）
│   ├── research/               100 份研究报告（R0–R11、H25x 裁决）
│   ├── success-cases/          成功案例矩阵（脱敏）
│   └── methodology/            操作与反汇编纪律
├── src/
│   ├── exploit-src/        早期 exploit 源码与目标偏移定义
│   ├── dirtyfrag/          CVE-2026-43284 DirtyFrag 工具工程（Android App + JNI）
│   └── bvl-root/           BVL-AN16 独立工程（CVE-2026-43499 触发脚手架）
├── tools/analysis/         固件/内核分析脚本（Python）
└── firmware/README.md      固件获取说明（镜像不入库）
```

---

## *构建*

**环境**：Android NDK r27（或 r29）+ CMake 3.22+ + Gradle。

```bash
# DirtyFrag 工具（CVE-2026-43284 主线）
cd src/dirtyfrag && ./gradlew assembleDebug

# BVL-AN16 工程（CVE-2026-43499 脚手架）
cd src/bvl-root && ./gradlew assembleDebug
```

原生层（`app/src/main/jni`）由 CMake 构建为 `libexp.so`。  
注意：**禁止 `-static-pie`**（在目标设备上会 SIGSEGV），只做动态链接。

编译所需的 KernelSU 内核模块需自行按目标内核 KMI 构建或获取；本仓库不含预编译 `.ko`。

---

## 未包含的内容（及原因）

| 类别                 | 说明                                                                                                   |
| ------------------ | ---------------------------------------------------------------------------------------------------- |
| **固件镜像**（约 350 GB） | 体积远超 GitHub 限制（单文件 100 MB / 仓库软限 ~1 GB），且受厂商分发条款约束。获取方式见 [`firmware/README.md`](firmware/README.md)。 |
| **私钥与授权系统**        | `license_kit/`、签发私钥（`private.pem`）、`dk.bin`、发码器、硬编码口令 —— **已整体排除**，代码中相关字面量已替换为占位符。                  |
| **构建产物**           | `build/`、`.gradle/`、`.apk`、`.ko`、`.so`、`vmlinux` 等一律不入库（见 `.gitignore`）。                             |
| **设备日志**           | 含 IMEI / 序列号等硬件标识的原始日志（`log.db`、logcat）不入库。                                                          |
| **上游参考仓库**         | 第三方 exploit 仓库不 vendored 入库，仅以链接 + 署名方式引用，见 [`REFERENCES.md`](REFERENCES.md)。                        |

---

## 署名与许可

- 本仓库代码：**GPL-3.0**。
- 上游与第三方贡献：见 [`REFERENCES.md`](REFERENCES.md) 与 [`NOTICE`](NOTICE)。
- 其中 DirtyFrag 主线源自公开上游（mitschud → diabl0w → woshigenm 血统链），本项目的工作副本在其基础上增加了激活校验、资产加密与防逆向加固；**签发私钥与口令不在本仓库中**。

## 免责声明

本软件按「原样」提供，不含任何明示或暗示的担保。作者不对使用本仓库内容造成的任何设备损坏、数据丢失、保修失效或法律后果负责。请遵守所在地法律法规。
