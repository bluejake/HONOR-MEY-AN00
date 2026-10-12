# BVL-AN16（荣耀 Magic6 Pro）10.0.0.175 临时 root 可行性裁决

> 核验日期：2026-10-12  
> 设备：BVL-AN16 · 10.0.0.175(C00E175R110P8) · Android 16 · MagicOS 10.0.0 · 内核 `6.1.157-android14-11-g7d3922fade43` · 安全补丁 2026-08-01 · 基带 MSM.2272.MPSS.DE.5.0.217（SM8735 / sun）

## 结论先行

| 维度 | 结论 |
|------|------|
| 是否支持临时 root | **支持（理论判据成立），但当前没有可直接运行的现成方案** |
| 最可能路线 | CVE-2026-64560（posix-cpu-timers UAF）+ KernelSU-Next android14-6.1 KO |
| 实测状态 | 64560 race 在 BVL 上跑过 60s 未命中窗口；kallsyms 恢复尚未完成 |
| DirtyFrag / 43284 | **已死**，probe 实测 `GATE_FAIL` |
| 回滚 / 降级 / 升级绕过 | **不可行**；BL 锁死 + 无旧固件 |

## 已核验的内核证据

- `firmware_bvl/bvl175_config.txt`：
  - `CONFIG_MODVERSIONS=y`
  - `CONFIG_KASAN_HW_TAGS=y`
  - `CONFIG_ARM64_VA_BITS_39=y`
  - `CONFIG_RANDOMIZE_KSTACK_OFFSET=y`
  - `# CONFIG_AF_RXRPC is not set`
- KSU 资产：`refs/kernelsu-android14-6.1.ko`
  - vermagic：`6.1.166-dirty SMP preempt mod_unload modversions aarch64`
  - KMI：`android14-6.1`（与 BVL 同 KMI）
- CVE-2026-64560 上游修复版本：`6.1.180`（第三方安全库 / 官方 CVE 记录交叉确认）。BVL `6.1.157` < `6.1.180` ⇒ **漏洞未修补**。

## GitHub 可 root 方案列举

| 路线 | GitHub 仓库（镜像加速后） | 目标版本 | BVL 适配状态 | 备注 |
|------|--------------------------|----------|--------------|------|
| **64560 移植** | `a23bc/op13-cve-2026-64560` | 6.6.118-android15-8（OnePlus 13） | 需移植 | 自带 `tools/kallsyms_extract.py`、`tools/port_target.py`、`tools/btf_offsets.py` |
| **64560 移植** | `Wangs-official/opace6-cve-2026-64560` | 6.6.118-android15-8（OnePlus Ace 6） | 需移植 | 中文 README，提供 `boot-campaign.bat/sh` |
| **64560 移植** | `NebuSec/CyberMeowfia/security-research/Ndays/Android-CVE-2026-64560` | 6.6.118-android15-8（Pixel 10 Pro） | 需移植 | README 宣称成功率 >50% |
| 64560 分析/PoC | `villager1314/CVE-2026-64560-Analysis` | 通用 Linux | 不可直接 root | 仅 UAF 触发器，无完整提权链 |
| 43499 GhostLock | `quyicheng03-boop/ghostlock` 等大量设备分支 | 多设备 6.6.x / 5.15.x | **未确认** | BVL 是否仍残留 43499 需精确验证（修复版本有争议） |
| DirtyFrag | `jingmatrix/pixel-ksu-root` 等 | 6.6.x | **已死** | 6.1 路径 `MSG_SPLICE_PAGES` 未 backport |
| RxRPC | — | — | **已死** | 内核未编译 `CONFIG_AF_RXRPC` |
| CVE-2026-49881 | — | — | **已死** | 本机无相关代码，且本身不 root |

## 判死方案说明

- **CVE-2026-43284 DirtyFrag**：BVL 的 DF probe 返回 `GATE_FAIL`（`xfrm` socket EACCES、`capbnd=0`、`user_ns=no`）；6.1 的 `ip_append_page` 无 caller、`udp_sendpage` 的 `MSG_SPLICE_PAGES` 未 backport，导致 payload 半死不活。
- **CVE-2026-43500 RxRPC**：`CONFIG_AF_RXRPC is not set`。
- **CVE-2026-49881**：本机无相关代码，且该 CVE 本身不直接造成 root。
- **系统回滚 / 降级 / OTA 绕过**：BL 锁死，无旧固件下载通道，不可行。

## 要让 BVL 真正 root，还需要完成

1. **kallsyms 恢复**：从 `firmware_bvl/bvl175_Image` 完整恢复符号表；op13 的 `tools/kallsyms_extract.py` 可以再试。
2. **符号 / 偏移重算**：64560 exploit 中硬编码的 24 `LINK_` 符号地址 + 45 `DP_` offset 全部针对 6.1.157 重算（6.6 → 6.1 struct layout 不同）。
3. **结构体 offset 获取**：`struct k_itimer`、`timerqueue_node`、`signal_struct`、`cred` 等关键结构需通过 BTF 或反推得到。
4. **race 调参**：timer/exec 线程数、CPU affinity、冷却时间针对 6.1.157 和 16GB 大内存调优。
5. **KSU late-load 验证**：确认 `kernelsu-android14-6.1.ko` 能在 BVL 上通过 `MODVERSIONS same_magic` 加载（DNN 6.6.127→6.6.118 有实证）。
6. **APK 化（如需要）**：把 Shizuku + fork 隔离 + 反混淆加固流程再走一遍（参考 v2.4.x 实现）。

## 诚实状态

| 项目 | 状态 |
|------|------|
| KSU-Next android14-6.1 KO 资产 | ✅ 已就位 |
| 64560 漏洞版本判据（6.1.157 < 6.1.180） | ✅ 已确认 |
| BVL kallsyms 恢复 | ❌ 失败（token_table 校验未通过） |
| 64560 race 上机命中 | ❌ 60s / 16 线程未触发 |
| 43499 在 6.1.157 是否仍残留 | ❓ 修复版本有争议，待精确验证 |

## 最终答复

**荣耀 Magic6 Pro（BVL-AN16）10.0.0.175 支持临时 root 的理论判据成立，但 GitHub 上没有可直接运行的 BVL 专用方案。**

唯一被确认可行的抓手是 **CVE-2026-64560 移植路线**：以上 3 个 6.6.118 的 GitHub exploit 仓库可作为移植基础，配合已就绪的 `kernelsu-android14-6.1.ko` 完成动态加载。DirtyFrag、RxRPC、49881 已判死；43499 是否可用尚需独立验证。
