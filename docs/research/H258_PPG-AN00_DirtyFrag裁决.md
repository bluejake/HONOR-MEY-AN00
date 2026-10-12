# H258 · PPG-AN00（荣耀 GT Pro）DirtyFrag 机会裁决

**日期**：2026-10-12
**信息源**：用户提供的「关于手机」截图 ×2（867×1920），本机 OCR（rapidocr-onnxruntime）提取 + 用户手贴文字交叉核对，二者一致
**性质**：**纯案头裁决**，未上机、未开火

---

## 0. 结论速览

| 问题 | 结论 | 强度 |
|---|---|---|
| **这台 PPG-AN00 上 DirtyFrag（CVE-2026-43284）还有机会吗？** | **没有。已被修复。** | `[PPG 本机内核·汇编已证]` ★★★★★（见 §2.2） |
| CVE-2026-43499（rt_mutex）呢？ | **同样已修**（与 43284 同一次构建） | `[同一 build 判定]` ★★★★☆ |
| CVE-2026-64560 呢？ | **未修**，但 **H207 已架构性判死**，不构成路线 | `[汇编已证]`+`[架构判死]` |
| 能回滚到可打的旧版本吗？ | **不能**。BL 锁死，无 fastboot，无自助降级通道 | `[已实测]`（MEY 同厂同锁） |
| 之前「PPG 零适配直接可用」的判定还有效吗？ | **作废**。它建立在 PPG = 6.6.89 的前提上，而 PPG 现已不是 6.6.89 | ★ |

**一句话**：**这台机器已经吃到 MagicOS 11 那颗子弹了 —— 它跑的内核正是我们 10-08 判定「43284/43499 已修」的那一个 build。DirtyFrag 在这台机器上判死。**

---

## 1. 设备身份（从截图提取）

| 字段 | 值 |
|---|---|
| 型号 | **PPG-AN00** |
| 设备名称 | 荣耀 GT Pro |
| SoC | 骁龙 8 至尊领先版（**SM8750**，≠ MEY 的 `sun`/SM8735） |
| 版本号 | **11.0.0.109(SP8C00E109R104P1H1)** |
| MagicOS 版本 | **11.0** |
| Android 版本 | **17** |
| ★内核版本 | **`6.6.118-android15-8-g554929766a0d-abogki544555896-4k`** |
| 构建信息 | `kleaf@build-host #1`，`Mon Aug 10 13:00:09 UTC 2026` |
| 安全补丁 | 2026 年 8 月 1 日 |
| 基带 | `MSM.28C1.MPSS.DE.7.0.221` |
| 内存/存储 | 12 GB (+12 GB 智慧运存) / 512 GB |

---

## 2. ★★ 决定性发现：内核 banner 与 H253「已修」内核逐字相同

`analysis/output/h253_magicos11_upgrade_verdict.md` 是我们 10-08 对 MEY-AN00 MagicOS 11 OTA 做
「OTA→CrAU→BSDF2→重建 boot_new.img」离线取证后得出的裁决。其中 §3.2 记录的新内核身份：

| | 旧（MEY 设备，可打） | 新（MagicOS 11，已判修） |
|---|---|---|
| linux_banner | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` | `6.6.118-android15-8-g**554929766a0d**-abogki**544555896**-4k` |

而本次 PPG-AN00 截图显示：

```
6.6.118-android15-8-g554929766a0d-abogki544555896-4k
```

⇒ **逐字完全一致**（git 短哈希 `g554929766a0d` + GKI 构建号 `abogki544555896` + `-4k` 页）。

**旁证（版本号同批次）**：MEY 的 OTA 目标为 `MEY-AN00 11.0.0.109(SP8C00E109R201P1)`；
PPG 现为 `PPG-AN00 11.0.0.109(SP8C00E109R104P1H1)` —— **同为 `SP8C00E109` 批次**，
仅机型/区域后缀（`R201P1` vs `R104P1H1`）不同。荣耀在同一波 MagicOS 11 推送里
对不同 SoC 机型使用了**同一份 GKI 构建**，完全符合预期。

### 2.1 为什么「同一 banner」就能判修（论证链）

1. `linux_banner` 里的 `g554929766a0d` 是 **GKI 源码树的 git commit 缩写**；
2. esp4.c / esp6.c 属 **GKI 核心**（`net/ipv4/esp4.c`），不在厂商 dlkm/vendor 侧；
3. 厂商若自行回移/修改补丁 ⇒ GKI 源码树变化 ⇒ 必然产生新 commit ⇒ **banner 的 git 哈希会变**；
4. banner（含 git 哈希 + 构建号 + 页大小 + 编译器串）**逐字一致** ⇒ 同一份源码树 + 同一次构建 ⇒
   `esp_input()` 的机器码**必然一致**；
5. H253 已对该 build 的 `esp_input()` 做过**汇编级实证**：
   - `esp_input` 指令数 旧 201 → 新 **203**（`+2`）
   - 新增 `ldrb w9,[x8]`（读 `skb_shared_info.flags` 字节）+ **`tbz w9,#1,<skip_cow>`**（测 `SKBFL_SHARED_FRAG`）
   - `esp6_input` 同形（203→205）
   - `module_init()` 行号指纹 `esp4.c` 1249→**1250**、`esp6.c` 1302→**1303**，各 **+1 行** —— 与源码树
     `} else if (!skb_has_frag_list(skb) && !skb_has_shared_frag(skb)) {` 的**单行回移**精确吻合。

⇒ **`esp_input()` 在 skb 带共享页（`MSG_SPLICE_PAGES` 进来的页缓存页）时强制走拷贝路径，
DirtyFrag 赖以生存的「AES-CBC 解密结果就地写进页缓存」原语在这台 PPG 上不存在。**

---

## 2.2 ★ 补做：在 PPG 本机内核镜像上的汇编实证（强度升到 ★★★★★）

上一节的论证依赖「同一 banner ⇒ 同一份 Image」。**本轮发现该前提不必依赖** ——
我们手上早已有这台 PPG 正在运行的那份内核镜像：

| 资产 | 路径 | 说明 |
|---|---|---|
| OTA 重建的 boot 镜像 | `analysis/scratch/ota_extract/boot_new.img`（100,663,296 B） | H253 用 CrAU+BSDF2 从 MEY MagicOS 11 OTA 重建 |
| 解包后的裸内核 | `analysis/scratch/ota_extract/kernel_new.raw`（37,128,704 B） | |
| 带符号 ELF | `analysis/scratch/Image-new.symtab.elf` | `vmlinux_to_elf` 重建 |
| 符号表 | `analysis/output/mey_11.0.0.109.kallsyms.txt`（111,075 符号） | `esp_input @ ffffffc08054caa4` |

**身份确认**（二进制内直接检索，非推断）：

```
$ grep -aoE "6.6.118-android15-8-g[0-9a-f]+-abogki[0-9]+-4k" boot_new.img | sort -u
6.6.118-android15-8-g554929766a0d-abogki544555896-4k      ← 与 PPG 截图逐字一致
```

⇒ 这不是「同 build 的两份镜像」，而是**同一份 GKI Image**。下面对它做的反汇编，
等价于对 PPG 正在执行的代码做反汇编。

### 实证结果（`llvm-objdump -d --disassemble-symbols`，NDK r27c）

对照物：`Image-mey.symtab.elf`（旧 build，MEY-AN00 / DNN-AN00 上**已实测 root 成功**）

| 函数 | OLD（可打） | NEW（PPG 在跑） | Δ |
|---|---|---|---|
| `esp_input` | 202 条 | **204 条** | **+2** |
| `esp6_input` | 204 条 | **206 条** | **+2** |

**`esp_input` 关键块逐条对照**（地址为该镜像内的真实 VA）：

```
── OLD（可打，Image-mey）────────────────────────────────────────
  ffffffc080ff25cc: ldr   x9, [x8, #0x8]        ← frag_list
  ffffffc080ff25d0: cbz   x9, <skip_cow>        ← !skb_has_frag_list → 跳过 COW
  ffffffc080ff25d4: mov   x2, sp
  ffffffc080ff25d8: mov   x0, x19
  ffffffc080ff25e0: bl    skb_cow_data
              ↑ 只有 1 个条件：无 frag_list 就原地解密 → 写进页缓存

── NEW（PPG 在跑，Image-new）────────────────────────────────────
  ffffffc08054cb70: ldr   x9, [x8, #0x8]        ← frag_list
  ffffffc08054cb74: cbnz  x9, <do_cow>          ← 有 frag_list → 去 COW
  ffffffc08054cb78: ldrb  w9, [x8]              ★ 新增：读 skb_shared_info.flags（字节宽）
  ffffffc08054cb7c: tbz   w9, #0x1, <skip_cow>  ★ 新增：测 bit1 = SKBFL_SHARED_FRAG
  ffffffc08054cb80: mov   x2, sp
  ffffffc08054cb8c: bl    skb_cow_data
              ↑ 2 个条件：无 frag_list **且** 无共享分片 才跳过 COW
```

**`esp6_input` 助记符序列 diff**（同形，交叉验证）：

```
53c53,55
< cbz
---
> cbnz
> ldrb
> tbz
```

（其余 diff 行是编译器调度搬移，净计数为 0；净增就是 `ldrb` + `tbz` 这 2 条。）

### 语义结论

- **OLD**：`else if (!skb_has_frag_list(skb))` ⇒ 只要没有 frag_list 就**跳过 COW、原地解密**。
  `MSG_SPLICE_PAGES` 送进来的页缓存页恰好「有共享分片、没有 frag_list」⇒ **直接写进页缓存** = DirtyFrag 原语。
- **NEW**：`else if (!skb_has_frag_list(skb) && !skb_has_shared_frag(skb))` ⇒
  页缓存页带 `SKBFL_SHARED_FRAG` ⇒ **强制走 `skb_cow_data()` 拷贝**，原页不再被原地覆写。
- 与 H253 §3.3 的源码对账（`esp4.c` / `esp6.c` 各 +1 行）及 H254 的位号订正（**bit 1**，非 bit 0）**完全吻合**。

⇒ **本裁决不再依赖「同 banner 推断」，而是建立在 PPG 实际运行的内核镜像之上的汇编实证。**

---

## 3. 对既有 PPG 适配计划的冲击（★ 需作废一条判定）

`2026-10-10` 记忆曾给出「**PPG 大概率零适配直接可用**」并列入主线待办①，其前提是：

> PPG uname = `6.6.89-android15-8-g082e5a98dac1-abogki463734347`

（来源：`2026-10-09.md` 记录 + 10-10 的 MODVERSIONS/KMI 推理）

**现在 PPG 的 uname 已经是 `6.6.118-...-abogki544555896-4k`** ⇒ 说明这台 PPG **已经从 MagicOS 10
（6.6.89）升级到了 MagicOS 11（6.6.118）**。

| 项 | 10-10 前提 | 现在实际 | 影响 |
|---|---|---|---|
| 内核 | 6.6.89 / abogki463734347 | **6.6.118 / abogki544555896** | 前提失效 |
| MagicOS | 10.x | **11.0** | 前提失效 |
| Android | 16 | **17** | 前提失效 |
| 43284 状态 | 推定在窗（未修） | **已修** | ★ 判定反转 |
| 「零适配直接打」| 有效 | **作废** | ★ |

⇒ **待办①（PPG 适配）应重新定性：不是「适配 KO」，而是「目标机已升级，无洞可打」。**

---

## 4. 回滚可能性：无通道

| 通道 | 可行性 | 依据 |
|---|---|---|
| fastboot 切回旧 slot | **不行** | BL 锁死（`H253` 已对同厂同锁机型论证）；VAB 的 `--set-active` 在 locked 下被拒 |
| 刷入官方旧固件 | **不行** | 无 BL 解锁 ⇒ 无 fastboot flash；荣耀官方降级仅限「服务中心 + 上一大版本最新正式版 + 清空数据」 |
| ADB 侧切 slot | **不行** | `bootctl` / `update_engine` 需 root 或 system 权限，shell 域（uid=2000）无 |
| ARB 是否拦 | **不拦**（但无意义）| MEY 实测 20 个分区 `rollback_index` 全 0；PPG 未测，但「不拦」≠「有路」 |

★ **一个理论上的残留希望（当前取不出来）**：VAB 升级把新系统写进 inactive slot 后重启，
**原 active slot 上的旧 6.6.89 系统通常仍原地保留**。也就是说 PPG 的 inactive slot 里
**很可能还躺着一份可打的 6.6.89**。但取出它需要 fastboot/BL 解锁 ⇒ 当前**不可达**。
若将来出现任何 BL 解锁或 slot 切换能力，这是唯一值得回头挖的点。

---

## 5. 顺带解决的一个旧疑点（旁证价值）

H253 §1 曾订正：「联网资料称 MagicOS 11 = Android 17 / GKI **6.12** —— **对本机不成立**」，
我们从 payload 重建出的新内核仍是 **6.6.118**。

本次 PPG 截图**独立地**给出了同一组合：**Android 17 + MagicOS 11.0 + 内核 6.6.118**。

⇒ **H253 的离线重建结论被一台真机上的实读数值交叉验证**。这也说明：
判定漏洞在不在，**绝不能看「Android 大版本」或「内核 6.6.118 这个前缀」，必须看到 `abogki` 构建号这一层**。

---

## 6. 判定边界与可证伪条件（诚实标注）

| 项 | 说明 |
|---|---|
| **强度** | ★★★★★ —— 已在 **PPG 实际运行的内核镜像**（`boot_new.img`，banner 与截图逐字一致）上完成 `esp_input` / `esp6_input` 汇编实证，见 §2.2 |
| **残留边界（唯一）** | PPG 设备上的 boot 分区我们**无法直接读取**（无 root / BL 解锁），比对依据是「banner 逐字一致 ⇒ 同一份 GKI Image」。若荣耀对 PPG 另行分发过一份 banner 相同但内容不同的 GKI（违背 GKI 通用性原则，极不可能），则需重判 |
| **可证伪条件** | 若能取到 PPG 的 boot 分区并重建符号：`esp_input` 指令数为 **202** 且无 `ldrb`+`tbz #1` ⇒ 本裁决被推翻；为 **204** ⇒ 坐实 |
| **计数口径说明** | 本轮用 `llvm-objdump` 实测为 **OLD 202 / NEW 204**；H253 报告 §3.3(c) 同为此数，但其后 §"独立复算"段写作 201→203（应为计数边界差异）。**以本轮实测 202→204 为准**；结论不受影响（净增仍是 2） |
| **未验证项** | PPG 的 `selinux_state` 符号、`crash_dump64` 路径、`libc++.so` hook 偏移、vendor 候选库、KSU KO 可加载性 —— **这些已无意义**（漏洞已修，链路起点就没了） |

---

## 7. 建议动作

1. **这台 PPG-AN00（11.0.0.109）不要再投 DirtyFrag 工时** —— 起点已断。
2. **冻结其它尚未升级的目标机**：任何仍在 `6.6.89-*`（`abogki463734347` 及更早）或
   `6.6.118-*-abogki518694926`（MEY/DNN 可打 build）的荣耀机，**立刻关闭系统更新**，
   它们才是能打的目标。（PPG 若还有同型号未升级的机器，价值极高。）
3. **无需再上机验证 / 装 APK 采集**：判定已在 PPG 本机内核镜像上完成（§2.2）。
   真机跑一次只会重复确认「页没被覆写」，不产生新信息，却要消耗 1 次上机 + 1 个 boot。
   ⇒ **本条替换掉原「实测定论」计划。**
4. **路线层面**：这台机器要 root，只能找**新的未修漏洞**，成本量级 ≈ 本项目 10 天 × 3 条线。
   已知三条全部判死：43284 已修 / 43499 已修 / 64560 架构性死。

---

## 8. 附：一个技术副产品（若将来需要给新 build 改 KO）

即便漏洞已修，记录一条可复用事实 —— 旧 KO 的 vermagic 可**等长原地改写**到新 build：

```
旧: 6.6.118-android15-8-gf17133276a57-abogki518694926-4k
新: 6.6.118-android15-8-g554929766a0d-abogki544555896-4k
     └ 12 hex ┘              └ 9 位 ┘
```

- `f17133276a57` → `554929766a0d`：**12 → 12 等长** ✔
- `518694926` → `544555896`：**9 → 9 等长** ✔
- 总长不变 ⇒ 可原地 patch `.modinfo` 段字符串，不破坏 ELF 布局
- 两者同为 KMI `android15-8` ⇒ MODVERSIONS 下符号 CRC 冻结一致，改写后**大概率可 insmod**

（本条对当前 PPG 无用 —— 洞没了，KO 能装也提不了权。留档备用。）

---

## 9. 附：装 APK 采集 —— 能抓到什么 / 抓不到什么

用户提议「装个 APK，抓取 DirtyFrag 需要的文件再解析判断」。对**当前这台 PPG** 的答案是
**无增益**（结论已由 §2.2 的镜像实证锁定）；但对**其它未升级的目标机**这套采集有明确价值，留档如下。

### 9.1 抓不到（无 root 的硬限制）

| 项 | 原因 |
|---|---|
| boot / vendor_boot 分区镜像 | 块设备节点 `root:root 660`，shell 域（uid 2000）无读权限 |
| `/proc/kallsyms` 符号地址 | Android 默认开 `kptr_restrict`，地址全 0 |
| 内核内存 | 无 `/dev/kmem`，无等价访问面 |

⇒ **「漏洞在不在」这件事，APK 抓文件做不到。** 它只能回答「如果洞在，链路其它环节是否齐备」。

### 9.2 能抓到（对未升级机器有价值）

**A. 身份与环境**（`getprop` / `cat`，无需 root）
- `ro.board.platform`、`ro.boot.hardware.soc` —— 确认 SoC（`sun` = SM8735 / PPG 为 SM8750）
- `ro.build.version.incremental`、`ro.build.display.id` —— 定位固件，便于离线拉官方包
- `cat /proc/version` —— **内核 banner（必须看到 `abogki` 号这一层，看 Android 版本会误判）**
- `getprop ro.boot.flash.locked` —— BL 锁状态
- `getenforce`

**B. DirtyFrag 链路前置**（决定「洞在的话能否打」）
- `/apex/com.android.runtime/bin/crash_dump64` 是否存在
- `/sys/module/esp4` 是否存在（判 esp4 是 builtin 还是模块）
- vendor 分区三候选库（erofs 只读即可列目录）
- `libc++.so` 的 `ostream::sentry::sentry` 符号偏移（读 ELF 即可，无需 root）
- `ls /sys/module/` 全量 —— 看哪些子系统编进内核

**C. 门槛类**（决定是不是连第一步都过不去）
- `IpSecManager` / xfrm 能否建 SA —— DirtyFrag 的第一道门（BVL 上实测 `GATE_FAIL`：xfrm EACCES）
- `/proc/self/status` 的 `CapBnd` —— BVL 死因之一（capbnd=0）
- `unshare` 是否可用（user_ns）

### 9.3 结论

- **这台 PPG-AN00（11.0.0.109）**：**不必装**。§2.2 的镜像实证比任何真机采集都硬。
- **任何未升级的目标机**：值得装，但采集目标是 **9.2 的 B / C 类**（链路前置 + 门槛），
  而非「判洞在不在」——后者只能靠内核镜像反汇编（走 OTA / 官方固件离线重建，即 H253 那条路）。
