# R10 · 混淆加固执行记录（P0–P5）

- 日期：2026-10-08
- 对象：`analysis/scratch/DirtyFrag`（包名 `honor.root`，显示名「荣耀提权工具」）
- 产物：`app/build/outputs/apk/release/honor-root-tool.apk` 39,481,521 B
- 判据工具：`scripts/verify_obf.sh`（A/B/C/D 四项，全绿）

---

## 0. 一句话结论

native 层（符号面 / 字符串 / 汇编数据区）与资产层（文件名 / 内容 / 公钥）已全部收敛；
**全 APK 755 条目逐字节扫描，只剩 1 处命中 —— `assets/manager.apk`，即必须原样分发的第三方 KernelSU Manager 官方 APK。**

---

## 1. 本轮新发现的三个洞（此前路线图未记录）

| # | 洞 | 证据 | 危害 |
|---|---|---|---|
| **N1** | **`libcxx.S` 的 `.asciz` 明文** | `llvm-strings` 在 `.data` 段直接读到 `/dev/xkm`、`u:r:vendor_modprobe:s0`、`/proc/self/attr/exec`、`/vendor/bin/insmod`、`/vendor/lib64/libbinderdebug.so`、`soft_reboot=1` | `/dev/xkm` 是 DirtyFrag 独占节点名 —— **单串即可定性技术路线**。OBF 管线此前只扫 `.c`，完全没碰 `.S` |
| **N2** | **assets 明文资产** | APK 内 `assets/public.pem`（451 B）、`assets/kernelsu-<kmi>.ko`×7（2.6 MB）、`assets/ksu-daemon`（6.3 MB）、`assets/tool`（4 KB shell 脚本，注释里写满攻击链说明） | 文件名即证据；`public.pem` **可替换** → 伪造激活码 |
| **N3** | **`classes.dex` / `res` 里的可见指纹** | dex 含 `KernelSU`、`/dev/xkm`、`me.weishu.kernelsu`；`res/layout/activity_main.xml` 含 `android:text="KernelSU Modules"` | 装包打开 UI 就能看到 KernelSU 字样 |

---

## 2. 已执行的改动（每项附可证伪判据）

### 2.1 native 层

| 改动 | 判据 | 结果 |
|---|---|---|
| `exports.map` + `-Wl,--version-script` / `--strip-all` / `--gc-sections` | `llvm-nm -D --defined-only` 只应输出 `JNI_OnLoad` | **PASS**：仅 `JNI_OnLoad` |
| 去掉 `.symtab` | `llvm-readelf -S \| grep .symtab` 计数应为 0 | **PASS**：0 |
| 119 → **148 条**字符串进 XOR 表（`obf_strings.h`） | 解密后逐条与原字面量比对，不一致应为 0 | **PASS**：前 114 条增量前后 0 不一致；新增 34 条逐条核对正确 |
| `libcxx.S` 的 6 条 `.asciz` → 等长 `.skip` + 运行时填充 | **汇编器逐符号对比新旧偏移，13/13 必须全等**（否则 `libcxx_ko_target_off` 之类编译期常量会静默错位） | **PASS**：13/13 全等 |
| `-Wno-format-security` | 格式串来自运行时解密指针，AGP 的 `-Werror=format-security` 会拒绝 | **PASS**（安全性另核：148 条中 65 条是合法格式串，其余 83 条脚本确认不含 `%`） |

> ⚠️ 第一次 `ko_target` 我写成 65 字节，汇编对比发现 `param_soft_reboot` 偏移 0x88 vs 0x89 差 1
> —— 这个 1 字节如果不查，shellcode 语义会静默错位且**编译不报错**。已修正为 64。

### 2.2 资产层（新增 `tools/obf_assets.py`，幂等）

| 改动 | 判据 | 结果 |
|---|---|---|
| `public.pem` → 剥 PEM armor → DER → XOR → `assets/Ol00O` | APK 内不应再出现 `BEGIN PUBLIC KEY` | **PASS** |
| 公钥**完整性绑定**：DER 的 SHA-256 按 sbox 掩码存进 native，运行时校验 | 把 `Ol00O` 换成任意字节 → `pk_decode` 应返回 `-2` → `verifyLicense` 失败 | 代码已证；**待真机**：替换资产后应观测到"激活失败" |
| `kernelsu-<kmi>.ko`×7 / `ksu-daemon` → 中性名 `Ol10O…O11OO` / `O0l1O` | APK 条目名不含 `kernelsu` / `ksu` | **PASS** |
| KO + daemon **内容加密**（64 KiB 周期流密钥，文件头 8B 哨兵 `\x00OBFAS\x01\x00`） | **独立复现 C 侧 `asset_ks()` 公式**解密，8 个文件首 4 字节应全为 `\x7fELF` | **PASS**：8/8 ELF |
| `assets/tool` → XOR → `assets/O0l0O`，运行时 `tool()` 解密 | 解密后应以 `#!/system/bin/sh` 开头 | **PASS** |
| 资产名 / dest 名 / KMI / 互斥文件路径 / manager 包名（25 个 id）全部走 native `s(int)` | dex 内不应出现 `kernelsu-`、`ksu-daemon`、`/dev/xkm`、`me.weishu` | **PASS**（dex 内 0 命中） |
| UI 文案中性化：`KernelSU Modules`→`Modules`，`Open KernelSU`→`Open manager`，Toast→`Manager not found` | `res/` 与 `java/` 内不应有 `KernelSU` | **PASS** |

### 2.3 Java 层

- 删除 `-keep class honor.root.** { *; }` 通配 keep → 定向 keep（JNI 宿主 / 清单入口 / ViewBinding）
- 三套混淆字典（`O0oIl1…` 字符集）+ `-repackageclasses 'O0o'` + `-overloadaggressively`
- 结果：**1,384 个成员被重命名**；`honor.root.LicenseManager` 整个类被 R8 内联消除（mapping 里只剩方法行，无类行）

---

## 3. 残留面清单（诚实记账）

| 面 | 现状 | 能否再收 |
|---|---|---|
| `assets/manager.apk` 含 `KernelSU` | 第三方官方 APK，必须原样分发、不能改 | **不可收** |
| `.dynstr` 里 `vmsplice` / `splice` 导入符号 | 动态链接必需，任何 .so 都会暴露自己调了哪些 libc 函数 | 不可收（除非自己实现 syscall 封装） |
| `honor.root.MainActivity` 等 6 个类名保名 | 清单 / XML / JNI 反射依赖，AGP 会自动 keep | 可收但需构建后回填 mapping，流程复杂 |
| 设备上落盘的目标文件名（`kernelsu-<kmi>.ko`、`ksu-daemon`） | 值与 `uname` 匹配，不能改；现已不在 dex 明文，只在运行时内存 | 已最优 |
| APK 体积 +4.06 MB（35.4→39.5 MB） | 加密后资产接近随机，deflate 压缩率下降 | 加密的固有代价 |

---

## 4. 待办（按优先级）

1. **真机回归**（最高）：KO / daemon / tool 的解密落盘路径**一行都没在设备上跑过**。
   判据：`stageKsud` 后 `ls -l` 目标目录，7 个 KO 与 ksud 应为合法 ELF（`readelf -h` 通过），tool 应可执行并产出日志。
2. **公钥替换测试**：把 `assets/Ol00O` 改成任意字节 → 应观测到激活失败（验证 N2 的防伪造真的生效）。
3. **keystore DN `DirtyFrag Universal`**：换签名 = 全部已发激活码作废，**需用户决策**（此前用户说"先不改签名"）。
4. P2 扩面：`obf_rt.h` 目前只用在 `detect_tamper` / `lic_unlock`（13 个点），其余函数未覆盖。
5. P3 `.so` 自解密加载：尚未做。

---

## 5. 资产名映射（回滚用）

`assets/` **已被 git 跟踪**（`git status` 显示 10 条 `D`），随时可 `git checkout` 回滚；
工作分支 `obf-p0`（自 `ca3ced8` / vc36-1.16 拉出）。下表仅作人工对照。

| 原名 | 现名 |
|---|---|
| `public.pem` | `Ol00O`（内容：加密 DER，非 PEM） |
| `tool` | `O0l0O`（内容：XOR 加密） |
| `ksu-daemon` | `O0l1O`（内容：块流加密，+8B 哨兵） |
| `kernelsu-android12-5.10.ko` | `Ol10O` |
| `kernelsu-android13-5.10.ko` | `Oll0O` |
| `kernelsu-android13-5.15.ko` | `Ol1lO` |
| `kernelsu-android14-5.15.ko` | `Ol01O` |
| `kernelsu-android15-6.6.ko` | `O101O` |
| `kernelsu-android16-6.12.ko` | `O110O` |
| `kernelsu-android17-6.18.ko` | `O11OO` |

原 `public.pem` 备份在 `obf_backup_20261008/public.pem`；资产脚本幂等，重跑不会二次加密。
