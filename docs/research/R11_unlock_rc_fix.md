# R11 · 「unlock failed」根因定位与修复

日期 2026-10-08 · 设备 MEY-AN00（离线期间完成，纯静态 + 离线自测）

## 结论（一句话）

> `lic_unlock()` 的**成功路径 `return 1`**，而 `crypto_core.h` 的契约和 `exp.c:n0()` 的判定都要求 **`0 = 成功`**。
> 函数体内**根本不存在 `return 0`**，所以 `n0()` 恒为 false → `runExploit()` 恒抛 `IllegalStateException("unlock failed")`，
> **与激活码是否正确、设备码是否匹配、证书指纹是否一致完全无关**。

---

## 1. 证据链

### 1.1 契约（crypto_core.h:15-21）— [源码]

```
 * Returns 0 on success; 1..8 = failure step (1 lic format, 2 KEK mac,
 * 3 blob magic, 4 blob len, 5 blob mac, 6 bundle magic, 7 entry/hash,
 * 8 alloc). Diagnostic field builds only. */
```

### 1.2 实现（crypto_core.c, lic_unlock 全函数 return 清单）— [源码]

| 行内偏移 | 语句 | 返回码 |
|---|---|---|
| +10 | 参数/长度非法 | 1 |
| +33 | KEK MAC 不符 | 2 |
| +44 | blob magic 不符 | 3 |
| +47 | blob 长度不符 | 4 |
| +52 | blob MAC 不符 | 5 |
| +55 | malloc 失败 | 8 |
| +59 | bundle magic 不符 | 6 |
| +62 | count 越界 | 8 |
| +71 / +79 | 成员 off/len 越界或 sha 不符 | 7 |
| **+86** | **`g_unlocked = 1; return 1;` ← 成功路径** | **1（应为 0）** |

**10 条 return，无一条返回 0。**

### 1.3 调用方（exp.c:808-813）— [源码]

```c
int rc = lic_unlock(...);
REPORTLN(OBF(84), rc, tampered, blob_len);   // "unlock diag: rc=%d tamper=%d blob=%zu"
ok = (rc == 0) ? JNI_TRUE : JNI_FALSE;
```

→ `ok` 恒为 false。

### 1.4 上游归属（git）

`git show HEAD:app/src/main/jni/crypto_core.c` 与 `git show HEAD:app/src/main/jni/exp.c`
**同样是 `return 1` + `ok = (rc == 0)`** ⇒ **不是我们加固引入的回归，是上游既有缺陷**。
本轮只改了失败分支加 `OPAQUE_T()`（anti-tamper 包装），未触碰返回值。

### 1.5 汇编差分证明 — [汇编已证]

单独把 `crypto_core.c` 编成带符号 arm64 目标文件（`-O1`，NDK r27c clang），
新旧两版各自反汇编 `lic_unlock` 尾部：

```
旧版(return 1):  49c: 52800020   mov w0, #0x1
新版(return 0):  49c: 2a1f03e0   mov w0, wzr
```

唯一差异即返回值，其余指令完全一致。

---

## 2. 修复

`app/src/main/jni/crypto_core.c` 成功路径：

```c
    g_pt = pt; g_pt_len = pt_len; g_count = count;
    g_entries = entries; g_payload = payload;
    g_unlocked = 1;
    /* MEY FIX: contract in crypto_core.h says 0 = success ... */
    return 0;
```

---

## 3. 排除的其它嫌疑（都已证伪，勿重复排查）

| 嫌疑 | 判据 | 结论 |
|---|---|---|
| `detect_tamper()` 误报致毒化 | 解码 `detect_tamper` 读的是 `/proc/self/status`（`TracerPid:`）与 `/proc/self/maps`（`frida`/`gadget`），两者任何 app 均可读 | 正常机 tamper=0，**不是它** |
| 证书指纹不一致 | `apksigner verify --print-certs` SHA-256 = `70f81aca…0923`，与 `license_kit/cert_fp.txt` 逐字符相同 | 排除 |
| 设备码算法不一致 | Java `deviceCode()` = `SHA256(ANDROID_ID\|FINGERPRINT)` upper-hex；`gen_license.py` 同式 | 排除 |
| 签名/加密/资产包坏 | 见 §4 离线全链自测 GREEN | 排除 |
| 激活码长度 | 实际 **472** 字符（Base64 of 352B）；README 写的 464 是笔误，代码无任何 464 约束 | 仅文档 |

**注意**：`lic_is_unlocked()` 在成功路径已被置 1，所以只要 Java 不抛异常，`n1` 本来是能跑的。
也就是说这个 bug 的表现是「永远走不到 exploit」，而不是「exploit 静默失败」——与历史现象吻合。

---

## 4. 离线全链自测（独立透镜，GREEN）

`gen_license.py` 优先用封印件 `enc_private.bin`/`enc_dk.bin`，需一次性 `ISSUER_PASS`（封印时随机生成、未留存）。
新增 `analysis/scratch/license_selftest.py`：注入明文私钥源，**不复制任何密钥**，复用 `gen_license` 自身的 `self_test()`。

```
[.] code=0123…CDEF
[.] blob=352B  license=472 chars
[+] self-test OK: sig verify + reject, KEK->DK->blob, 8/8 members sha-verified (order-mapped)
```

覆盖：RSA 验签 + 错误载荷拒签 → KEK(HKDF) → MAC → DK → `payload.bin` HMAC → AES-CTR 解密 → `DFASSET1` → 8/8 成员 SHA-256 对账 `bundle_hashes.h`。

⇒ 加密/签名/设备绑定三段全部正确；**唯一阻断就是返回码**。

---

## 5. 重建与验收

| 项 | 结果 |
|---|---|
| `BUILD SUCCESSFUL`（12s） | ✅ |
| native 确已重编 | `libexp.so` 09:52:33 > `crypto_core.c` 09:46:36 ✅ |
| APK | `honor-root-tool.apk` **35,418,397 B**（+8 B） |
| `verify_obf.sh` A/B/C/D | **全部 PASS** |
| 签名证书指纹 | `70f81aca…0923`，**未变**（已发/待发激活码继续有效）✅ |
| `postbuild_clean.sh` | mapping.txt 已归档 `obf_private_20261008_095804`，APK 内无残留 |

### 5.1 C 项新出现的 4 处泄漏 —— 已知且可逆的降级

`--no-encrypt`（用户要求「先不加密」）把 **UMH shell 脚本以明文内嵌进 `libexp.so` 的 `.rodata`**，
带回 `ksud` / `KernelSU` / `kernelsu` / `/data/local` 四个指纹串（偏移 0x56ee / 0x57c4 / 0x5a51 / 0x5be6）。

处置：`verify_obf.sh` 增加 `OBF_NOENC=1` 开关，把这 4 个串标为 allowed，**其余 15 个键仍必须干净**：

```
C. 敏感串 0 泄漏（OBF_NOENC=1）   PASS (0)
```

恢复加密只需重跑 `tools/obf_assets.py`（不带 `--no-encrypt`）+ 重新 assembleRelease，
然后把 `OBF_NOENC` 去掉再验收。

---

## 6. 上机交接（设备插回后）

脚本：`analysis/scratch/device_handover.sh`

**关键设计**：设备码**不**用 `adb shell settings get secure android_id`。
Android 8+ 的 ANDROID_ID 按（签名键, user）隔离，adb 读到的是 `com.android.shell` 的值，
与 `honor.root` 在 app 内读到的**不是同一个**——用 adb 值发码必然「device mismatch」。
正确途径：装包 → 首启 → app 自己把 `device_code=<64hex>` 打进 logcat（`honorroot` TAG，MainActivity:312）。

流程：
```
source toolchain/env.sh
bash analysis/scratch/device_handover.sh
```
0. 基线（boot_id / kernel / uid / getenforce）
1. `adb install -r`
2. 首启抓 `device_code=`
3. `license_selftest.py <code> license.txt`（离线签发，自带全链自测）
4. push `license.txt` → `/sdcard/Android/data/honor.root/files/` + 回读校验
5. **单发** `am start --ez auto_run true`（一 boot 一发）
6. 判据：`unlock diag: rc=0 tamper=0` + `id -u`=0 + `getenforce`≠Enforcing + boot_id 是否变化

---

## 7. 待办（更新后）

1. **上机跑 step 5-6**（设备一回来即可执行；`rc=0` 是本次修复的直接判据）
2. 公钥替换测试：改 `assets/Ol00O` 任一字节 → 应观测激活失败
3. keystore DN `DirtyFrag Universal`（换 = 全部激活码作废，需用户决策）
4. 决定是否回退 `--no-encrypt`（当前：功能性优先、4 个指纹串在 .so 内）
5. P2 扩面（现覆盖 13 点）、P3 `.so` 自解密 loader 未做
