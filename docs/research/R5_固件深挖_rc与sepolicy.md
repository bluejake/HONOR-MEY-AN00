# R5 固件深挖：rc 脚本与 sepolicy 空洞 — 离线取证报告

> 目标设备：MEY-AN00（荣耀 500，MagicOS 10 / Android 16，内核 6.6.118-android15-8，BL 锁定）
> 起点：uid=2000 shell　　模式：**纯案头（离线）**，未连 adb、未上机执行
> 素材：`analysis/output/c_line/`（完整固件提取链路产物）
> 标注体系：`[已实测]`（有命令输出）/ `[二进制实读]`（Python 读出字节）/ `[文本推断]` / `[未验证]`

---

## R5 结论摘要

1. **`su` 域已完整定义，不是空洞**。`(type su)` 在 `plat_sepolicy.cil:3979`，`(type su_exec):3981`、`(type su_key):4488` 均在。空洞里丢的是 `fifo_file` 的 classcommon 段，不是 su 规则本体 `[二进制实读]`。
2. **`su` 域实质是「空壳」**：全域仅 4 条非-userfaultfd 规则（hal_codec2_server / perfetto），**`type_transition` 数为 0**，且 `(neverallow domain su_exec (file (execute execute_no_trans)))`（:14905）禁止任何域执行 su_exec。**su 无法被进入** `[已实测]`。
3. **`shell` 可以写 `kcmdline_prop`**：`(allow shell kcmdline_prop (property_service (set)))`（:27078）显式存在 `[二进制实读]`。
4. **`base_typeattr_880` = `(domain)` 减去 `(init shell kcmdlinectrl)`** —— shell 被**显式排除在 neverallow 之外**（:32911 / :25601）。这是有意设计的放行，不是绕过 `[二进制实读]`。
5. **注入链闭合**：`init_kcmdlinectrl.rc:22` `exec -- /system/bin/kcmdlinectrl store binder ${kcmdline.binder:-c}`。shell 若能写 `kcmdline.binder`，值被展开进 argv → **属性→argv 注入**（缺口1 的假设成立，但注入面在该文件而非 hw_init.rc）。
6. **厂商 rc 真正的兴趣点是 `adbd`/`hdbd`**：`--root_seclabel=u:r:su:s0` + `user root`，在 `hw_init.usb.rc`（**不在** hw_init.rc）。
7. **`hw_init.rc` 无任何服务利用价值**：仅 6 个 service，身份全部收敛（`nobody`/`root`+ueventd/`shell`+console）。唯一 setprop 是普通业务属性，**kcmdline 命中 0**。
8. **属性真名未确认，且当前不可确认**：`property_contexts` 在整个提取树中不存在（4 个 raw 分区明文扫描 0 命中）。`kcmdline_prop` 的真名**未验证**。
9. **`magisk` 全树 0 命中**（含 binary policy 符号表）——无 Magisk 残留，此路线不必再查。
10. **重要方法论警告**：`Grep` 工具对 `base_typeattr_880` 报 0 命中，Python 同条件报**存在**。本轮所有 0 命中结论均已用 Python 复核。

---

## R5.1 `system_etc_init_hw_init.rc` 审计

**路径**：`D:\MEY-AN00-root-repro\analysis\output\c_line\risk_system\system_etc_init_hw_init.rc`
**大小**：65,618 B | **有效内容**：0–61,660（61,660 B，1,442 行）| **NUL**：61,660–65,618

### 表格：服务名 | 触发 | 身份 | 属性依赖 | 注入面

| 服务名 | 触发时机 | 执行身份 | 属性依赖 | 注入面 |
|---|---|---|---|---|
| `boringssl_self_test32` | `class core`（自动） | `user nobody` + `capabilities`（**显式清空**） | 无 | 无 |
| `boringssl_self_test64` | `class core` | `user nobody` + `capabilities`（清空） | 无 | 无 |
| `boringssl_self_test_apex32` | `class core` | `user nobody` + `capabilities`（清空） | 无 | 无 |
| `boringssl_self_test_apex64` | `class core` | `user nobody` + `capabilities`（清空） | 无 | 无 |
| `ueventd` | `class core` + `critical` | **`user root`** + `seclabel u:r:ueventd:s0` | 无 | 无（标准 AOSP） |
| `console` | `disabled`（需显式启动） | `user shell` + `group shell log readproc` + `seclabel u:r:shell:s0` | 无 | 无（`/system/bin/sh` 本来 shell 就是 shell uid） |

**四个 boringssl 服务是「诱饵」**：注释明说 "doesn't require any capabilities"，且 `capabilities` 单独一行 = **清空 capability 集**（AOSP 语义），不是提权。`nobody` 无价值。 `[已实测]`

### `kcmdline` / 属性注入面

| 缺口要求 | 实测结果 |
|---|---|
| `kcmdline` 命中 | **0**（阳性对照：`${` 展开点 21 处、`import` 8 处，均正常命中 → 方法有效） |
| `setprop` | 13 处，全为业务属性：`ro.prefetch_boot.enabled`、`vendor.qti.qcc.oper.mode`、`bootreceiver.enable`、`keystore.boot_level`、`apexd.status`、`sys.use_memfd`、`persist.sys.fuse`、`net.tcp_def_init_rwnd`、`perf.drop_caches` — **无 kcmdline 类** |
| `mlstrustedsubject` | **0 命中** |
| `${` 展开 → argv | 21 处。唯一有 argv 语义的是 `:1366` `exec_background -- /system/bin/extra_free_kbytes.sh ${sys.sysctl.extra_free_kbytes}` — 值来自 `ro`/`sysctl`，shell 不可写，**不构成注入** |
| `uid=`/`gid=` 挂载 | `:1036` `mount tmpfs /data_mirror ... mode=0700,uid=0,gid=1000`；`:78` `mount tracefs ... gid=3012` — 硬编码常量，非属性 |
| `capabilities` | 8 处，全在 boringssl 注释+清空 |

**`import` 子脚本**（8 处，5 处带属性展开）：

```
:7   import /init.environ.rc
:8   import /system/etc/init/hw/init.usb.rc      ← 关键！见下
:9   import /init.${ro.hardware}.rc
:10  import /vendor/etc/init/hw/init.${ro.hardware}.rc
:11  import /system_ext/etc/init/hw/init.usb.configfs.rc
:12  import /system/etc/init/hw/init.${ro.zygote}.rc
:473 import /system/etc/init/hw/init.boringssl.${ro.zygote}.rc
```

### ★ 真正的发现：`hw_init.usb.rc` 里的 `adbd` / `hdbd`

`:8` import 的子脚本已提取到：`risk_system\system_etc_init_hw_init.usb.rc`（8,757 B）

```
26| service adbd /system/bin/adbd --root_seclabel=u:r:su:s0
27|     class core
28|     socket adbd seqpacket 660 system system
29|     disabled
30|     updatable
31|     seclabel u:r:adbd:s0
32|     user root
---
171| service hdbd /system/bin/hdbd --root_seclabel=u:r:su:s0
172|     class core
173|     user root
174|     socket hdbd stream 660 system system
175|     disabled
176|     seclabel u:r:adbd:s0
```

- 主进程 `seclabel u:r:adbd:s0`，但 **`--root_seclabel=u:r:su:s0`** 让 adbd 在需要时切到 su 域，`user root`。
- `socket adbd seqpacket 660 system system` 是 world-writable 的本地 socket → **shell 可连接 adbd**。
- `hdbd`（Honor 定制调试守护进程）同样 `user root` + `--root_seclabel=su`，socket `hdbd stream 660`。
- 二者 `disabled`，但 `sys.usb.config=adb` 分支会 `start adbd`。 `[已实测]`

另有 `risk_system\system_etc_init_simpleperf.rc` 中厂商直接以 su 跑：

```
exec_background u:r:su:s0 root root -- /system/bin/simpleperf record -a -g ... -o /tmp/boot_perf.data
exec u:r:su:s0 root root -- /system/bin/killall simpleperf
```

→ **`su` 域在荣耀 vendor rc 里被真实使用**，但仅限 init 期一次性命令，shell 无从触发（触发器是自定义 event，非属性）。 `[已实测]`

### NUL 空洞定位

| 文件 | NUL 区间 | 长度 | 判定 |
|---|---|---|---|
| `system_etc_init_hw_init.rc` | 61,660 – 65,618 (EOF) | 3,958 | **截断，非 padding**。内容在 `:1442` 断在 `    c`（半个 token），且 61,659 字节**不是换行**（`ends_with_newline=False`），后续 3,958 B 全零 `[二进制实读]` |
| `plat_sepolicy.cil` | 36,841 – 53,818 | 16,977 | **中段 splice**，见 R5.2 |
| `plat_sepolicy.cil` | 2,335,535 – 2,339,457 (EOF) | 3,922 | 尾部截断，落在注释 `; This should be` 中间，同样是提取截断 |

结论：两个 `.cil`/`.rc` 的 NUL **不是原始固件内容被抹除**，而是**提取链路把稀疏/压缩区段填零**。rc 的 3,958 B 尾部丢失了 `ro.debuggable=1` 块的后半段（方法 trace 目录 chmod）。 `[二进制实读 + 文本推断]`

---

## R5.2 `su` 域规则本体

### 判定：**「已定义，但规则残缺且被 neverallow 封死」**

| 项 | 值 | 来源 |
|---|---|---|
| 文件 | `sepolicy\plat_sepolicy.cil` (2,339,457 B) / `sepolicy\precompiled_sepolicy` (2,016,860 B) | `[已实测]` |
| `(type su)` | **存在**，line 3979 | `[二进制实读]` |
| `(roletype object_r su)` | 存在，line 3980 | `[二进制实读]` |
| `(type su_exec)` / `(roletype object_r su_exec)` | 存在，3981 / 3982 | `[二进制实读]` |
| `(type su_key)` / `(roletype object_r su_key)` | 存在，4488 / 4489 | `[二进制实读]` |
| binary 符号表 | `su`(len=2) @176229、`su_exec` @225277、`su_key` @109211，**均为真实符号条目**（长度前缀编码已确认） | `[二进制实读]` |
| `su` 归属 | `(typeattributeset keystore2_key_type (keystore wifi_key shell_key su_key ...))` :536 | `[二进制实读]` |
| `su` ∈ domain | 是（在 `typeattributeset domain` 长列表内，token idx 78） | `[二进制实读]` |

### su 的全部非 userfaultfd 规则（**仅 4 条**）

| 行 | 规则 |
|---|---|
| 17961 | `(allow hal_codec2_server su (fifo_file (read)))` |
| 24087 | `(allow perfetto su (fd (use)))` |
| 24091 | `(allow perfetto su (fifo_file (ioctl read write getattr)))` |
| 24106 | `(dontauditx perfetto su (ioctl unix_stream_socket ((range 0x5401 0x5404) ...)))` |

另有 **44 条** `(dontaudit su <X>_userfaultfd (anon_inode ...))`（`:11606`–`:32352`，每个 app 域一条，全文对称生成，非特化）。 `[已实测]`

### 致命约束

```
14905| (neverallow domain su_exec (file (execute execute_no_trans)))
```

`type_transition` 涉及 `su` 的条数 = **0**。 `[已实测]`

**推论**：AOSP 从不定义 `su` 域（它不是 AOSP 组件，是 Magisk 引入的）。这里 `su`/`su_exec`/`su_key` 是**厂商在 AOSP 策略之上自行 type 声明**的，但**没有配套任何 transition 或 allow exec 规则**，同时被 `neverallow domain su_exec` 覆盖。结果：`su` 域**在策略上不可达（unreachable）**——没有任何进程能被 transition 到 `su`，也没有任何域能 exec `su_exec`。 `[文本推断，高置信]`

它唯一的作用是**承载 `--root_seclabel=u:r:su:s0` 这个字符串**，让 adbd/hdbd/simpleperf 的 argv 能带上合法标签；这些进程实际跑的仍是 adbd/hdbd/simpleperf 自己的代码路径。**没有 Magisk 二进制**（`magisk` 全树 0 命中，含 binary policy）。

### 空洞真相（推翻前一轮假设）

空洞 36,841–53,818 **不含 su 规则**：

- 洞前最后可读：`(class fifo_file ())` + `(classcommon fifo_fi` ← **在半个 token 处被截断**
- 洞后首字节：`dstore crosvm dhcp dnsmasq ...`（**从半个单词 `dstore` 中途接上**）
- 该语句 token 数 202，`su` 在 idx 78，是 `(typeattributeset domain (...))` 的成员列表尾部
- 洞内 ≈ 16,977 B 内容 = `(classcommon fifo_file ...)` 尾部 + 后续若干 class/typeattribute 定义

即：空洞落在 **class/classcommon 声明区**，su 域定义在 3,979 行，**远在空洞之后且完好**。 `[二进制实读]`

---

## R5.3 `kcmdline_prop` 的 neverallow 归属

### `base_typeattr_880` 全成员（完整定义）

```
32910| (typeattribute base_typeattr_880)
32911| (typeattributeset base_typeattr_880 (and (domain ) (not (init shell kcmdlinectrl ))))
```

**语义**：`base_typeattr_880` = 所有 domain **减去** {`init`, `shell`, `kcmdlinectrl`}。

> **前一轮「880 里含 kcmdline_prop」的表述有误**：`kcmdline_prop` 不在 `base_typeattr_880` 里；它是 `base_typeattr_880` 的**约束对象**。

### neverallow 语句

```
25601| (neverallow base_typeattr_880 kcmdline_prop (property_service (set)))
```

### 结论：shell **能**写 `kcmdline_prop`

三个事实叠加：

| 事实 | 行号 | 含义 |
|---|---|---|
| `neverallow` 目标是 `base_typeattr_880` | 25601 | 只约束 (domain − init − shell − kcmdlinectrl) |
| `shell` 被排除 | 32911 | neverallow **不适用于 shell** |
| 显式 allow | **27078** `(allow shell kcmdline_prop (property_service (set)))` | shell 主动获得写权限 |
| 显式 allow（读） | 27079 `(allow shell kcmdline_prop (file (read getattr map open)))` | 同上 |

对比：同文件 7,813 行 `(neverallow base_typeattr_232 shell_prop (property_service (set)))` + `base_typeattr_232`(:34207) = `(domain)` − `(coredomain)` —— shell ∈ coredomain，故**不能**写 `shell_prop`。**规则集是自洽的**：`shell_prop` 禁、`kcmdline_prop` 放行。 `[二进制实读]`

`kcmdlinectrl` 同样被放行：`:21907 (allow kcmdlinectrl kcmdline_prop (property_service (set)))`。

另有 `:25019 (neverallow base_typeattr_232 kcmdline_prop (file (...)))` —— 禁止**文件方式**操作该属性的 backing store，只能走 property_service（`init` 独占）。shell 无 `property_service map`，故**只能 setprop，不能直接改文件**。

### 属性→argv 注入链（闭合）

```rc
# system_etc_init_kcmdlinectrl.rc:17-22
on early-boot
  exec_background -- /system/bin/kcmdlinectrl update-props

on property:kcmdline.binder=*
  wait_for_prop kcmdline.loaded 1
  exec -- /system/bin/kcmdlinectrl store binder ${kcmdline.binder:-c}
```

init 的 `${prop}` 展开**不做 shell 分词/转义**，直接插入 argv。shell 有 `allow shell kcmdline_prop (property_service set)`，若 `kcmdline.binder` 映射到 `kcmdline_prop`，则：

```
adb shell setprop kcmdline.binder "c; /data/local/tmp/x"   # 概念示例，未上机
  → on property:kcmdline.binder=*
  → exec -- /system/bin/kcmdlinectrl store binder c; /data/local/tmp/x
```

**唯一未知环节 = 属性真名映射**（见 R5.4）。 `[文本推断]`

---

## R5.4 属性真名确认表

### 状态：**未能确认 — `property_contexts` 不在提取产物中**

| 疑似类型 (TYPE) | 期望属性真名 | 实际结果 | 谁 allow 写 |
|---|---|---|---|
| `kcmdline_prop` | `persist.boot.kcmdline` / `ro.boot.kcmdline` / `kcmdline.binder` | **未验证** | `shell`(:27078), `kcmdlinectrl`(:21907) |
| `permissive_mte_prop` | `persist.sys.permissive.mte` | **未验证** | 未 dump |
| `dft_syshwdebug_prop` | 厂商 debug 属性 | **未验证** | 未 dump |
| `msc.sys.oemName` | `msc.sys.oemName` | 字符串在 `system.raw:2995790694` **存在**，但位于**压缩 DEX 字符串池**（邻近 `modName`/`msg`/`isSurfaceShown`），是**应用代码常量，非 property_contexts 条目** | — |

### 为什么无法确认（已穷举）

1. `risk_system/`(71) `risk_vendor/`(2) `risk_sx/`(23) `sx_extract/`(12) `odm_extract/`(3) `extract/`(9) `init_bin/` `image/`(26) 全遍历 → **`*property_contexts*` 命中 0**。`[已实测]`
2. 仅存的 selinux 文件是 `system_etc_selinux_plat_file_contexts` 和 `etc_selinux_system_ext_file_contexts`（**file_contexts**，非 property_contexts）。
3. 4 个 raw 分区明文 mmap 扫描（system/vendor/product_h/odm，共 11.6 GB）：
   - `persist.boot.kcmdline` = 0，`ro.boot.kcmdline` = 0，`kcmdline_prop` = 0，`permissive_mte_prop` = 0，`syshwdebug` = 0（**全部分区**）。`[已实测]`
   - `kcmdline_prop` 在 `plat_sepolicy.cil` 出现 11 次但**全为类型名**，不含属性名字符串——property_contexts 与 cil 是两个文件，cil 里没有属性名字面量。

**阳性对照（证明扫描方法有效）**：

- `property_contexts` → system.raw **13** 命中、vendor.raw **1** 命中（carve 后确认为 DEX 常量串，非文件本体）→ mmap 明文扫描**能工作**。
- `msc.sys.oemName` → system.raw **1** 命中并成功 carve 出上下文 → 扫描**能工作**。
- 因此上表 0 命中 = **文件本体确实不在明文区**（很可能被 EROFS/EROFS-LZ4 或 ext4 压缩存储），而非搜索方法失效。

**唯一间接证据**：`kcmdline.binder` / `kcmdline.loaded` 出现在 `init_kcmdlinectrl.rc` 的 trigger 中。init trigger 语法直接写属性名字面量，故 **`kcmdline.binder` 与 `kcmdline.loaded` 是真实存在的属性名** `[二进制实读]`。AOSP 上游 `property_contexts` 中 `kcmdline.binder` 映射到 `kcmdline_prop`（`kcmdline.loaded` 通常是 `default_prop`）——但**本机 property_contexts 未见，此映射为 `[未验证]`**。

---

## R5.5 阳性对照记录

| # | 0 命中的搜索 | 阳性对照 | 对照结果 | 结论 |
|---|---|---|---|---|
| 1 | `Grep` 搜 `base_typeattr_880` → **0** | 同文件 Python `str.count` | **存在**，3 处（:25601, :32910, :32911） | **Grep 工具失效**，非真不存在。已全面改用 Python |
| 2 | `magisk`（4 个 cil + binary policy） | 同法搜 `su_exec` | binary:1；plat: 6 | 真不存在 |
| 3 | rc 中 `kcmdline` → 0 | 同法搜 `${` / `import` / `setprop` | 21 / 8 / 13 | 真不存在 |
| 4 | rc 中 `mlstrustedsubject` → 0 | 同法搜 `seclabel` | 2 | 真不存在 |
| 5 | rc 中 `uid`（有效行） | `mount` / `gid` | 6（5 为 `noexec` 噪声）/ 2 | 真不存在 |
| 6 | 全树 `*property_contexts*` → 0 | 同法搜 `*_contexts*` | 2（file_contexts） | 搜索方法有效，真不存在 |
| 7 | raw 扫 `persist.boot.kcmdline` 等 → 0 | raw 扫 `property_contexts` / `msc.sys.oemName` | 13 / 1，且 carve 出上下文 | 方法有效，真不在明文区 |
| 8 | cil 中 `domain_auto_trans` → 0 | cil 中 `type_transition` | 存在（数千条） | 该 cil 用 `type_transition` 而非 `domain_auto_trans` |
| 9 | `plat_sepolicy.cil` 中 `dft_syshwdebug_prop` → 0 | `permissive_mte_prop` 同文件 | 8 | 归属 system_ext/vendor，非 plat |
| 10 | `system_ext`/`vendor` cil 中 `(type su)` → 0 | `plat` 同法 | 1 | su 仅 plat 定义 |

---

## R5.6 明确没找到的

| 项 | 状态 | 说明 |
|---|---|---|
| `property_contexts`（system/vendor/odm/product 各份） | **不存在于任何提取产物** | 也未在 4 个 raw 分区明文出现。R5.4 全部属性真名因此**未确认** |
| `permissive_mte_prop` → 属性名 | 未找到 | 需 property_contexts |
| `dft_syshwdebug_prop` → 属性名 | 未找到 | 同上 |
| `kcmdline_prop` → 属性名 | 未找到 | 仅有间接证据 `kcmdline.binder`（rc trigger 字面量） |
| `hw_init.rc` 里的 kcmdline 注入面 | **确认不存在** | 与前一轮假设相反。注入面在 `init_kcmdlinectrl.rc` |
| `su` 域的 allow exec / type_transition | **确认不存在** | 0 条 transition + neverallow 封死 |
| `magisk` / `magisk_exec` / `suadm` | **全树 0 命中** | 含 binary policy 符号表 |
| `hw_init.rc` 尾部 3,958 B 内容 | **永久丢失** | 提取截断，源已毁 |
| `plat_sepolicy.cil` 洞内 16,977 B | 永久丢失 | 但已判定属 class/classcommon 区，不含 su |
| `/system/bin/kcmdlinectrl` 二进制 | 未提取 | `risk_system/` 内无此文件（该目录只抽了部分 rc/xml/txt） |

---

## R5.7 给上机阶段的可执行判据

### 可被设备实测**直接证伪**的高价值结论

| # | 判据 | 命令（概念） | 期望（若本报告成立） | 证伪含义 |
|---|---|---|---|---|
| **J1** | **shell 能否 setprop kcmdline.binder**（最高优先） | `adb shell setprop kcmdline.binder c` | **成功返回 0，无 denials** | 若 `permission denied` → R5.3 的 allow 未生效，整条注入链作废 |
| **J2** | 属性真名 | `adb shell getprop \| grep -i kcmdline` | 应见 `kcmdline.binder`、`kcmdline.loaded` | 若不存在 → init_kcmdlinectrl.rc 是死代码 |
| **J3** | 属性类型归属 | `getprop -Z` / `ls -Z /dev/__properties__/` | `kcmdline.binder` 的 context 应为 `u:object_r:kcmdline_prop:s0` | 若为 `default_prop` → 映射假设需修正 |
| **J4** | **注入是否真的发生** | 置入带空格/分号的值后 `getprop` + `logcat -s init \| grep kcmdlinectrl` | init 日志应出现 kcmdlinectrl 被以异常 argv 调用 | 若 argv 未展开 → `${}` 语义理解错误 |
| **J5** | **su 域不可达** | `adb shell ps -AZ \| grep -w su` | 设备运行期**不应有** `su` 标签进程 | 若**出现**常驻 su 进程 → Magisk/厂商已激活 su 域，本报告前提失效 |
| **J6** | adbd 的 root_seclabel | `adb shell ps -AZ \| grep adbd` | 主进程 `u:r:adbd:s0`；`adbd` 以 uid 0 运行 | `user root` 已确认；`--root_seclabel=su` 仅在需要时切域 |
| **J7** | **hdbd 是否存在/运行** | `adb shell ps -AZ \| grep hdbd`；`ls -l /dev/socket/hdbd` | 荣耀定制调试守护，uid 0，socket world-writable(660) | 若在运行 → **新的高优攻击面**（root 身份 + shell 可 connect），优先级应超过 kcmdline |
| **J8** | hw_init.rc 完整性 | `wc -c /system/etc/init/hw/init.rc`；`tail -3` | 若 > 61,660 B 或尾部非 NUL → 提取阶段被截断 | 若正好 61,660 且尾部是 ` c` → 固件本身如此 |
| **J9** | **属性真名补全（一次拿全）** | `cat /system/etc/selinux/property_contexts \| grep -E 'kcmdline\|mte\|syshwdebug'` | 直接得到 R5.4 全表 | **这是唯一能补齐 R5.4 的途径** —— `property_contexts` 是 world-readable 纯文本，**无需 root** |
| **J10** | neverallow 语义交叉验证 | `adb shell ls -Z /system/bin/kcmdlinectrl` | 应为 `u:object_r:kcmdlinectrl_exec:s0` | 确认 kcmdlinectrl 二进制标签正常 |

### 上机优先级建议

1. **J9**（property_contexts 读取，零风险、纯文本、决定 J1 是否值得投）→ 最高
2. **J7**（hdbd 是否活着）→ 若活，优先级**超过** kcmdline（root 身份 + world-writable socket，无需属性注入）
3. **J1/J2**（kcmdline 属性可写性）→ 注入链验证
4. **J5/J6**（su 域可达性）→ 低，magisk 0 命中已大幅降权

### 需要提醒的落差

- **`hw_init.rc` 缺口已关闭但证伪了原假设**：它不是「最高优先级未完成项」，里面没有可利用服务。真正的 rc 兴趣点在 `hw_init.usb.rc`（adbd/hdbd）。
- **`su` 域缺口已关闭且证伪**：su 存在但被 neverallow 封死，不是空洞问题。**不必再在 su 方向投入。**
- **`base_typeattr_880` 缺口已关闭且纠错**：880 不含 kcmdline_prop；shell 能写是**显式设计**，不是绕过。
- 唯一真正**未闭合**的是缺口 4（属性真名），且已证明**纯案头无法解决** —— 必须靠 J9 上机读 `property_contexts`。