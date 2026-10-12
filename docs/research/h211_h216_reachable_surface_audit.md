# H211–H216 · 可达攻击面重新测绘与逐靶判决

> 设备：MEY-AN00（荣耀 500 / SM8735 / `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`）
> 会话：2026-10-06 续做（skill `magicpad3-root-handoff` 安装后首轮）
> 纪律：**真机开火 = 0 发**（`boot_id` 全程 `ba30251b-07f6-4bcb-8a6d-a569da07e4a0` 不变）
> 全部结论来自 `.ko` 自身字节 + 设备实测；**零内核源码**。

---

## §0 一句话结论

**本轮未能产出 uid 0。** 已知四条线（43499 写原语 / sigreturn 画布 / 栈重占 / 64560）
经独立复核**全部维持判死**；按 H209 §W4「应做攻击面重测绘」的指引执行后，
**可达面已用设备端 open 穷举穷尽（仅 14 个节点，见 §6.1）**，逐靶审计结果如下：

| 靶 | 判决 | 依据强度 |
|---|---|---|
| `/dev/tango32` (`tango32.ko`) | ★ **判死** | 上游 ARM64 `CONFIG_COMPAT` 支持代码（author `Amanieu d'Antras`）；且**实测可达**，审计有效 |
| `/dev/kgsl-3d0` | ⚠️ **无驱动** | 设备与内核镜像中**均无 kgsl 驱动**（见 §4） |
| `/dev/fmps` | ⚠️ **不可达** | 实测 `DENIED`（0666 被 SELinux 拒）—— 与项目结论一致 |
| `/dev/chrMiscDevice` (`chr_misc_device.ko`) | ⚠️ **不可达 ⇒ H214 作废** | 实测 `DENIED`。审计结论「长度有界」虽正确，但**对象不可达**（见 §6.1c） |
| `/dev/sop_unprivileged` / `sop_privileged` (`xodata.ko`) | ⚠️ **不可达 ⇒ H216 作废** | 两者实测均 `DENIED`（见 §6.1c） |
| `/dev/sensorevent` (`sensorevent.ko`) | ⚠️ **不可达** | `crw-rw---- system:system`，实测 `DENIED` |
| `/dev/ashmem` | ⚠️ **不可达（但 `/dev/ashmem<boot_id>` 可达）** | ★ SELinux **文件名级**差异，见 §6.1b |
| **`/dev/binder`** | ⬜ **可达，未审** | ★ 本轮新发现，全项目唯一未碰的大面 |
| `/dev/hwlog_exception`、`file_deleted` (`logger.ko`) | ⬜ **可达，未审** | 面大 |

> ★★ **本轮最重要的净产出**：**可达面被穷举**，并证明项目历史上重点投入的
> `fmps` / `chrMiscDevice` / `sop_*` / `sensorevent` **从 shell 域根本打不开**。
> 这个事实比任何单个驱动的审计结论都更有价值 —— 它一次性排除了大量看似有戏的方向。

---

## §1 独立复核：三条硬墙（全部重验通过）

| # | 复核项 | 本轮独立证据 | 判决 |
|---|---|---|---|
| 1 | shell 拿不到 `CAP_SYS_RESOURCE` | `CapPrm=0`、**`CapEff=0`**、`CapBnd=0x8000c0`（**不含 bit24**） | ⇒ 封死 `prctl(PR_SET_VMA_ANON_NAME)` 这条**唯一几何命中（112/112）**的栈喷溅原语 |
| 2 | 单路 cfu 无 112B 完整覆盖 | 与 H209 §W2 独立一致 | ⇒ 43499 的「必须把 112B 写进 W 内核栈」前提**未打破** |
| 3 | `/dev/fmps` 不可达 | `ls -Z` ⇒ `u:object_r:fmps_device:s0`；shell open ⇒ `Permission denied` | ⇒ **0666 ≠ 可达**（新铁律） |

**#1 的独立价值**：H206 §6.5 由「测 `prctl` 返回 EINVAL」推出能力墙；本轮**一条命令直接读 `CapEff`** 即证，
且解释了为何「几何 112/112 命中」也无用 —— **墙在权限，不在几何**。此后不必再讨论该原语。

---

## §2 可达面测绘方法（新增工具 `h212_node_to_module.py`）

```
① 设备端：穷举 /dev/*，按 shell 域实际 open(rw) 能力筛选（不信 0666，信实测）
   ⇒ 可达字符设备仅 13 个，构成 4 族：
      tango32 / chrMiscDevice / kgsl-3d0 / fastrpc-cdsp / uhid+uinput /
      logger 族(file_deleted,hwlog_exception,hwlog_dubai) / hwbinder + 标准节点
② 离线端：把 502 个 .ko（analysis/output/b_line/kos/）的 .modinfo 名字 +
   .rodata 字符串与可达节点名对撞 ⇒ 得到「节点 → 模块」确定映射
③ 交叉：模块内 fops 表槽位重定位 ⇒ 确定每个节点的 ioctl/mmap/read 入口地址
```

**副产品：可达节点的 fops 入口（本轮首次给出）**

| 节点 | 模块 | 入口 |
|---|---|---|
| `/dev/tango32` | `tango32.ko` | 上游 `compat_ioctl` 转发层（无自定义逻辑） |
| `/dev/chrMiscDevice` | `chr_misc_device.ko` | `chr_misc_ioctl` `.text+0x870`（1168 B） |
| `/dev/sop_unprivileged` | `xodata.ko` | `sop_ioctl_unprivileged` `.text+0x800`（0x3d8）+ `sop_mmap_unprivileged` `.text+0xc00` |
| `/dev/sop_privileged` | `xodata.ko` | `sop_ioctl_privileged` `.text+0x004`（0x3b4）+ `sop_mmap_privileged` `.text+0x3e0` |

---

## §3 逐靶判决（汇编级）

### 3.1 `chr_misc_device.ko` —— 全部长度受硬上界约束 ⇒ 判死

三个 ioctl（`0x40044201` / `0x40044301` / `0x40044302`）的**用户可控长度**全部被挡：

```asm
; ── 0x40044301：从用户结构取 16-bit 长度 w21，再按 w21 拷进 skb
008c: ldrh  w0, [sp, #0xc]        ; w0 = 用户长度
0090: cmp   w0, #0x3f9
0094: b.hs  #0x380                ; ★ ≥0x3f9 ⇒ 拒绝
00d4: ldrh  w21, [sp, #0xc]       ; w21 = 用户长度（≤0x3f8）
00d0: ...  RELOC __alloc_skb      ; 分配
00e0: mov   x1, x21  RELOC skb_put ; ★ skb 缓冲 = 同长度
00f0: mov   x2, x21               ; ★ copy_from_user 长度 = 同长度
; ⇒ 分配长度 == 拷贝长度，无溢出

; ── 0x40044302：走 chr_kernel_write_protocoldb，长度全部编译期常量
023c: mov   w2, #0x3f8            ; kmalloc(0x3f8)
0250: mov   w2, #0x3f8            ; copy_from_user(..., 0x3f8)   ← 常量
; ⇒ 无用户可控长度
```

**可证伪判据**：若存在溢出，必须找到一处「分配长度 < 拷贝长度」的路径。
全函数 1168 B 内**不存在**（已逐条核对）。

### 3.2 `xodata.ko` 非特权入口 —— 设计如此，非漏洞 ⇒ 判死

`sop_ioctl_unprivileged` 只有两条命令，均作用于**调用者自己的 mm**：

```
cmd 0xc120ff02：copy_from_user(栈缓冲 sp+8, 0x120)
                 ldr w2,[sp,#0x110] ; cmp w2,#0x101 ; b.hs → 拒绝   ★ 有界
                 ⇒ 在 agent_tracked_list 里按名字查找，回填一个 VMALLOC 指针
cmd 0x4120ff03：copy_from_user(栈缓冲 sp+8, 0x120)
                 get_task_mm()                    ; ★ 只取 current 的 mm
                 mmap_read_lock; mtree_load(mm+0x40, 用户 addr)
                 ★ 校验 [(u64)sp+0x118] 是否真的等于 VMA->vm_start，
                   且 [vma+8] == 用户 addr+len  ⇒ 只接受「已存在且完全匹配」的自己 VMA
                 mmap_write_lock; remap_vmalloc_range(vma, 自身 vmalloc 缓冲)
                 ⇒ 把自己的 vmalloc 缓冲映射进自己进程
```

⇒ 非特权 fops 的存在是**设计意图**（供非特权采集方读取内核收集的数据）；
入口**只操作 current 的 mm**，无跨进程/无任意地址读写。**非漏洞。**

### 3.3 `fmps.ko` —— 权限墙，非代码问题

`ls -Z` 已确认 SELinux 类型 `fmps_device`；shell 域 open 直接 `Permission denied`。
**即使节点是 0666 也不可达。** 该模块（项目曾重点攻关）对本路径**零价值**。

---

## §4 重要负面发现：本机不存在 kgsl 驱动

| 检查 | 结果 |
|---|---|
| 设备 `/vendor/lib/modules`（= `/vendor_dlkm/lib/modules`，462 项） | **无 kgsl/adreno .ko** |
| 设备 `find / -name "*kgsl*"` | 只回 `lib*_adreno.so`（用户态），**无驱动** |
| `/proc/config.gz` | **`KGSL`/`ADRENO` 命中 0 行**（7787 行全量 grep） |
| 内核 `vmlinux-mey.elf` 6 段（`.kernel`+`.bss`+symtab） | 字符串 **无** `kgsl-3d0` |
| `governor_msm_adreno_tz.ko` | 含 `kgsl-3d0` 字面量，但它只是**依赖方**，不是驱动本体 |

⇒ `/dev/kgsl-3d0`（`472:0`，`crw-rw-rw-`）**可 open 却无驱动**：最可能是
**ueventd 依据预置的 device 声明创建了节点，而驱动未加载**。
⇒ ★ **结论：Qualcomm GPU 这条（历史上极高产出的）攻击面，在本机【不存在】。**

**可证伪判据**：若能找到该节点对应的 `alloc_chrdev_region` 调用者（major 472），结论即被推翻。
本轮在 502 个模块中未找到。

---

## §5 本轮新增工具（可直接复用）

| 脚本 | 用途 |
|---|---|
| `analysis/scratch/h211_tango_dis.py` | **KO 反汇编正确姿势**：relocatable `.ko` 的 `st_value` 是 **section 相对**，必须 `get_section(shndx).data()[off:off+size]`。用文件偏移会读到 ELF header，产生「fops 槽全是垃圾」的假象 |
| `analysis/scratch/h212_node_to_module.py` | **可达节点 → 模块**自动映射（`.modinfo` + 字符串 + ioctl 槽重定位 + cfu 计数） |
| `analysis/scratch/h213/h214_chrmisc*.py` | `chr_misc_device.ko` 全反汇编（含重定位注解） |
| `analysis/scratch/h215/h216b_xodata*.py` | `xodata.ko` fops 槽解析（`.rela.rodata` addend = `.text` 内偏移）+ 非特权入口反汇编 |

**环境**：python = `<HOME>\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe`；
`capstone 5.0.9` + `pyelftools 0.33` 已装到 **`D:\MEY-AN00-root-repro\pyenv`**（用 `PYTHONPATH` 指过去）。

---

## §6 可达面**穷举定稿**与剩余未审项（诚实版）

### §6.1 ★★★ 可达集合是**穷举**的，不是抽样

用设备端脚本对字符设备逐个 `open(O_RDWR)` / `open(O_RDONLY)` 实测（**显式路径，不用 glob**），
`shell` 域真正能打开的**只有 14 个**（完整集合，非候选）：

```
RW  /dev/ashmem<boot_id>     ← ★ 注意：/dev/ashmem 本体被 DENIED！见下
RW  /dev/binder              ★ 本轮首次发现 shell 可达
RW  /dev/file_deleted                            ← logger.ko
RW  /dev/hwbinder
RW  /dev/hwlog_exception                          ← logger.ko
RW  /dev/kgsl-3d0          ← 可 open 但无驱动（§4）
RW  /dev/null  /dev/ptmx  /dev/random  /dev/urandom  /dev/zero
RW  /dev/tango32                                  ← 已判死（上游 compat）
RW  /dev/uhid   RW  /dev/uinput                   ← 项目已深挖
```

### §6.1b ★★ 两个必须记住的 **SELinux 文件名级**陷阱（本轮实测打脸两次）

| 节点 | DAC 权限 | 实测结果 | 解释 |
|---|---|---|---|
| `/dev/ashmem` | `crw-rw-rw-` root:root | ❌ **DENIED** | 名字被 SELinux 策略判不可达 |
| `/dev/ashmem<boot_id>`（同 `10:259`，同一驱动） | `crw-rw-rw-` root:root | ✅ **RW** | ★ **同样是 ashmem，仅名字不同就可达** |
| `/dev/chrMiscDevice` | `crw-rw-rw-` system:system | ❌ **DENIED** | 0666 但 shell 域被拒 |
| `/dev/fmps` | `crw-rw-rw-` root:root | ❌ **DENIED** | 同上 |
| `/dev/tango32` | `crw-rw-rw-` system:system | ✅ RW | 少数真正可达的 0666 节点 |

⇒ ★★★ **铁律修正**：**DAC 权限位（含 0666）对「是否可达」零信息量**，
必须逐个 `open()` 实测；且**同一驱动的不同节点名可达性可以不同**。
（本节早先版本用 `glob` 测试，因 `/dev/$f` 被 shell 展开成多个路径而给出**假 DENIED**，
已改为显式逐路径测试 —— 这是第三次因 glob 得到错误结论，务必记住。）

### §6.1c ★★★ 由此产生的**重大作废**

| 之前的判断 | 实测真相 | 后果 |
|---|---|---|
| `/dev/chrMiscDevice` 可达 ⇒ 深审 `chr_misc_device.ko`（H213/H214） | ❌ **DENIED** | ★ **H213/H214 的审计对象【不可达】，全部作废**（结论「长度有界」仍然正确，但已无关紧要） |
| `/dev/sop_unprivileged` 可达 ⇒ 审 `xodata.ko`（H215/H216） | ❌ **DENIED**（`/dev/sop_privileged` 亦 DENIED） | ★ **H215/H216 同样作废** |
| `/dev/sensorevent` 可达（下一步首选） | ❌ **DENIED** | 从靶清单移除 |
| `/dev/fmps` 可达（项目长期主攻） | ❌ **DENIED** | 确认（与项目结论一致） |

⇒ ★★★★ **本轮真正的净产出不是「又审了两个驱动」，而是：可达面被穷举，且证明
项目历史上重点投入的若干节点（`fmps`、`chrMiscDevice`、`sop_*`、`sensorevent`）
从 shell 域根本打不开** —— 这个事实比任何单个驱动的审计结论都更有价值。

### §6.2 穷举后**真正剩余**的未审面

| # | 靶 | 模块 | 备注 |
|---|---|---|---|
| 1 | **`/dev/binder`** | `binder` + `binder_alloc`（内建，`/sys/module/binder` 存在；节点指向 `/dev/binderfs/binder`） | ★ 全项目**唯一还没碰过且确认可达**的大面。但 shell 无 binder 上下文（`servicemanager` 客户端在 `system` 域），**可达深度待验** |
| 2 | `/dev/hwbinder` | 同 binder 框架 | HIDL 侧，多为 vendor 域 |
| 3 | `/dev/hwlog_exception`、`file_deleted` | `logger.ko`（428 KB） | 可达，面大，未审 |
| 4 | `/dev/ashmem<boot_id>` | ashmem（内建） | 可达；项目已大量使用（H67/H70/H75…），非新面 |
| 5 | `/dev/kgsl-3d0` | **无驱动** | 已判死 |

**★ 方法论结论（必须遵守）**：
筛选顺序必须是 **设备端逐路径 open 穷举 → 再看代码**；
且 **禁用 glob**（会因 shell 展开产生假阴性）。
本轮 §6.1 即该流程的定稿产物。

### §7 最终结论（本会话定稿）

- 本机**已知全部利用线（43499 写原语 / sigreturn 画布 / 栈重占 / 64560）均已闭合**，
  独立复核未推翻任何一条。
- **可达面已穷举**（14 个节点），其中 `tango32`/`chrMiscDevice`/`xodata` 三个已逐条审到判死，
  `kgsl` 经确证**在本机不存在**，`fmps`/`sensorevent` 等**实测不可达**。
- ⇒ 继续必须依赖**新的、可达的内核内存破坏原语**，且候选面只剩
  **`/dev/binder`（唯一未碰过的大面，可达深度待验）** 与 `logger.ko`。
- ⇒ **本机不存在可由现状直接复现的临时 root 链。**
