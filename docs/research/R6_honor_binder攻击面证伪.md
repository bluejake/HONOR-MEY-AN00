# R6 honor_binder 攻击面独立验证 — 离线审计报告

> 目标设备：MEY-AN00（荣耀 500，Android 16，内核 6.6.118-android15-8，BL 锁定）
> 模式：**纯案头（离线）**，未连 adb、未上机执行
> 审计对象：`R2_内核侧漏洞候选.md` 提出的 B2 候选「honor_binder」
> 唯一设备侧准据：`analysis/scratch/Image-mey` 反汇编 + `mey_6.6.118.kallsyms.txt`
> 标注体系：`[汇编已证]` / `[源码推断未验证]` / `[已实测]`。**本报告无任何 `[已实测]` 结论。**

---

## R6 结论摘要

**判决：证伪**（主论断不成立；仅「编入主 Image」与「缺 `check_buffer()`」两项子命题部分成立）

依据一行：`honor_binder_alloc_do_copy_from_buffer` 唯一 BL 目标是 `memcpy`、全函数 0 条 AT/TLBI/ldtr 指令、无任何用户指针入参，其 `[alloc+0x18]`/`[alloc+0x48]` 访问是遍历 binder_alloc 内核页数组而非 MMU 页表翻译，且唯一调用点在 procfs `show` 路径、输入长度被 clamp 至 ≤0x10e、uid=2000 shell 无 SELinux 授权 —— 「手工页表翻译 + 绕过 uaccess 审计 + SELinux/SPL 结构上不可能覆盖」三重论断全部不成立。

### 参考树限定（必须随结论一并引用）

`refs/google_kernel_GKI-6.6.118-android15.8/` 已被判定版本自相矛盾 —— `Makefile` 声明 `VERSION=6 PATCHLEVEL=6 SUBLEVEL=118`，但 `mm/shmem.c` 含 442 处 folio（6.10+ 特征），且树来自第三方个人账号（`ravindu644 <<EMAIL-REDACTED>>`）的单 commit `9d973d6ae35f1b3ab00a94270efed1bc153d72da`（2026-07-29，"kernel: added droidspaces support"）。**故该树仅用于回答「攻击面是否存在」，不得作为设备侧行为的依据。** 本报告的所有设备侧结论一律以 `Image-mey` 反汇编为唯一准据，源码仅用于命名与语义对照。

---

## R6.1 符号定位结果

`[汇编已证]` honor_binder 全家共 **19 个符号，全部编入主 Image，无一为模块**。

主 Image 范围：`0xffffffc080000000 .. 0xffffffc082368a00`（`Image-mey` = 37,128,704 字节 = `0x2368a00`）。全部 19 个符号地址均落在该区间内，最大偏移 `0x1307xxx` < `0x2368a00`。

| # | 符号 | 地址 | 类型 | 归属 |
|---|---|---|---|---|
| 1 | `honor_binder_alloc_do_copy_from_buffer` | `0xffffffc08064b8e4` | `T` | 主 Image |
| 2 | `honor_binder_transaction_proc_show` | `0xffffffc08064bb2c` | `T` | 主 Image |
| 3 | `honor_binder_state_show` | `0xffffffc08064bea0` | `T` | 主 Image |
| 4 | `honor_binder_stats_show` | `0xffffffc08064bec8` | `T` | 主 Image |
| 5 | `honor_binder_transactions_show` | `0xffffffc08064c224` | `T` | 主 Image |
| 6 | `honor_binder_transaction_log_show` | `0xffffffc08064c3d8` | `T` | 主 Image |
| 7 | `honor_binder_failed_transaction_show` | `0xffffffc08064c404` | `T` | 主 Image |
| 8 | `honor_binder_transaction_proc_open` | `0xffffffc080f1f79c` | `t` | 主 Image |
| 9 | `honor_binder_state_open` | `0xffffffc080f1f7cc` | `t` | 主 Image |
| 10 | `honor_binder_stats_open` | `0xffffffc080f1f7fc` | `t` | 主 Image |
| 11 | `honor_binder_transactions_open` | `0xffffffc080f1f82c` | `t` | 主 Image |
| 12 | `honor_binder_transaction_log_open` | `0xffffffc080f1f85c` | `t` | 主 Image |
| 13 | `honor_binder_failed_transaction_open` | `0xffffffc080f1f88c` | `t` | 主 Image |
| 14 | `honor_binder_transaction_proc_fops` | `0xffffffc081307010` | `d` | 主 Image (.data) |
| 15 | `honor_binder_state_fops` | `0xffffffc081307118` | `d` | 主 Image (.data) |
| 16 | `honor_binder_stats_fops` | `0xffffffc081307220` | `d` | 主 Image (.data) |
| 17 | `honor_binder_transactions_fops` | `0xffffffc081307328` | `d` | 主 Image (.data) |
| 18 | `honor_binder_transaction_log_fops` | `0xffffffc081307430` | `d` | 主 Image (.data) |
| 19 | `honor_binder_failed_transaction_fops` | `0xffffffc081307538` | `d` | 主 Image (.data) |

**函数大小** `[汇编已证]`：`0xffffffc08064b8e4` 的 size = **0xE4（228 字节）**，由下一符号 `debug_no_space_locked @0xffffffc08064b9c8` 确定（`binder_alloc_get_free_space @0xffffffc08064b858` → **honor_binder_alloc_do_copy_from_buffer** → `debug_no_space_locked`）。

**邻接关系** `[汇编已证]`（该函数被直接插入标准 binder_alloc 代码区中间，非独立模块）：

```
ffffffc08064b824 T binder_alloc_shrinker_exit
ffffffc08064b858 T binder_alloc_get_free_space
ffffffc08064b8e4 T honor_binder_alloc_do_copy_from_buffer   <== 插入点
ffffffc08064b9c8 t debug_no_space_locked
```

**厂商前缀全量统计** `[汇编已证]`：

| 前缀 | 命中数 |
|---|---|
| `honor_` | **19** |
| `hndl_` | 0 |
| `hisi_` | 51 |
| `huawei_` | 0 |
| `magic_` | 3 |
| `vendor_` | 8 |

**关键否证** `[汇编已证]`：19 个 honor_binder 符号中，**没有任何一个是 ioctl / misc / dev / char_device 相关**。命名体系为 `show` + `open` + `fops` —— 这是 procfs 惯用形态，不是驱动入口形态。

---

## R6.2 反汇编实证

`[汇编已证]` 全函数 228 字节逐条（`Image-mey`，capstone arm64）：

```asm
0xffffffc08064b8e4:  paciasp
0xffffffc08064b8e8:  stp      x29, x30, [sp, #-0x50]!
0xffffffc08064b8ec:  stp      x26, x25, [sp, #0x10]
0xffffffc08064b8f0:  stp      x24, x23, [sp, #0x20]
0xffffffc08064b8f4:  stp      x22, x21, [sp, #0x30]
0xffffffc08064b8f8:  stp      x20, x19, [sp, #0x40]
0xffffffc08064b8fc:  mov      x29, sp
0xffffffc08064b900:  mov      x22, x0                    ; x22 = arg0 (binder_alloc*)
0xffffffc08064b904:  mov      w0, #-0x16                 ; -22 = -EFAULT
0xffffffc08064b908:  cbz      x22, #0xffffffc08064b9a4    ; arg0==NULL -> -EFAULT
0xffffffc08064b90c:  mov      x23, x1                    ; x23 = arg1 (binder_buffer*)
0xffffffc08064b910:  cbz      x1, #0xffffffc08064b9a4     ; arg1==NULL -> -EFAULT
0xffffffc08064b914:  mov      x20, x3                    ; x20 = arg3 (内核线性地址)
0xffffffc08064b918:  cbz      x3, #0xffffffc08064b9a4     ; arg3==NULL -> -EFAULT
0xffffffc08064b91c:  mov      x19, x4                    ; x19 = arg4 (bytes)
0xffffffc08064b920:  cbz      x4, #0xffffffc08064b9a0     ; arg4==0 ->返回 0
0xffffffc08064b924:  mov      x21, x2                    ; x21 = arg2 (buffer_offset)
0xffffffc08064b928:  mov      w25, #0x1000               ; PAGE_SIZE
0xffffffc08064b92c:  mov      x26, #-0x100000000000000    ; x26 = 0xffff000000000000
; ---------------- 页循环体开始 ----------------
0xffffffc08064b930:  ldr      x8, [x23, #0x58]           ; x8  = buffer->user_data
0xffffffc08064b934:  ldr      x9, [x22, #0x18]           ; x9  = alloc->buffer
0xffffffc08064b938:  sub      x8, x8, x9                 ; user_data - buffer
0xffffffc08064b93c:  add      x9, x8, x21                ; + buffer_offset
0xffffffc08064b940:  ldr      x8, [x22, #0x48]           ; x8  = alloc->pages
0xffffffc08064b944:  lsr      x10, x9, #0xc              ; index = off >> PAGE_SHIFT
0xffffffc08064b948:  add      x8, x8, x10, lsl #5        ; &pages[index]  (sizeof=32)
0xffffffc08064b94c:  ldr      x8, [x8, #0x10]            ; lru_page->page_ptr
0xffffffc08064b950:  cbz      x8, #0xffffffc08064b9c0     ; page_ptr==NULL -> 返回剩余字节
0xffffffc08064b954:  and      x9, x9, #0xfff             ; pgoff = off & (PAGE_SIZE-1)
0xffffffc08064b958:  sub      x10, x25, x9              ; PAGE_SIZE - pgoff
0xffffffc08064b95c:  cmp      x19, x10
0xffffffc08064b960:  csel     x24, x19, x10, lo          ; size = min(bytes, PAGE_SIZE-pgoff)
0xffffffc08064b964:  mov      x10, #-0x100000000000000
0xffffffc08064b968:  b        #0xffffffc08064b974         ; <== 无条件跳过下列两条(死代码)
0xffffffc08064b96c:  ldr      x10, [x8]          ; ---- 不可达 ----
0xffffffc08064b970:  bic      x10, x26, x10, lsl #3      ; ---- 不可达 ----
0xffffffc08064b974:  lsl      x8, x8, #6                 ; page_to_virt: page << 6
0xffffffc08064b978:  mov      x0, x20                   ; dst = 内核线性地址
0xffffffc08064b97c:  mov      x2, x24                   ; n
0xffffffc08064b980:  and      x8, x8, #0xfffffffffff000   ; & PAGE_MASK
0xffffffc08064b984:  orr      x8, x10, x8                ; (low24 bits from page, i.e. PFN)
0xffffffc08064b988:  add      x1, x8, x9                 ; src = virt + pgoff
0xffffffc08064b98c:  bl       #0xffffffc080552d90        ; memcpy(dst,src,n)  <== 唯一外部调用
0xffffffc08064b990:  subs     x19, x19, x24              ; bytes -= size
0xffffffc08064b994:  add      x20, x20, x24              ; dst  += size
0xffffffc08064b998:  add      x21, x24, x21              ; off  += size
0xffffffc08064b99c:  b.ne     #0xffffffc08064b930         ; while(bytes)
; ---------------- 返回 ----------------
0xffffffc08064b9a0:  mov      w0, wzr                  ; 全部复制完 -> 返回 0
0xffffffc08064b9a4:  ldp      ... (epilogue)
0xffffffc08064b9b8:  autiasp
0xffffffc08064b9bc:  ret
0xffffffc08064b9c0:  mov      w0, w19                  ; page_ptr==NULL -> 返回剩余未复制字节数
0xffffffc08064b9c4:  b        #0xffffffc08064b9a4
```

### 判据 1：是否真自己做页表翻译 —— **否（证伪）**

`[汇编已证]` 三条独立证据：

**证据 1：唯一 BL 目标是 `memcpy`，不是 `copy_from_user`。**

`0xffffffc080552d90` 的同址符号别名（6 个）：`__memcpy` / `__memmove` / `memcpy` / `memmove` / `__pi_memcpy` / `__pi_memmove`。**该地址不含 `__check_object_size`，不含 `__arch_copy_from_user`，不含任何 uaccess 组件。**

决定性阳性对照 —— 真实 `copy_from_user` 链的实际构成（`copy_from_user_nofault @0xffffffc0809e70e4`，size 0x118）的两个 BL：

| 调用点 | 目标 | 归属 |
|---|---|---|
| `0xffffffc0809e713c` | `0xffffffc080053338` | `__check_object_size` (+0x0) |
| `0xffffffc0809e717c` | `0xffffffc080195fc0` | `__arch_copy_from_user` (+0x0) |

即：**用户内存复制的真实指纹 = `__check_object_size` + `__arch_copy_from_user`**（后者用 `ldtr`/`sttr` 未特权访问指令实现，配合 PAN 解除）。`honor_binder_alloc_do_copy_from_buffer` 的唯一 BL 是 `memcpy`，与该指纹无任何交集。

**证据 2：函数体内 uaccess 指令计数为 0。**

capstone 助记符扫描（228 字节全量）：

| 指令类 | honor 函数 | `__arch_copy_from_user`（阳性对照） | `binder_alloc_copy_from_buffer` |
|---|---|---|---|
| `AT`（S1E1R） | **0** | 7 | **0** |
| `TLBI` | **0** | 12 | 34 |
| `ldtr`/`sttr`（PAN 型 uaccess） | **0** | 大量 `ldtr xN,[x1]` | **0** |
| `BL` | 1（→memcpy） | 3 | 3（全部 →memcpy） |

> **注意**：本项目早期曾用位域公式扫描 AT/TLBI，阳性对照失败（对 `__arch_copy_from_user` 亦得 0），已判定该扫描器公式错误并作废。**唯一可信证据是 capstone 助记符输出**（见 R6.6）。

**证据 3（最关键）：`[alloc+0x18]`/`[alloc+0x48]` 是 binder_alloc 自己的内核页数组，不是 MMU 页表。**

指令模式 `[x22,#0x18]` → `sub` → `[x22,#0x48]` → `lsr #0xc` → `add x8,x8,x10,lsl #5` → `ldr [x8,#0x10]` → `page << 6` → `& ~0xfff` → `bl memcpy`，与参考树 `[源码推断未验证]` 的 `binder_alloc_get_page()` **逐行对应**：

```c
static struct page *binder_alloc_get_page(struct binder_alloc *alloc,
                          struct binder_buffer *buffer,
                          binder_size_t buffer_offset, pgoff_t *pgoffp)
{
    binder_size_t buffer_space_offset = buffer_offset +
        (buffer->user_data - alloc->buffer);      // <- [x23,#0x58] - [x22,#0x18]
    pgoff_t pgoff = buffer_space_offset & ~PAGE_MASK;  // <- and #0xfff
    size_t index = buffer_space_offset >> PAGE_SHIFT;   // <- lsr #0xc
    struct binder_lru_page *lru_page;
    lru_page = &alloc->pages[index];                  // <- [x22,#0x48] + index*32
    *pgoffp = pgoff;
    return lru_page->page_ptr;                         // <- ldr [x8,#0x10]
}
```

**语义判定**：`alloc->pages` 是 binder 自己维护的 `struct binder_lru_page` 数组（元素大小 0x20 = 32 字节，由 `add x8,x8,x10,lsl #5` 直接编码），存放的是**内核已分配好的 struct page 指针**。`page << 6 | pfnum` 是 arm64 的 `page_to_virt()` 线性映射，与 MMU 虚拟地址翻译（需 AT 指令 + 页表遍历 + TLBI）**机制完全不同**。整个过程**不接触任何用户虚拟地址**。

**结论**：这是一个「把 binder buffer 的内核页内容拷到内核栈缓冲区」的 `memcpy` 包装器，走的是 binder_alloc 子系统一贯的线性映射路径。R2 所称「手工做页表翻译绕过内核统一 user 内存访问审计」在此**被直接证伪**。

**附带发现** `[汇编已证]`：死代码区间 `0xffffffc08064b96c`–`0xffffffc08064b970`（`ldr x10,[x8]` / `bic x10,x26,x10,lsl #3`）因 `0xffffffc08064b968` 的无条件 `B → 0xffffffc08064b974` 而**不可达**。同样的死代码在上游 `binder_alloc_copy_from_buffer` 中同样存在（`0xffffffc0801198e4 B → 0xffffffc0801198f0`）—— **再次印证 honor 版是上游代码的机械复制，仅删减了边界检查**。

### 判据 2：用户完全可控字段 —— **无任何用户指针进入该函数**

`[汇编已证]` 唯一调用点 `0xffffffc080651680` 位于 `print_binder_transaction_brief_ilocked`（`0xffffffc0806514a4`，+0x1dc）内部，参数装载序列：

```asm
0xffffffc080651630:  ldr      x28, [x23, #0x60]        ; x28 = binder_node/binder_buffer（内核对象）
0xffffffc080651634:  cbz      x28, #0xffffffc080651688
0xffffffc080651638:  ldr      x8, [x28, #0x40]         ; x8  = 某内核字段（长度/大小）
0xffffffc08065163c:  cmp      x8, #0x29                 ; < 0x29 = 41 -> 放弃
0xffffffc080651640:  b.lo     #0xffffffc080651688
0xffffffc080651644:  cmp      x8, #0x10f                ; > 0x10f -> 需 clamp
0xffffffc080651648:  mov      w9, #0x10e                ; 上限 0x10e = 270
0xffffffc08065164c:  add      x10, x27, #0x1a8          ; binder_alloc* (内核对象 +0x1a8)
0xffffffc080651650:  add      x0, sp, #0xc0              ; 内核栈缓冲区
0xffffffc080651654:  mov      w1, wzr
0xffffffc080651658:  mov      w2, #0x110                ; memset 0x110 字节
0xffffffc08065165c:  str      x10, [sp, #0x30]
0xffffffc080651660:  csel     w27, w9, x8, hi           ; len = min(len, 0x10e)
0xffffffc080651664:  bl       #0xffffffc080552fc0        ; memset
0xffffffc080651668:  sxtw     x4, w27                   ; arg4 = (ssize_t)len
0xffffffc08065166c:  ldr      x0, [sp, #0x30]           ; arg0 = binder_alloc*
0xffffffc080651670:  add      x3, sp, #0xc0              ; arg3 = 内核栈缓冲区 (sp+0xc0)
0xffffffc080651674:  mov      x1, x28                   ; arg1 = binder_buffer*
0xffffffc080651678:  mov      x2, xzr                  ; arg2 = 0 (buffer_offset 硬编码)
0xffffffc08065167c:  str      x27, [sp, #0x28]
0xffffffc080651680:  bl       #0xffffffc08064b8e4        ; >>> 调用 <<<
```

| 参数 | 实参来源 | 是否用户可控 |
|---|---|---|
| arg0 `alloc` | `x27+0x1a8`（内核 binder 对象） | **否** |
| arg1 `buffer` | `x28 = [x23,#0x60]`（内核 binder 对象） | **否** |
| arg2 `buffer_offset` | **硬编码 `xzr` = 0** | **否** |
| arg3 `src` | `sp+0xc0`（内核栈，先 memset 0x110） | **否** |
| arg4 `bytes` | `[x28,#0x40]`，**clamp 至 ≤0x10e，且要求 ≥0x29** | **间接、受限** |

`[汇编已证]` 补充：全 Image 的 BL imm26 扫描（291,999 个 BL 站点）确认 `honor_binder_alloc_do_copy_from_buffer` **只有 1 个调用点** `0xffffffc080651680`。无 ioctl 派发、无 syscall 直达路径。

### 判据 3：翻译失败语义 —— **返回剩余字节数，非 -EFAULT、非静默继续**

`[汇编已证]` 全部失败分支：

| 条件 | 地址 | 行为 |
|---|---|---|
| `arg0 == NULL` | `0xffffffc08064b908` | `w0 = -22` → **返回 -EFAULT** |
| `arg1 == NULL` | `0xffffffc08064b910` | **返回 -EFAULT** |
| `arg3 == NULL` | `0xffffffc08064b918` | **返回 -EFAULT** |
| `arg4 == 0` | `0xffffffc08064b920` | `w0 = 0` → 返回 0 |
| `page_ptr == NULL` | `0xffffffc08064b950` | `0xffffffc08064b9c0: mov w0, w19` → **返回剩余未复制字节数** |
| 全部完成 | `0xffffffc08064b9a0` | 返回 0 |

**返回值语义 = `copy_from_user` 式「返回未复制字节数」的部分拷贝语义**（与参考树 `binder_alloc_copy_user_to_buffer` 的 `Return: bytes remaining to be copied` 契约一致 `[源码推断未验证]`）。

**不存在 type confusion**：失败时 `w0` 被显式置为剩余字节数，调用点 `0xffffffc080651684: cbz w0, #0xffffffc080651690` 对返回值做严格非零判定，非零即走 `0xffffffc080651688` 退出路径。**既非静默继续、也不存在「失败后仍按成功路径用缓冲区」的分支。**

**附带发现** `[汇编已证]`：调用点之后紧接对 memcpy 结果的魔数校验（`0xffffffc080651690`–`0xffffffc0806516bc`）：

```asm
0xffffffc080651690:  ldrb     w8, [sp, #0xc8]
0xffffffc080651694:  cmp      w8, #0x54      ; 'T'
0xffffffc080651698:  b.ne #0xffffffc080651688
0xffffffc0806516a0:  cmp      w8, #0x53      ; 'S'   (byte @0xc9)
0xffffffc0806516a4:  b.ne     ...
0xffffffc0806516ac:  cmp      w8, #0x59      ; 'Y'   (byte @0xca)
0xffffffc0806516b0:  b.ne     ...
0xffffffc0806516b8:  cmp      w8, #0x53      ; 'S'   (byte @0xcb)
0xffffffc0806516bc:  b.ne #0xffffffc080651688
0xffffffc0806516c0:  ldr      w8, [sp, #0xcc]
0xffffffc0806516c4:  cmp      w8, #8          ; 后续长度 >= 8
0xffffffc0806516c8:  b.lo     #0xffffffc080651688
```

**→ 实际魔数为 `0x54 0x53 0x59 0x53` = ASCII `"TSYS"`。**

**R2 报告错误** `[汇编已证]`：R2 第 448 行写作 `"TRUS"`（`0x54 0x52 0x55 0x53`）。第 2 字节实测 `0x53` 而非 `0x52`，第 3 字节实测 `0x59` 而非 `0x55`。**该魔数记录有误。**

> （注：早前在 Image 中检索 `b"TSYS"` 曾命中 `0xffffffc0815fc2a3`，经打印上下文确认为 errno 字符串表 `ERESTARTSYS` 的子串，属假阳性。真实魔数来源是上述 4 次 `cmp`，与该字符串无关。）

---

## R6.3 与标准 binder 实现的对账

| 维度 | 上游 `binder_alloc_copy_from_buffer` | honor 版 | 差异 |
|---|---|---|---|
| 反汇编地址 | `0xffffffc080119830`（size 0x2a8 = 680 B） | `0xffffffc08064b8e4`（size 0xe4 = 228 B） | honor 版短 452 字节 |
| 外部调用 | 3× `__memcpy` | 1× `__memcpy` | honor 版只循环一次不做双分支 |
| `check_buffer()` | **有** | **无** | **唯一实质差异** |
| `alloc->buffer` `[+0x18]` | 有 | 有 | 相同 |
| `alloc->pages` `[+0x48]` | 有 | 有 | 相同 |
| `lsr #0xc` + `lsl #5`（×32） | 有 | 有 | 相同 |
| `page_ptr [+0x10]` | 有 | 有 | 相同 |
| `page_to_virt`（`lsl #6`/`and`/`orr`） | 有 | 有 | 相同 |
| 死代码区间 | 有（`0xffffffc0801198e4`） | 有（`0xffffffc08064b968`） | 相同 |
| `AT`/`ldtr` uaccess 指令 | 0 | 0 | **相同** |

**源码侧对照** `[源码推断未验证]`：参考树 `drivers/android/binder_alloc.c:1305`

```c
int binder_alloc_copy_from_buffer(struct binder_alloc *alloc,
                  void *dest, struct binder_buffer *buffer,
                  binder_size_t buffer_offset, size_t bytes)
{
    return binder_alloc_do_buffer_copy(alloc, false, buffer, buffer_offset,
                       dest, bytes);
}

static int binder_alloc_do_buffer_copy(...)
{
    /* All copies must be 32-bit aligned and 32-bit size */
    if (!check_buffer(alloc, buffer, buffer_offset, bytes))   // <<< honor 版缺此检查
        return -EINVAL;
    while (bytes) { ... memcpy_from_page / memcpy_to_page ... }
}
```

**`check_buffer()` 缺失导致丢失 5 项边界保证** `[源码推断未验证]`（`binder_alloc.c:1207`）：

```c
static inline bool check_buffer(struct binder_alloc *alloc,
                struct binder_buffer *buffer,
                binder_size_t offset, size_t bytes)
{
    size_t buffer_size = binder_alloc_buffer_size(alloc, buffer);
    return buffer_size >= bytes &&                        // 1. 长度上界
        offset <= buffer_size - bytes &&                 // 2. offset+bytes 不越界
        IS_ALIGNED(offset, sizeof(u32)) &&                // 3. 4 字节对齐
        !buffer->free &&                                  // 4. buffer 未被 free
        (!buffer->allow_user_free || !buffer->transaction);// 5. 事务未终结
}
```

**关键澄清**：缺失 `check_buffer()` 是**逻辑缺陷（缺边界检查）**，**不是 uaccess 审计绕过**。其危害上限受调用点 clamp 约束（`len ∈ [0x29, 0x10e]`，`buffer_offset` 恒为 0），不构成用户可控越界。

**函数名更正** `[汇编已证]`：R2 引用的 `binder_alloc_buf_copy_from_user` 在该 6.6 参考树中**不存在**（`git grep` exit=1，阳性对照 `git show HEAD:drivers/android/binder.c` 成功读出 7,357 行，证明检索机制有效）。真实存在的是：

- `binder_alloc_copy_user_to_buffer()` — 含 `copy_from_user`，**真正的用户内存入口**
- `binder_alloc_copy_to_buffer()` / `binder_alloc_copy_from_buffer()` — 走 `memcpy_*_page`，**纯内核页拷贝**

honor 版对应的是**后者**（内核页→内核栈），而非前者（用户内存→内核页）。

---

## R6.4 ioctl 派发表 —— **不存在**

`[汇编已证]` 6 个 `file_operations` 按 `include/linux/fs.h` 权威布局逐槽解析，**非空槽位仅 4 个，且 6 个 fops 完全同构**：

| 槽位偏移 | 成员名 | 6 个 fops 的取值 |
|---|---|---|
| +0x00 | `owner` | NULL |
| +0x08 | `llseek` | `seq_lseek` (`0xffffffc0802e60ec`) |
| +0x10 | `read` | `seq_read` (`0xffffffc080062ca0`) |
| +0x18 | `write` | **NULL** |
| +0x20 | `read_iter` | **NULL** |
| +0x28 | `write_iter` | **NULL** |
| +0x30 | `iopoll` | NULL |
| +0x38 | `iterate_shared` | NULL |
| +0x40 | `poll` | NULL |
| +0x48 | **`unlocked_ioctl`** | **NULL** |
| +0x50 | **`compat_ioctl`** | **NULL** |
| +0x58 | **`mmap`** | **NULL** |
| +0x60 | `mmap_supported_flags` | NULL |
| +0x68 | `open` | 各不相同（6 个 `honor_binder_*_open`） |
| +0x70 | `flush` | NULL |
| +0x78 | `release` | `single_release` (`0xffffffc080063ca8`) |
| +0x80 | `fsync` | NULL |

各 fops 的 `open` 槽：

| fops | 地址 | open 槽 |
|---|---|---|
| `honor_binder_transaction_proc_fops` | `0xffffffc081307010` | `honor_binder_transaction_proc_open` (`0xffffffc080f1f79c`) |
| `honor_binder_state_fops` | `0xffffffc081307118` | `honor_binder_state_open` (`0xffffffc080f1f7cc`) |
| `honor_binder_stats_fops` | `0xffffffc081307220` | `honor_binder_stats_open` (`0xffffffc080f1f7fc`) |
| `honor_binder_transactions_fops` | `0xffffffc081307328` | `honor_binder_transactions_open` (`0xffffffc080f1f82c`) |
| `honor_binder_transaction_log_fops` | `0xffffffc081307430` | `honor_binder_transaction_log_open` (`0xffffffc080f1f85c`) |
| `honor_binder_failed_transaction_fops` | `0xffffffc081307538` | `honor_binder_failed_transaction_open` (`0xffffffc080f1f88c`) |

**结论**：`unlocked_ioctl`、`compat_ioctl`、`mmap`、`write`、`write_iter` **全部为 NULL**。

- **无任何 ioctl cmd 值可列**（R2 隐含的 ioctl 派发面不存在）
- **`missing`/`capable` 检查无从谈起** —— 没有派发器，也就没有 `capable(CAP_SYS_ADMIN)` 之类检查可供审计
- **R2 隐含前提「uid=2000 shell 能调到的 cmd」在结构上不存在**

**唯一可达链路** `[汇编已证]`：

```
用户态 read(2) on /proc/binder/honor_binder_logs/<node>
  → seq_read (fops +0x10)
    → single_open 绑定的 show 回调
      → honor_binder_transaction_proc_show (0xffffffc08064bb2c) 等 6 个 show
        → print_binder_transaction_brief_ilocked (0xffffffc0806514a4)
          → honor_binder_alloc_do_copy_from_buffer (0xffffffc08064b8e4)   ← 唯一调用点
```

---

## R6.5 用户态入口 + SELinux 授权

### 无 `/dev/` misc 设备

`[汇编已证]` 19 个 honor_binder 符号中无任何 dev/misc 符号。proc 注册点反汇编（`0xffffffc080f1f2e0` 起）：

```asm
0xffffffc080f1f2e8:  adrp     x8, #0xffffffc081307000     ; 遍历已有 proc 节点表
0xffffffc080f1f2ec:  ldr      x1, [x8, #0xed0]
0xffffffc080f1f31c:  adrp     x1, #0xffffffc0815d8000
0xffffffc080f1f324:  mov      x0, x19
0xffffffc080f1f328:  bl       #0xffffffc080f1f680        ; proc_mkdir
...
0xffffffc080f1f340:  adrp     x1, #0xffffffc081609000
0xffffffc080f1f348:  adrp     x2, #0xffffffc081307000
0xffffffc080f1f34c:  add      x2, x2, #0x10              ; honor_binder_transaction_proc_fops
0xffffffc080f1f354:  mov      x3, xzr
0xffffffc080f1f358:  bl       #0xffffffc0802c47b8        ; proc_create
...
0xffffffc080f1f36c:  ldr      x0, [x20, #0x68]
0xffffffc080f1f370:  adrp     x1, #0xffffffc081685000
0xffffffc080f1f374:  add      x1, x1, #0xe23             ; "honor_binder_logs"
0xffffffc080f1f378:  bl       #0xffffffc080f1f680        ; proc_mkdir("honor_binder_logs")
0xffffffc080f1f390:  adrp     x2, #0xffffffc081307000
0xffffffc080f1f394:  add      x2, x2, #0x10              ; 再注册 transaction_proc
0xffffffc080f1f3b8:  add      x2, x2, #0x118             ; state_fops
0xffffffc080f1f3dc:  add      x2, x2, #0x220             ; stats_fops
0xffffffc080f1f400:  add      x2, x2, #0x328             ; transactions_fops
0xffffffc080f1f424:  add      x2, x2, #0x430             ; transaction_log_fops
0xffffffc080f1f44c:  add      x2, x2, #0x538             ; failed_transaction_fops
```

`proc_mkdir` ×2 + `proc_create` ×6。

### 真实路径：`/proc/binder/honor_binder_logs/*`

`[汇编已证]` 7 个节点，注册于 procfs `binder` 目录下：

| 路径 | fops |
|---|---|
| `/proc/binder/honor_binder_logs/` | （目录，`proc_mkdir`） |
| `.../transaction_proc` | `honor_binder_transaction_proc_fops` |
| `.../state` | `honor_binder_state_fops` |
| `.../stats` | `honor_binder_stats_fops` |
| `.../transactions` | `honor_binder_transactions_fops` |
| `.../transaction_log` | `honor_binder_transaction_log_fops` |
| `.../failed_transaction` | `honor_binder_failed_transaction_fops` |

### SELinux 授权：uid=2000 shell 无权访问

`[汇编已证]` 唯一含 honor_binderfs 策略的文件为 `analysis/output/c_line/sepolicy/system_ext_sepolicy.cil`（plat=0, system_ext=39, vendor=0）。

**7 条 `genfscon binder` 规则**（路径 → 类型映射）：

```
(genfscon binder "/honor_binder_logs/failed_transaction_log" (u object_r honor_binderfs_logs_failed_transaction ((s0) (s0))))
(genfscon binder "/honor_binder_logs/transaction_proc"        (u object_r honor_binderfs_logs_transaction_proc ((s0) (s0))))
(genfscon binder "/honor_binder_logs/transaction_log"         (u object_r honor_binderfs_logs_transaction_log ((s0) (s0))))
(genfscon binder "/honor_binder_logs/transactions"            (u object_r honor_binderfs_logs_transactions ((s0) (s0))))
(genfscon binder "/honor_binder_logs/state"                   (u object_r honor_binderfs_logs_state ((s0) (s0))))
(genfscon binder "/honor_binder_logs/stats"                   (u object_r honor_binderfs_logs_stats ((s0) (s0))))
(genfscon binder "/honor_binder_logs"                         (u object_r honor_binderfs_logs ((s0) (s0))))
```

**17 条 `allow` 规则，主体仅 4 个 domain**：

| 主体 domain | 授权目标 |
|---|---|
| `dumpstate` | `honor_binderfs_logs`(dir), `_transaction_proc`, `_failed_transaction`, `_transactions` |
| `logserver` | 全部 6 个文件 + dir |
| `surfaceflinger` | `honor_binderfs_logs`(dir), `_transaction_proc` |
| `system_server` | `honor_binderfs_logs`(dir), `_transaction_proc`, `_failed_transaction`, `_transactions` |

**→ `shell` 不在任何一条 allow 的主体中。**

这意味着 uid=2000 shell 在 enforcing 模式下访问 `/proc/binder/honor_binder_logs/*` 会被 SELinux 拒绝，**且该拒绝发生在 procfs `read(2)` 的 SELinux 文件打开检查阶段，根本走不到 `seq_read` → `show` → `honor_binder_alloc_do_copy_from_buffer`**。

### 对 R2「SELinux 结构上不可能覆盖」的修正

`[汇编已证]` **R2 此处判断正确，但理由完全不同于其所述**：SELinux 确实构成结构性阻断（shell 无授权），**但这与「是否手工页表翻译」无关，也与「代码编入主 Image 而非 .ko」无关**。真正的阻断来自：

1. **无 ioctl 派发面**（`unlocked_ioctl` 全 NULL）—— uid=2000 无任何 ioctl 可发
2. **无用户指针入参**（arg3 为内核栈地址）—— 即便可达也无从构造 type confusion
3. **SELinux shell 无授权** —— 唯一入口 procfs read 被拒绝
4. **输入长度硬约束**（`len ∈ [0x29, 0x10e]`，`buffer_offset ≡ 0`）

即：**「编译进主 Image ⇒ SPL 覆盖不了」这一推论链条不成立**；主 Image 内核代码同样受 `genfscon` 的 procfs 类型标注约束，SELinux 机制对主 Image 与模块**一视同仁**。R2 据此推出「SELinux 结构上不可能覆盖」是把「代码位置」与「SELinux 作用域」错误关联。

---

## R6.6 阳性对照记录

按纪律要求，所有「0 命中」结论均附阳性对照。

| # | 检查项 | 阳性对照 | 结果 |
|---|---|---|---|
| 1 | GKI 树 `binder.c` 可读性 | `git show HEAD:drivers/android/binder.c \| wc -l` | **7,357 行**（读取机制有效） |
| 2 | `binder_alloc_buf_copy_from_user` 不存在 | `git grep -c ... HEAD -- drivers/android/` exit=1 | 确认不存在（对照 #1 有效） |
| 3 | `struct file_operations` 槽位布局 | 用 `ddebug_proc_fops` / `wakeup_sources_proc_fops` / `iom_enable_proc_fops` 校准；`ddebug` 的 `write` 槽正确落在 +0x18 | 布局正确 |
| 4 | BL 扫描器有效性 | 全 Image 291,999 个 BL 站点成功解析 | 有效 |
| 5 | `__memcpy` 地址归属 | `0xffffffc080552d90` 同址 6 别名 | 确认 |
| 6 | capstone AT/TLBI 助记符可见性 | `__arch_copy_from_user` 实测含 **7 AT + 12 TLBI** | capstone 有效 |
| 7 | **位域 AT/TLBI 扫描器** | 对 `__arch_copy_from_user` 得 **AT=0, TLBI=0**（失败） | **公式错误，已作废，改用 capstone 助记符** |
| 8 | 首次位域扫描器（`op=(w>>24)&0x1f`） | 把 `stp x29,x30,[sp,#-0x50]!`（`0xA9BF7BFD`，`&0x1F=0x09`）误判为 AT | **误报，已作废** |
| 9 | capstone `disp` 是否已缩放 | `raw=0xb → disp=0x58` | 已缩放，反汇编偏移可信 |
| 10 | CIL 解析器（括号配平 + token 保留） | 顶层语句 8930；`(allow ` 6647 次；`(allow shell ` **23** 次 | 有效 |
| 11 | CIL 解析器（`''.join(cur)` 拼接版） | `(allow ` 得 **0** 条（token 边界被破坏） | **失败，已改用 token 列表版** |
| 12 | `grep -rl honor_binderfs` | SIGTERM 超时中断（非 0 命中） | 改用 Python 直读文件，7 条 genfscon 确认存在 |
| 13 | 魔数 `TSYS` 字符串假阳性 | `b"TSYS"` 命中 `0xffffffc0815fc2a3`，上下文为 errno 表 `ERESTARTSYS` | 假阳性，改用调用点 `cmp` 实证 |
| 14 | 调用点归属（awk 版） | awk `strtonum` 精度丢失，误判为 `trace_raw_output_binder_txn_latency_free` | 改用 Python 整数解析，得 `print_binder_transaction_brief_ilocked` (+0x1dc) |
| 15 | kallsyms 检索机制 | `grep -c binder` = 841；`misc_register` = `ffffffc0804ea124 T` | 有效 |
| 16 | `arm64_mm_entry` / `access_ok` / `__copy_from_user` 0 命中 | `access_ok` 的 8 次命中全是 vhost/iotlb 等无关同名符号 | **不可用于论证**，改走 capstone 指令级证据 |
| 17 | GKI 树版本矛盾 | `Makefile` 6.6.118 vs `mm/shmem.c` folio 442 处 | 矛盾确认 |

**adrp/add 扫描器修复记录**：`(a)` 打印时误用 dict 整数键而非名称；`(b)` **遗漏 `immlo`** —— 写成 `sx((w1>>5)&0x7ffff,21)`，未拼入 `immlo=((w1>>29)&3)<<2`。该 bug 被阳性对照抓到（连已知被引用的 `0xffffffc08064bb2c` 都扫不到）。修复为：

```python
imm = sx((((w1>>5)&0x7ffff)<<2) | ((w1>>29)&3), 21)
```

修复后成功定位 6 个 fops 的全部引用点。

---

## R6.7 给上机阶段的可执行判据

> 以下为**待上机执行**的验证计划，本次审计未执行（遵守禁令）。

### 判据 1：证伪 honor_binder 攻击面（最高优先，零风险）

```bash
# 1a. 确认 proc 节点存在
adb shell ls -lZ /proc/binder/honor_binder_logs/
# 1b. 确认 shell 域被 SELinux 拒绝 —— 本判据的核心
adb shell cat /proc/binder/honor_binder_logs/transaction_proc
#   预期：Permission denied (denied { read } for "transaction_proc")
#   若实际可读 => sepolicy 与本次离线分析不符，需重新审计 plat_sepolicy.cil
```

**判决标准**：若 1b 返回 `Permission denied`，则 uid=2000 shell 在 SELinux 层即被阻断，R2 论断的「可实证攻击面」不成立 —— 与本次离线结论一致。

### 判据 2：验证「缺 `check_buffer()`」这一唯一残留缺陷

```bash
# 制造大量 binder 事务后读取，观察是否 oops
adb shell run-as system_server cat /proc/binder/honor_binder_logs/transaction_proc > /tmp/o 2>&1
adb shell dmesg | grep -iE "honor|binder_alloc|slab|out of bounds|page fault"
```

**判决标准**：

- 无 oops → `check_buffer()` 缺失因 clamp 而不可达，**该缺陷亦不可利用**，R2 无剩余可用攻击面
- 出现 oops → 记录地址，判断是 OOB 读（信息泄露）还是 OOB 写（提权原语）

### 判据 3：确认 honor 版是机械复制（可选，低价值）

```bash
adb shell cat /proc/kallsyms | grep honor_binder    # 若 kptr_restrict 放开
```

**判决标准**：19 个符号齐全且地址相对偏移一致 → 离线分析结论可直接迁移；若有符号缺失 → 需重新 dump Image。

---

## 附：R2 报告错误清单

| R2 位置 | R2 论断 | 本次实证结果 | 标注 |
|---|---|---|---|
| 355 | honor_binder 符号存在于 kallsyms | **成立**，共 19 个，全在主 Image | `[汇编已证]` |
| 424 | 唯一调用点 `0xffffffc080651680` | **成立**，位于 `print_binder_transaction_brief_ilocked` +0x1dc | `[汇编已证]` |
| 448 | 魔数 `"TRUS"` (0x54 0x52 0x55 0x53) | **错误**，实测 `0x54 0x53 0x59 0x53` = `"TSYS"` | `[汇编已证]` |
| — | 「手工做页表翻译，绕过 uaccess 审计」 | **证伪**：唯一 BL → `memcpy`；0 条 AT/TLBI/ldtr；遍历 binder_alloc 内核页数组 + `page_to_virt` | `[汇编已证]` |
| — | 「编入主 Image 而非 .ko ⇒ SELinux 结构上不可能覆盖」 | **证伪**：主 Image 代码同样受 `genfscon` 约束；真实阻断来自无 ioctl 派发面 + shell 无授权，非代码位置 | `[汇编已证]` |
| — | 「存在 ioctl 派发面」 | **证伪**：`unlocked_ioctl`/`compat_ioctl`/`mmap` 全部 NULL | `[汇编已证]` |
| — | 引用函数名 `binder_alloc_buf_copy_from_user` | **该函数在 6.6 树不存在**，真实名为 `binder_alloc_copy_from_buffer` | `[源码推断未验证]` |
| 472-476 | fops 槽位审计 | **方向正确但结论错误**：4 个非空槽位（llseek/read/open/release），无 ioctl | `[汇编已证]` |
| 508 | B2 候选条目（新增可实证攻击面） | **不成立**：无 ioctl、无用户指针、shell 无 SELinux 授权、长度硬 clamp | `[汇编已证]` |

**最终结论**：R2 的 honor_binder 论断在「攻击面确实存在于符号表/Image 中」这一事实层面成立，但在**「可实证、可利用」层面证伪**。三项核心机制论断（手工页表翻译、绕过 uaccess、SELinux 结构上不可覆盖）均与设备侧反汇编事实不符。honor 版 `honor_binder_alloc_do_copy_from_buffer` 是标准 binder_alloc 内核页拷贝函数的机械删减版（缺 `check_buffer()`），其唯一用途是 procfs 只读诊断输出，无用户可控输入向量。**建议从 B2 候选中移除，或降级为「仅在已有内核读原语下的信息泄露次要线索」。**