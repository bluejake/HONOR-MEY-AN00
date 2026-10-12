# A 线 · 逆向交叉印证：`honor_tsa.ko` ioctl 攻击面完整分析

日期：2026-10-05 · H38 轮 · 样本 `analysis/output/b_line/kos/honor_tsa.ko`（18,096 B，REL）
方法：capstone 反汇编 + `.rela.text` 重定位解析（REL 需重定位才能确定 bl 真实目标）

---

## 0 结论先行

**`/proc/honor_tsa_info/stack_info/ioctl` 是本项目迄今发现的唯一「用户态可下 ioctl 进内核」的荣耀私有入口，
且其实现直接把 `sprint_symbol` 暴露给用户态 —— 这是一个符号 oracle。**
它印证并强化了 MEMORY §3.4 待办第 1 条（当时仅凭猜测写下「`sprint_symbol` 是任意地址→符号 oracle」）。

---

## 1 样本基本信息

| 项 | 值 |
|---|---|
| 节区布局 | `.text` @ file `0x1000` size `0x304`（仅 772 B，极小） |
| 导出符号 | `tsa_stack_info_ioctl@0x94` `tsa_stack_info_show@0x2ec` `tsa_stack_info_lseek@0x54` `tsa_stack_info_read@0x34` `tsa_stack_info_open@0x4` `tsa_stack_info_release@0x74` `tsa_stack_info_fops`(r) |
| 未定义符号 | `__arch_copy_from_user` `__arch_copy_to_user` `memset` `fortify_panic` `__stack_chk_fail` `seq_read` `single_open` `proc_create` `proc_mkdir` `remove_proc_entry` `alt_cb_patch_nops` |
| `.rodata` 字符串 | `honor_tsa_info` / `stack_info` / `ioctl` / `tsa_stack_info_ioctl` / **`%s - unknown cmd %x`** |

⚠️ `fortify_panic` + `__stack_chk_fail` 存在 ⇒ 该模块**启用 FORTIFY_SOURCE 与栈保护**，
栈上溢出/越界会被立即 abort ⇒ 不是明显的栈溢出靶点。

---

## 2 `tsa_stack_info_ioctl` 完整语义（0x94–0x304 全解）

### 2.1 ioctl cmd 只有一个（不是分派表）
```
0x00b4  mov  w9, #0xac01
0x00bc  movk w9, #0xc2a8, lsl #16      ; w9 = 0xc2a8ac01
0x00c0  cmp  w1, w9                     ; w1 = ioctl cmd
0x00c8  b.ne #0x238                     ; 不匹配 → 走 printk("unknown cmd %x") 路径
```
⇒ **有效 cmd = `0xc2a8ac01`**（魔数风格）。其余 cmd 走 unknown 分支（只打印，不做事）。

### 2.2 栈上缓冲 0x2a8 字节
```
0x00d4  mov  x0, sp
0x00dc  mov  w2, #0x2a8
0x00e0  bl   memset                     ; memset(sp, 0, 0x2a8)
0x00ac  sub  sp, sp, #0x2b0             ; 栈帧 0x2b0（含 8 字节 PAC/对齐余量）
```

### 2.3 ★★ 直接改写页表基址寄存器（反取证/跨地址空间机制）
```
0x011c  mrs  x8, daif
0x0120  msr  daifset, #3               ; 关中断
0x0124  ldr  x9, [x20, #8]             ; 取 mm->pgd（用户页表基址）
0x0128  mrs  x10, ttbr1_el1
0x012c  mov  x11, x9
0x0130  bfxil x11, x10, #0, #0x30      ; 拼接
0x0134  msr  ttbr1_el1, x11            ; ★ 改写 TTBR1
0x0138  msr  ttbr0_el1, x9             ; ★ 改写 TTBR0
0x013c  isb
0x0140  msr  daif, x8                  ; 恢复中断
```
退出时对称恢复（`0x15c`–`0x17c`：`ttbr1 - 0x1000` 作为还原值）。

⇒ 语义：**在关中断窗口内临时把目标进程的页表装进来**，直接在用户地址空间读数据。

### 2.4 ★★★ 符号 oracle（核心发现）
```
0x0144  and  x1, x19, #0xff7fffffffffffff   ; x1 = arg & 消除 tag 位
0x0148  mov  x0, sp                           ; 目标 = 栈缓冲
0x014c  mov  w2, #0x2a8
0x0150  bl   __arch_copy_from_user           ; 把 0x2a8 字节当作内核地址从内核拷到栈缓冲
...
0x0184  mov  x8, sp
0x0188  ldr  x1, [sp]                         ; x1 = *(u64*)sp  ← 目标地址
0x018c  add  x0, x8, #8                       ; dst = sp+8
0x0190  bl   sprint_symbol                    ; ★ 把该地址渲染成符号名
0x0194  cmp  w0, #1
0x0198  b.lt #0x264                           ; 返回值 <1（失败）→ 返回 -14
...
0x01ec  and  x0, x19, #0xff7fffffffffffff
0x01f0  mov  x1, sp
0x01f4  mov  w2, #0x2a8
0x01f8  bl   __arch_copy_to_user              ; ★ 把结果回传用户态
```

**数据流（权威版）**：
```
用户 ioctl(fd, 0xc2a8ac01, arg)
  → memset(sp, 0, 0x2a8)
  → [切页表]
  → __arch_copy_from_user(sp, arg, 0x2a8)   ← arg 被当作【内核地址】读 0x2a8 字节
  → sprint_symbol(sp+8, *(u64*)sp)          ← 第一个 u64 被当作【待解析符号的地址】
  → [恢复页表]
  → __arch_copy_to_user(arg, sp, 0x2a8)     ← 结果写回用户 buf
```

⚠️ 注意方向：`__arch_copy_from_user`/`copy_to_user` 的**语义在此被反用** ——
它并非"从用户读/往用户写"，而是在切好的页表下把**内核地址**当数据源/目标。
`arg` 被当作内核地址使用 ⇒ **若 arg 是可控的内核地址，可造成任意内核读 + 符号名回显**。

---

## 3 攻面评估

| 项 | 判定 |
|---|---|
| cmd 数量 | 1 个（`0xc2a8ac01`），无分派表 ⇒ 面窄但深 |
| 是否需 `CAP_SYS_ADMIN` | 设备上该 proc 节点 `stat` 被拒（`-?????????`）⇒ **需先解决可打开性** |
| 缓解 | FORTIFY + 栈保护 ⇒ 栈溢出路走不通 |
| **危险度** | ★★★★ 若可打开：`arg` 作为内核地址被 `copy_from_user` 读取 ⇒ **内核任意读**；`sprint_symbol` 回显符号名 ⇒ **可绕过 KASLR 拿符号名** |
| 前置 | `/proc/honor_tsa_info/stack_info/ioctl` 当前 `dr-xr-xr-x root:root`，**需 0600→0666 或 root 身份** |

⇒ 这正是 MEMORY §3.4 待办第 1 条的**完整机理**。
⚠️ 但注意：**只解决"可打开"不够**——`arg` 必须是**内核地址**，
而我们目前**只能写数据段、不能读数据段以外的地址**（H37 判决：代码段读不了），
所以这个 oracle 的实用价值取决于能否在数据段内找到一个"已知的内核指针"当 `arg`。

---

## 4 与 H37 判决的关系（重要）

H37 判定：**kernel image 代码段不可读** ⇒ 改代码路线全灭。
但本发现**不与它矛盾**，反而互补：

| 方向 | H37 结论 | 本发现提供的新路 |
|---|---|---|
| 改内核**代码** | ❌ 全灭 | 无（也不需要）|
| 改内核**数据** | ✔ 可写 | 已有 `modprobe_path` 等 |
| **读内核数据** | ❌ 代码段读不了 | **本 ioctl 可能是绕过读限制的通道**（若可打开）|

⇒ 后续应把「让 `/proc/honor_tsa_info/stack_info/ioctl` 可打开」作为一条独立待验证项，
而不是 MEMORY 里"改 mode"这种简单假设（因为 `arg` 必须是内核地址才有意义）。

---

## 5 尚未查实（下一步）

1. `tsa_stack_info_show@0x2ec`（最大的函数，0x12B 字节）未反汇编 —— 可能含 task 遍历 + 栈扫描，是第二个攻击面。
2. `ioctl_entry`（bss，16 B）与 `stack_info_de`/`tsa_info_de` 的实际类型未知。
3. `alt_cb_patch_nops` 被引用 ⇒ 该模块用了 vendor hook 机制（对应 A 线 §AL 的 32 个 OGKI hook）。
4. **未验证**：`ioctl` 节点的实际权限位与 SELinux 标签（`stat` 被拒是 SELinux 还是 DAC，需分别测）。
