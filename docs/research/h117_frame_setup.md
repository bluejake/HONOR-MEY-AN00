# H117–H120 · 帧构造侧（`setup_rt_frame` / `get_sigframe` / `sigsp`）完整判死报告

**设备**：MEY-AN00 ｜ MagicOS 10.0.0.175 ｜ A16 ｜ SM8735 ｜ 内核 `6.6.118-android15-8`（4K 页）
**基线**：`_text = 0xffffffc080000000` ｜ `CONFIG_ARM64_VA_BITS=39` ⇒ `TASK_SIZE_MAX = 0x8000000000`
**boot_id**：`2888f136-4ff1-487b-8d4c-58e02e1897e0`（H117–H120 全程未变，无 panic）
**vmlinux 基线**：`analysis/scratch/Image-mey`（ARM64 raw Image，`0xfa405a4d`）+ `analysis/output/kallsyms_mey_an00.txt`

---

## 零、结论一句话

> **「帧构造侧」判死。** `get_sigframe()` 的 `access_ok(user->sigframe, sp_top - sp)` 是**双界完备的无符号比较硬闸门**，`sigsp()` 的 altstack 分支即使返回内核 VA 也会被拦住；compat 路径因 32 位算术**数学上不可能**越界。
> **`sas_ss_sp` / `sas_ss_size` 的真实能力 = 「指定内核在信号投递时往哪个【已映射用户 VA】写 0x1250 字节的 regs 镜像」—— 无内核任意写价值。**

---

## 一、源码链（`arch/arm64/kernel/signal.c`）

### 1.1 `sigsp()` —— `include/linux/sched/signal.h:652`
```c
static inline unsigned long sigsp(unsigned long sp, struct ksignal *ksig)
{
    if (unlikely((ksig->ka.sa.sa_flags & SA_ONSTACK)) && !sas_ss_flags(sp))
#ifdef CONFIG_STACK_GROWSUP
        return current->sas_ss_sp;
#else
        return current->sas_ss_sp + current->sas_ss_size;   // ★ arm64 走这条
#endif
    return sp;
}
```

### 1.2 `get_sigframe()` —— `signal.c:1048`
```c
init_user_layout(user);
err = setup_sigframe_layout(user, false);
if (err) return err;

sp = sp_top = sigsp(regs->sp, ksig);                    // ← 唯一 sp_top 来源

sp = round_down(sp - sizeof(struct frame_record), 16);  // frame_record = {u64 fp; u64 lr;} = 16B
user->next_frame = (struct frame_record __user *)sp;

sp = round_down(sp, 16) - sigframe_size(user);          // sigframe_size = round_up(max(size, 0x1250), 16)
user->sigframe = (struct rt_sigframe __user *)sp;

if (!access_ok(user->sigframe, sp_top - sp))            // ★★ 唯一闸门
    return -EFAULT;
return 0;
```

### 1.3 关键尺寸（源码 + 反汇编双证）
| 项 | 值 | 来源 |
|---|---|---|
| `sizeof(struct rt_sigframe)` | `0x1250`（`siginfo 0x80` + `ucontext 0x11d0`） | H113 bionic 实测 + 内联体 `mov w10,#0x1250` |
| `sizeof(struct frame_record)` | `0x10` | 源码 |
| `init_user_layout: user->size` | `0x250`（`offsetof(rt_sigframe, uc.uc_mcontext.__reserved)`） | 内联体 `mov w9,#0x250` |
| `user->limit` | `0x1220`（`0x250 + 0x1000 - 0x10 - 0x20`） | 内联体 `mov w8,#0x1220` |
| **`sigframe_size(user)`** | **`0x1250`**（被 `max` 钳住） | 内联体 `cmp x9,x10(#0x1250); csel hi` |
| `sigframe` 与 `sp_top` 的差 | **恒 `0x1260`** | 内联体 `sub x8,x8,x23` |

### 1.4 `setup_return()` —— `signal.c:1077`
```c
regs->regs[0] = usig;
regs->sp      = (unsigned long)user->sigframe;    // ★ regs->sp ← 我们指定的 sigframe
regs->regs[29] = (unsigned long)&user->next_frame->fp;
regs->pc      = (unsigned long)ka->sa.sa_handler;
/* bti/tco/sme 处理 */
regs->regs[30] = (unsigned long)sigtramp;
```
⇒ **唯一写入 `regs` 的就是 `sp`/`pc`/`regs[0]`/`regs[29]`/`regs[30]`，全部为用户语义值，无内核语义。**

---

## 二、设备镜像反汇编交叉验证

**符号定位**（`do_notify_resume` 内联了 `handle_signal`→`setup_rt_frame`→`get_sigframe`）：
```
0xffffffc08049c570  T do_notify_resume      ← 内联体起点（= __arm64_sys_rt_sigreturn 结束点）
0xffffffc08049e3a8  T setup_sigframe_layout ← 冷路径独立函数
```

### 2.1 `get_sigframe` 内联体（`+0x288`..`+0x344`）
```asm
; ---- sigsp() 的 SA_ONSTACK 判定 ----
+0x28c  ldurb w9,[x29,#-0x5d]     ; sa_flags 第 3 字节  (sa_flags @ x29-0x60)
+0x290  tbnz  w9,#3, +0x1248      ; SA_ONSTACK = 0x08000000 ⇒ (>>24)&0xff = 0x08 ⇒ bit3 ✓
+0x290  ldr   x8,[x19,#0xf8]      ; x8 = regs->sp（x19 = regs）

; ---- sigsp altstack 分支（out-of-line @ +0x1248）----
+0x1248 ldr   x9,[x20,#0x8c0]     ; current->sas_ss_size
+0x124c cbz   x9, +0x290          ; size==0 → return sp
+0x1250 ldr   w11,[x20,#0x8c8]    ; current->sas_ss_flags
+0x1254 ldr   x10,[x20,#0x8b8]    ; current->sas_ss_sp
+0x1258 tbnz  w11,#0x1f, +0x126c  ; SS_AUTODISARM → 直接 altstack
+0x125c subs  x11, x8, x10         ; regs->sp - sas_ss_sp
+0x1260 b.ls  +0x126c              ; sp <= ss_sp → altstack
+0x1264 cmp   x11, x9
+0x1268 b.ls  +0x290              ; ★ on_sig_stack(sp) 真 → return sp（静默忽略 altstack）
+0x126c add   x8, x10, x9          ; ★★ x8 = sas_ss_sp + sas_ss_size = sp_top
+0x1270 b     +0x290

; ---- get_sigframe 主算术 ----
+0x294  ldr   x9,[sp,#0x40]        ; user->size
+0x298  mov   w10,#0x1250
+0x29c  cmp   x9,x10
+0x2a0  csel  x9,x9,x10,hi         ; x9 = max(size, 0x1250) = sigframe_size
+0x2a4  and   x10,x8,#~0xf         ; round_down(sp_top,16)
+0x2a8  neg   x9,x9
+0x2ac  sub   x28,x10,#0x10        ; next_frame
+0x2b0  and   x10,x9,#~0xf         ; -round_up(sigframe_size,16) = -0x1250
+0x2b8  add   x23,x10,x28          ; ★ sigframe
+0x2bc  sub   x8,x8,x23            ; ★★ size = sp_top - sigframe  （恒 0x1260）
+0x2c0  stp   x23,x28,[sp,#0x30]

; ---- access_ok 内联体 ★★★ ----
+0x2c4  tbnz  w9,#0x15, +0x2f4     ; 分支 A
+0x2c8  ldr   x10,[x20]
+0x2cc  tbnz  w10,#0x1a, +0x2f4    ; 分支 A（未启用 MTE/TBI 时走 B）
+0x2d0  mov   x9,#0x8000000000     ; ★ TASK_SIZE_MAX = 1<<39
+0x2d4  mov   w25,#1
+0x2d8  cmp   x8,x9
+0x2dc  b.hi  +0x218               ; ← 界① size > limit ⇒ EFAULT
+0x2e0  sub   x8,x9,x8             ; limit - size
+0x2e4  cmp   x8,x23
+0x2e8  b.lo  +0x218               ; ← 界② addr > limit-size ⇒ EFAULT
+0x2ec  add   x14,x23,#0x80
+0x2f0  b     +0x320

; 分支 A（MTE/TBI 变体）
+0x2f4  mov   x11,#0x8000000000
+0x2fc  cmp   x8,x11
+0x300  b.hi  +0x218               ; ← 界① 同
+0x304  lsl   x10,x23,#8
+0x308  sub   x8,x11,x8
+0x30c  and   x10,x23,x10,asr#8     ; untagged_addr(addr)
+0x310  cmp   x8,x10
+0x314  b.lo  +0x218               ; ← 界② 同（含 untagged）
```

### 2.2 ★ 判死依据（三条，全部反汇编实读）

| # | 依据 | 说明 |
|---|---|---|
| **D1** | **双界完备**：`b.hi` + `b.lo` 两条无符号比较，无回绕缺口 | `cmp x8,x9; b.hi`（size 上界）+ `sub x8,x9,x8; cmp x8,x23; b.lo`（addr 上界）。`b.lo` 是**无符号**小于 ⇒ 内核 VA（`0xffffffc0…`）> `limit-size`（`0x7fff…`）⇒ 必拒 |
| **D2** | **`size` 恒为 `0x1260`，与 `sp_top` 绝对值无关** | `+0x2bc sub x8,x8,x23` 中 `x8 = sp_top`、`x23 = sigframe = sp_top - 0x1260` ⇒ `size ≡ 0x1260`。故界①永远通过、界②永远等价于 `sigframe <= 0x7ffffffd9a0` |
| **D3** | **`on_sig_stack()` 保护优先于 altstack** | `+0x125c..+0x1268`：`regs->sp` 落在 `[sas_ss_sp, sas_ss_sp+sas_ss_size)` 内 ⇒ `b.ls +0x290` ⇒ **`return sp`，完全不用 altstack**。这使得「`ss_sp` 小 + `ss_size` 巨大让 `sp_top` 回绕到内核 VA」的攻击**被前置拦死** |

### 2.3 `current` 关键偏移（反汇编实读，来源：`[x20+…]`，`x20 = current`）
| 字段 | 偏移 | 依据 |
|---|---|---|
| `current->sas_ss_sp` | **`+0x8b8`** | `+0x1254 ldr x10,[x20,#0x8b8]` |
| `current->sas_ss_size` | **`+0x8c0`** | `+0x1248 ldr x9,[x20,#0x8c0]` |
| `current->sas_ss_flags` | **`+0x8c8`** | `+0x1250 ldr w11,[x20,#0x8c8]` |
| `regs->sp` | **`+0xf8`** | `+0x290 ldr x8,[x19,#0xf8]` |

---

## 三、compat（AArch32）路径判死

**`compat_get_sigframe()`（`arch/arm64/kernel/signal32.c:~296`）**：
```c
compat_ulong_t sp = sigsp(regs->compat_sp, ksig);          // ★ 32 位类型
frame = compat_ptr((compat_uptr_t)((sp - framesize) & ~7)); // ★ 32 位运算 + 截断
if (!access_ok(frame, framesize))
    frame = NULL;
```

**判死依据**：`sp` 与 `framesize` 均为 `compat_ulong_t`（32 位）⇒ `(sp - framesize) & ~7` 在 32 位内回绕 ⇒ `compat_uptr_t` 截断 ⇒ `frame ≤ 0xFFFFFFFF`。
`TASK_SIZE_MAX(compat)` = `0x100000000`（`TASK_SIZE_32`）⇒ **数学上不可能越出用户 VA，连「加法回绕」的操作空间都不存在。**

另外调用方 `compat_setup_rt_frame` / `compat_setup_frame` 用 `if (!frame) return 1;` 直接返回错误 ⇒ `signal_setup_done(1)` ⇒ `force_sigsegv`。

---

## 四、真机实测（H117b / H118 / H119 / H120，四轮，全部单发前台，boot_id 全程未变）

### 4.1 H117b · `sigaltstack(2)` 值域检查（fork 隔离）
**探针**：`tools/h117b_altstack.c`
**结论：`do_sigaltstack` 完全不检查 `ss_sp` 的值域（无 `access_ok`、无 `TASK_SIZE` 检查）。**

| 组 | 输入 | 结果 |
|---|---|---|
| A1/A2 | `size=0x1000/0x13ff` | `-ENOMEM(12)`（< `MINSIGSTKSZ=0x1400`）|
| **A3** | `size=0x1400` | **OK** ← 下界临界点 |
| **B1–B6** | `size=0x7ffff000` … `0xffffffffffffffff` | **全部 OK** ← **无上界** |
| **D1** | `sp=0xffffffc080000000`（内核 _text） | **OK，回读一致** ★★★ |
| **D2** | `sp=0xffffff8000000000`（内核 direct） | **OK** ★★★ |
| D3/D4/D5 | `0x8000000000` / `0xffffffff0000` / `0xfffffffffffff000` | 全部 OK |
| F1 | `SS_DISABLE` | OK（`sp=0,size=0,fl=0x2`）|
| F2 | `SS_ONSTACK` | OK（**内核静默忽略**，回读 `fl=0x0`）|
| F3/F5 | `flags=0x4` | `-EINVAL(22)` |
| F4 | `SS_AUTODISARM` | OK（`fl=0x80000000`）|

> ★ **这解释了为什么会有「帧构造侧」这条线**：`ss_sp` 确实可以随便填 —— 闸门全在下游 `get_sigframe`。

### 4.2 H118 · `get_sigframe` 闸门（`tools/h118_altstack_deliver.c`）
| # | case | ss_sp | 结果 |
|---|---|---|---|
| 00 | 基线（合法 mmap）| `0x79277e2000` | `code=0`（handler 跑完）← **独立透镜：altstack 通道工作** |
| **01** | 内核 `_text` | `0xffffffc080000000` | **SIGSEGV(11)** ✓ |
| **02** | 内核 direct | `0xffffff8000000000` | **SIGSEGV(11)** ✓ |
| **03** | `0x4000000000`（< limit 但未映射）| | **SIGSEGV(11)** ← 证明「不是只拦内核 VA」|
| 04 | `sp=0 size=0x1000` | | `-ENOMEM` |
| 05 | `sp=0x1000 size=0xffffffffffff0000` | | `code=0`（`fl=0x1` ⇒ `on_sig_stack` 真 ⇒ 走普通栈）|

### 4.3 H119 · `sigsp()` 加法回绕边界（`tools/h119_sigsp_wrap.c`）★ 最有信息量
| # | 目标 | 算出 sigframe | 观测 | 判读 |
|---|---|---|---|---|
| **00** | 基线 | `0x73c7151da0`（用户）| `HANDLER_ENTERED sp=0x73c7151d10` | ✅ **帧真的写进那块 mmap** |
| 01 | sp_top→内核 | `0xffffffc080000da0` | **SIGSEGV** | `access_ok` 拒 |
| 02 | sp_top=0 | `0xffffffffffffeda0` | `HANDLER_ENTERED sp=0x7fdc...`（普通栈）| `on_sig_stack` 真 ⇒ 静默回退 |
| 03 | sp_top=LIMIT+0x2000 | `0x8000000da0`（越界）| **SIGSEGV** | `access_ok` 拒 |
| **04** | sp_top=LIMIT+0x1260 | **`0x8000000000`（恰好 == LIMIT）** | `HANDLER_ENTERED`（普通栈）| `on_sig_stack` 真 |
| **05** | sp_top=用户高位 | **`0x7effffffeda0`（< LIMIT，数学上应过）** | **SIGSEGV** ⚠️ | ★★ **第二层拦截：`__put_user` 缺页 ⇒ EFAULT** |
| 06 | size=0 | — | `-ENOMEM` | `min_ss_size` |

> ★★ **T5 是关键的「失败源分离」证据**：`access_ok` 的数学条件**全部满足**（`sigframe < LIMIT`），却仍 `SIGSEGV` ⇒ 证明拦截来自 **`__put_user` 缺页**（第二层）。**两层独立不可绕。**

### 4.4 H120 · 帧落地地址全权可控（`tools/h120_frame_aim.c`）★★★ 能力边界
反解 `ss_sp`/`ss_size` 使命中指定 `target`，4 个 case **全部 `hit=1` 且正常投递**：

| # | `target`（= sigframe）| 观测 | 判读 |
|---|---|---|---|
| 00 | `base+0x400000` | `HANDLER_ENTERED sp=0x6df566af70` | ✅ 帧写在 target |
| 01 | `base+0x10000` | `HANDLER_ENTERED sp=0x6df527af70` | ✅ |
| 02 | `base+0x7fe000` | `HANDLER_ENTERED sp=0x6df5a68f70` | ✅ |
| 03 | 主栈下方 `0x100000` | `HANDLER_ENTERED sp=0x7fce0461b0` | ✅ |

**⇒ 结论：`sas_ss_sp` / `sas_ss_size` 是「内核往哪个【已映射用户 VA】写 0x1250 字节 regs 镜像」的完全可控旋钮。**

---

## 五、能力边界汇总（精确，可证伪）

| 能力 | 状态 | 判据 |
|---|---|---|
| 指定帧落地地址（用户 VA、已映射）| ✅ **可** | H120 4/4 `hit=1` |
| 帧越出用户 VA（→ 内核 VA）| ❌ **不可** | H119 T1/T3 SIGSEGV；反汇编 D1/D2 |
| 帧落未映射用户 VA | ❌ **不可** | H119 T5 SIGSEGV（`__put_user` 缺页）|
| 用 `sp_top` 加法回绕规避闸门 | ❌ **不可** | H119 T2/T4 静默回退；反汇编 D3 |
| compat(32 位) 路径越界 | ❌ **数学不可能** | `signal32.c` 32 位算术 |
| **⇒ 内核任意写** | ❌ **零价值** | 写入内容 = 我们自己 regs 镜像，写目标限定已映射用户 VA |

---

## 六、新增判死清单（并入总表）

| ID | 判死对象 | 依据 |
|---|---|---|
| **G1** | `sigsp()` altstack 分支返回内核 VA ⇒ 帧写内核 | `access_ok` 双界拦（反汇编 D1）+ H118 T1/T2 + H119 T1 |
| **G2** | `sp_top - sp` 算术回绕绕闸门 | `size ≡ 0x1260` 恒定（D2），无回绕空间 |
| **G3** | `ss_sp` 小 + `ss_size` 巨 ⇒ `sp_top` 回绕到内核 VA | `on_sig_stack()` 前置保护（D3）+ H119 T2/T4 |
| **G4** | `access_ok` 通过但缺页未拦 | `__put_user` 第二层拦（H119 T5）|
| **G5** | compat(`compat_get_sigframe`) 越界 | 32 位算术截断（`signal32.c`）|
| **G6** | `setup_return()` 写 `regs` 产生内核语义 | 仅写 `sp/pc/regs[0]/regs[29]/regs[30]`，全用户语义 |

---

## 七、方法学副产品（可跨设备继承）

1. **「失败源分离」手法**：构造 `access_ok` 数学条件满足但物理不可写的用例（H119 T5），把「`access_ok` 拦」与「缺页拦」两个失败源**分开**——这是判定「闸门有几层」的通用手法。
2. **反解目标反推输入**：不从输入推输出，而是**指定期望的中间量**（sigframe）反解输入（`ss_sp`/`ss_size`）。H120 用此法把「能力边界」从「观察」变成「构造」。
3. **`on_sig_stack()` 类前置保护**：凡是「内核维护一个区间 + 用区间包含性做判定」的地方，都可能存在「设巨大 size 让区间罩住当前状态 ⇒ 判定翻转」的副作用 —— 此处它**保护**了内核；反向利用需要先绕开它。
4. **out-of-line 冷路径识别**：内联体里 `tbnz` 跳出的远地址（如 `+0x1248`）就是被外提的分支，**必须跟进去看**，否则会把「保护逻辑」误判为「无保护」。

---

## 八、产物清单

| 文件 | 说明 |
|---|---|
| `tools/h118_altstack_deliver.c` | get_sigframe 闸门验证（6 case）|
| `tools/h119_sigsp_wrap.c` | sigsp 加法回绕边界（7 case）|
| `tools/h120_frame_aim.c` | 帧落地地址全权可控（4 case）|
| `analysis/scratch/h117_get_sigframe.py` | TASK_SIZE_MAX 常量定位 |
| `analysis/scratch/h117_get_sigframe2.py` | get_sigframe 内联体完整反汇编 |
| `analysis/scratch/h117b_sigsp.py` | sigsp altstack 冷路径反汇编 |
| `analysis/output/h117_frame_setup.md` | 本报告 |

---

## 九、下一步（剩余未穷尽面）

| 面 | 状态 | 说明 |
|---|---|---|
| **A. 厂商 cdev ioctl 面** | **未穷尽（最高优先）** | H112 收敛结论；shell 域唯一未扫的大面 |
| B. L1 (`rb_erase`) / L2 (`rt_mutex`) 存档原语 | 用户指令下冻结 | 详见 MEY-TECH §10–§14 |
| C. 非 pstate 控制流落点 | H115 全树零命中 | 已穷尽 |
| D. SROP / 信号域 | **本轮 + H111/H113–H116 全部穷尽** | **判死** |
