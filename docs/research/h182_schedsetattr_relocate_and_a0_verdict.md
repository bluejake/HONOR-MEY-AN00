# H182 —— `sched_setattr` 真实路径重定位 + A0 裸调用隔离判决

> 轮次：**H182**｜日期：2026-10-06｜boot：`5176c1fc-654f-4150-b4b0-943962f09ff1`（**A0 未消耗**）
> 前序：H181（`analysis/output/h181_j1_pi_blocked_on_verdict.md`）
> 判决等级：**已实测**（真机 A0 + `chrt` 双透镜一致）

---

## 0. 一句话结论

★★ **H181 的核心归因「`sched_setattr` 调用路径本身就会 page fault」被证伪。**
裸调同一条 syscall ⇒ `rc=0` 正常返回、**零崩溃**。
⇒ 崩溃源在 **S1(futex 真环) 或 S3(setpriority)**，二者之一在 S4 之前已把内核状态破坏。
⇒ **H142「panic ⇒ 栈可重占」判据链彻底作废**（其前提「S4 可用」已被实测否证）。

---

## 1. ★★ 离线突破：`sched_setattr@0x55f830` 是个**无调用者的孤立符号**

H181 把 `sched_setattr@0xffffffc08055f830` 当作 syscall 路径入口，并据此得出「`pi=true` 硬编码」。

### 1.1 全镜像 `bl` 扫描（零调用者）

扫描方法（★ 必须用正确的段映射，H179 之前的扫描脚本就是漏了 `off=0x1c0`）：

```
段映射：Image-mey.symtab.elf  SHT_PROGBITS idx=1
        addr = 0xffffffc080000000   off = 0x1c0   size = 0x2368a00
扫描：对 [off, off+size) 每 4 字节取 u32，匹配 (w>>26)==0x25 (BL)
       imm26 符号扩展后 pc + imm*4 == target
```

| 符号 | 地址 | 调用者数 | 调用者 |
|---|---|---|---|
| `sched_setattr` | `0xffffffc08055f830` | ★ **0** | —— |
| `sched_setattr_nocheck` | `0xffffffc08016a5f4` | 1 | `0x17cf2c`（`sugov_init+0x11c`） |
| `_sched_setscheduler` | `0xffffffc080169800` | 1 | `0x55f81c`（`sched_setscheduler+0x10`） |

★ `sched_setattr@0x55f830` 只有 4 条指令、**零调用者** ⇒ 它不可能是 syscall 路径。
（`sched_setattr_nocheck` 的唯一调用者是 `sugov_init`，说明那是 EEVDF/`sugov` 内部自用符号。）

### 1.2 真实路径：syscall 入口**直调** `__sched_setscheduler`

`__arm64_sys_sched_setattr@0xffffffc08055fa18` 的 0x400 窗口内全部 `bl`：

| PC | 目标 | 符号 |
|---|---|---|
| `0x55fc28` | `0x552fc0` | `memset` |
| `0x55fc38` | `0x53338` | `__check_object_size` |
| `0x55fca4` | `0x195fc0` | `__arch_copy_from_user` |
| `0x55fd28` | `0x28764` | `__rcu_read_lock` |
| `0x55fd34` | `0x7fb3c` | `find_task_by_vpid` |
| `0x55fd60` | `0x2877c` | `__rcu_read_unlock` |
| ★ **`0x55fd7c`** | **`0x169894`** | **`__sched_setscheduler`** |
| `0x55fda0` | `0x1dfda8` | `__put_task_struct` |
| `0x55fdbc` | — | `check_zeroed_user` |
| `0x55fdfc` | `0x567e9c` | `__getparam_dl` |

⇒ **中间不经过 `0x55f830`。**

### 1.3 ★ 权威的 `pi` / `flags` 证据（本轮新增）

```asm
0x…55fd6c: mov  x1, sp        ; attr = 栈上 sched_attr
0x…55fd70: mov  x0, x19       ; p    = find_task_by_vpid() 结果
0x…55fd74: mov  w2, #1        ; ★ pi    = 1
0x…55fd78: mov  w3, #1        ; ★ flags = 1
0x…55fd7c: bl   __sched_setscheduler
```

| 项 | H181 记的地址 | 本轮权威地址 | 结论 |
|---|---|---|---|
| `pi=1` | `0x55f83c`（孤立符号内） | ★ **`0x55fd74`** | 结论同，依据**已修正** |
| `flags=1` | 未记录 | ★ **`0x55fd78`** | ★ **新发现** |

★ `flags=1`（`SCHED_FLAG_RESET_ON_FORK`）在 syscall 路径上**硬编码注入**，用户态无法规避。
它让 `__sched_setscheduler` 进入 `sched_reset_on_fork` 分支 —— 这是 J1 完全没排除的、
只在 `sched_setattr` 路径上出现的额外代码。
用户态 `uflags`（第 3 参）被单独处理：`0x55fd64 ldrb w8,[sp,#8]` + `0x55fd68 tbnz w8,#4`（`SCHED_FLAG_DL_OVERRUN=0x10`）。

---

## 2. ★ `__sched_setscheduler` 第 2 参 `x1` 是 **`sched_attr*`，不是 policy 整数

序言里 `ldr w25, [x1, #4]` 曾让我误判「解引用策略整数」。实证来自 `_sched_setscheduler@0x169800`
的栈构造（它是 `sched_setscheduler(2)` 的内核侧包装）：

```asm
_sched_setscheduler@0x169800:
  0x169820: ldr   w8, [x0, #0x88]     ; task->prio      (0x88)
  0x169824: ldr   w9, [x2]            ; param->sched_priority
  0x169830: sub   w8, w8, #0x78      ; - 120
  0x16983c: str   w1, [sp, #4]        ; [sp+0x04] = policy
  0x169840: stp   w8, w9, [sp, #0x10] ; [sp+0x10] = nice, [sp+0x14] = priority
  0x16985c: and   w2, w3, #1          ; pi = flags & 1
  0x169860: mov   x1, sp              ; ★ x1 = 栈上 sched_attr
  0x169864: mov   w3, #1
  0x169868: bl    __sched_setscheduler
```

栈上布局（= `struct sched_attr`，与 `kernel/sched/core.c` 一致）：

| 栈偏移 | 字段 |
|---|---|
| `sp+0x00` | `size` |
| `sp+0x04` | `sched_policy` ← `ldr w25,[x1,#4]` 读的就是它 |
| `sp+0x08` | `sched_flags` |
| `sp+0x10` | `sched_nice` |
| `sp+0x14` | `sched_priority` |
| `sp+0x18/0x20/0x28` | `sched_runtime` / `deadline` / `period`（`stp xzr,xzr` 清零） |

★ 故 `__sched_setscheduler` 真实原型是
`long __sched_setscheduler(task_struct *p, struct sched_attr *attr, bool pi, u64 flags)`
—— **H181/H179 把第 2 参当 `int policy` 的心智模型是错的**（虽不影响既有结论方向）。

---

## 3. 崩点范围内全部 `bl` 目标符号化（H181 只给了裸地址）

窗口 `0x169894` → `0x16a224`（`rt_mutex_adjust_pi` 调用点）内 52 条 `bl`/`b`，`bl` 目标按身份归类：

| 符号 | 出现次数 | PC | 性质 |
|---|---|---|---|
| `cpuset_unlock` | ★ **3** | `0x169c3c` / `0x169dd0` / `0x16a21c` | ★ 调度类（原头号嫌疑 `0x95b3c4`） |
| `__checkparam_dl` | 1 | `0x169970` | ★ **DEADLINE 类**（原嫌疑簇 `0x567exx`） |
| `__setparam_dl` | 1 | `0x169f08` | ★ DEADLINE |
| `dl_param_changed` | 1 | `0x169cb8` | ★ DEADLINE |
| `sched_dl_overflow` | 1 | `0x169da8` | ★ DEADLINE |
| ★ `__traceiter_android_vh_uclamp_validate` | 1 | `0x169d20` | ★ **vendor hook**（原嫌疑 `0x588738`） |
| `capable` | 2 | `0x169aa8` / `0x169c58` | 权限 |
| `security_task_setscheduler` | 1 | `0x169abc` | LSM |
| `cpuset_lock` | 1 | `0x169b74` | 调度类 |
| `task_rq_lock` / `update_rq_clock` | 1 / 1 | `0x169b88` / `0x169b90` | 调度类 |
| `dequeue_task` / `enqueue_task` | 1 / 1 | `0x169e78` / `0x16a0f0` | ★ `__seize_task_rq` 路径 |
| `reweight_task` | 1 | `0x169f98` | fair |
| `__schedule` | 1 | `0x169d6c` | 调度 |
| `static_key_enable` | 1 | `0x169c4c` | 静态键 |
| `raw_spin_lock/unlock*` | 6 | 多处 | 锁 |
| `__rcu_read_lock` / `unlock` | 2 | `0x169a68` / `0x169a80`,`0x169a8c` | RCU |

### 3.1 ★ `0x16a1a4..0x16a1cc` 是 CFI 检查，不是 page fault

```asm
0x16a1a4: ldr   x8, [x20, #0xb8]        ; vendor hook 指针
0x16a1b4: ldur  w16, [x8, #-4]          ; CFI type id
0x16a1b8: movk  w17, #0xc264
0x16a1bc: movk  w17, #0x712b, lsl #16   ; w17 = 0x712bc264
0x16a1c0: cmp   w16, w17
0x16a1c4: b.eq  #0x16a1cc
0x16a1c8: brk   #0x8228                 ; ★ CFI 失败 trap（非 page fault）
0x16a1cc: blr   x8                      ; 调 vendor hook
```

★ 不匹配时是 `brk #0x8228`（CFI trap），**不会产生 `page_request`** ⇒ 排除 CFI 为崩点。

### 3.2 ★ `0x16a210..0x16a224` 那个双门

```asm
0x16a210: tbz  w21, #0, #0x16a228      ; ① if (!pi) 跳过 rt_mutex_adjust_pi
0x16a214: ldr  w8, [sp, #0x1c]
0x16a218: tbz  w8, #0, #0x16a220       ; ② if ([sp+0x1c].bit0 == 0) 跳过 cpuset_unlock
0x16a21c: bl   cpuset_unlock
0x16a220: mov  x0, x19
0x16a224: bl   rt_mutex_adjust_pi
```

★ `w21` = 第 4 参 `pi`（H181 结论保留，依据改为 `0x55fd74`）。
★ `[sp+0x1c].bit0` 是 cpuset 是否需要 unlock 的标志。

---

## 4. ★★★ A0 判决实验（**H182 主成果**）

### 4.1 ★ H181 归因的逻辑漏洞（本轮发现）

H181 的 j1「唯一变量 = 不发 tgkill」，但 j1 **仍然跑完了 S1(futex 真环) 和 S3(setpriority)**。
⇒ j1 只证伪了「**S2 画布投递**是崩溃的必要条件」，
⇒ **没有排除 S1/S3**，因此「崩在 S4」是**推断，不是实测**。

★ 项目连续四发（`verify` / `badmode` / `j1` / H142）都建立在「S4 可用」这个**从未验证**的前提上。

### 4.2 A0 设计（零风险）

```c
if (!strcmp(mode, "a0")) {
    logx("[A0] --- A0_A: 进入 mmap 前 ---\n");     // 步进标记
    int *dummy = mmap(...); *dummy = 0;
    logx("[A0] --- A0_B: mmap OK，即将调 sched_setattr ---\n");
    long a0rc = do_sched_setattr(0, SCHED_OTHER, 0);   // ★ pid=0 ⇒ 内核解析为 current
    logx("[A0] --- A0_C: sched_setattr 已返回 ---\n");
    return 0;
}
```

**唯一变量**：只调一次 `sched_setattr`。
**不做**：futex 拓扑 / `LOCK_PI` / `WAIT_REQUEUE_PI` / `CMP_REQUEUE_PI` / `tgkill` / `setpriority` / 任何内核写。
★ **零内核数据修改** ⇒ 即使崩也不会污染后续判断（虽然实测没崩）。

### 4.3 实测结果

```
$ adb shell /data/local/tmp/h182.exe a0
=== h175_staged uid=2000 mode=a0 ===
=== [A0] 裸 sched_setattr 隔离验证 ===
[A0] 唯一变量 = 只调 sched_setattr，不做 S1/S2/S3 任何一步
[A0] --- A0_A: 进入 mmap 前 ---
[A0] A0_A OK
[A0] --- A0_B: mmap OK，即将调 sched_setattr ---
    sched_setattr(tid=0 pol=0) rc=0 errno=0(Success)     ★ rc=0
[A0] --- A0_C: sched_setattr 已返回 ---
[A0] ★★★ A0 结论：sched_setattr **未崩溃**
=== RC=0 ===
--- boot_id --- 5176c1fc-654f-4150-b4b0-943962f09ff1    ★ 未变
```

`history.log` 尾部仍停在 H181 的 `20261006015851-16727041` ⇒ **无新 panic**。

### 4.4 ★ 第二透镜：`chrt`（零编译、零 push、系统二进制）

设备自带 `/system/bin/chrt`（toybox 0.8.12-android）。

| 发 | 命令 | RC | 是否进内核 | boot_id |
|---|---|---|---|---|
| 1 | `chrt -R -o 0 /system/bin/true` | 1 | ✘ toybox 拒（`0 > -1`） | 不变 |
| 2 | `chrt -R -o 1 /system/bin/true` | 1 | ✘ toybox 拒 | 不变 |
| 3 | `chrt -R -b 0 /system/bin/true` | 1 | ✘ `-R` 不接受非 RT 策略 | 不变 |
| ★ 4 | `chrt -b 0 /system/bin/true`（SCHED_BATCH） | ★ **0** | ✔ 真正执行 | ★ 不变 |
| ★ 4 | `chrt -i 0 /system/bin/true`（SCHED_IDLE） | ★ **0** | ✔ 真正执行 | ★ 不变 |
| — | `chrt -m`（只读查询） | 0 | 不含 setattr | 不变 |

★ `chrt` 走 `do_sched_setscheduler@0x16c618`（与 `sched_setattr` **不同**入口），
**两个入口都不崩** ⇒ 崩溃源比 `__sched_setscheduler` 更靠后，且只在 S1/S3 之后才出现。

### 4.5 判决表

| 实验 | 变量 | 结果 | 结论 |
|---|---|---|---|
| H179 `verify` | T/V 落死区空洞 | `page_request` | —— |
| H180 `badmode` | T 落 `init_cred` | `page_request` | 与 T/V 无关 |
| H181 `j1` | **不发 tgkill**（S1+S3 照跑） | `page_request` | S2 投递非必要条件 |
| ★ **H182 A0** | **只调 sched_setattr** | ★ **`rc=0`，不崩** | ★ **sched_setattr 本身无罪** |
| ★ **H182 chrt** | **系统二进制改策略** | ★ **RC=0，不崩** | ★ **两入口均无罪** |

★ **若「崩在 S4」成立，则应观测到 A0 崩溃；实际观测到 A0 `rc=0` 成功返回 ⇒ 该结论错误。**
（可证伪判据，已闭合）

---

## 4.6 ★★★ B1 / B2 / B3 —— 四格判决，锁定「S4 必需 + S1 前提」

A0 排除 S4 后，崩源只剩 S1 或 S3。补三发做 2×2 分离，**每发唯一变量、零内核数据写**：

| mode | 变量 | 实现 | 实测输出 | 结果 | `boot_id` |
|---|---|---|---|---|---|
| **A0** | 只调 S4 | `mmap` + `sched_setattr(0, OTHER, 0)` | `rc=0 errno=0(Success)` | ★ **不崩** | 不变 |
| **B1** (`a1`) | S3+S4 | A0 + `setpriority(1)` | `setpriority rc=0` → `sched_setattr rc=0` | ★ **不崩** | 不变 |
| **B2** (`a2`) | 只跑 S1 | 完整 futex 真环 + `ETIMEDOUT`，W 直接 return | `EDEADLK` ✔ → `ETIMEDOUT` ✔ → `B2-RETURN` ✔ → `RC=0` | ★ **不崩** | 不变 |
| **B3** (`a3`) | S1+S3 | B2 + `setpriority(1)`，**不调 S4** | `S3 rc=0` → `B3-RETURN` ✔ → `RC=0` | ★ **不崩** | 不变 |
| **J1** | S1+S3+S4 | H181 已测 | —— | ★ **`page_request`** | **变了** |

### 判决表

| S1 futex | S2 画布 | S3 nice | S4 setattr | 结果 |
|---|---|---|---|---|
| ✘ | ✘ | ✘ | ✔ | 不崩 |
| ✘ | ✘ | ✔ | ✔ | 不崩 |
| ✔ | ✘ | ✘ | ✘ | 不崩 |
| ✔ | ✘ | ✔ | ✘ | 不崩 |
| ✔ | ✘ | ✔ | ✔ | ★ **崩** |

### ★★ 因果链（本项目至今最干净的一次定位）

**S4 无罪**（裸调 `rc=0`）**＋ S4 必需**（缺 S4 即便有 S1+S3 也不崩）
**＝ 崩溃是 S4 对 S1 遗留状态的首次解引用。**

★ 这**重新支持 H180 的 P1**（`rt_mutex_adjust_pi` 解引用野 `pi_blocked_on`），
但给出了**正确的因果链**——H181 误以为 P1 被证伪，实际上它只是漏掉了「S1 是必要前提」这一格。

精确机制（H179 反汇编 + H182 判定闭合）：

1. S1 的 `FUTEX_WAIT_REQUEUE_PI` 带 1s 超时 ⇒ 走 `ETIMEDOUT`；
   `rt_mutex_cleanup_proxy_lock@0xffffffc0810813a4` **不清 `task->pi_blocked_on`**（H179 已证）
   ⇒ `pi_blocked_on` 悬垂指向 `waiter = SP0 - 0x210`（位于 `futex_wait_requeue_pi` 的 0x1c0 栈帧内）。
2. 该栈帧已退出 ⇒ 内存内容被后续调用覆写 ⇒ `pi_blocked_on` 成为**指向任意内容的野指针**。
3. S2 投递画布会**主动把它改成一个可读的伪造 waiter**（那是利用，本意如此）。
4. H181/J1 **不投递** ⇒ 野指针保持"随机"内容 ⇒ S4 解引用时命中未映射页 ⇒ `page_request`。
5. ★ **所以 J1 的崩溃不是"S2 的锅"，而是"S2 缺席导致野指针未被接管"** ——
   J1 想验证画布必要性，却意外测到了野指针的默认致命性。

### 可证伪判据

> **若 P1 成立**（S4 解引用悬垂 `pi_blocked_on`），则：
> ① 缺 S4 时即便有 S1+S3 也不崩 ⇒ ★ **已观测（B3 `RC=0`）**
> ② 有 S4 无 S1 时不崩 ⇒ ★ **已观测（A0/B1 `rc=0`）**
> ③ 两者齐备时崩 ⇒ ★ **已观测（J1 `page_request`）**
> 三条全部成立 ⇒ **P1 成立，H181 的「S4 本身有罪」被证伪。**

### 下一发（B4，判决性收口）：让 `pi_blocked_on` 指向**可读**地址

★ 既然 P1 成立，**不必让野指针随机命中未映射页**——把 `waiter` 指向一个**确定可读**的
内核地址（如 `&init_task` 或 `.data..percpu` 空洞），`ldr x21,[x19,#0x938]` 之后的
`ldr w9,[x21,#0x18]` / `ldr x21,[x21,#0x58]` 就不会 page fault。

| 发 | mode | 变量 | 判据 |
|---|---|---|---|
| ★ **B4** | `a4` | 复用 S1，但让 ETIMEDOUT 后 **`pi_blocked_on` 指向 `&init_task`**（经由不投递+栈残留填充，或改用无超时的 S1 让 waiter 保持有效） | 不崩 ⇒ ★★ **P1 精确确认**（崩点就是 waiter 解引用） |

★ 更省的做法：B4 直接**去掉 S1 的 1 秒超时**（传 `NULL` 而非 `to`），
让 W 永久阻塞在 `futex_wait_requeue_pi` 里、栈帧不退出 ⇒ `pi_blocked_on` 指向**仍有效**的
栈上 waiter ⇒ 此时 S4 由**另一个线程**发起。
这是 H142 原始设想的正确形态（H142 的错在于用 ETIMEDOUT 路径 + 崩了就以为栈可重占）。

---

## 5. 崩溃源锁定：S1 或 S3

### 5.1 新头号嫌疑：S1 造成的悬垂 `pi_blocked_on`

H179 已证（反汇编）：
`rt_mutex_cleanup_proxy_lock@0xffffffc0810813a4` **不清 `task->pi_blocked_on`**
（只操作 lock 内部 `lock->{owner,waiters,...}`，全程无 `str` 到 `task+0x938`）。

而 S1 的 `FUTEX_WAIT_REQUEUE_PI` **带 1 秒超时**（`h175_staged.c:266` 传入 `to`）
⇒ 走 `ETIMEDOUT` 路径 ⇒ `pi_blocked_on` 悬垂指向**已退栈**的栈内存
（`waiter = SP0 - 0x210`，位于 `futex_wait_requeue_pi` 的 0x1c0 栈帧内）。
⇒ 随后 S3(`setpriority`)、S4 在**同一线程栈**上继续执行 ⇒ 覆写该区域 ⇒ S4 里若解引用即 page fault。

### 5.2 待排除：S3 `setpriority` 的副作用

`setpriority(PRIO_PROCESS, 0, 1)` 本身不改 `pi_blocked_on`，
但会走 `set_user_nice` → 可能触发 `rt_mutex_adjust_prio` / 迁移 fair 实体。
H179 已证 S3 是**必要步骤**（`tree.prio=0` vs `task->prio≈139` ⇒ `cmp` 不等才不进早退门），
但它的**副作用是否破坏状态**从未单独验证。

### 5.3 下一步：A0 二分（各 1 boot）—— ★ **已完成，见 §4.6**

| 发 | mode | 变量 | 判据 | 实测 |
|---|---|---|---|---|
| A0 | `a0` | 只调 `sched_setattr` | 判 S4 | ★ **不崩** |
| ★ B1 | `a1` | 裸 `setpriority` + `sched_setattr` | 判 S3 | ★ **不崩 ⇒ S3 无罪** |
| ★ B2 | `a2` | 只跑 S1 futex 环，不调 S3/S4 | 判 S1 自身 | ★ **不崩 ⇒ S1 自身无罪** |
| ★ B3 | `a3` | S1+S3（不调 S4） | 判组合 | ★ **不崩** |
| ★ **B4** | `a4`（**待做**） | 去 S1 超时，让 `pi_blocked_on` 保持有效 | 精确确认 P1 | 待做 |

★ **判决已从「S4 有罪」翻转为「S4 必需 + S1 前提」，P1 重新成立。**

---

## 6. 铁律增补

| # | 规则 | 依据 |
|---|---|---|
| **★54** | ★★★ **「排除某个变量」不等于「定位到另一个变量」。** H181 的 j1 只跳过了 S2，**S1/S3 照跑**，却把结论写成「崩溃在更早处（sched_setattr 前段）」——把「S4 自身有罪」当成了实测。**跳过的变量必须与被跳过的变量在同一发里被明确列出。** | 实测（A0 推翻） |
| **★55** | ★★★ **触发路径必须先单独裸调用验证，再叠加前置状态。** 本项目连续五发（verify/badmode/j1/H142/本轮）都在「S4 可用」这个从未验证的前提上。**A0 式隔离调用是任何多步利用链的强制第一步。** | 实测 |
| **★56** | ★★ **kallsyms 里的 `T` 符号不等于「它被调用过」。** `sched_setattr@0x55f830` 零调用者却是 `T`。**引用任何函数前必须用全镜像 `bl` 扫描确认调用者存在**；孤立符号往往是 LTO/合并的产物或同地址别名。 | 反汇编 + 全镜像扫描 |
| **★57** | ★★ **全镜像 `bl` 扫描必须用正确的段映射。** `Image-mey.symtab.elf` 的唯一大段为 `addr=0xffffffc080000000, off=0x1c0, size=0x2368a00`；**漏掉 `off=0x1c0` 会让所有 PC 算错、结果恒为「零调用者」。** 这个 bug 差点让本轮误判「sched_setattr 不可达」。 | 实证（漏 off ⇒ 0 命中；修正 ⇒ 1 命中） |
| **★58** | ★★ **「某函数有零调用者」是**强反常信号**，必须追到底。零调用者的 `T` 符号往往说明真正入口在别处（`__arm64_sys_*`），而 H181 据此得出的「硬编码证据」实际来自错误对象（结论巧合正确，依据错误）。 | 实测 |
| **★59** | ★ **步进标记（每步前 fflush 落盘）是崩溃定位的最低成本手段。** H181 无法判定「崩在哪一步之后」正是因为日志被 panic 截断；A0 的 `A0_A/A0_B/A0_C` 三段标记让「崩点被夹在哪两步之间」成为可判定的。 | 实测 |
| **★60** | ★ **优先用设备自带工具做零成本判决。** `chrt`（toybox）让 A0 的第二透镜**零编译、零 push**；编译器找不到时（NDK 曾一度失联）这仍是有效路径。 | 实测 |
| **★61** | ★ **NDK r27c 在本机的位置**：`<HOME>\.workbuddy\binaries\android\android-ndk-r27c\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android24-clang.cmd`（★ 不在 PATH、不在常规 SDK 位置，需全盘 `ndk*` 目录名搜索定位）。★ 不要用 `-lpthread`（r27c 已并入 libc）。 | 实证 |
| **★62** | ★ **push 到设备必须用 POSIX 路径**（`/data/local/tmp/xxx`）。带 `MSYS_NO_PATHCONV=1` 时 Windows 形式路径（`D:/...`）会被当字面量，导致 `remote secure_mkdirs() failed`。 | 实证 |
| **★63** | ★★★ **多步利用链必须做 2×2 因子分离，不能只做「单变量剥离」。** H182 用 4 发（只有 S4 / S3+S4 / 只有 S1 / S1+S3）才分离出真相：**每一步单独都不崩，只有 S1+S3+S4 齐备才崩**。★ 单变量剥离（「去掉 S2 看崩不崩」）在存在**状态残留交互**时只能得到「该变量非必要」，无法定位真凶。 | 实测 |
| **★64** | ★★★ **「变量非必要」≠「变量无罪」，更≠「其他变量有罪」。** H181 的 j1 证明 S2 投递非必要，随即推断「S4 本身有罪」——**方向完全错误**。真实结构是 S2 **恰好是唯一能让野指针变得可利用的变量**，它的缺席反而使野指针随机命中未映射页。 | 实测 |
| **★65** | ★★ **ETIMEDOUT 路径会留下悬垂 `pi_blocked_on`**（`rt_mutex_cleanup_proxy_lock` 不清它），⇒ 用超时 futex 建立 PI waiter 的方案**天然带一个野指针**。要么去掉超时让栈帧保持有效，要么主动把 waiter 指向确定可读地址。 | 反汇编 + 实测 |
| **★66** | ★ **步进标记（`A0_A`/`A0_B`/`B3-RETURN` 等）+ `fflush` 是差分实验的标配**。panic 会截断 stdout，没有步进标记就无法判定「崩在哪一步之后」，只能靠 boot_id 变化做二值判断，信息量浪费。 | 实测 |

---

## 7. 设备状态

| 项 | 值 |
|---|---|
| serial | `A22C026319001339` |
| boot_id | **`5176c1fc-654f-4150-b4b0-943962f09ff1`** |
| | **A0/B1/B2/B3 四发全部零副作用 ⇒ 该 boot 仍完整未消耗** |
| `getenforce` | **Enforcing**（未 root） |
| `id -u` | **2000** |
| 设备端工具 | `/data/local/tmp/h182.exe` 17,128 B md5 `03ca187e1eec1f5ffdb8dad25eea84d6` |
| `history.log` 末条 | `20261006015851-16727041`（H181；A0/B1/B2/B3 **均未新增**） |

★ 判决性优势：**四发差分跑完，boot 一次未消耗。** 这是「A0 式隔离优先」纪律的直接回报。

---

## 8. 文件清单

**修改**
- `tools/h175_staged.c`（★ 新增 `a0`/`a1`/`a2`/`a3` 四个判决 mode + `g_stop_after_s1` / `g_stop_before_s4` 标志 + `A0_A/A0_B/A0_C`、`B2-RETURN`、`B3-RETURN` 步进标记）
- `tools/h175.exe` → 未改

**新建**
- `tools/h182.exe` 17,128 B md5 `03ca187e1eec1f5ffdb8dad25eea84d6`
- `analysis/output/h182_schedsetattr_relocate_and_a0_verdict.md`（本文件）

**编译命令**
```bash
"<HOME>/.workbuddy/binaries/android/android-ndk-r27c/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android24-clang.cmd" \
  -O2 -o tools/h182.exe tools/h175_staged.c
# ★ 不加 -lpthread（r27c 已并入 libc）
```

**push**
```bash
adb.exe push tools/h182.exe /data/local/tmp/h182.exe   # ★ POSIX 路径
adb.exe shell 'chmod 755 /data/local/tmp/h182.exe'
```

---

## 9. 置信度标注

| 结论 | 等级 |
|---|---|
| `sched_setattr@0x55f830` 零调用者 | **已实测**（全镜像 `bl` 扫描） |
| syscall 真实路径 `0x55fa18` 直调 `__sched_setscheduler@0x169894` | **已实测**（反汇编） |
| `pi=1` @ `0x55fd74`、`flags=1` @ `0x55fd78` | **汇编已证**（未单独变更验证 flags 行为） |
| `__sched_setscheduler` 第 2 参 = `sched_attr*` | **汇编已证**（`_sched_setscheduler` 栈构造） |
| CFI 段（`brk #0x8228`）非 page fault | **汇编已证**（未实测触发） |
| ★ **裸 `sched_setattr` 不崩（A0）** | ★ **已实测**（`rc=0`） |
| ★ **`chrt -b 0` / `chrt -i 0` 不崩** | ★ **已实测**（`RC=0`，两 syscall 入口） |
| ★ **S3(setpriority) 无罪（B1）** | ★ **已实测**（`rc=0`） |
| ★ **S1 单独无罪（B2）** | ★ **已实测**（`B2-RETURN` + `RC=0`） |
| ★ **S1+S3 无罪（B3）** | ★ **已实测**（`B3-RETURN` + `RC=0`） |
| ★★ **S4 必需 + S1 前提：崩溃 = S4 首次解引用 S1 悬垂的 `pi_blocked_on`（P1 成立）** | ★ **已实测**（四格判决，见 §4.6） |
| ★ H181「S4 本身有罪」被证伪 | ★ **已实测** |
| ★ H142 判据链作废 | ★ **已实测**（前提被否证） |
| 「崩点精确在 `0x…814c8` / `0x…814ec`」 | **未验证基线**（PC 仍未取得；P1 强支持但非直证） |
| 去掉 S1 超时后 `pi_blocked_on` 保持有效 | **未验证基线**（B4 待做） |
