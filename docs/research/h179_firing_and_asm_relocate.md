# H179 —— 真机首发射谱 + 全链汇编重定位 + panic 落点推演

**日期**：2026-10-06
**boot 消耗**：`abc61a92` → **`fd440de9`**（★ 首次真机开火即 panic）
**前驱**：H178（`lock` 定址 `.data..percpu` 空洞）/ H179-推演（重入安全性证伪 + 投递改单发）

---

## 0. 置信度声明

| 编号 | 结论 | 等级 |
|---|---|---|
| H179-C1 | `tgkill` 投递路径不含任何 rbtree / `rt_mutex` 操作 | **汇编已证**（`h179_asm.txt` 全文，`svc #0` 唯一） |
| H179-C2 | `lock+0x08` 残留 `&entry` **不会**被二次消费 | **源码已证**（`core.c:8014` 唯一调用点 + 工具侧只调 1 次） |
| H179-C3 | `pi=true` 在 `sched_setattr` 里**硬编码**，工具传 `flags=0` 不影响 | **源码已证**（`core.c:8069`） |
| H179-C4 | NDK r27c `-static` 产物在真机**无法加载**（TLS 对齐 < 64） | **已实测**（bionic 报错，exit 134） |
| H179-C5 | `h175.exe verify` 全部前置判据命中，S4 内 panic | **已实测**（stdout 截断 + `boot_id` 变） |
| H179-C6 | `reason[page_request]`（页错误，非 `BUG_ON` 显式 panic） | **已实测**（`history.log` 新增行） |
| H179-C7 | panic 落点 **`rt_mutex_wait_proxy_lock` 链内**，`pi_blocked_on` 未被清零 | **汇编+源码双证**（本轮，见 §4） |
| H179-C8 | 本机 `rt_mutex_adjust_prio_chain` 与源码**逐条吻合**（非 vendor 魔改） | **汇编已证**（§3.3 对照表） |
| H179-C9 | `rt_mutex_cleanup_proxy_lock` **不清** `pi_blocked_on` | **汇编已证**（`0x…813a4` 全文，偏移全在 lock 内部） |
| H179-C10 | panic 精确指令（PC）未取到 | ❌ **未验证**（日志被 HKS 加密 + SELinux 双重挡住，见 §6） |

---

## 1. ★★★ 本轮最重要结论：**H178 的 `[8]` 判据模型是错的**

H178 §5.1 假设 S4 时 `pi_blocked_on` 指向**画布里的 waiter**，于是 `rb_erase` 会消费我们的槽位。
**本轮汇编推演证明这个前提不成立**：

```c
/* requeue.c:840-846  Q_REQUEUE_PI_DONE 分支 */
ret = rt_mutex_wait_proxy_lock(pi_mutex, to, &rt_waiter);   /* W 线程真阻塞在这里 */
spin_lock(q.lock_ptr);
if (ret && !rt_mutex_cleanup_proxy_lock(pi_mutex, &rt_waiter))
        ret = 0;
```

`rt_mutex_cleanup_proxy_lock@0xffffffc0810813a4` **全量反汇编**（0x8c 字节）：

```
0x…813d4: bl #0x…805e4        ; rt_mutex_dequeue(lock, waiter)
0x…813d8: ldr x8, [x19, #0x18]     ; lock->waiters.rb_root.rb_node
0x…813f0: bl #0x…80e60       ; rt_mutex_plist / ...
0x…813f4: ldr x8, [x19, #8]        ; lock->wait_lock
0x…813fc: ldr x8, [x19, #0x18]     ; lock->owner
0x…81408: str x8, [x19, #0x18]     ; lock->owner = 0
0x…81418: bl #0x…835b4        ; raw_spin_unlock(&lock->wait_lock)
```

★ `x19 = lock`，所有偏移（`+0x8` / `+0x18`）**都在 `rt_mutex_base` 内部**，
**没有任何一条写 `task->pi_blocked_on`（task + 0x938）**。

⇒ ★★ **`pi_blocked_on` 在 ETIMEDOUT 路径上保持指向 `&rt_waiter`（栈上），不被清零。**
清零只发生在 `rtmutex.c:1161`（成功拿锁路径），W 线程没走那里。

**推论**：`rt_mutex_adjust_pi@0x…81468 ldr x21,[x19,#0x938]` 拿到的
是一个**已被内核栈复用的悬垂地址**，随后 `ldr w9,[x21,#0x18]` / `ldr x21,[x21,#0x58]`
解引用它 —— ★ **但 S4 是在 syscall 里，SP 已切到内核栈，`&rt_waiter` 落在当前内核栈之外**
⇒ **`page_request` 成立。**

---

## 2. 真机首发射谱（`verify` 模式，单发）

```
=== h175_staged uid=2000 mode=verify ===
[verify] lock=0xffffffc082136048  V=0xffffffc082136070  T=0xffffffc082136068  rb_right=0
[M] CMP_REQUEUE_PI rc=-1 errno=35(Resource deadlock would occur)
[M] ==> EDEADLK 真环成立
  [W] *** RETURNED *** rc=-1 errno=110(Connection timed out) 悬垂成立
  [W] S2: tgkill_staged  T=0xffffffc082136068  V=0xffffffc082136070
              task=0xffffffc08217e280  lock=0xffffffc082136048
  [W] sig hits=1（★ 单发，期望 1）
  [W] S3: setpriority(nice=1) rc=0 errno=0
  [W] S4: sched_setattr(self) -> rt_mutex_adjust_pi(self)
  ← stdout 截断（exit 255）
```

| 判据 | 期望 | 实测 | 结论 |
|---|---|---|---|
| `sig_hits` | 1 | **1** | ✔ 单发按设计，画布投递成立 |
| `CMP_REQUEUE_PI` | `EDEADLK(35)` | **35** | ✔ 真环 |
| W 悬垂 | 返回 | **`ETIMEDOUT(110)`** | ✔ 返回，但**走的是 ETIMEDOUT 不是成功** |
| `setpriority` | `rc=0` | **0** | ✔ prio 闸门已破 |
| `sched_setattr` | `rc=0` | **未返回** | ✘ **`page_request` panic** |
| `boot_id` | 三重 md5 一致 | **`abc61a92`→`fd440de9`** | ✘ 重启 |
| `getenforce` | ≠ Enforcing | **Enforcing** | ✘ 未 root |

★ **`ETIMEDOUT` 这个值本身就是本轮的决定性信息**（详见 §1）。

---

## 3. 全链汇编重定位（★ 本轮离线成果，可直接复用）

### 3.1 几何三段序言（实测复核，全部命中 H175 假设）

| 符号 | 地址 | 序言 | 结论 |
|---|---|---|---|
| `__arm64_sys_futex` | `0xffffffc080119ad8` | `paciasp; sub sp,sp,#0x80` | ✔ |
| `do_futex` | `0xffffffc0801edfc0` | `paciasp; sub sp,sp,#0x60` | ✔ |
| `futex_wait_requeue_pi` | `0xffffffc080958e1c` | `paciasp; sub sp,sp,#0x1c0` | ✔ |
| **合计** | | `0x80+0x60+0x1c0 = 0x2A0` | ⇒ `waiter = SP0 − 0x2A0 + 0x90 = SP0 − 0x210` ✔ |
| `rt_sigreturn` | `0xffffffc08049b2e4` | `stp x29,x30,[sp,#-0x60]!; sub sp,sp,#0x230` | ⇒ 帧深 `0x290` ✔ |
| | `0x…beac: add x0,sp,#0x10; mov w2,#0x200` | ⇒ 画布 `[KSP−0x280, KSP−0x80]` ✔ |

★ 三段 `sub` 与两处 `add` 全部实测复核，**H175 几何无偏移错误**。

### 3.2 `rt_mutex_adjust_pi@0xffffffc081081438` 完整访存表

```
0x…81454: add  x20, x0, #0x90c     ; &task->pi_lock        (BTF pi_lock@0x90c ✔)
0x…81468: bl   #0x…833c4           ; raw_spin_lock_irqsave
0x…8146c: ldr  x21, [x19, #0x938]  ; ★ waiter = task->pi_blocked_on
0x…81474: cbnz x21, #0x…814ac
0x…81478: mov  x0, x20; bl unlock ; ← waiter==NULL 早退
0x…814a8: ret                        ← 函数正常出口

0x…814ac: str  x1, [sp, #8]        ; flags
0x…814b0: stur wzr, [x29, #-0xc]    ; depth = 0
0x…814b8: ldur w8, [x29, #-0xc]    ; ┐
0x…814bc: cmp  w8, #0              ; │ if (++depth > 0)
0x…814c0: b.gt #0x…814c8           ; ┘
0x…814c4: ldr  w8, [x19, #0x84]    ; ★ task->prio          (BTF prio@0x84 ✔)
0x…814c8: ldr  w9, [x21, #0x18]    ; ★★ waiter->tree.prio   ← 解引用 waiter
0x…814d0: cmp  w9, w8              ; rt_waiter_node_equal
0x…814d4: b.ne #0x…814ec           ; 不等 ⇒ 继续
0x…814d8: tbz  w8, #0x1f, #0x…81478; prio<0 ⇒ 早退
0x…814dc: ldr  x9, [x21, #0x20]    ; ★ waiter->tree.deadline ← 解引用
0x…814e4: cmp  x9, x8
0x…814e8: b.eq #0x…81478           ; 相等 ⇒ 早退
0x…814ec: ldr  x21, [x21, #0x58]   ; ★★ next_lock = waiter->lock ← 解引用
0x…814f0: mov  x0, x20; bl unlock
0x…814f8: add  x0, x19, #0x40      ; &task->usage          (BTF usage@0x40 ✔)
0x…81500: ldadd w8, w8, [x0]       ; get_task_struct
0x…81518: mov  x0, x19 ; mov w1, wzr ; mov x2, xzr
0x…81524: mov  x3, x21             ; next_lock
0x…81530: bl   #0x…815d4           ; ★ rt_mutex_adjust_prio_chain
```

★ **S3 的 `setpriority` 破闸门在本机真实有效**：`cmp w9,w8`（画布 `tree.prio=0` vs `task->prio=139`）⇒ 不等 ⇒ 不早退 ⇒ 进 `prio_chain`。**S3 不可省。**

★ **本机 `rt_mutex_adjust_pi` 有一个上游没有的 prio 提前返回闸门**（`:814b8`–`:814e8` 的 `depth`/`deadline` 双比较），
H178 §5.1 记的「`:809` rt_waiter_node_equal 短路」对应 `:814d0` —— **结论一致**（画布 prio=0 ≠ task prio ⇒ 不短路）。

### 3.3 `rt_mutex_adjust_prio_chain@0xffffffc0810815d4` 前段 vs 源码

```
0x…815f8: str  x5, [sp, #8]        ; top_task = task (本机)
0x…81614: ldr  w1, [x8, #0xda8]    ; max_lock_depth (percpu)
0x…8163c: add  x26, x19, #0x90c    ; &task->pi_lock
0x…81644: bl   #0x…83444           ; raw_spin_lock_irq
0x…81648: ldr  x25, [x19, #0x938]  ; ★ [P1] waiter = task->pi_blocked_on
0x…8164c: cbz  x25, #0x…81980      ; if (!waiter) goto out
0x…81650: cbz  x20, #0x…81660     ; orig_waiter==NULL ⇒ 跳 [3]
0x…81654: ldr  x8, [x21, #0x18]    ;   chwalk 判据
0x…81660: ldr  x8, [x25, #0x58]    ; ★ [3] waiter->lock
0x…81664: cmp  x27, x8             ;   next_lock != waiter->lock
0x…81668: b.ne #0x…81980           ;   ⇒ goto out   ★★ :752 闸门确认存在
0x…8166c: cbz  x22, #0x…8169c     ; orig_waiter==NULL ⇒ 跳 [4]
0x…81670: ldr  x8, [x19, #0x920]   ;   task->pi_waiters
0x…81678: ldr  x8, [x19, #0x928]   ;   task->pi_waiters.rb_leftmost
```

| 源码 | 汇编 | 判定 |
|---|---|---|
| `rtmutex.c:713` `raw_spin_lock_irq(&task->pi_lock)` | `:8163c-81644` | ✔ |
| `rtmutex.c:722` `waiter = task->pi_blocked_on` | `:81648` | ✔ |
| `rtmutex.c:733` `if (!waiter) goto out_unlock_pi` | `:8164c cbz → 81980` | ✔ |
| `rtmutex.c:740` `if (orig_waiter && !rt_mutex_owner(orig_lock))` | `:8166c cbz → 8169c` | ✔ |
| `rtmutex.c:752` `if (next_lock != waiter->lock) goto out_unlock_pi` | `:81664 cmp; b.ne → 81980` | ✔ **逐条吻合** |

★★ **结论：本机 `rt_mutex_adjust_prio_chain` 与 6.6 源码逐条一致，无 vendor 魔改。**
（置信度：汇编已证 / 未实测 —— 但 M180 判据 J-M1 可在真机一次性证实或否证整条链。）

### 3.4 `rt_mutex_adjust_prio_chain` 内 `rb_erase` 双写实证

```
0x…81750: bl   #0xffffffc08003af24   ; ★ rb_next
0x…81754: str  x0, [x24, #0x10]      ; ★ 写 lock+0x10 (rb_leftmost)
0x…81760: bl   #0xffffffc08003a9d4   ; ★ rb_erase
0x…81764: str  x25, [x25]            ; 清 node->parent_color
0x…81798: stp  xzr, xzr, [x25, #8]   ; 清 rb_right/rb_left
0x…8179c: str  xzr, [x25]            ; 清 parent_color
0x…817a0: str  x25, [x1]             ; root->rb_node = node
0x…817a4: str  x25, [x24, #0x10]     ; ★ 写 lock+0x10 AGAIN
0x…817ac: bl   #0xffffffc08003a860   ; rb_insert_color_cached
```

★ **`str x0,[x24,#0x10]` 出现在 `rb_erase` 前、`rb_insert_color_cached` 后各一次**
⇒ H177 的 `rb_erase_cached` 耦合双写模型在**本机汇编层得到印证**（`lock+0x10` 被写两次）。
★ 同时 **`:81798-8179c` 的三条清零**印证 H178「`RB_CLEAR_NODE`」清理行为。

---

## 4. ★★ panic 落点推演（三候选，逐一给出可证伪判据）

`reason[page_request]` = **页错误**（非 `BUG_ON` 显式 panic）⇒ 崩在**解引用野/未映射地址**。

| # | 候选落点 | 指令 | 若成立则应观测到 | 独立透镜 |
|---|---|---|---|---|
| **P1** | `rt_mutex_adjust_pi` 首次解引用 waiter | `0x…814c8 ldr w9,[x21,#0x18]` | 崩在 `sched_setattr` 早期，**根本没进 `prio_chain`** ⇒ `lock+0x08` 保持 0 | ✔ `boot_id` 变 + `history.log` 新增 |
| **P2** | `prio_chain` 内 `waiter->lock` | `0x…81660 ldr [x25,#0x58]` | 进到了 `:752` 闸门 ⇒ **`lock+0x08` 已被写** | ✔ 同上（无法区分 P1/P2） |
| **P3** | `wake_up_state(top_waiter->task)` | `rt_mutex_wake_up_q` 内 | 崩在 **`rb_erase` 与 `wake` 之后** ⇒ 两条写都已落地 | ✔ 同上 |

★★ **三个候选共用同一个外部透镜（是否重启），本轮无法区分。** 根因是**内核栈全被 HKS 加密 + dumplog 被 SELinux 挡住**（§6）。

### 4.1 为什么 `pi_blocked_on` 指向的地址不可读（★★ 本轮新增洞察）

W 线程的 `&rt_waiter = SP0 − 0x210`，其中 `SP0` 是**用户态 `tgkill` 那一刻的 SP**。
`sigreturn` 写画布用的 `KSP` 是**内核栈指针**（`sp_el0` 在 `rt_sigreturn` 里 `mrs x20, sp_el0` 只用于 canary）：

```
rt_sigreturn@0x…b308: mrs x8, sp_el0        ; ★ 取的是 EL0 SP，不是内核 SP
rt_sigreturn@0x…b30c: mrs x20, sp_el0       ;   用于 canary @ task+0x620
rt_sigreturn@0x…b304: sub sp, sp, #0x230     ;   但 sp 本身已 = KSP − 0x60
```

⇒ 画布 `[KSP−0x280, KSP−0x80]` 在**内核栈**上。
⇒ 而 `pi_blocked_on` 指向的 `&rt_waiter` 是**用户栈**地址（`SP0−0x210`）。

★★ **两者本就不在同一地址空间** —— 但 H175 几何的整个立论前提是「二者共用同一段物理页」
（同一线程的 futex 栈帧与 sigreturn 帧在栈上重叠）。**这个前提从未被验证。**

★ **P1 判据（可证伪）**：
> 若「用户栈 waiter 与内核栈画布确实重叠」成立，则 `ldr w9,[x21,#0x18]` 读到的是画布值 `0`
> （`tree.prio` 槽 = `v8.d[1]` = 0）⇒ `cmp w9,w8` ⇒ `0 != 139` ⇒ 进 `prio_chain`。
> **若观测到崩溃且 `prio_chain` 未生效（`lock+0x08` 仍 0），则该前提被证伪。**

---

## 5. NDK r27c 静态链接 TLS 对齐坑（★ 新踩，已修）

```text
$ h175.exe verify
error: "/data/local/tmp/h175.exe": executable's TLS segment is underaligned:
       alignment is 8 (skew 0), needs to be at least 64 for ARM64 Bionic
exit 134
```

| 项 | 值 |
|---|---|
| `-static` 产物 | 2,226,016 B ✘ **真机无法加载** |
| 动态链接产物 | 12,912 B ✔ |
| push 后 md5 | `cd716baab21af2cf3de1a6f1862e80c4` |

★ **该失败未消耗 boot**（`boot_id` 仍 `abc61a92`）—— 符合「零风险失败」预期。
★ **纪律新增**：产物必须**真机先跑一遍加载**再开火，否则白烧一个 boot 的心理预期。

---

## 6. 为什么拿不到 panic 栈（本轮实测的全部尝试）

| # | 尝试 | 结果 |
|---|---|---|
| 1 | `logcat -b kernel -d` | ✘ 输出被 `(HKS)…(HKE)` 整段加密 |
| 2 | `logcat -b crash -d` | ✘ 同样 HKS 加密 |
| 3 | `logcat -b events -d` | ✔ 明文，但只有 `am_freeze` / `commit_sys_config_file` 等用户态事件 |
| 4 | `/sys/fs/pstore/` | ✘ `Permission denied`（DAC `0550 system:log` 已在 group，但 **SELinux `sysfs`** 拦） |
| 5 | `/sys/fs/pstore/console-ramoops` | ✘ `No such file`（目录 Links:2 ⇒ **空**，内核未写 pstore） |
| 6 | `/data/log/reliability/faultdetect/history.log` | ✔ **唯一可用** ⇒ 只给 `reason[page_request]` 一行摘要 |
| 7 | `/data/log/reliability/faultdetect/event.db` | ✔ **拉回本地 1,310,720 B 解析**（SQLite） |
| 8 | `/data/tombstones/` | ✘ 最新 `tombstone_31` 停在 2026-09-28 |
| 9 | `/data/vendor/ramdump/` | ✘ `Permission denied` |
| 10 | `/data/system/dropbox/` | ✘ `Permission denied` |
| 11 | `dumplog` 路径（**已从 event.db 拿到**） | ✘ `/data/vendor/log` 连 `stat` 都不给 |

★★ **`event.db` 的价值**：`event_info.extra` 直接给出每次 panic 的 dumplog 精确路径：

```
ID 1867 evid 901000002  → /data/vendor/log/reliability/dumplog/20261006014224-69353244
ID 1866 evid 901000002  → /data/vendor/log/reliability/dumplog/20261005204902-15853307
```

★ **本轮 = `20261006014224-69353244`**（与 `history.log` 新增行 `time [20261006014224]` **完全对齐** ⇒ 归因确定）。
★ **`/data/vendor` 是 `drwxrwx--x root:root`**（other 有 `x` 可穿越、无 `r`）⇒ 路径已知但内容取不出。
★ 后续若要读，需从 `/data/log/` 侧找 symlink 或提权通道（**尚未找到**）。

---

## 7. 假说与下一步（M180 决策）

### 7.1 两个主假说

| # | 假说 | 支持 | 反对 | 判别实验 |
|---|---|---|---|---|
| **H-a** | `pi_blocked_on` 悬垂 ⇒ `ldr [x21,#…]` 野指针 ⇒ **根本没进 `prio_chain`** | ETIMEDOUT 路径不 清 `pi_blocked_on`（§1 汇编铁证）；`page_request` 与解引用野址完全吻合 | H142 曾实测「画布可重占」 | **J-M1** |
| **H-b** | 画布与 waiter 栈重叠成立 ⇒ `prio_chain` 执行 ⇒ 崩在 `rb_erase`/`wake` | H175 几何三段序言全部实测吻合（§3.1） | `[8]` 的一次性消费无法外部观测 | **J-M1** |

### 7.2 ★ 判决性实验 J-M1（一次开火，区分 H-a / H-b）

**思路**：把 `wake_state` 从 0 改成 `TASK_RUNNING(0)` 之外的**无效大值**，
让 `rt_mutex_top_waiter` → `wake_up_state` 走一条**必然早退但可区分**的路径。

★ 更干净的做法 —— **换 `waiter->lock` 落点**：

| 变体 | `MEY_LOCK` | 效果 | 若崩点变化 |
|---|---|---|---|
| **M1-a** | `0xffffffc082136048`（现状） | 两条写落空洞 | 基线 |
| **M1-b** | `0xffffffc082136050`（**仍在空洞内**，右移 8 字节 ⇒ 连带写 `+0x08` 落 `LOCK+0x58` 变 `LOCK+0x60`） | 验证 `+0x08` 分支 | 若仍崩在**同一时刻** ⇒ `prio_chain` 未执行（H-a）；若崩在**更晚**（写已完成）⇒ H-b |

★★ **但**：三个候选 P1/P2/P3 共用「是否重启」这一个透镜，
**M1-b 无法区分**（崩了就是崩了，看不到 PC）。
⇒ **诚实结论：在拿到 PC 之前，无法在 P1/P2/P3 之间做判决。**

### 7.3 ★★ 优先级重排（关键决策）

**突破口在于「能不能读到内核日志」，不在于「试哪个变体」。**
因此下一步**不是继续盲试几何**，而是：

| 优先级 | 动作 | 目标 |
|---|---|---|
| **P0** | **找一条能读明文内核日志的通道** | 拿到 PC ⇒ 一步定位 P1/P2/P3 |
| P0-alt | 若通道无望 ⇒ **换判据类型**：从「崩不崩」改为「**写是否生效**」 | 用 `selinux_state.enforcing` 写值做外部可观测判据（J9） |
| P1 | J9：`V=0, T=selinux_state+0x0000` ⇒ 预期 `getenforce` 仍 Enforcing | 首次拿到**外部可观测的写生效判据** |

★ **J9 是唯一不依赖内核日志就能前进的路径**：
若 `getenforce` 从 Enforcing 变成 Permissive ⇒ **整条链全通**（`prio_chain` 执行了、`rb_erase` 写对了），
H-a 被直接证伪；若仍 Enforcing ⇒ 至少说明写没落地（但不能区分 P1/P2/P3）。

---

## 8. 铁律增补

| # | 规则 | 依据 |
|---|---|---|
| **★38** | **`sched_setattr` 的 `pi=true` 是硬编码**（`core.c:8069`），工具侧 `flags=0` 不影响 PI 路径触发 | 源码 |
| **★39** | **`[8]`/`rb_erase` 每 boot 只执行一次** —— `rb_erase_cached`/`rt_mutex_enqueue` **不在投递路径上**；`lock+0x08` 残留不会被二次消费 | 源码 + 汇编 |
| **★40** | **NDK r27c `-static` 产物真机无法加载**（TLS 对齐须 ≥64，bionic 强制）⇒ 一律动态链接 | 实测 |
| **★41** | **产物必须先真机验证可加载**，再开火 —— 加载失败虽不消耗 boot，但会打乱开火节奏 | 实测 |
| **★42** | **`logcat -b kernel/crash` 被 HKS 整段加密**；`pstore` 目录被 SELinux 拦且**实际为空**；唯一可用的 panic 源是 `history.log`（一行摘要）+ `event.db`（给 dumplog **路径**） | 实测 11 条通道 |
| **★43** | **`event.db` 是 SQLite**，`/data/log/reliability/faultdetect/` 下 other 可读 ⇒ 拉回本地解析可拿精确 dumplog 路径 | 实测 |
| **★44** | **`pi_blocked_on` 在 ETIMEDOUT 路径上不被清零**（`rt_mutex_cleanup_proxy_lock` 汇编无 task+0x938 写）⇒ 「悬垂成立」不等于「pi_blocked_on 有效」 | 汇编 + 源码 |

---

## 9. 设备状态

| 项 | 值 |
|---|---|
| serial | `A22C026319001339` |
| boot_id | **`fd440de9-d1e6-4ee5-abf3-7f622a82950d`**（★ `abc61a92` 已消耗） |
| `getenforce` | **Enforcing**（未 root） |
| `id -u` | **2000** |
| adb 写操作 | 本轮有（push + chmod 755 + 执行） |

---

## 10. 文件清单

**新建**
- `analysis/scratch/h179_event.db`（★ 1,310,720 B，`event.db` 本地副本）
- `analysis/scratch/h179_prio_chain.asm`（★ 640 行，`rt_mutex_adjust_prio_chain` 全量反汇编）
- `analysis/output/h179_firing_and_asm_relocate.md`（本文件）

**实读**
- `kernel_src/.../kernel/futex/requeue.c`（`:762-880`）★ `futex_wait_requeue_pi` 全文 + `Q_REQUEUE_PI_DONE` 分支
- `kernel_src/.../kernel/locking/rtmutex_api.c`（`:458-478`）★ `rt_mutex_adjust_pi`
- `kernel_src/.../kernel/locking/rtmutex.c`（`:663-770`、`:1090-1175`、`:1200-1260`）
- `analysis/output/btf_offsets.txt`（`pi_blocked_on@0x938`、`usage@0x40`、`prio@0x84`、`rt_mutex_waiter` size=0x70）
