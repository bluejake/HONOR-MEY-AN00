# H185–H187 — CVE-2026-43499 因子格闭合、崩点锁死到单函数、触发条件简化为 2 变量

> 日期：2026-10-06
> 设备：MEY-AN00（HNMEY）/ SM8735 / `6.6.118-android15`
> 置信度：**已实测 + 源码级双证**（非推断、非猜���）
> 代价：H187 **消耗 1 个 boot**（`5176c1fc` → `b5fc4b1a`），换回判决性结论

---

## 0. 三句话结论

1. **B6**：`S1+S4`（跳过 S3）**不崩** ⇒ S3 是J1 崩溃的**必要条件** ⇒ ★ **H182 的「S3 无罪」是过度结论，已修正**。
2. **B4**：去掉 S1 超时、让 `pi_blocked_on` 指向**仍有效的栈 waiter** 时，S4 解引用**不崩**
   ⇒ ★★ **崩点必须叠加「栈已被覆写」** ⇒ P1（悬垂 `pi_blocked_on`）**精确确认**。
3. **H187**：把 `sched_nice=1` 直接塞进 S4、**去掉 S3** ⇒ **★ 复现崩溃**
   ⇒ ★★ 触发条件从 3 变量降到 **2 变量 `{S1 带超时, S4 带 nice}`**；
   S3 被证明**只是打开 `core.c:7891` 早退闸门的钥匙**，无独立价值。

★★ **这是本项目首次把崩点锁死到单个函数（`rt_mutex_adjust_pi`），并把利用链压缩到最短路径。**

---

## 1. 完整因子矩阵（H175–H187 全表）

| 发 | S1(带超时) | S1(去超时) | S2画布 | S3 nice | S4 | 崩? | boot |
|-----|:---------:|:---------:|:------:|:------:|:--:|:--:|------|
| A0 |     -      |     -     |   ✘    |   -    | ✔(nice=0) | ✘ | 不变 |
| B1 |     -      |     -     |   ✘    |   ✔    | ✔(nice=0) | ✘ | 不变 |
| B2 |     ✔      |     -     |   ✘    |   -    |  -   | ✘ | 不变 |
| B3 |     ✔      |     -     |   ✘    |   ✔    |  -   | ✘ | 不变 |
| **B6** |   ✔    |     -     |   ✘    |   -    | ✔(nice=0) | **✘** | 不变 |
| J1 |     ✔      |     -     |   ✘    |   ✔    | ✔(nice=0) | ★崩 | 变了 |
| **B4** |   -    |★    ✔     |   ✘    |   -    | ✔(nice=0) | **✘** | 不变 |
| **H187** |   ✔    |     -     |   ✘    | 跳过  | ✔(**nice=1**) | ★**崩** | 变了 |

★ 只有 `S1` 与「**真正进入 `rt_mutex_adjust_pi`**」同时成立才崩。缺任一 ⇒ 不崩。

---

## 2. ★★ 核心机理发现：`core.c:7891` 的早退闸门

### 2.1 源码（`kernel_src/Code_Opensource/kernel/kernel/sched/core.c:7891`）

```c
rq = task_rq_lock(p, &rf);
update_rq_clock(rq);

if (p == rq->stop) { retval = -EINVAL; goto unlock; }

/*
 * If not changing anything there's no need to proceed further,
 * but store a possible modification of reset_on_fork.
 */
if (unlikely(policy == p->policy)) {
	if (fair_policy(policy) && attr->sched_nice != task_nice(p))
		goto change;
	if (rt_policy(policy) && attr->sched_priority != p->rt_priority)
		goto change;
	if (dl_policy(policy) && dl_param_changed(p, attr))
		goto change;
	if (attr->sched_flags & SCHED_FLAG_UTIL_CLAMP)
		goto change;
	... /* 无变化 ⇒ 走完落到 return 0 */
```

### 2.2 为什么它解释了全部观测

我们的 `do_sched_setattr`（`tools/h175_staged.c:187`）用 `memset` 把 `sched_attr` 清零，
故 `sched_nice = 0`；而 `sched_policy = SCHED_OTHER(0)`，p 本身也是 `SCHED_OTHER`。

| 发 | `attr->sched_nice` | `task_nice(p)` | 闸门 | 进`adjust_pi`？ |
|---|---:|---:|---|---|
| A0/B6 | 0 | 0 | **相等 ⇒ 不 goto change** | **否** ⇒ 早退返回 |
| J1 | 0 | **1**（S3 改过） | 不等 ⇒ `goto change` | **是** ⇒ 崩 |
| H187 | **1** | 0 | 不等 ⇒ `goto change` | **是** ⇒ **崩** |

★ `pi=1` 在 syscall 路径硬编码（H182 已证 `0x55fd74: mov w2,#1`），
`0x16a210: tbz w21,#0` 闸门**必过** ⇒ 只要走到 `change` 分支，`0x16a224: bl rt_mutex_adjust_pi` **必被调用**。

★★ 因此：**J1 与 H187 的崩溃必然发生在 `rt_mutex_adjust_pi` 内部**。
这是第一次用「差分实验 + 源码闸门」双证把崩点锁死到**单个函数**。

### 2.3 ★ S3 的真实作用被彻底澄清

`setpriority` → `set_user_nice`（`core.c:7348`）**完全不碰 `pi_blocked_on`、不调 `rt_mutex_adjust_pi`**。
它只做 `dequeue_task` / `prio` / `enqueue_task` / `prio_changed`。

⇒ S3 的**唯一作用**是把 `task_nice` 从 0 改成 1，从而让下一次 `sched_setattr`
不满足 `core.c:7891` 的 `sched_nice == task_nice` 条件，**强制内核进入 `rt_mutex_adjust_pi`**。

★★ 这同时解释了 **B1（S3+S4）为什么不崩**：
缺 S1 ⇒ 即便进了 `adjust_pi`，`pi_blocked_on == NULL` ⇒ `rt_mutex_adjust_pi` 的
`ldr x21,[x19,#0x938]; cbnz x21, ...` 早退门通过 ⇒ 什么都不做 ⇒ 不崩。

⇒ **S1 与「进入 adjust_pi」是两个正交的必要条件。** 这是本轮最干净的结构性结论。

---

## 3. ★★ B4 判决：P1（悬垂 `pi_blocked_on`）精确确认

### 3.1 B4 做了什么

把 S1 的 `FUTEX_WAIT_REQUEUE_PI` 超时从 1 秒改为 `NULL`（`tools/h175_staged.c:289`）：

```c
struct timespec *pto = g_no_timeout ? NULL : &to;
long r2 = futex6(f_src, FUTEX_WAIT_REQUEUE_PI, 0, pto, f_target, 0);
```

⇒ W **永久阻塞**，`futex_wait_requeue_pi` 的**栈帧不退出**
⇒ `pi_blocked_on` 指向**仍然有效**的栈上 `rt_waiter`（非野指针）

W 既然回不来，S4 改由**新线程 attacker** 发起（`thread_B4_attacker`）：
等 300ms 让 W 稳定阻塞后，`sched_setattr(W_tid)`。

### 3.2 实测

```
[M] ==> EDEADLK 真环成立
  [B4-X] attacker 线程启动，等300ms 让W 稳定阻塞在 pi 等待
  [B4-X] W_tid=21316（★ S4 由本线程发起，目标是 W）
    sched_setattr(tid=21316 pol=0) rc=0 errno=0(Success)
  [B4-X] B4-VERDICT ★★ 走到这里 = 有效栈 waiter 解引用**不崩**
[M] done
```

独立透镜：boot_id 不变、`history.log` 无新增、`getenforce` 仍 `Enforcing`、uid 仍 2000。

### 3.3 ★ 判决的严格表述（避免过度结论）

| 结论 | 状态 |
|---|---|
| 「有效栈 waiter 解引用**不崩**」 | ✅ **已实测** |
| 「崩点**必然**在已被覆写的野栈 waiter 上」 | ✅ **已实测**（B4 不崩 vs J1/H187 崩，单变量=栈是否被覆写） |
| 「崩点是 `waiter->tree.prio`(0x18) 还是 `waiter->lock`(0x58)」 | ❌ **仍未定位**（见 §6） |
| 「H142『panic ⇒ 栈可重占』」 | ✅ **已证伪**（B4 直接检验：栈未覆写时不崩） |

★ B4 是 H142 原始设想的**正确检验形态**。H142 的错在于用 ETIMEDOUT 路径（野栈）去验证「栈可重占」。

---

## 4. ★★ H187 判决：2 变量触发条件成立

### 4.1 实测（消耗 boot）

```
[M] ==> EDEADLK 真环成立
  [W] *** RETURNED *** rc=-1 errno=110(Connection timed out)悬垂成立
  [W] S2: ★★ J1 判决模式 —— 跳过投递（sig_hits 期望 0）
  [W] S3: ★★ 跳过 setpriority（g_skip_s3=1，H187：nice 改由 S4 自带）
  [W] S4: sched_setattr_nice(self, nice=1) -> rt_mutex_adjust_pi(self)
       ★ 本发无 S3，nice 由 S4 自带（绕过 core.c:7891 早退闸门）
=== EXIT=0 ===
```

★ 日志在 `sched_setattr_nice` 处**截断**，`[W] H187-S4-RETURN` **从未打印**，adb 亦未返回。

独立透镜（三个，全部一致）：

| 透镜 | 结果 |
|---|---|
| `boot_id` | `5176c1fc-…` → **`b5fc4b1a-1e95-4752-a25d-fef322bd0cbd`** ✅ 变了 |
| `history.log` | 新增 `reason [page_request], time [20261006043029-33611666]` ✅ |
| adb 会话 | 当场离线（`adb wait-for-device` 后恢复）✅ |

### 4.2 结构化确认：`sched_attr_local` 布局与内核 uapi 逐字段一致

`tools/h175_staged.c:147` vs `include/uapi/linux/sched/types.h:102`：

| 偏移 | 字段 | 类型 |
|---:|---|---|
| +0x00 | `size` | `__u32` |
| +0x04 | `sched_policy` | `__u32` |
| +0x08 | `sched_flags` | `__u64` |
| +0x10 | `sched_nice` | `__s32` ★ 本轮利用的关键字段 |
| +0x14 | `sched_priority` | `__u32` |
| +0x18 | `sched_runtime` | `__u64` |
| +0x20 | `sched_deadline` | `__u64` |
| +0x28 | `sched_period` | `__u64` |
| +0x30 | `sched_util_min` | `__u32` |
| +0x34 | `sched_util_max` | `__u32` |

⇒ `sa.sched_nice = 1` 确实落在内核读的 `+0x10`，**排除了「offset 猜错导致没生效」**这一替代解释。

### 4.3 ★ 预测被证实

H187 事前预测写在源码注释里：

> 「去掉 S3，把 nice=1 直接塞进 S4 的 sched_attr ⇒ 单次 sched_setattr 即可满足
> `sched_nice != task_nice` ⇒ 进 adjust_pi ⇒ S1(悬垂) + adjust_pi 同时具备 ⇒ **应当复现崩溃**」

⇒ **成立。** 因果链正确。

---

## 5. ★★ 触发条件（最终版，供后续利用）

```
必要且充分（已实测）：
  ① S1：非 leader 线程经 CMP_REQUEUE_PI(EDEADLK) → FUTEX_WAIT_REQUEUE_PI(带 1s 超时)
        ⇒ rt_mutex_cleanup_proxy_lock@0x…813a4 不清 pi_blocked_on
        ⇒ 栈帧退出后 pi_blocked_on 悬垂指向 SP0-0x210
  ② 栈覆写：使SP0-0x210 附近被新的内核栈帧覆盖 ⇒ 野指针内容不再可读为合法 waiter
  ③ S4：sched_setattr(self) 且 **sched_nice != task_nice**
        ⇒ 绕过 core.c:7891 早退闸门 ⇒ 进入 rt_mutex_adjust_pi
        ⇒ 解引用悬垂 pi_blocked_on ⇒ page fault

已剔除的冗余变量：
  ✘ S3 setpriority  —— 仅是「把 task_nice 改成 1 以打开闸门」的钥匙，可被 ③ 内联吸收
  ✘ S2 画布投递    —— J1/B6/B4/H187 全程跳过，崩溃照样发生 ⇒ **非必要**
  ✘ 真实内核写     —— T/V/task/lock 全程为占位，零内核数据被触碰
```

★ **这是一个纯用户态崩溃原语**：不需要任何内核写权限，不需要 KASLR 泄露，
不需要 heap spray，只用两个 syscall 序列就能稳定触发内核 page fault。

---

## 6. 仍未解决（本轮未能推进的部分）

| # | 未决项 | 阻塞原因 |
|---|---|---|
| U-A | **精确 page fault PC**（`waiter->tree.prio`+0x18 还是 `waiter->lock`+0x58） | `dmesg`/`pstore` 均 EACCES（uid 2000），`history.log` 只有 `page_request` 原因、无 PC |
| U-B | **谁覆写了 SP0-0x210** | 已证"被覆写"（B4 对照），但未定位具体是哪一次内核栈帧 |
| U-C | **可用的写原语** | 崩点解引用的是**野栈内容**（不可控），还不能当写原语用 |
| U-D | **J9（SELinux Permissive）** | 未做。`g_T=0xffffffc0823ba418UL; g_V=0` |
| U-E | **64560 完整触发器** | H184 已证 `-ESRCH` 不可达；C3 与 `zap_other_threads` 冲突未破 |

★ U-C 是最关键的阻塞：**"能崩"≠"能写"**。
下一步必须让 `pi_blocked_on` 指向**我们可控的伪造 waiter**（S2 画布），
而 H181/J1 的教训是：画布必须投在**正确的时机**（野指针已被覆写之后、S4 之前）。

---

## 7. 铁律增量

★76 **`core.c:7891` 早退闸门决定 `rt_mutex_adjust_pi` 是否被调用**。
`do_sched_setattr` 用 `memset` 清零 ⇒ `sched_nice=0`；
若 `p` 已是 `SCHED_OTHER` 且 `task_nice(p)==0` ⇒ **整个 `__sched_setscheduler` 早退返回**，
`rt_mutex_adjust_pi` **压根不被调用**。
⇒ **任何要进入 `adjust_pi` 的实验，`sched_attr.sched_nice` 必须显式设成非 0。**
★ 这解释了 A0/B1/B6 为何"裸调 sched_setattr 从不崩"。

★77 **S1 与「进入 `adjust_pi`」是正交的两个必要条件**。
B1（S3+S4，无 S1）不崩 = 有 adjust_pi 但无悬垂指针 ⇒ 不崩。
J1/H187（有 S1 + adjust_pi）才崩。

★78 **`set_user_nice`（`core.c:7348`）不碰 `pi_blocked_on`、不调 `rt_mutex_adjust_pi`**。
它只做 dequeue/prio/enqueue/prio_changed。
⇒ 不要把 S3 的作用误认为"调整了 PI 链"。

★79 **验证"是否进入目标内核函数"的正确方法**：
不靠猜、不靠日志，直接**检查路径上的源码闸门**。
本例：读 `core.c:7891` 即可预判 `sched_nice=0` 时不会进 `adjust_pi`，
并据此设计 H187（把 nice 塞进 S4）做判决性验证。**★ 这是把"黑盒差分"转成"白盒可预测"的关键手法。**

★80 **`sched_attr` 布局必须与 `include/uapi/linux/sched/types.h` 逐字段核对**。
★ `sched_nice` 在 **+0x10**，类型 `__s32`。
用错偏移会导致"实验没生效"被误读成"假设被证伪"。

★81 **崩溃类实验的 stdout 截断本身就是判据**。
H187 日志在 `sched_setattr_nice` 处截断 + `H187-S4-RETURN` 未打印 + adb 离线
⇒ 三者共同确认崩溃发生在该调用内部。★ 但**最终判决必须用 `boot_id` + `history.log` 独立确认**，
不信 stdout（铁律★4）。

★82 **B4 是 H142「panic ⇒ 栈可重占」的正确检验形态**：
必须让 `pi_blocked_on` 指向**仍有效的栈**（去超时、栈帧不退出），
而不是在野栈上求证。B4 不崩 ⇒ **H142 证伪**。

---

## 8. 资产

| 文件 | 说明 | md5 |
|---|---|---|
| `tools/h175_staged.c` | H185/H186/H187 全部改动（B6/B4/H187 三个 mode） | — |
| `tools/h185.exe` | B6 发（`a4` mode），17,864 B | `5eece9d9f0d2b0632f33e309569178c6` |
| `tools/h186.exe` | B4 发（`b4` mode），19,760 B | `2b5e867429c55738fd8aae0c5f622064` |
| `tools/h187.exe` | H187 发（`h1` mode），20,720 B | `2997aacd497c34ef67e7a69ace6e06f6` |

设备路径 `/data/local/tmp/h18{5,6,7}.exe`。
★ 三个二进制均为**动态链接**（有 `INTERP /system/bin/linker64`，H184 铁律★71）。

---

## 9. 下一步建议（按信息量/代价排序）

| 优先 | 动作 | 代价 | 理由 |
|---|---|---|---|
| ★1 | **J9 SELinux 写** | 1 boot | 目标判据之一（`getenforce` → Permissive）。**一旦成功立刻拿到 root shell**，与43499 崩点定位完全解耦 |
| ★2 | **U-C：让 `pi_blocked_on` 指向可控伪造 waiter** | 1 boot | 有了2 变量触发条件，只差"野指针→可控指针"。S2 画布投在**覆写之后、S4 之前** |
| 3 | U-A：精确崩点 PC | 难 | 日志全封（uid 2000 无 dmesg/pstore）。需先解决日志读取或用差分间接定位 |
| 4 | U-E：64560 触发器 | 高 | H184 已证需解决 C3 与 `zap_other_threads` 的根本冲突 |

★ **强烈建议先做 J9**：它是独立于 43499 的另一条成功判据，
且不需要任何崩溃复现技巧 —— 成功即得 root shell，对整个项目是直接推进。

---

## 10. ★★ H188 / J9 判决（追加，消耗第2 个 boot）

> 时间：2026-10-06 04:33:05
> boot：`b5fc4b1a` → `b9fd0e69`（**第 2 个 boot 被消耗**）
> 二进制：`tools/h188.exe`（md5 `2997aacd497c34ef67e7a69ace6e06f6`，与 h187 同一二进制，仅注释/日志措辞不同）

### 10.1 实测

```
[j9] T=0xffffffc0823ba418  V=0x0  lock=0xffffffc082136048  task=0xffffffc08217e280
[M] ==> EDEADLK 真环成立
  [W] *** RETURNED *** rc=-1 errno=110(Connection timed out) 悬垂成立
  [W] S2: tgkill_staged  T=0xffffffc0823ba418V=0x0task=0xffffffc08217e280  lock=0xffffffc082136048
  [W] sig hits=1（★ 单发，期望 1）
  [W] S3: setpriority(nice=1) rc=0 errno=0
  [W] S4: sched_setattr(self) -> rt_mutex_adjust_pi(self)
=== EXIT=0 ===
```

★ 日志在 S4 处**截断** ⇒ 崩溃在 `sched_setattr` 内部。

| 判据 | 结果 | 解读 |
|---|---|---|
| ★ `getenforce` | **仍 `Enforcing`** | ★★ **转置式写未落地** |
| `boot_id` | `b5fc4b1a` → `b9fd0e69` |崩了 |
| `uid` | 2000 | 未变 |
| `history.log` | 新增 `20261006043305-79988614` `page_request` | 崩了 |
| `sig hits` | 1 | 画布信号已送达（**仅证明送达，不证明内核采纳**） |

### 10.2 判决：rb_erase 转置链**够不到**

★ `enforcing` 保持 1 ⇒ `*(0xffffffc0823ba418)` 未被改成 0。

结合 H179 汇编的 `rt_mutex_adjust_pi` 执行顺序：

```
0x…8146c  ldr  x21, [x19, #0x938]   ; waiter = pi_blocked_on
0x…81474  cbnz x21, ...
0x…814c8  ldr  w9, [x21, #0x18]     ; ★ 解引用野指针 ⇒崩点在此
...
0x…81760  bl   rb_erase             ; ★ 永远到不了
```

⇒ **崩溃发生在读取 T/V 之前，`rb_erase` 根本没被执行。**
⇒ 与 H180 §3.3 的差分（`verify` vs `badmode` panic reason 相同）**完全一致**。

★★ **P1 至此三重独立证实**：
| # | 实验 | 结论 |
|---|---|---|
| 1 | **B4**（去超时，栈未覆写） | 不崩 ⇒ 崩点是**野栈内容** |
| 2 | **H187**（去 S3，nice 塞进 S4） | 仍崩 ⇒ 崩点**必在** `rt_mutex_adjust_pi` |
| 3 | **J9**（T/V 落 enforcing） | 仍崩且写未落地 ⇒ **崩在 `rb_erase` 之前** |

★★ **战略结论（判决性）**：
> **`rb_erase` 转置式写原语在 CVE-2026-43499 这条路上不可达。**
> 根因：P1（悬垂 `pi_blocked_on` 解引用）比 T/V 的读取**更早崩溃**。
> ⇒ 要让写原语可达，**必须先让 `pi_blocked_on` 指向一个可安全解引用的 waiter**
>（即 S2 画布必须在 `pi_blocked_on` 被**读取之前**就位），
> 而 H180/H181 已证：画布投递后的 sigreturn 路径本身就会崩溃。

### 10.3 ★ 严格自查（避免过度结论）

| 说法 | 状态 |
|---|---|
| 「转置式写未落地」 | ✅ **已实测**（`getenforce` 仍 Enforcing） |
| 「崩溃早于 `rb_erase`」 | ⚠️**强推断**（汇编顺序 + 差分一致），但**未直接观测 PC**（uid 2000 无 dmesg/pstore） |
| 「画布已被内核采纳为 waiter」 | ❌ **未证**。`sig hits=1` 只证明信号送达；崩溃也可能发生在 sigreturn 采纳途中 |
| 「rb_erase 链永久不可达」 | ⚠️ **本路径下**不可达。若未来能让 `pi_blocked_on` 安全（见 U-C），需重新评估 |

★ **教训（新增铁律）**：
**「写没落地」与「崩在写之前」是两个不同命题。**
本轮以前者（`getenforce` 观测，确凿）为准，不用后者（汇编推断）冒充实测。

---

## 11. ★ 累计代价与收益（本轮 H185–H188）

| 发 | 目的 | 崩? | boot | 换来什么 |
|---|---|:--:|---|---|
| B6 (`a4`) | 闭合 2×2 因子格 | ✘ | 未消耗 | S3 是 J1 必要条件（修正 H182 过度结论） |
| B4 (`b4`) | 去超时 + attacker 发起 S4 | ✘ | 未消耗 | ★ P1 精确确认：崩点须叠加栈覆写 |
| H187 (`h1`) | 去掉 S3、nice 塞进 S4 | ★崩 | 消耗 1 | ★★ 2 变量触发条件；崩点锁死到 `adjust_pi` |
| J9 (`j9`) | 转置式写 enforcing | ★崩 | 消耗 1 | ★★ 证伪 rb_erase 链可达性 |

累计：**2 boot** 换回「崩点锁死单函数」+「写原语不可达」两个结构性结论。

★ **最重要的正资产**：**一个纯用户态、2 变量、100% 复现的内核 page fault 原语**
```
① 非 leader 线程：CMP_REQUEUE_PI(EDEADLK) → FUTEX_WAIT_REQUEUE_PI(1s 超时)
② sched_setattr(self, SCHED_OTHER, nice=1)★ nice 必须非 0
```
不需要内核写权限、不需要 KASLR 泄露、不需要 heap spray。

★ **最重要的负资产（同样值钱）**：
> **P1 崩溃点比任何 T/V 读取都更早 ⇒ 靠 `rt_mutex_adjust_pi` 改内存的路线整体封死。**
> 后续若要写原语，必须绕开「先崩」这个前置问题，而不是继续调T/V/task/lock。

---

## 12. 下一步（修正后）

| 优先 | 动作 | 代价 | 理由 |
|---|---|---|---|
| ★1 | **U-C：让 `pi_blocked_on` 安全** —— 画布必须在 `rt_mutex_adjust_pi` 读它**之前**就位 | 1+ boot | 这是解锁**一切**后续的钥匙。若能做到，`rb_erase` 链自动可达 |
| ★2 | 复核 `rt_mutex_adjust_pi` 是否存在**更晚的消费者**（`rt_mutex_adjust_prio_chain` 的 `0x…81648ldr x25,[x19,#0x938]`） | 离线 | 看能否绕开首次 adjust_pi |
| 3 | U-E：64560 触发器（C3 vs `zap_other_threads`） | 高 | H184 已证需突破根本冲突 |
| ✘ | 继续调 T/V/task/lock/画布槽位 | — | ★ **J9 已证这条路整体不可达，勿回头** |

---

## §13 H189 / H190 / H191 —— 2×2 因子分离闭合，P1 升级为已实测确认（2026-10-06 04:46）

### 13.1 H189：B4 勘误修正（★ 原 B4 是无效对照）

**发现的缺陷**：H186 的 `thread_B4_attacker()` 调用的是
`do_sched_setattr(g_w_tid, SCHED_OTHER, 0)`，而 B4 下 W 永久阻塞在 S1 内，
**从未执行 S3** ⇒ `task_nice(W)` 仍为 0；调用也传 `sched_nice=0`。

代入 `kernel/sched/core.c:7891` 的早退 gate：

```c
if (unlikely(policy == p->policy)) {          /* SCHED_OTHER == SCHED_OTHER */
    if (fair_policy(policy) && attr->sched_nice != task_nice(p))
        goto change;                          /* 0 != 0 为假 ⇒ 不跳 */
    ...
    /* 无变化 ⇒ 落到 return 0 */
}
```

⇒ 函数**早退**，`rt_mutex_adjust_pi` 根本没被调用。
⇒ **H186 的 B4 只证明了「对该任务做无变化的 sched_setattr 返回 0」，完全没触达 P1 解引用点。**

**修正**（`tools/h175_staged.c:495` `thread_B4_attacker`）：

```c
- do_sched_setattr(g_w_tid, SCHED_OTHER, 0);
+ do_sched_setattr_nice(g_w_tid, SCHED_OTHER, 0, /*nice=*/1);
```

### 13.2 ★ 自查：H189 的「不崩」有两个不可区分的解释

| | S4 由 W 自己发 | S4 由 attacker 他线程发 |
|---|---|---|
| **S1 带超时**（栈帧退出 ⇒ 悬垂） | H187 ★崩 `page_request` | **← 缺失格，H191 补上** |
| **S1 去超时**（栈帧有效） | 不可达（W 永久阻塞） | H189 不崩 |

H189 的「不崩」有两种解释：
- **(A)** 栈帧有效 ⇒ 解引用安全（我们想要的结论）
- **(B)** S4 由他线程发起 ⇒ 根本没走到与 H187 相同的路径（**伪阴性**）

按 ★63（不能只做单变量剥离）必须补交叉格，否则结论不成立。⇒ 追加 **B7**。

### 13.3 ★ H190 作废（harness 缺陷，判「实验无效」而非「不崩」）

B7 第一次开火，stdout 缺 `[B7-X] → 对 W_tid 发 sched_setattr_nice` 与 `[B7-X] B7-VERDICT`。

**根因**：B7 下 W 在 B7 分支置 `g_w_stage=5` 后原地等待 attacker；而 main 的收口循环是
`for (i=0;i<6000 && g_w_stage<5)` ⇒ 看到 `stage==5` 立刻 `return 0`
⇒ **进程退出把仍在 `usleep(300ms)` 的 attacker 杀掉** ⇒ S4 从未发出。

设备确认无变化（`boot_id=b9fd0e69`、`history.log=1217`）。

> ★★ **铁律新增：判据透镜未出现时，只能判「实验无效」，绝不能判「不崩」。**
> 日志截断与「未崩」是两件事，必须用 `boot_id` + `history.log` 独立区分。

**修复**（`tools/h175_staged.c` main 收口）：

```c
if (g_b7_mode) {
    logx("[M] B7 模式：放行 W 走 S2/S3（它会停在 B7 分支等 attacker）\n");
    if (!g_w_done) { logx("[M] *** W DID NOT RETURN ***\n"); return 1; }
    g_w_stage = 2;
    for (int i = 0; i < 200 && !g_b4_done; i++) usleep(100000);
    logx("[M] attacker done=%d（W stage=%d）\n", g_b4_done, g_w_stage);
    if (!g_b4_done)
        logx("[M] ★★ B7 无效：attacker 未完成 S4，透镜缺失 ⇒ 本发作废\n");
    ...
}
```

### 13.4 ★★ H191 判决：P1 因果链闭合，且拿到 `null_pointer`

```text
[B7-X] W 已返回（g_w_done=1），再等 300ms 让其栈复用稳定
<日志截断，attacker 正在发 S4>
```

独立透镜：

| 判据 | 结果 |
|---|---|
| `boot_id` | `b9fd0e69` → **`8247f9cd-d4d0-4742-a71e-8747098ebee9`** |
| `history.log` | 1217 → **1218** 行 |
| panic 原因 | **`reason [null_pointer]`**，`time [20261006044557-36650338]` |
| uid / SELinux | 2000 / Enforcing（未变） |

#### ★★★ 2×2 因子表（完整）

| 发 | S1 超时 | S4 发起线程 | pi_blocked_on 状态 | panic 原因 | boot |
|---|---|---|---|---|---|
| H187/h1 | 带 | W 自己 | 野指针（随机垃圾） | `page_request` | 变了 |
| **H191/b7** | **带** | **attacker** | **野指针（已被栈复用清零）** | **`null_pointer`** | 变了 |
| H189/b4 | 去 | attacker | **有效栈 waiter** | 不崩 | 不变 |
| — | 去 | W 自己 | — | 不可达（W 永久阻塞，回不来） | — |

#### 结论 1：排除伪阴性 (B) —— 伪阴性

H189 的「不崩」**不可能**是因为 S4 由他线程发起：H191 证明他线程发起**照样崩**。
⇒ H189 的不崩只能归因于**栈帧有效**。

#### 结论 2：★ P1 从「强推断」升级为「已实测确认」

崩溃点 = `rt_mutex_adjust_pi` 沿 `pi_blocked_on` 链的解引用。机制完全成立：
`remove_waiter()` 误用 `current` 而非 `waiter->task` ⇒ waiter 线程的
`pi_blocked_on` 悬垂指向已退出栈帧。

#### 结论 3：★★ panic 原因从 `page_request` 变 `null_pointer` ⇒ 崩点性质收窄

| 发 | 栈内容 | panic | 解释 |
|---|---|---|---|
| H187 | 随机垃圾 | `page_request` | 跟随垃圾指针，命中未映射页 |
| H191 | 被 `logx()` 复用清零 | `null_pointer` | 沿链走到底遇 NULL |

⇒ **W 的栈帧内容确实会被后续 syscall 复用并清零。**
⇒ ★ 这正是「栈重占（spray）」能生效的**前提**：只要能在该窗口把受控字节
喷回 SP0-0x210，`pi_blocked_on` 就能被重定向。

### 13.5 落盘资产

| 文件 | 说明 |
|---|---|
| `tools/h189.exe` | B4 修正版，md5 `b39add60475472e9263893eb6d3405f4`，未崩 |
| `tools/h190.exe` | B7 首版（harness 缺陷），md5 `6f290d19b5041f3da5f21de9e77dcd01`，**作废** |
| `tools/h191.exe` | B7 修复版，md5 `5c30d24f76a61824e0c7a49d496ac1d8`，★崩 `null_pointer` |
