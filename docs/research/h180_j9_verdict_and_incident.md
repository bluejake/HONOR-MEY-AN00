# H180 —— J9 判决性实验「写是否生效」+ 一次误开火的事故记录

**日期**：2026-10-06
**boot 消耗**：`fd440de9` → **`fbea9a7f`**（★ **误开火，非计划**）
**前驱**：H179（首发射谱 + 全链汇编重定位）

---

## 0. 置信度声明

| 编号 | 结论 | 等级 |
|---|---|---|
| H180-C1 | **`selinux_state = 0xffffffc0823ba418` 权威**，`enforcing = +0x000`，**1 字节（bool）** | **汇编已证**（`sel_read_enforce` / `sel_write_enforce` 双证 + kallsyms 吻合） |
| H180-C2 | **H100/H101/H102 对 `0x23ba418` 的「证伪」是错的**（统计口径错误） | **汇编已证** |
| H180-C3 | **H177 §J9 的原设计是循环自证、零信息量** | **逻辑已证** |
| H180-C4 | J9 转置式设计：写 `*(enforcing)=0` ⇒ `getenforce` 应变 Permissive | **设计已定，待实测** |
| H180-C5 | `badmode` 误开火亦产生 `page_request`（`20261006015531`） | **已实测** |
| H180-C6 | `badmode`（`T=init_cred, V=0`）与 `verify`（`T/V` 落空洞）**崩法相同** | **已实测，★ 高度异常** |

---

## 1. ★★★ 本轮最大收获：**H100 的「证伪」是错的，`selinux_state` 地址一直是对的**

### 1.1 H100/H101/H102 的证伪链

```text
H100 三环对照表：
| `0x23ba418` | — | 7×LDRB + 0×LDR_W | — | ❌ **已证伪** | 需重定位 |
H101：「0x23ba418 已证伪，候选 0x23e2c20，962 候选待收敛」
```

**证伪依据 = 汇编统计「7×LDRB + 0×LDR_W」**（即「只看到 `ldrb`，没看到 `ldr w`」）。

### 1.2 本轮汇编实证（★ 推翻）

**读路径**（`getenforce` 的实现）：

```
sel_read_enforce@0xffffffc08080b8c8:
  0xffffffc08080b908: adrp  x2, #0xffffffc08163c000    ; "Enforcing\0" 常量
  0xffffffc08080b8f4: adrp  x2, #0xffffffc08163c000
  0xffffffc08080b8f8: add   x2, x2, #0x380
  0xffffffc08080b908: adrp  x8, #0xffffffc0823ba000    ; ★ 与 kallsyms 完全一致
  0xffffffc08080b90c: str   wzr, [sp, #0x10]
  0xffffffc08080b910: str   xzr, [sp, #8]
  0xffffffc08080b914: ldrb  w3, [x8, #0x418]           ; ★ enforcing = +0x000
  0xffffffc08080b918: bl    #0xffffffc080066494         ; snprintf(buf, 0xc, "Enforcing"/"Permissive", enforcing)
```

**写路径**（`setenforce` 的实现）：

```
sel_write_enforce@0xffffffc08080b968:
  0xffffffc08080ba30: adrp  x24, #0xffffffc0823ba000   ; ★ 同一基址
  0xffffffc08080ba34: ldrb  w22, [x24, #0x418]          ; 读旧值
  0xffffffc08080ba38: cmp   w23, #0                    ; 新值
  0xffffffc08080ba3c: cset  w21, ne
  0xffffffc08080ba40: cmp   w22, #0
  0xffffffc08080ba44: cset  w8, ne
  0xffffffc08080ba48: cmp   w21, w8
  0xffffffc08080ba4c: b.eq  #0xffffffc08080ba90        ; 相同则跳过
  0xffffffc08080ba9c: ldr   x0, [x25, #0x8d8]          ; securityfs_dirent
  0xffffffc08080baa0: ldr   w6, [x25, #0x8e0]          ; smp_rmb / 反作弊
  0xffffffc08080bac8: bl    #0xffffffc080870684          ; selinuxfs_notify
  0xffffffc08080bacc: strb  w25, [x24, #0x418]          ; ★ 写 enforcing
```

### 1.3 三环闭合

| 环 | 内容 | 结果 |
|---|---|---|
| ① 源码 | `struct selinux_state { bool enforcing; … }`（SELinux 树不在本项目源码里） | — |
| ② 汇编 | `adrp 0x823ba000` + `ldrb/strb [#0x418]` | `0xffffffc0823ba418` |
| ③ kallsyms | `ffffffc0823ba418 B selinux_state` | **完全一致 ✔** |
| ③ 邻符号 | `0x…410 avc_latest_notif_update.notif_lock`（−8）／`0x…498 selinux_init.__key`（+0x80） | 结构边界自洽 ✔ |

★★ **H100 的「7×LDRB+0×LDR_W」是把 `ldrb` 误当成「不是 `enforcing` 访问」——
`enforcing` 本来就是 `bool` 字段，本该用 `ldrb`。统计口径错了，结论错了。**

⇒ **`0xffffffc0823ba418` 是本机 `selinux_state` 的权威地址。**
⇒ **H101/H102 记的「候选 `0x23e2c20`」「962 候选待收敛」全部作废。**

---

## 2. ★★★ H177 §J9 的设计错误（循环自证）

H177 §6.5 原表：

| 判据 | 内容 |
|---|---|
| J9 | `[8]` 会自我撤销零值 \| `V=0, T=selinux_state+0x0000` ⇒ `getenforce` **仍为 Enforcing** |

★ **这是循环自证、零信息量**：
`enforcing` 的原值就是 1；把 0 写到 `T` 指向的地方，与 `enforcing` 无关；
⇒ **无论 `rb_erase` 有没有执行，`getenforce` 都必然仍是 Enforcing**。
H177 自己写「★ 这是 C7 的判决性实验」是**误判**。

### 2.1 正确设计：转置式（遵循 H177 §6.5 硬约束「禁 A3/B3」）

`rb_erase` 主写语义 = `*(node->rb_left) = node->__rb_parent_color`
⇒ 写地址 = `rb_left` = `T`，写值 = `parent_color` = `V`。

要写 `*(selinux_state.enforcing) = 0`：

| 量 | 取值 | 含义 |
|---|---|---|
| `T` | `0xffffffc0823ba418` | ★ **写地址** = `enforcing` |
| `V` | `0` | ★ **写值** = 0 ⇒ Permissive |
| 槽位 | `T`→`v8.d[0]`，`V`→`v7.d[0]` | H175 §3.3 映射表，**两槽独立** |
| `tree.prio` | 保持 `v8.d[1]` = 0 | ⇒ S3 prio 闸门（`0 != 139`）照常生效 ✔ |

### 2.2 8 字节写安全性（`enforcing` 只有 1 字节！）

`rb_erase` 写 8 字节 ⇒ 覆盖 `[0x…418, 0x…41f)`：

| 方向 | 邻符号 | 距离 | 判定 |
|---|---|---|---|
| 下界 | `avc_latest_notif_update.notif_lock` @ `0x…410` | **−8** | 不碰 ✔ |
| 上界 | `selinux_state` 自身 size = **0x80**（`0x…418`–`0x…498`） | — | 全在结构内 ✔ |
| 结构外 | `selinux_init.__key` @ `0x…498` | **+0x80** | 不碰 ✔ |

⇒ ★ **8 字节写安全。**

### 2.3 ★ 连带写落点的副作用（必须记账）

`V = 0` ⇒ `V & ~3 = 0` ⇒ `parent == NULL` ⇒ 走
`rbtree_augmented.h:203  WRITE_ONCE(root->rb_node, new)`

⇒ ★★ **连带写变成 `*(lock+0x08) = T`**，即把 `lock->waiters.rb_root.rb_node`
写成 `0xffffffc0823ba418`（一个野值）。

| 项 | 评估 |
|---|---|
| 是否溢出空洞 | ❌ 不溢出（`lock+0x08` 在 `LOCK=0x…6048` 的 0x38 空洞内） |
| 是否有消费者 | ★ `rb_insert_color_cached`（`:817ac`）随即重建树，`str x25,[x24,#0x10]` + `rb_insert_color_cached` |
| 残留风险 | 中 —— 本发只执行一次，`lock` 是死区空洞 ⇒ **残留无消费者** |

★ 但这带来一个**意外的判决价值**：
若崩点从「`prio_chain` 早期」移动到「`rb_insert_color_cached` 之后」，
就说明主写/连带写**都执行完了** ⇒ `prio_chain` 确实跑过。

---

## 3. ★★★ 事故记录：一次**计划外**的 boot 消耗

### 3.1 发生了什么

我按 ★41 铁律做「先验加载再开火」，执行：

```bash
adb shell "/data/local/tmp/h180.exe badmode"
```

意图：用非法 mode 只走 `main` 参数解析，验证二进制可加载（不触发 futex 拓扑）。
**但 `main` 的 `else` 分支（`badmode` 落入）会设置 `T/V` 后继续走完整流程** ——
`m`map` + 三次 `FUTEX_LOCK_PI` + 建 W/O 线程 + `CMP_REQUEUE_PI` + 投递 + `sched_setattr`。

⇒ ★★★ **二进制加载验证的语义与「开火」完全等价。**

### 3.2 实际发射谱

```
=== h175_staged uid=2000 mode=badmode ===
[badmode] T=0xffffffc082190790 V=0x0（写 *(0xffffffc082190790) = 0x0）
[M] topology: W holds f_chain, waits f_target(O); O holds f_target, waits f_chain(W)
  [W] LOCK_PI(f_chain) rc=0 errno=0
  [O] LOCK_PI(f_target) rc=0 errno=0
[M] W_tid=14889 触发真环...
[M] CMP_REQUEUE_PI rc=-1 errno=35(Resource deadlock would occur)
[M] ==> EDEADLK 真环成立
  [W] *** RETURNED *** rc=-1 errno=110(Connection timed out) 悬垂成立
[M] W done=1 ret=-110
  ← stdout 截断（exit 255）
```

`boot_id`：`fd440de9` → **`fbea9a7f`**
`history.log`：1213 → **1214** 行，新增 `time [20261006015531-80225989] reason [page_request]`

### 3.3 ★★★ 这个「废发」提供了**判决性数据点**

| 维度 | `verify` 发（01:42:24） | `badmode` 发（01:55:31） | 对比 |
|---|---|---|---|
| `T` | `LOCK+0x20`（`.data..percpu` **空洞**） | **`0xffffffc082190790`（`init_cred`，真实内核数据！）** | ★ 落点天差地别 |
| `V` | `LOCK+0x28` | `0` | ★ `V&~3` 从 `≠0` 变 **`0`** |
| 连带写路径 | `__rb_change_child` 的 `+0x08` 分支 | ★ **`parent==NULL` ⇒ `root->rb_node` 分支** | ★ **分支完全不同** |
| panic reason | `page_request` | `page_request` | **完全相同** |

★★ **判决性推论**：

> `T` 落在**真实内核数据**（`init_cred`）vs 落在**死区空洞**，
> `V` 的连带写路径**完全不同**（`+0x08` 分支 vs `parent==NULL` 分支），
> **但两次的 panic reason 完全一致（`page_request`）**。

⇒ **强烈指向：崩溃发生在 `rb_erase` / `__rb_change_child` 之前的某条固定路径。**

⇒ ★★ **若崩溃真在 `rb_erase` 内**：
- `verify` 发：`V=LOCK+0x28` ⇒ `V&~3≠0` ⇒ 读 `*(LOCK+0x30)`；
- `badmode` 发：`V=0` ⇒ `V&~3=0` ⇒ **不读**，直接写 `root->rb_node`。
- 两发读/写的地址集合**完全不同** ⇒ **panic 地址应不同** ⇒ reason 却是同一个。

⇒ ★★★ **合理解释：崩在 `pi_blocked_on` 解引用（H179 §4 的 P1 候选），
而非 `rb_erase`（P2/P3）。**

★★ **这是本项目第一次拿到能区分 P1/P2/P3 的差分数据点。**

| 若 | 则 |
|---|---|
| 崩点读写的地址集合随 `T/V` 变 | P2/P3（在 `rb_erase` / `wake` 内） |
| **崩点与 `T/V` 无关** | ★★ **P1（`pi_blocked_on` 解引用）** |

实测结果 ⇒ **P1**。

### 3.4 与 H179 §4.1 的「悬垂地址」假说吻合

```c
/* rtmutex_api.c:466-467  rt_mutex_adjust_pi */
waiter = task->pi_blocked_on;
if (!waiter || rt_waiter_node_equal(...)) return;
next_lock = waiter->lock;
```

```asm
0x…8146c: ldr  x21, [x19, #0x938]   ; waiter = task->pi_blocked_on（悬垂）
0x…814c8: ldr  w9,  [x21, #0x18]   ; ★ 若 x21 不可读 ⇒ page_request
0x…814ec: ldr  x21, [x21, #0x58]   ; ★ next_lock = waiter->lock
```

★ W 线程的 `&rt_waiter = SP0 − 0x210`（**用户态 SP0**），
而 S4 是在 syscall 内、`sp = KSP` ⇒ **`pi_blocked_on` 指向的地址在当前上下文不是有效映射**。

★★ 这就是 `page_request`，且**与 `T`/`V` 无关**（因为崩在这两条 `ldr` 之前，
`T`/`V` 根本没被读到）。

---

## 4. 铁律增补

| # | 规则 | 依据 |
|---|---|---|
| **★45** | ★★ **`main` 的 `else` 分支不是「只解析参数」，它会走完整开火流程**。任何 `h175_staged <mode>` 调用**都是一次真实开火**。加载验证必须用**独立小工具**（只做 `dlopen` 式检查）或 `--dryrun` 显式开关。 | 实测（消耗 `fd440de9`） |
| **★46** | **`selinux_state = 0xffffffc0823ba418`**，`enforcing` = `+0x000`，`bool`（1 字节，`ldrb`/`strb`）。H100/H101/H102 的「证伪」与「962 候选」**全部作废**。 | 汇编双证 + kallsyms |
| **★47** | **判据设计铁律**：凡「写 0 到某处 ⇒ 某标志不变」型判据都是**循环自证**。判决性判据必须让**被观测量的值发生可观测变化**（`V=地址, T=0` 转置式，而非 `V=0, T=地址`）。 | 逻辑 |
| **★48** | **差分发可分离崩溃路径**：改变 `T`/`V` 使读写地址集合完全不同，若 panic reason 不变 ⇒ 崩溃在这些值被读之前。 | H180 §3.3 实测 |

---

## 5. 下一步（M181）

### 5.1 P1 假说已高度可信，需要一次判决性验证

| 假说 | 内容 | 判决实验 |
|---|---|---|
| **P1** | 崩在 `0x…814c8 ldr w9,[x21,#0x18]` —— `pi_blocked_on` 悬垂 | ★ **让 `pi_blocked_on` 变 NULL** ⇒ `cbnz` 不成立 ⇒ 直接 `0x…81478` 早退 ⇒ **必不崩** |
| P2/P3 | 崩在 `rb_erase` / `wake_up_state` | 与 §3.3 差分矛盾，已弱化 |

★ **M181 判决实验（M181-J1）**：
> **不投递画布**（`sig_hits` 应为 0），只跑 W 线程的 S1–S4。
> - 若**不崩** ⇒ `pi_blocked_on` 真的是 NULL（画布投递是让它变野指针的必要条件）⇒ **P1 确认**
> - 若**崩** ⇒ `pi_blocked_on` 与画布无关，崩溃在更早处 ⇒ 需重新定位

⇒ 这是**零风险变体**（不改任何内核数据，只少一次 `tgkill`），且判据独立（崩/不崩）。

### 5.2 若 P1 确认，问题变为「如何让 `pi_blocked_on` 指向**可读**的伪造 waiter」

| 方向 | 内容 | 风险 |
|---|---|---|
| **A** | 把 `waiter` 放到**内核栈**上（需要 `SP0` 绝对地址 ⇒ **U5 未解**） | 阻塞 |
| **B** | 让 `pi_blocked_on` 指向**已知的可读内核地址**（如 `.data..percpu` 空洞）| ★ **无需 U5！** |
| C | 让 `pi_blocked_on` 指向 `init_task` 内部某处（`0xffffffc08217e280` 已知可读） | 可行 |

★ **方向 B/C 是本项目的重大解锁点**：
`pi_blocked_on` 只需要「可读 + 字段布局对」，
**不需要在栈上**。把 `waiter->lock` 指向空洞、把 `tree` 字段指向别的空洞 ⇒ 全部字段都可读可控。

⇒ ★★ **若 B/C 成立，则整条链无需 U5 即可推进 stage8（写 `cred`）。**

---

## 6. 设备状态

| 项 | 值 |
|---|---|
| serial | `A22C026319001339` |
| boot_id | **`fbea9a7f-d126-409d-919f-782022374447`** |
| `getenforce` | **Enforcing**（未 root） |
| `id -u` | **2000** |
| adb 写操作 | 有（push + chmod 755 + 执行） |
| 工具 | `/data/local/tmp/h180.exe` md5 `b1986b8fc7d653bf5772330ef9a38348`（13,584 B，动态链接） |

---

## 7. 文件清单

**修改**
- `tools/h175_staged.c`（★ 新增 `j9` 模式，含 `selinux_state` 转置式写 + 连带写副作用记账）
- `tools/h175.exe` → 重新编译为 13,584 B（动态链接）

**新建**
- `analysis/scratch/h180_j9.asm`（921 行，llvm-objdump 全量）
- `analysis/output/h180_j9_verdict_and_incident.md`（本文件）
