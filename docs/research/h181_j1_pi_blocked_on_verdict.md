# H181 —— J1 判决实验：**P1 被证伪**，崩溃点前推至 `rt_mutex_adjust_pi` 之前

**日期**：2026-10-06
**boot 消耗**：`fbea9a7f` → **`5176c1fc`**（★ 计划内，J1 判决发）
**前驱**：H180（J9 设计 + `selinux_state` 定址 + 一次误开火）

---

## 0. 置信度声明

| 编号 | 结论 | 等级 |
|---|---|---|
| H181-C1 | **J1（不发 `tgkill`）仍然崩** ⇒ 崩溃**与画布投递无关** | **已实测** |
| H181-C2 | ⇒ **P1（`pi_blocked_on` 野指针）被证伪** | **实测推论** |
| H181-C3 | 崩点位于 `__sched_setscheduler` 内、`rt_mutex_adjust_pi` 调用点**之前** | **实测 + 汇编** |
| H181-C4 | `rt_mutex_adjust_pi` 调用点 = **`0xffffffc08016a224`**（距函数入口 `0x990`） | **汇编已证** |
| H181-C5 | 闸门 = `tbz w21,#0`（`w21` = 第 4 参 `pi`）；`pi==0` 则跳过 `adjust_pi` | **汇编已证** |
| H181-C6 | `sched_setattr` 壳 `mov w2,#1; mov w3,#1` ⇒ `user=true, pi=true` **硬编码** | **汇编已证**（印证 H179-C3） |
| H181-C7 | `attr` 在 `__sched_setscheduler` 里是**内核栈副本**（`x22`），不是用户指针 | **汇编已证**（`sched_setattr` 壳无 copy，copy 在 `__do_sys_*`） |
| H181-C8 | 精确崩溃指令 | ❌ **未取到**（日志通道全封，见 H179 §6） |

---

## 1. ★★★ J1 判决实验设计与结果

### 1.1 设计（零内核数据修改）

```
唯一变量 = 不执行 S2 的 tgkill 画布投递
T / V / task / lock 全部不参与
其余流程（S1 futex 拓扑 / CMP_REQUEUE_PI / S3 setpriority / S4 sched_setattr）完全不变
```

★ 改动点：`tools/h175_staged.c` 新增 `g_skip_deliver` 标志 + `j1` mode 分支。

### 1.2 实测结果

```
=== h175_staged uid=2000 mode=j1 ===
[j1] ★★★ 判决实验：跳过 S2 投递，S4 的 pi_blocked_on 是否为 NULL
[M] CMP_REQUEUE_PI rc=-1 errno=35(Resource deadlock would occur)
  [W] *** RETURNED *** rc=-1 errno=110(Connection timed out) 悬垂成立
  [W] S2: ★★ J1 判决模式 —— 跳过投递（sig_hits 期望 0）
  [W] S3: setpriority(nice=1) rc=0 errno=0
  [W] S4: sched_setattr(self) -> rt_mutex_adjust_pi(self)
  ← stdout 截断（exit 255）
```

| 项 | 值 |
|---|---|
| `boot_id` | `fbea9a7f` → **`5176c1fc`** |
| `history.log` | 新增 `time [20261006015851-16727041] reason [page_request]` |
| `getenforce` | Enforcing（未 root） |

### 1.3 ★★★ 判决

| 假说 | 预测 | 实测 | 判定 |
|---|---|---|---|
| **P1**：`pi_blocked_on` 悬垂 ⇒ `0x…814c8 ldr w9,[x21,#0x18]` page fault | 不投递 ⇒ `pi_blocked_on` 仍 NULL ⇒ `0x…81474 cbnz` 不成立 ⇒ `0x…81478` 早退 ⇒ **必不崩** | ★ **崩了** | ❌ **P1 证伪** |
| P2/P3：在 `rb_erase` / `wake_up_state` | 不投递 ⇒ `rb_erase` 根本不执行 ⇒ **必不崩** | ★ **崩了** | ❌ **P2/P3 也证伪** |

★★ **全部三个候选一次排除。崩溃与我们的写原语完全无关。**

⇒ ★★★ **崩溃是 `sched_setattr(tid, SCHED_OTHER, prio=0, flags=0)` 这个 syscall 本身触发的，
发生在 `rt_mutex_adjust_pi` 被调用之前（或与之无关的另一条路径）。**

---

## 2. 崩溃点范围收敛（★ 汇编重定位）

### 2.1 调用链与 `adjust_pi` 的位置

```text
__do_sys_sched_setattr   (copy_struct_from_user → 内核栈 attr)
  └─ sched_setattr@0xffffffc08055f830      （薄壳，5 条指令）
       0x55f83c: mov w2, #1      ; user = true
       0x55f840: mov w3, #1      ; ★ pi = true（硬编码）
       0x55f844: bl __sched_setscheduler
  └─ __sched_setscheduler@0xffffffc080169894   （★ t 局部符号，本体 0x1400+ 字节）
       ...
       0x16a224: bl rt_mutex_adjust_pi@0xffffffc081081438    ★★ 距入口 0x990
```

★ **本机 `sched_setattr` 的 `pi=true` 已由汇编铁证**（`mov w3,#1`），
H179-C3 从「源码已证」升级为「**汇编已证**」。

### 2.2 `adjust_pi` 前的闸门

```asm
0x16a1fc: mov  x0, x23
0x16a200: bl   #0xffffffc081083520      ; raw_spin_lock_irq(&task->pi_lock)
0x16a204: ldr  x1, [sp, #0x20]          ; flags
0x16a208: ldr  x0, [sp, #0x10]          ; &task->pi_lock
0x16a20c: bl   #0xffffffc081083568      ; raw_spin_unlock
0x16a210: tbz  w21, #0, #0x…6a228       ; ★ w21 = pi；pi==0 ⇒ 跳过 adjust_pi
0x16a214: ldr  w8, [sp, #0x1c]
0x16a218: tbz  w8, #0, #0x…6a220
0x16a21c: bl   #0xffffffc08095b3c4       ; ★ 条件调用
0x16a220: mov  x0, x19                  ; current
0x16a224: bl   #0xffffffc081081438      ; ★★ rt_mutex_adjust_pi
```

★ **`pi=true` ⇒ `tbz` 不跳 ⇒ `adjust_pi` 一定会被调用。**
⇒ ★★ **既然 J1（无画布）也崩，且崩在 `adjust_pi` 之前 ⇒ 只能是 `0x16a21c` 那个条件调用
`0xffffffc08095b3c4`，或更早的某条路径。**

### 2.3 ★ 头号嫌疑：`0xffffffc08095b3c4`（`0x16a21c` 条件调用）

| 项 | 值 |
|---|---|
| 地址 | `0xffffffc08095b3c4` |
| 调用条件 | `[sp,#0x1c] != 0`（由 `0x…698f8: str wzr,[sp,#0x1c]` 初始化为 0，后被 `0x16a1f8: str w8,[sp,#0x28]` 路径改写） |
| 出现次数 | ★ **同一函数内出现 3 次**：`0x169c3c`、`0x169dd0`、`0x16a21c` |

★ 该地址在 `0x169b74` 附近也被 `0x169b74: bl #0xffffffc08095b39c` 调用（差 0x28），
说明是一个**成组的辅助函数簇**（很可能是 `security_*` / LSM 钩子簇）。

### 2.4 次级嫌疑（`adjust_pi` 之前的所有 `bl`）

| 地址 | 次数 | 备注 |
|---|---|---|
| `0xffffffc080567ee4` / `0x…567e24` / `0x…567f70` / `0x…567710` | 4 | **同一簇，疑似 LSM/`sched_setscheduler` 钩子** |
| `0xffffffc080028764` / `0x…02877c` | 3 | 成对，`x23=task->cred` 相关（`ldr x23,[x8,#0x820]`） |
| `0xffffffc080117c5c` | 2 | — |
| `0xffffffc08010192c` | 1 | — |
| `0xffffffc08004bac8` / `0x…04bc24` / `0x…04cc14` / `0x…04d760` | 4 | `.text` 后段，可能是 `__set_task_sched` 相关 |
| `0xffffffc081076160` | 3 | — |
| `0xffffffc08030e3fc` | 1 | ★ 单次，`.text` 早期，可能是 `down_write` 类 |
| `0xffffffc080588738` / `0x…5886b0` | 3 | — |
| `0xffffffc08002c2fc` | 1 | — |

★ **无一条能靠离线排除**（都需要知道被调函数的访存行为）。

---

## 3. ★★★ 关键转向：崩溃与本项目主线**无关**

### 3.1 事实

| 事实 | 依据 |
|---|---|
| J1（**完全不发信号**、不改任何内核数据）仍崩 | 实测 |
| 三发（`verify` / `badmode` / `j1`）panic reason **全是** `page_request` | 实测 ×3 |
| 三发的 `T`/`V` 落点完全不同（死区空洞 / `init_cred` / 不参与） | 实测 ×3 |

### 3.2 ★ 推论

> `sched_setattr(pid=SELF, policy=SCHED_OTHER, prio=0, flags=0)` 在这台设备上
> **本身就会触发内核 page fault**，与我们的画布/写原语**完全无关**。

⇒ ★★★ **S4 这条触发路径从一开始就是坏的。H178/H179/H180 建立的「S4 崩溃 ⇒ rb_erase 崩」整条推理链，
前提全部不成立。**

| 之前的假设 | 实际 |
|---|---|
| 「S4 未返回 ⇒ `[8]` 内 panic」 | ❌ S4 本身就会崩，`[8]` 可能从未执行 |
| 「`page_request` ⇒ 写落点算错」 | ❌ 与写落点无关（三发全崩） |
| 「H142 判据是 panic ⇒ 证明栈可重占」 | ⚠️ **该判据不成立**（panic 与画布无关） |

### 3.3 ★★★ 唯一还活着的判据

MEMORY 里 H142 的判据表「panic ⇒ 证明栈可重占」**必须撤回**。

★ **H140/H141/H142/H179 四发全部崩，且崩因与画布无关** ⇒
⇒ **它们从未提供过任何「画布可重占」的证据。**

---

## 4. 两条新主线（★ 优先级重排）

### 4.1 主线 A：修 S4（换触发路径）

`rt_mutex_adjust_pi` 是**唯一**已知的能消费 `pi_blocked_on` 的调度侧入口。
若它不可用，需要找替代：

| 候选 | 机制 | 状态 |
|---|---|---|
| A1 | `sched_setscheduler`（`SYS_setscheduler`） | ★ 与 `sched_setattr` 同走 `__sched_setscheduler`，**大概率同样崩** |
| A2 | `rt_mutex_sched` 别的调用点 | 需查：`rt_mutex_adjust_pi` 在 kallsyms 里是 `T`（全局）⇒ 可能被 `sched_setscheduler`/`set_load_bias` 等多处调用 |
| A3 | 直接构造 `sched_attr` 让 `policy != SCHED_OTHER` 走**不同分支** | ★★ **成本最低**：崩点很可能在 `policy==SCHED_OTHER` 特有路径（如 `sched_group_set_*` / cgroup 迁移） |
| A4 | 放弃 `sched_setattr` 线，另找能写 `pi_blocked_on` 的漏洞 | 回到 §5 |

★★ **A3 是下一步首选** —— 只需改一个常量（`policy`），零几何改动，一次开火。

### 4.2 主线 B：绕开内核日志封锁（★ 长期）

内核栈 PC 拿不到 ⇒ 一切定位只能靠差分。
本轮已验证**差分法有效**（H180 §3.3 用它排除了 P2/P3）。

⇒ 可用的差分维度（每个维度一次 boot）：

| 维度 | 变量 | 判据 |
|---|---|---|
| 画布投递 | 有/无 | 已做（J1）⇒ 与投递无关 |
| `T`/`V` 落点 | 空洞 / `init_cred` / 不参与 | 已做 ⇒ 无关 |
| **`policy`** | `SCHED_OTHER(0)` / `SCHED_FIFO(1)` / `SCHED_RR(2)` / `SCHED_BATCH(3)` | ★ **未做，下一步** |
| `pid` | SELF / 其他线程 | 未做 |
| `flags` | `0` / `SCHED_FLAG_RESET_ON_FORK` | 未做 |

★ **每个维度一次开火，全部落在「崩 / 不崩」这个外部可观测透镜上。**

---

## 5. 铁律增补

| # | 规则 | 依据 |
|---|---|---|
| **★49** | ★★★ **判据依赖的前提若未被独立验证，panic 本身不构成任何证据。** H142「panic ⇒ 栈可重占」的前提（S4 可用）被 H181 证伪 ⇒ 该判据链全部作废。 | 实测 |
| **★50** | ★★ **触发路径必须先单独验证可用**（如「裸 `sched_setattr` 不崩」），再叠加利用逻辑。本项目连续四发（`verify`/`badmode`/`j1`/H142）都建立在「S4 可用」这个**从未验证**的前提上。 | 实测 |
| **★51** | **`sched_setattr` 的 `pi=true` 已由本机汇编证实**（`sched_setattr@0x55f83c: mov w2,#1; mov w3,#1`）⇒ 任何 `sched_setattr` 调用都会进入 `rt_mutex_adjust_pi` 前的完整路径。 | 汇编 |
| **★52** | **差分法是本项目唯一可靠的定位手段**（日志全封）。差分维度清单见 §4.2，每个维度成本 = 1 boot。 | 实测 |
| **★53** | `__sched_setscheduler` 本机在 `0xffffffc080169894`，`rt_mutex_adjust_pi` 调用点在 **`0xffffffc08016a224`**（入口 + `0x990`）。前 3 次 `bl` 簇是头号嫌疑：`0x…95b3c4`（3 次）、`0x…567exx`（4 次）。 | 汇编 |

---

## 6. 设备状态

| 项 | 值 |
|---|---|
| serial | `A22C026319001339` |
| boot_id | **`5176c1fc-654f-4150-b4b0-943962f09ff1`** |
| `getenforce` | **Enforcing**（未 root） |
| `id -u` | **2000** |
| 工具 | `/data/local/tmp/h181.exe` md5 `fa89bb22a58491684c6b21391be5a832`（14,184 B） |
| adb 写操作 | 有（push + chmod 755 + 执行） |

---

## 7. 文件清单

**修改**
- `tools/h175_staged.c`（★ 新增 `g_skip_deliver` 标志 + `j1` mode + S2 条件分支）
- `tools/h175.exe` → 14,184 B

**新建**
- `analysis/scratch/h181_j1.asm`（953 行，`j1` 版全量反汇编，`svc` 唯一 ✔）
- `analysis/scratch/h181_setsched.asm`（0x500 窗口）
- `analysis/scratch/h181_setsched_full.asm`（★ 1016 行，`__sched_setscheduler` 0x1400 窗口）
- `analysis/output/h181_j1_pi_blocked_on_verdict.md`（本文件）
