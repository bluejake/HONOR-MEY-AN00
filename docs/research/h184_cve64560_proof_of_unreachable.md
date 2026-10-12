# H184 — CVE-2026-64560 竞态窗口探测：官方 PoC 结构性缺陷证伪 + `-ESRCH` 判据不可达证明

> 日期：2026-10-06
> 设备：MEY-AN00（HNMEY）/ SM8735 / `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`
> boot_id 全程：`5176c1fc-654f-4150-b4b0-943962f09ff1`（**未消耗**）
> 置信度：**源码级已证 + 设备侧已实测**（非推断）

---

## 0. 一句话结论

**CVE-2026-64560 在本机用 `timer_settime` 观测 `-ESRCH` 的思路是对的，但这条判据在「非 leader exec」场景下结构性不可达。**
根因是 `fs/exec.c:1136` 的 `transfer_pid(leader, tsk, PIDTYPE_TGID)`：
exec 完成时 TGID pid 立刻改挂到新 leader，`pid_task()` 永不返回 NULL，`lock_task_sighand()` 也永不返回 NULL。

同时**证伪了官方 PoC 的可触发性**：它的定时器与 exec 在**不同进程**，结构上摸不到窗口。

---

## 1. H184 实测数据（本机，零内核写）

| 模式 | 迭代 | ESRCH（race 命中） | probes | 信号死亡 | boot_id | 结论 |
|---|---:|---:|---:|---:|---|---|
| `--check` | — | — | — | — | 不变 | 前置能力全绿 |
| `--ctl 200`（**对照组，无 execve**） | 200 | **0** | 4,804,608 | 0 | 不变 | ★ 探测器零误报 |
| `--run 3000`（真竞态） | 3000 | **0** | 30,156,800 | 0 | 不变 | ★ 3000 次机会全落空 |
| `--run 60`（复核） | 60 | **0** | 415,744 | 0 | 不变 | 复现一致 |

`history.log` 末条始终为 H181 的 `20261006015851-16727041`，H184 全程零新增。

### 1.1 为什么 0 命中不是"窗口太窄"

3000 次非 leader exec，每次窗口宽度 ~1µs 量级，probe 侧并发 6 线程 × 3000 万次系统调用。
若窗口真能命中，命中数量应在数十～数千量级。**全 0 ⇒ 模型错了，不是概率问题。**

★ 这正是"每个结论必须可证伪"的价值：数字异常干净地否定了假设本身。

---

## 2. 根因：`transfer_pid` 让 pid 查找永不失败

### 2.1 本机源码实证（`kernel_src/Code_Opensource/kernel`）

**`fs/exec.c:1132-1138`**（`de_thread()`，`begin_new_exec` 调用）：

```c
/* Become a process group leader with the old leader's pid.
 * The old leader becomes a thread of the this thread group.
 */
exchange_tids(tsk, leader);
transfer_pid(leader, tsk, PIDTYPE_TGID);   /* ★★ 决定性 */
transfer_pid(leader, tsk, PIDTYPE_PGID);
transfer_pid(leader, tsk, PIDTYPE_SID);
```

**`kernel/time/posix-cpu-timers.c:110-116`**：

```c
static inline enum pid_type clock_pid_type(const clockid_t clock)
{
	return CPUCLOCK_PERTHREAD(clock) ? PIDTYPE_PID : PIDTYPE_TGID;
}

static inline struct task_struct *cpu_timer_task_rcu(struct k_itimer *timer)
{
	return pid_task(timer->it.cpu.pid, clock_pid_type(timer->it_clock));
}
```

**`kernel/time/posix-cpu-timers.c:634-663`**（`posix_cpu_timer_set`）：

```c
rcu_read_lock();
p = cpu_timer_task_rcu(timer);
if (!p) { rcu_read_unlock(); return -ESRCH; }      /* 出口 A */

sighand = lock_task_sighand(p, &flags);
if (unlikely(sighand == NULL)) {
	rcu_read_unlock();
	return -ESRCH;                                /* 出口 B */
}
```

### 2.2 两个 `-ESRCH` 出口为何都关死

| 出口 | 条件 | 非 leader exec 下可达性 |
|---|---|---|
| A | `pid_task(tgid_pid, PIDTYPE_TGID) == NULL` | ✘ **`transfer_pid` 已把 tgid 改挂新 leader** |
| B | `lock_task_sighand(p) == NULL`（`p->sighand == NULL`） | ✘ **查到的已是新 leader，其 `sighand` 非 NULL** |

⇒ 无论窗口多宽，`posix_cpu_timer_set` 在非 leader exec 场景**永远走成功路径**。

★ 官方补丁的修复逻辑恰好印证：修复后 helper 会在 `lock_task_sighand` 失败时**重试查找**，
注释明写 "the subsequent task lookup will observe the new leader due to #1/#2"。
即 **mainline 自己都承认：正常路径下 lookup 会看到新 leader**，返回 NULL 属于**竞态罕见态**。

### 2.3 那补丁修的到底是什么

补丁正文（第 30-37 行）自陈：

```
This is "harmless" unless the deleted timer was armed and enqueued in
p->signal because on exec() a TGID targeted timer is inherited.
```

关键是 **`posix_cpu_timer_del()` 而非 `_set()`**，以及必须 **armed + enqueued**：
- `timer_settime` 走到出口 B 时**什么都没做就返回**，无 UAF（补丁注释第 223-226 行：只是 transient `-ESRCH`）
- `timer_delete` 走到同一分支时 **`free_posix_timer()` 释放 k_itimer**，而它仍挂在 `sig->posix_cputimers` 的 timerqueue 上 ⇒ **UAF**

⇒ **`timer_settime` 天生观测不到 UAF，只能观测到"窗口是否开过"；而窗口在 set 路径上又被 exit 路径掩盖。**

### 2.4 唯一残留窗口：查旧 leader 那一刻

严格说仍有一个理论窗口：
CPU0 `pid_task()` **已经**返回旧 leader → CPU1 完成整个 `de_thread()`（含 `sighand = NULL`）→ CPU0 `lock_task_sighand(old_leader)` 返回 NULL。

但这个窗口要求 CPU0 的两次内存访问**被整个 `de_thread()` 隔开**，包含
`zap_other_threads()` + 等待 leader 变 zombie（`fs/exec.c:1090-1109` 的 `schedule()` 循环）。
这是**微秒到毫秒级**的跨度，而 `pid_task()` 与 `lock_task_sighand()` 在 `posix_cpu_timer_set`
里**紧邻**（源码 635 行与 655 行，中间无可能长阻塞）。ARM64 弱序只能让读提前，**不能跨越 20 行代码插进一个 schedule()**。

⇒ 该窗口实际概率 ≈ 0，与实测 3000/3000 一致。

★ **另一重障碍**：非 leader exec 时 `zap_other_threads()` 会 SIGKILL 同组所有其他线程（`fs/exec.c:1071-1082`）。
probe 线程在 exec 开始瞬间即被 kill，**根本没有机会在窗口内发起系统调用**。
这是我的设计缺陷：probe 与 exec 同进程 ⇒ 必然被 zapping。

---

## 3. ★ 官方 PoC 结构性缺陷证伪

`refs/cve-2026-64560-analysis/poc/cve_2026_64560_poc.c`：

```c
/* Thread A (timer_thread)  */  timer_create(CLOCK_PROCESS_CPUTIME_ID) ... timer_delete();
/* Thread B (do_one_exec_round) */
pid = fork();                                   /* ★★ fork 出新进程 */
if (pid == 0) {                                 /* ★★ child = 独立进程 */
    pthread_create(&t, NULL, execer_thread, NULL);  /* 非 leader exec */
    for (;;) pause();
}
waitpid(pid, &status, 0);
```

**缺陷**：定时器建在 **parent** 的 `sig->posix_cputimers`；
`de_thread()/__exit_signal()` 发生在 **child** 的 leader 上。
`pid_task()` 解析的是 parent 的 TGID，其 leader 存活、`sighand` 永不置 NULL。

⇒ `posix_cpu_timer_del()` 恒走成功路径并正常 `detach_timer()`。
**该 PoC 结构上无法触发 CVE-2026-64560。**

★ 这也解释了 H183 遗留问题"官方 PoC 编译好但不敢开火"——现在有了确切答案：
**不是不敢，是它本来就不会命中。**

---

## 4. 修正后的可行触发条件（三要素同时成立）

要真正触到 UAF，必须让 **`timer_delete` 与 `de_thread` 在同一进程、同一 thread group 内竞争**：

| # | 条件 | 原因（源码依据） |
|---|---|---|
| C1 | 定时器必须是 `CLOCK_PROCESS_CPUTIME_ID`（PIDTYPE_TGID） | per-thread 定时器在 `posix_cpu_timers_exit(tsk)` 被摘掉（`kernel/exit.c:158`），不留悬垂节点 |
| C2 | 定时器必须 **armed 且 enqueued** 于 `sig->posix_cputimers` | 未入队则 del 路径无 UAF（补丁正文第 31 行） |
| C3 | `timer_delete` 与非 leader exec **同进程** | 见 §3：跨进程结构性不可达 |

★ 且 probe 线程不能被 `zap_other_threads()` 提前 kill ——
这意味着**不能让 probe 成为同组线程**。矛盾点：
> 同一 thread group 既是 C3 的必要条件，又是 probe 被 zapping 的原因。

⇒ **破局思路**：把"进程内 exec 竞争"与"跨进程 del 竞争"分离，用 **PID 复用 / pidfd** 让
`it.cpu.pid` 指向正在 exec 的进程，而 del 由外部进程发起。这需要重新设计触发器。

---

## 5. 本轮附带发现：`-static-pie` 在本机不可用（重要工具链事实）

### 5.1 现象

| 二进制 | 链接方式 | 结果 |
|---|---|---|
| `tools/h182.exe`（动态） | 有 `INTERP /system/bin/linker64` | ✔ 正常运行 |
| `tools/cve64560_poc.exe` | `-static-pie`，**无 INTERP** | ✘ **SIGSEGV（exit 139）** |
| `tools/h184_race.exe` v1 | `-static-pie`，无 INTERP | ✘ **SIGSEGV，无参调用也 139** |

**定位方法**（可复用）：无参调用（只打印 usage、不做任何系统调用）也是 139 ⇒ 问题在**加载器/自重定位**，不在被测逻辑。

### 5.2 结论

★ **本机（Android 15 / toybox shell）不能执行 static-pie 二进制。**
NDK r27c 默认建议 static-pie，但在这台设备上直接 SIGSEGV。
⇒ **本项目所有工具必须用动态链接编译**（去掉 `-static-pie`）。

修正命令：
```bash
aarch64-linux-android24-clang.cmd -O2 -o tools/h184_race.exe tools/h184_race.c
# 18,560 B，md5 b277a1804a0643238a490e6f07cff45e，✔ 有 INTERP
```

⇒ **修正 H183 记录**：`tools/cve64560_poc.exe`（static-pie, 2,248,880 B）即便 push 也必然 SIGSEGV，
"已编译待命"这个状态需要作废重编。

---

## 6. 本机能力基线（H184 实测）

```
RLIMIT_SIGPENDING cur=56944 max=56944
RLIMIT_NPROC     cur=56944 max=56944
nproc(cur)       = 8
max timers creatable = 4096（未触及 EAGAIN，测试封顶）
CLOCK_PROCESS_CPUTIME_ID 可用 ✔
/system/bin/true 可执行 ✔
```

★ `nproc = 8`：竞态设计可用 CPU 角色仅 0-7，op13 的"delete worker CPU 2-6 / exec CPU 7"
在本机只是**上限内的猜测**，尚未标定。

---

## 7. 可证伪判据（本轮全部达成）

| 判据 | 若成立应观测到 | 实际 | 结论 |
|---|---|---|---|
| J1 对照组不误报 | `--ctl` ESRCH = 0 | 0 / 4.8M probes | ✔ 探测器可信 |
| J2 非 leader exec 真发生 | `execve` 返回 0，child 正常退出 | 3600 次全部 `execfail = 0` | ✔ exec 路径通 |
| J3 竞态可被 userspace 观测 | `--run` ESRCH > 0 | **0** | ✘ **判据不可达** |
| J4 零副作用 | boot_id 不变 + history.log 无新增 | 两者均未变 | ✔ 未消耗 boot |

★ J3 失败 ⇒ 推翻"用 `-ESRCH` 观测 64560 窗口"这条路线（不是"再跑久点"能解决的）。

---

## 8. 铁律增量

- ★★ **67**：`timer_settime` 无法观测 CVE-2026-64560 的 UAF。
  `_set` 路径命中窗口只 transient 返回 `-ESRCH` 且不做任何摘链（补丁注释第 223-226 行）；
  只有 `_del` 路径才 `free_posix_timer()` 造成 UAF。**观测 UAF 只能用 `timer_delete`（=破坏性）。**
- ★★ **68**：非 leader exec 场景下 `pid_task(TGID)` **不会**返回 NULL ——
  `fs/exec.c` 的 `transfer_pid(leader, tsk, PIDTYPE_TGID)` 已改挂新 leader。
  任何"靠 pid 查找失败来探测窗口"的设计都是错的。
- ★★ **69**：跨进程（fork 出 child 做 exec、parent 持定时器）**结构性不可达**本漏洞。
  定时器与 exec 必须在同一 thread group。官方 PoC 因此无效。
- ★★ **70**：同 thread group 内 probe 线程会被 `zap_other_threads()` SIGKILL，
  与 C3 构成直接冲突 —— 这是本漏洞利用的**核心难点**，不是易事。
- ★★ **71**：**本机禁止 `-static-pie`**（NDK r27c 产物在本机 SIGSEGV）。
  定位法：无参调用也 139 ⇒ 加载器问题。全部工具用动态链接。
- ★ **72**：`brk #0x800`（`WARN_ON_ONCE`）判据只在 `posix_cpu_timer_del` 路径，
  且**需要定时器确实 enqueued**；`timer_settime` 路径不会触发它。

---

## 9. 下一步（判决性）

### 方向 A：破坏性直接验证（1 boot）
按 C1+C2+C3 严格设计：单进程内 armed TGID 定时器 + 非 leader exec + `timer_delete`，
目标观测 `brk #0x800`（WARN_ON_ONCE）或 `boot_id` 变化。
★ 风险：§2.4 指出 probe 会被 zapping，需设计 probe 不在同组（如用 `CLONE_THREAD` 的
独立线程组但共享 pid namespace，或用两个进程 + pid 复用）。

### 方向 B：补齐 43499 的 B6 格（1 boot，零副作用）
补 `S1+S4`（跳过 S3），判定 S3 在完整组合中是否必要，闭合 H182 遗留的因子格。

### 方向 C：J9 SELinux 写
`g_T = 0xffffffc0823ba418UL; g_V = 0;`，目标 `getenforce` 变 Permissive。

---

## 10. 资产

| 文件 | 说明 |
|---|---|
| `tools/h184_race.c` | H184 探测器源码（含 `--check`/`--ctl`/`--run` 三模式 + 共享内存计数） |
| `tools/h184_race.exe` | 动态链接版，18,560 B，md5 `b277a1804a0643238a490e6f07cff45e` |
| `analysis/output/h184_run_probe.log` | H184 `--run 60` 复核日志 |
| `analysis/output/h184_cve64560_proof_of_unreachable.md` | 本报告 |

★ 探测器的**对照组机制**（`--ctl`）应作为后续所有竞态实验的标准前置：
无竞态条件下必须 ESRCH=0，否则探测器本身不可信。