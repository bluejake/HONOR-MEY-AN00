# pselect / plant 落点校准 —— **无 root 版思路**

> 适用范围：**尚未拿到 uid0**（进程身份 = shell / Shizuku 派生）阶段。
> 目标：在**不依赖 root** 的前提下，(1) 判断"多轮不重启"是否可行；(2) 把 plant 的**真实落点**量准。
> 本文只给方法，不含任何设备特定数值。

---

## §1 先决问题：失败属于哪一类？（决定"多轮不重启"能否成立）

关键认知：**`panic_on_oops` 只覆盖四类失败中的一类**。先用一发**已知会失败**的探针把类别定出来。

| 类别 | 现象 | 能否用 sysctl 兜住 |
|---|---|---|
| oops（打死当前任务，内核继续） | 进程消失；内核日志有 `Oops` / `BUG:`；**设备活着** | ✅ `panic_on_oops=0` |
| panic | 内核主动崩，**有 panic 标记**（pstore / ramoops / pmsg） | ✅ 但要先关掉触发源（如 `panic_on_warn`） |
| hung task / lockup | `hung_task` / `softlockup` / `rcu stall` 日志，随后复位 | ⚠️ `hung_task_panic=0`、`softlockup_panic=0`、`hardlockup_panic=0`，但**看门狗仍可能赢** |
| **静默复位（无任何标记）** | 直接重启，**查不到任何记录** | ❌ **拦不住** —— secure world / PMIC 看门狗 |

**判据与动作**

```
# 1) 关掉所有能关的
echo 0 > /proc/sys/kernel/panic_on_oops     # 需要 root 才能写；没 root 就先只"读值"记录
cat  /proc/sys/kernel/panic_on_oops /proc/sys/kernel/panic_on_warn \
     /proc/sys/kernel/hung_task_panic /proc/sys/kernel/softlockup_panic \
     /proc/sys/kernel/hardlockup_panic
# 2) 打一发已知失败，然后看内核日志里"最后发生了什么"
logcat -b kernel | tail -200        # 见 §2：这是没有 root 时读内核日志的正路
```

- **有标记 → 可拦**：把对应开关关掉，多轮不重启就有基础。
- **无标记 → 红灯**：说明失败发生在**持锁上下文**（如 `pi_lock` / futex 锁内）或不可恢复路径，**任何 sysctl 都救不了**。这时不要指望"崩了能活"，必须走 §5 的**"让错落本身不致命"**。

---

## §2 没有 root 时，你能拿到的观测量

| 数据源 | 无 root 可用？ | 给什么 |
|---|---|---|
| `/proc/<tid>/syscall` | ✅ 读**自己进程的线程**即可（同进程 ptrace 判定） | `nr args… **sp** **pc**` ← **阻塞瞬间的真实内核栈指针** |
| `/proc/<tid>/wchan` | ✅ | 阻塞在哪个内核函数（**确认实际走了哪条路径**） |
| `logcat -b kernel` | ✅（shell 有 READ_LOGS） | `Oops/BUG:`、**fault address**、`hung_task`/`lockup` 记录 |
| `dmesg` | ⚠️ 用户版常被 `dmesg_restrict` 挡 | 同上，可能读不到 |
| `/proc/<tid>/stack` | ❌ 需 root | 内核栈回溯（有 root 后是首选） |
| `/sys/fs/pstore`、panic 落盘分区 | ❌ 需 root | panic 现场 |
| `/proc/<tid>/stat` 的 `kstkesp/kstkeip` | ⚠️ 新内核基本清零 | 基本没用 |

**核心结论**：**能免费拿到的关键量是 `/proc/<tid>/syscall` 里的 `sp`。** 用它替代"帧算术累加"。

读法（进程内、对**阻塞中的**线程）：

```sh
for t in /proc/self/task/*; do
  printf '%s ' "${t##*/}"
  cat "$t/wchan"; echo
  cat "$t/syscall"          # 形如：202 0x... 0x... ... <sp> <pc>
done
```

> 注意：被调度出的线程读 `syscall` 才是它的**阻塞点**；`running` 表示它此刻在跑（读到的是上一个 syscall 的残值）。

---

## §3 方法 A（替代帧算术）：**跨载体 sp 差分**

思路：同一处 plant，用**不同载体**各阻塞一次，分别读各自阻塞点的 `sp`。
两者相减 = **相对帧深**，**不需要知道内核栈顶，也不需要 root**。

**步骤**

1. 选一个"帧最干净、最可信"的载体做**基准**（例如阻塞路径里只有一个 `poll` 帧的那种）；
2. 对每个载体 `C ∈ {基准, pselect, sendmsg, mcast, …}`：
   - 让目标线程进入 `C` 并**稳定阻塞**；
   - 读 `/proc/<tid>/syscall` 的 `sp`，并用 `/proc/<tid>/wchan` 记下阻塞函数名；
   - 同时记下你**在用户态放进该载体的缓冲**的目标偏移（plant 的逻辑偏移）；
3. 计算 `Δsp(C, 基准) = sp_C − sp_基准` → 这是**实测**的帧深差；
4. 与"只对**确实在栈上的那几帧**"做的静态 prologue 量算对账：
   - 若 `Δsp` 与静态值差一截 → **差的那一截来自哪一帧**立刻暴露（不再需要"整链猜"）；
   - 用 `wchan` 双重确认走的是哪条 `do_futex` / `select` 路径（`futex_wait_requeue_pi` vs 其它）。

**产出**：一张表 `载体 → 阻塞点 sp → wchan → 相对深度 → 与静态模型之差`。
**价值**：把"反汇编模型 vs 实测对不上"这个矛盾**定位到具体某帧**，而不是继续在整链上加减。

---

## §4 方法 B：**让崩溃变成信息**（自描述 plant）

不要再只做"存活 / panic"二分。让**错落自己报出落点**：

1. plant 的值做成**自描述序列**：

   ```
   word_i = BASE + i * STRIDE        // STRIDE 取明显可辨识的步长
   ```

2. 一旦 oops，从**内核日志**里取 fault address：

   ```sh
   logcat -b kernel | grep -iE 'Unable to handle|Oops|BUG:' | tail -20
   ```

3. `X`（fault address）必然等于序列中的某个值：

   ```
   i = (X - BASE) / STRIDE      ⇒  "第 i 个 word 被当作指针解引用了"
   ```

4. 由 `i` 反推**落点偏移** = `i` 与 plant 起点的关系 → **一发解码**，不用二分。

**前提**：能读到 fault address。无 root 时正路是 `logcat -b kernel`；若它也拿不到，退化为 §5 的"非致命命中指示"。

---

## §5 方法 C：**错落安全设计 + 非致命命中指示**（uid0 之前最重要）

在拿到 uid0 之前，一次复位往往意味着**前置链条全部重跑** → 扫描成本翻几倍。所以宁可把"错落"设计成无害：

1. **plant 目标优先选"只被比较、不被解引用"的字段**（`prio` / `state` 这类小整数域）。
   错落最多导致一次错误决策，而不是野指针。`NEO11_PSELECT_PRIO` 的方向就是对的 —— 需要补的是**"错落那半边也要落在安全值域"**。
2. **只在必要窗口内 plant**，其余区域填"自洽且无害"的值，避免产生"半截指针"。
3. **命中指示换成非致命信号**（任何一条即可，优于"存活/panic"）：
   - 目标 syscall 的**返回值**变化；
   - **时序差**（阻塞时长/唤醒顺序）；
   - `/proc/<tid>/wchan` 变化（阻塞点被改写）；
   - 自己在 `logcat -b kernel` 放的一条**可辨识日志**（若通道允许）。

---

## §6 扫描循环的工程形态（设备无关）

```
1) 前置：读/关 panic 开关，并记录"哪一类失败不可拦"（§1）
2) 参数表驱动：每轮一组参数（深度 / 偏移 / 载体 / 填充值）
3) 打一发 → 探活（PC 侧 adb echo、或设备侧心跳文件）
4) 结果归档四类：
     存活且命中      → 记录参数，收工
     存活未命中      → 记录，继续
     oops/panic 有标记 → 记为"错落"，继续（这类可恢复）
     静默复位（无标记）→ 记为"看门狗" + **记录最后一组参数**（最有价值的数据点）
5) 输出 CSV；采用二分/梯度推进；每轮把"上一轮最后一组参数"写盘，防止复位丢失
```

**要点**：**把"复位"当成数据点**，而不是失败——它精确地告诉你"这组参数落在危险区"。

---

## §7 建议的执行优先级

1. **§1 失败分类**（一发已知失败 + 内核日志）→ 决定后面走"拦得住"还是"必须设计成不崩"；
2. **§3 跨载体 sp 差分**（无 root 可做）→ 用实测替换帧算术，矛盾定位到帧；
3. **§4 自描述 plant**（无 root 可做，靠 `logcat -b kernel`）→ 一发解码落点；
4. **§5 错落安全化**（并行做）→ 把复位概率压到最低；
5. **§6 扫描循环**（最后落地）→ 用它把剩余不确定度扫掉。

> 一句话总结：**用"阻塞点的 sp"量几何，用"fault address + 自描述值"读落点，用"只被比较不被解引用的字段 + 非致命指示"替代存活/panic 二分。** 这三件事都不需要 uid0。

---

## §8 命令速查

```sh
# 阻塞线程的观测（进程内）
for t in /proc/self/task/*; do echo "== ${t##*/}"; cat "$t/wchan"; echo; cat "$t/syscall"; done

# 内核日志（无 root 的正路）
logcat -b kernel | grep -iE 'Unable to handle|Oops|BUG:|hung_task|softlockup|rcu.*stall' | tail -50

# 失败分类相关开关（能读先读；能写才写）
for k in panic_on_oops panic_on_warn hung_task_panic softlockup_panic hardlockup_panic; do
  printf '%-20s = %s\n' "$k" "$(cat /proc/sys/kernel/$k 2>/dev/null || echo '(无)')"
done
```
