# MEP-AN00 临时 Root 攻关 — 状态交接（压缩版）

> 设备：Honor MEP-AN00（MagicOS 10.0.0.175 / C00E170R404P2 / Android 16）>   
> 内核：`6.6.118-android15-8-gf17133276a57-abogki518694926-4k`，构建 `#1 SMP PREEMPT Sun May 31 12:01:53 UTC 2026`>   
> BL 锁定 · SELinux Enforcing · **未 root** · 全程未写任何分区>   
> 目标：CVE-2026-43499（rt_mutex stack-UAF）提权

---

## 1. 文件与真伪（已核对）

| 文件                | 结论                                                                                                                                                            |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `boot.img` 内嵌内核   | **就是本机内核**：版本串+构建时间戳与 `/proc/version` 逐字一致；内核体在 **偏移 0x1000（4096 页对齐，不是 header_size=1584）**，逐字节 == `kernel.raw` == `poc/honor_kernel.bin`（sha256 `e8ce5dbf…`） |
| `update_sd_base/` | `MEP-LGRP1-CHN 10.0.0.175`，与设备 `10.0.0.175 / 10DLDLD175C00E170` 对齐                                                                                            |
| `xbl_config.elf`  | 仅 SoC 级（`qcom,pakala` = SM8750，与设备 `ro.board.platform=sun` 同芯片）；**无机型/版本，对 exploit 参数零贡献**                                                                    |

**参数来源分工**：符号表(116,605)/BTF/IKCONFIG/**载体偏移**/锚点偏移 → 全部来自 `boot.img` 的内核；tracefs 事件 ID、zoneinfo、KASLR base → 运行时；`P0_PHYS_*` → **已废弃不用**（见 §3）。

---

## 2. 已解决（不要再回头验证）

### 2.1 KASLR 泄漏 ✅（本会话最大成果）

tracefs：`sched_blocked_reason` 的 `caller` 字段在**二进制** `trace_pipe_raw` 里不受 `kptr_restrict` 遮蔽。

- `SLIDE_TRACEFS_ROOT = /sys/kernel/tracing`（shell 可读**可写**）
- `SLIDE_TRACEFS_EVENT_ID = 109`
- 锚点 `worker_thread+0x17c` = **0x185864**；次锚点 `rcu_gp_fqs_loop+0x144` = **0x28b38**
- 跨 8+ boot 全部成功、**设备零复位**；链随后 `task = base + 0x217e280` 是真实运行时地址
- 参考：`xrzcc/s26-m1q-ghostlock-selinux` 的 `polygraphene/src/slide_tracefs.c`

### 2.2 载体（原死结）✅ 已实测

`do_ipv6_setsockopt` 两个分支的深栈拷贝，**无缝拼齐全部 14 个 waiter word**（waiter 基准 = entry−0x1b0）：

| opt                            | 拷贝                                 | 落点          | 覆盖 waiter       | buffer 内偏移  |
| ------------------------------ | ---------------------------------- | ----------- | --------------- | ----------- |
| 46 (`MCAST_JOIN_SOURCE_GROUP`) | 264B → `sp+0x40`                   | entry−0x290 | words **0..4**  | `0xe0 + 8k` |
| 48 (`MCAST_MSFILTER`)          | 260B → `sp+0x148`（**先 memset 清零**） | entry−0x188 | words **5..13** | `8(k−5)`    |

- **shell 域可达**（普通 setsockopt，不需要 app 域 / `/dev/fmps`）
- 实测拷贝落地：opt46→errno 99(EADDRNOTAVAIL)、opt48→errno 22(EINVAL) = **先拷贝后校验**
- 实测安全：**200 轮双发零副作用**（对照跑 `SLIDE_MCAST_SELF_FIRE=0` 设备存活）
- 自开火 `sched_setattr` 帧深 **0x120 < 0x140**，刮不到 plant（离线确认）

### 2.3 布局三方一致 ✅

`rt_mutex_waiter`（MEP 非紧凑）：`tree.prio 0x18 / tree.deadline 0x20 / pi_tree 0x28 / pi_tree.prio 0x40 / pi_tree.deadline 0x48 / task 0x50 / lock 0x58 / wake_state 0x60 / ww_ctx 0x68`  
→ walk 反汇编读取、BTF、target.h **三者一致**。  
页侧伪造对象（`rt_mutex_base` wait_lock 0x00 / waiters 0x08,0x10 / owner 0x18；fake task 全字段）**与 BTF 全中**。

### 2.4 P0 依赖已摘除 ✅

6 处 `data_addr(ASHMEM_MISC_FOPS)` → `text_addr(...)`（映像空间+KASLR 修正）。因为 tracefs 让 base 在布置 waiter **之前**就已知，别名无必要。原值本身自相矛盾：`0x81960000` 是 `/proc/zoneinfo` 首个 **managed** PFN，而内核映像区是 reserved。

### 2.5 写原语语义 ✅

`try_cfi_stage()` 判据：`*(ASHMEM_MISC_FOPS) == fake_fops` → **写目标 = `ASHMEM_MISC_FOPS`（可写 .data 指针字段，把 ashmem_misc.fops 指向伪造表）；写值 = `fake_fops`**。被 `CONFIG_STRICT_KERNEL_RWX=y` + `RODATA_FULL_DEFAULT_ENABLED=y`（.rodata 只读）反证。

---

## 3. 唯一剩余卡点（2026-09-22 重写：原假设已证伪，真因是载波栈几何）

**结论：MCAST 载波的栈几何算错 0x1d0 字节 —— plant 与悬垂 waiter 完全不相交，所以任何 word 几何变体都必然 panic。**

### 3.1 §3 原假设（word5 = parent_color 被当成"指向 waiter 的指针"）已证伪

手册旧版引的那段反汇编是**两处指令错拼**：

```
0x1081aec: ldr x8, [x25, #0x28]!     ; x8 = waiter->pi_tree.parent_color
0x1081af0: cmp x8, x25               ; 这是 RB_EMPTY_NODE(&pi_tree) 判定，不解引用
0x1081ad4: ldr x0, [x8, #0x50]       ; ← 另一处！x8 = lock->waiters.rb_leftmost
0x1081ad8: ldr w1, [x8, #0x60]          (rt_mutex_top_waiter(lock))
0x1081adc: bl 0x4f0c4                ; 0x4f0c4 = wake_up_state（不是 wake_up_process）
```

即 chain 末端 `if (!rt_mutex_owner(lock)) { top_waiter = rt_mutex_top_waiter(lock);
if (prerequeue_top_waiter != top_waiter) wake_up_state(top_waiter->task, top_waiter->wake_state); }`。  
`pi_tree.parent_color` 的真实角色是 **rb_erase 的写值**（`ldr x9,[x0]; str x9,[x10]`），  
且节点被 `rt_mutex_enqueue_pi` 插入后会被 `rb_insert_color` 覆写成 1（RB_BLACK root），  
所以这个槽种什么值几乎无意义。

### 3.2 设备实测（一次一发，全部 panic）

| 变体                                                                            | 结果                                             |
| ----------------------------------------------------------------------------- | ---------------------------------------------- |
| `NEO11_PLANT_NO_WRITE=1 NEO11_PLANT_PI_PC_WAITER=1`（§3 单变量：word5→fake_w0，写关闭） | panic，log 停在 `plant: firing round=0` ⇒ §3 假设证伪 |
| `NEO11_PLANT_TREE_PRIO=121`（把 word3 钉成 walk 的 prio 闸门值，本应提前 return）           | panic ⇒ 读到的 word3 不是我们种的值                      |
| `NEO11_PLANT_BLANKET=121`（两份拷贝整段填同一值，覆盖 0x20c 字节）                             | panic ⇒ **不是值不对，是拷贝压根没落在 pi_blocked_on 指向的槽上** |


### 3.3 真因（离线实测：`poc/_stack_depth.py`）

- futex 侧（原假设**正确**）：`__arm64_sys_futex`(0x80) → `bl futex_wait_requeue_pi`(0x1c0)，    
  `rt_waiter` 局部在 `sp+0x90` ⇒ 悬垂 `pi_blocked_on` = **depth 0x1b0**，waiter 占 depths `[0x140, 0x1b0]`。
- setsockopt 侧（原假设**错 0x1d0**）：真实链    
  `__arm64_sys_setsockopt 0x10 → __sys_setsockopt 0x50 → do_sock_setsockopt 0x60 → sock_setsockopt 0x10
   → sk_setsockopt 0xd0 →(sk_prot->setsockopt，间接) ipv6_setsockopt 0x40 → do_ipv6_setsockopt 0x2c0`    
  ⇒ **D = 0x4a0**，而代码/旧脚本按 **0x2d0** 算。旧脚本只匹配 `sub sp,sp,#imm`，    
  漏掉 3 处 pre-index `stp …[sp,#-N]!` 帧，且 do_ipv6_setsockopt 真实帧是 `0x60+0x260=0x2c0`（只读到 0x260）。
- 后果：两份拷贝实际落在 depths **[0x250, 0x460]**，waiter 在 **[0x140, 0x1b0]** ⇒ **交集为空**（差 ≥0x34）。    
  walk 每一步读到的都是**未被覆盖的残留真 waiter** ⇒ 必 panic。且 do_ipv6_setsockopt 里**所有**    
  `copy_from_sockptr`/`memset` 目的地都在 depth ≥0x254（最浅即 opt48 的 `sp+0x148`），    
  **结构上够不到 waiter** ⇒ MCAST 方案不是调常量能救的，必须换载体。

**3.4j 2026-09-22：把 D 的 panic 讀通了 —— 那是「walk 順著鏈走到懸垂槽」的路徑，不是 dance 壞掉**

新工具/新開關（都已 build）：

- `NEO11_FIRE_NICE_SWEEP=1`：一次啟動內**連打 40 發**（nice −20..19 ⇒ p->prio 100..139），每發前半後各一行 fsync 日誌。    
  原理：閘門 `[waiter+0x18] == p->prio` ⇒ **沒崩的那個 nice 就是懸垂槽裡那 32 位值**（無讀回原語也能讀內核棧）。
- `NEO11_SIGRETURN_FILLREGS=1`：把 x0..x28 也填成載荷值（訊號送達時內核會把 x0..x30 快照進 `sigcontext.regs`）    
  ⇒ **整段 sigframe 無論切哪 512 字節都是 120**。⚠ 此模式**手勢會卡死**（waiter 進入無限 asm 迴圈後，    
  消費者端等不到 `sig_plant_ready`）⇒ 只能當「窗口上限」的旁證，別再用它做端到端。

本批三發：

| 配置                                                     | 結果                                                                 | 讀法                    |
| ------------------------------------------------------ | ------------------------------------------------------------------ | --------------------- |
| `sigreturn FILLREGS=1 + NICE_SWEEP`                    | 卡死（rc=124），日誌停在 `FILLREGS armed`，0 條 sweep                         | 手勢問題，見上               |
| `pselect BLANKET=120 + NICE_SWEEP`                     | **第 1 發（nice=−20 ⇒ p->prio=100）就 panic**（只寫了 "nice=-20" 沒有 "ret="） | 閘門不匹配 ⇒ walk 進來 ⇒ 立刻崩 |
| （早前）`FIRE_TARGET=owner NICE=0` = 存活 / `NICE=5` = panic | 見 §3.4i                                                            |                       |

**關鍵推理（本輪）**：對 owner 開火走的是**完全合法**的鏈：`task=owner`、`waiter=owner 的活 waiter`、  
`lock=chain`，然後 `task = rt_mutex_owner(chain)` = **waiter 線程** ⇒ walk 接著讀  
`waiter_thread->pi_blocked_on` = **那個懸垂指針** ⇒ 順著它讀到陳舊槽的欄位 ⇒ 才崩。  
⇒ **D/E 的 panic 不是「dance 弄壞鏈」，而是 walk 已經走到了懸垂槽、而那裡面的欄位不足以讓 walk 安全穿過**  
（walk 在 0x1081818–0x1081828 有 `if (waiter && waiter->lock != lock) → 走出` 的檢查，  
以及後續 `rt_mutex_dequeue_pi(task, waiter)` 的 rb 操作；欄位不對就變野指針）。  
⇒ 所以**真正的驗收判據是那條端到端路徑**（owner 開火 + 閘門不匹配 ⇒ 穿過懸垂槽 ⇒ 走到頁側寫原語），  
而 CFI 階段讀回 `*(ASHMEM_MISC_FOPS) == fake_fops` 是**唯一**的成功訊號。

**下批計劃（按價值，全部可用 `_sweep*.sh` 自動跑）**

1. **移植 reference 的表格形狀**（§3.4c）：棧上 tree/pi 只放 0/1（**不放指針**）、`task`→頁側 `fake_task`、     
   `lock`→頁側 `fake_lock`；確認頁側 `fake_lock` 的 pi_tree 真的裝著寫配對     
   （parent_color=寫值、rb_right=寫目標、rb_left=0）—— 目前 MEP 表把寫配對放在**棧** tree 節點上，     
   walk 一旦讀到就是野指針（§3.4c 已預警）。
2. 用 **owner 開火 + `NEO11_PUNCH_NICE` 使閘門不匹配**當**端到端測試**（一發一 boot），成功訊號看 CFI。
3. 若仍崩：拿 `NEO11_PSElect_RAMP` + 逐 8 字節段落二分（每段一 boot）確認 slot 到底在哪 ——     
   但注意「整段 512 字節全 120 都夠不到」已經排除了 0x080…0x280 這段 ⇒ ramp 只對**更深**的載體有意義。

**3.4k 2026-09-22：修好頁側一個真 bug（FOPS 模式 pi_waiters 是空的）+ 新增 trace 單向探針**

**本輪修復（已 build）**

1. **`util.c` `prepare_skb_payload()` 的 `PAGE_PAYLOAD_FOPS` 分支**：它把 `fake_lock.owner = fake_task|1`、     
   `fake_lock.waiters = fake_w0`、W0 的 pi_tree = 寫配對 {fake_fops, ASHMEM_MISC_FOPS, 0} 都設好了，     
   **唯獨 `fake_task.pi_waiters` 留成空樹**（SLIDE 模式才指向 W0 的 pi_tree）。於是 walk 走到     
   `rt_mutex_dequeue_pi(fake_task, W0)` 時，`rb_erase` 會在**不包含該節點的空樹**上操作 ⇒ 必崩。     
   已改成兩種模式都 publish `pi_waiters → fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF`。
2. **`fops.c` 新開關 `NEO11_PLANT_TASK_PAGE=1`**：棧上 word10（`waiter->task`）改指向**頁側 `fake_task`**     
   （reference 形狀；`NEO11_TASK_ALIAS=1` 仍是指向真 init_task 的直接映射別名）。
3. 日誌確認種下去的就是參考形狀：`fops: res-encode out[0..3]=<fake_task> <fake_lock> 3 0` ✓     
   （= task / lock / wake_state / ww_ctx，與 ghostlock-app 的 6.6 表一致）。

**新增判讀通道（本輪方法論收穫）**：`sched_pi_setprio` 事件的 `newprio = pi_task->prio`，而  
`pi_task` 正是 `task->pi_blocked_on->task` = **我們種的 word10**。所以：**把 word10 指向頁側對象、並在  
頁裡 `+0x84`（`task_struct.prio`，閘門反編譯已證實）放一個魔數 ⇒ walk 一旦走到 [11] 的  
`rt_mutex_adjust_prio`，trace 流裡就會打出這個魔數**（`comm=sh`）。這是**唯一不靠「崩不崩」的判讀**，  
且 trace 是流式導到主機的、能扛 panic。目前該事件在我們的開火窗口內**始終沒出現**  
⇒ walk 每次都在**到達 [11] 之前**就死了（此推論現在有正控支撐：合法 walk 也靜默，但我們看的是  
`comm=sh` 這一條，出現=一定到達）。

**本輪四發（頁修好後）全 panic**：`NEO11_TASK_ALIAS=1`+owner/不匹配、`NEO11_PLANT_TASK_PAGE=1`+waiter、  
`NEO11_TASK_ALIAS=1`+waiter。⇒ 頁側修復是必要的但不充分；walk 仍死在 [11] 之前。

**下一步（判據已就位，逐發一 boot）**：用「[11] 之前它會讀哪些欄位」逐項對齊 —— walk 迴圈在 [11] 之前  
會讀 `waiter->task`、`waiter->lock`、並比較 `tree.prio`（`rt_waiter_node_less`）與 `pi_tree`；  
把這些欄位按 reference 的值逐個種對（目前 tree/pi 的 prio 都還是 0/1 的猜值），每改一項看  
`sched_pi_setprio comm=sh` 是否出現（出現=走到 [11]=寫原語入口）。

**3.4l 2026-09-22：**&#x5169;個「不種植」正控 → plant 其實**落上了**，落點**比 pselect 可控窗更深**

**決定性正控（用 mcast 載體，它的兩支 setsockopt 在本機必失敗 ⇒ 等於完全不種植，槽裡留内核殘值）**

| 配置（都 mcast + `SLIDE_MCAST_SELF_FIRE=0`，不種植）                                | 結果       |
| -------------------------------------------------------------------------- | -------- |
| owner 開火 + `NEO11_PUNCH_NICE=5`（閘門**不**匹配 ⇒ walk 真的進鏈、會順鏈走到 waiter 線程的懸垂槽） | **存活** ✓ |
| **waiter 開火** + `NICE=0`（懸垂槽的殘值 prio=120 = p->prio ⇒ 閘門匹配 ⇒ return）        | **存活** ✓ |

⇒ **結論 1：這條鏈的 walk 本身是好的；只要槽裡是内核原本的殘值就能安全走完。**  
⇒ **結論 2：一旦用 pselect 種植就崩 ⇒ plant 確實**寫到了 walk 讀的那個&#x69FD;**（panic vs survive 的差別就是證據），  
只是我們的 word 映射讓 `ex[3]`(=tree.prio=120) 沒落在槽的 +0x18 上（落上就該閘門匹配 ⇒ 存活）。**

**為什麼不是「shift 調錯」**：pselect 的 verbatim 可控區 = in/out/ex 三個陣列，**物理上固定在深度  
0x200…0x188**（`bits`=sp+0x70、3×size=0x78，與 shift 無關）；`NEO11_PSELECT_BLANKET=120` 把這段  
**整段填 120** 仍然 panic ⇒ **槽的 +0x18 不在 [0x188, 0x200] 之内** ⇒ 槽在 **res 區那段**  
（深度 0x188…0x138，内核回寫位圖）⇒ 也就是說**waiter 比我們的模型深 ~0x20…0x70 字節**。  
（shift 掃描在此無用：它只改「哪個 waiter 字去哪個 fdset 字」，**不移窗**。）

**為什麼 sigreturn 載體也失敗**：它的 512 字節窗覆蓋 0x080…0x280，**本應包含 0x170 附近的槽** ⇒  
若它真的把我們的數據寫到那裡，閘門就該匹配 ⇒ 但 panic ⇒ **那 512 字節拷貝的源/目的與假設不符**  
（handler 自檢顯示 `__reserved` 開頭 `magic=0 size=0`，即那里**沒有有效的 `_aarch64_ctx` 頭**，  
拷貝到底取哪一段、寫到哪裡**從未在運行時驗證**）。⇒ 這條載體需要單獨驗一次。

**下一步（按此結論）**

1. **用 `sendmsg` 載體做深度探針**（已實現，覆蓋深度 **0x168…0x1d8**，正好是我們現在懷疑的區間）：     
   種 `tree.prio=120` + `NICE=0`，**存活 ⇒ 深度就是它**；掃 `SLIDE_SENDMSG_NAMELEN` 改變覆蓋位置。     
   （它的 word0 槽是 msghdr 的 iovec 用户指針，對**最終**利用不可用，但作為**深度標定**完全夠用，     
   因為閘門匹配時 walk 根本不會去讀 word0。）
2. 順帶把 `writev iovstack`（覆蓋 0x1b8…0x238）與 `process_vm_writev`（0x190…0x210）也當深度探針打，     
   三者窗口拼起來覆蓋 0x140…0x238 ⇒ 一定能框住真實深度。
3. sigreturn 載體：在 handler 裡把 `__reserved` 前 0x40 字節與 `vr` 前 0x40 字節**一起**打出來，     
   確認內核那 512 字節拷貝的源區間；再用「整段填 120」重測一次。
4. 深度一旦標定，回頭把 pselect 的 **res-encode 擴展**到覆蓋那個深度（res 區是内核回寫的位圖 ⇒     
   **只要 arm 對應 fd 就能把任意 64 位值寫進那一段** —— 這正是 res-encode 的機制，只是要按新深度重算映射）。

**3.4m 2026-09-22：tripwire 靜默的真正含義 = [11] 分支從未被進入（連健康的那一發也沒進）**

本輪三發（都 waiter 開火、`NICE=0` ⇒ p->prio=120，閘門值 120 種在不同深度）全 panic：  
`NEO11_PSELECT_PI_PRIO=120`（word8 → res_in[3] → 深度 0x170）、`word8+word3`、`word8+blanket`、  
`word8+word3+blanket`；再加一發 **`NEO11_PLANT_ALL=120`（word0..13 全 120）也 panic**。

⚠ **但 PLANT_ALL 那發的日誌裡沒有 res-encode 行 ⇒ 覆蓋範圍尚未證實**：per-word 的  
`res-encode ...` 行用的是 `pr_info`（走 logcat，被 HKS 加密屏蔽），只有 fops.c 的**匯總行**是  
`slide_diag_note`（寫 slide_child.log），而我在 PLANT_ALL 分支裡 early-return 把那行跳過了。  
⇒ **「槽在 [0x148,0x200] 之外」這個結論還不能成立**，必須先把 res-encode 的可見性補上。

**新認識（關鍵）**：`sched_pi_setprio` tripwire **在「不種植但存活」的正控裡也沒響**  
（`host_trace_ctrl.log` 中 0 條）⇒ **walk 從來沒進入 [11] 分支**（`rt_mutex_adjust_prio`），  
連健康的那一發都沒有。而 [11] 正是**寫原語的所在地**（`rt_mutex_dequeue_pi` → `rb_erase`）。  
⇒ 這解釋了為什麼 exploit 拿不到寫原語，也**回頭解釋了 reference 表格為什麼把 prio 填 1**：  
`rt_waiter_node_less`/`rt_mutex_adjust_prio` 只在「頂 waiter 的 prio 比 owner 當前 prio 更高（數值更小）」  
時才需要調整 ⇒ **偽造 waiter 的 prio 必須 < owner 的 prio（120），[11] 才會被進入** ⇒ 填 1 是刻意的。

**下一步（按順序）**

1. **補 res-encode 可見性**（純日誌、1 發、無崩）：把 `slide_pselect_put_waiter_word` 的 res 分支     
   改成 `slide_diag_note`（或兩者都寫），這樣 PLANT_ALL/任何種植的**逐字值**都進 slide_child.log     
   ⇒ 立刻能驗證「res 區到底有沒有被我們控制住」，把 §3.4l 的結論定死或推翻。
2. **tripwire 正控**：想辦法讓 [11] 真的被進入 —— 對 owner 開火時把它的 prio **提高**（`NICE=-5` ⇒ 115）     
   而鏈上頂 waiter（偽造/殘值 prio=1）更低 ⇒ 需要調整 ⇒ [11] ⇒ tripwire 應響。響了就證明 tripwire 可用，     
   之後所有欄位對齊都能用它判讀。
3. 再把偽造 waiter 的 `tree.prio`/`pi_prio` 對齊到「< owner prio」並確認頁側 `fake_lock.owner`/pi_waiters     
   （已修）能讓 [11] 走到 `rb_erase` ⇒ 那時才是真正的寫原語。

**3.4n 2026-09-22：**&#x5100;器修好（前幾輪的 tripwire 結論作廢）**+ res-encode 證實可控 + 兩條硬結論**

**⚠ 方法論修正（重要）**：`_sweep5/6` 與 tripwire 正控那幾輪的 trace 抓取**根本沒生效** ——  
`host_trace_*.log` 裡 `sched_pi_setprio` **總共 0 條**，而同窗口系統本來就有 10+ 條（第一發有 10 條）。  
原因：**exploit 的 tracefs KASLR 洩漏會自己重設事件集，把我事先打開的 `sched_pi_setprio` 關掉**。  
修法：`_watch2.sh`（已 push 到 `/data/local/tmp/watch2.sh`）改成**先等 `leak ok`、再開事件、再 `cat trace_pipe`**。  
⇒ **修好後同一窗口抓到 648 / 394 條事件** ✓，前幾輪「tripwire 0 條」的推論**全部作廢**。

**本輪兩條硬結論（都在儀器可用後取得）**

1. **res-encode 確實可控且現在可見**（已把 per-word 行從 `pr_info` 改成 `slide_diag_note`，進 slide_child.log）：

```
res-encode pi_prio w=8  g=18 -> res_in[3]  v=0000000000000001
res-encode task   w=10 g=20 -> res_out[0] v=ffffffe58d97e280
res-encode lock   w=11 g=21 -> res_out[1] v=ffffff8aba9604d0
res-encode wake_state w=12 g=22 -> res_out[2] v=0000000000000003
```

⇒ 種植覆蓋的深度區間**確實**是 waiter word 0..13 ⇒ **深度 0x1b0…0x148**（word k 在 0x1b0−8k）；  
blanket 另覆蓋 verbatim 段 [0x188,0x200] ⇒ **聯集 [0x148, 0x200]**。  
2\. **`NEO11_PLANT_ALL=120`（全 14 字都種 120）仍 panic** ⇒ **懸垂槽的 `+0x18` 不在 [0x148, 0x200] 之内**  
⇒ **它不在「waiter 深度 0x1b0」這個模型裡**（與三次獨立驗證的 `&rt_waiter @ sp+0x90` **矛盾**）。  
3\. 修好儀器後重測 tripwire（owner 開火 + prio 改變 ⇒ 必然進鏈）：**我們進程 0 條事件**  
⇒ `rt_mutex_adjust_pi`（`MIN_CHAINWALK`）的 walk **從不進入 [11]**（寫原語所在地）。

**改動**：`fops.c` 的 `tree.prio` 預設值 **0 → 1**（reference 就是 1：讓偽造 waiter 的 prio 比 owner(120)  
高，迫使 walk 重新傳播優先級 ⇒ 進入 [11]）；`_watch2.sh` 修正事件開啟時機。

**下一步（按價值）**

1. **修 MCAST 載體的兩支 setsockopt**（本機 `A opt=46 errno=99 EADDRNOTAVAIL`、`B opt=48 errno=22 EINVAL`     
   ⇒ 從未成功過）。它覆蓋深度 **0x258…0x358**（比 sigreturn 更深）⇒ **唯一能測「槽比 0x280 更深」的載體**。     
   `SLIDE_PLANT_OPT_A/B` 已是開關，直接掃 opt/level/值即可。
2. **獨立驗 `rt_sigreturn` 載體到底有沒有把我們的數據寫進內核棧**（它覆蓋 0x080…0x280，本應涵蓋 0x170     
   附近的槽卻沒生效）。可用「handler 裡把 `__reserved` 前 0x40 與 `vr` 前 0x40 一起打出來」核對拷貝來源區間。
3. 兩者拼起來（sigreturn 0x080…0x280 + mcast 0x258…0x358）就能覆蓋 0x080…0x358 ⇒ 一定能框住真實槽位，     
   然後才回頭重算 pselect 的 res-encode 映射（機制已證實可用）。
4. 所有後續判讀**必須**用修好的 `_watch2.sh`（先 leak 後開事件），否則又是 0 條假陰性。

**3.4o 2026-09-22 ★突破★：**&#x4D;CAST 載體才是落得上的那個；pselect 載體覆蓋不到懸垂槽\*\*\**

**一、res-encode 端到端證實可用**（新增免崩讀回：`NEO11_NO_FIRE=1` 時 pselect 返回後把內核回寫的  
`in/out/ex` 讀回來打日誌 —— 內核的 `set_fd_set` 會把 res_in/res_out 覆寫進用户 fd_set）：

```
fops: PLANT_ALL value=120 words=0..13
res-encode all w=5..9  -> res_in[0..4]  v=0000000000000078
res-encode all w=10..13-> res_out[0..3] v=0000000000000078
fops: readback in0..3  = 78 78 78 78      ← 內核確實寫進去了
fops: readback out0..3 = 78 78 78 78
```

⇒ **pselect 的種植覆蓋深度 [0x148,0x1b0]（word 0..4 verbatim + word 5..13 走 res-encode）且值確實是 120**  
⇒ `NEO11_PLANT_ALL=120` 仍 panic ⇒ **懸垂槽不在 [0x148,0x1b0]**（§3.4n 的結論成立）。

**二、判別性實驗（★）**：用 **MCAST 載體**（它兩支 `do_ipv6_setsockopt` 的拷貝**在校驗之前**就落棧，  
所以 `opt=46 errno=99` / `opt=48 errno=22` 的報錯**不影響種植**；兩支合起來覆蓋深度 **[0x084,0x290]**）：

```
SLIDE_CARRIER=mcast SLIDE_MCAST_SELF_FIRE=0 NEO11_PLANT_BLANKET=125 NEO11_PUNCH_NICE=5
  ⇒ *** SURVIVED ***（plant: words w3(prio)=125 ...）
```

判據：種 125 + 開火 nice=5（p->prio=125）⇒ **閘門匹配 ⇒ return ⇒ 存活**；若沒種上，槽裡殘值 120≠125  
⇒ walk ⇒ 必崩。**存活 ⇒ MCAST 的種植確實落在槽的 +0x18 上** ✓✓✓

**⇒ 結論：懸垂槽在 [0x084,0x290] 內，但不在 pselect 的 [0x148,0x1b0] 內 ⇒ 我們一直用錯了載體。**  
（參考實作 `GhostLock-H80GT` 用的正是 **MCAST** 載體 —— 與此一致。）

**三、下一步（就是把表搬過去）**

1. `slide.c` 的 `slide_mcast_write_stage()` 目前用的是**舊表形**（write pair 放在棧上 tree 節點：     
   `w5=fake_fops`、`w7=…`，日誌 `w5(pi_pc)/w7(pi_left)` 可見）。**改成 reference 形狀**：     
   棧上 tree/pi 只放 0/1、`task`→頁側 `fake_task`、`lock`→頁側 `fake_lock`、`wake_state=3`，     
   並把 `tree.prio` 預設設為 **1**（比 owner 的 120 高 ⇒ 逼 walk 進 [11] = 寫原語）。
2. 用 **owner 開火 + 閘門不匹配**（`NEO11_FIRE_TARGET=owner NEO11_PUNCH_NICE=5`）做端到端驗收，     
   成功訊號 = CFI 階段讀回 `*(ASHMEM_MISC_FOPS) == fake_fops`（頁側 `fake_lock.owner=fake_task|1`、     
   `fake_task.pi_waiters→W0` 已在 §3.4k 修好）。
3. 判讀一律用修好的 `_watch2.sh`（先等 `leak ok` 再開事件）；tripwire 出現 `sched_pi_setprio`（comm 可能     
   是頁對象的零值 comm）就代表 walk 走到了 [11]。

**3.4p 2026-09-22：頁側欄位已齊、但寫原語仍未被「證明」；自開火路徑**不確定性大\**

**本輪做的**

1. `fake_task.pi_blocked_on`（0x938）從 `0` 改成 **`fake_w0`**（頁側 waiter，其 `lock=fake_lock`）——     
   這是讓 walk 在頁側那一層不停下、繼續走到 **[11]** 的必要條件（walk 讀 `task->pi_blocked_on`，     
   為 0 就直接 early-exit）。
2. 核查後確認 `fake_task` 其餘欄位**本來就是良性的**：payload 先 `memset` 清零 ⇒ `on_rq`/`on_cpu`/     
   `policy`/`sched_class` 全 0（`rt_mutex_setprio` 的 `task_on_rq_queued`/`task_current`/     
   `check_class_changed` 都不會 deref 假指針）；`prio`/`normal_prio`/`pi_lock`/`pi_waiters`/`pi_top_task`     
   也都已設 ✓。

**實測（四發 + 一發）**

| 配置                                                            | 結果                        |
| ------------------------------------------------------------- | ------------------------- |
| mcast **自開火關** + 種 120 + nice=0（閘門探針）                         | **存活** ⇒ 種植落上、頁側修復有效      |
| mcast **自開火開** + `FIRE_TARGET=owner` + nice=5 / nice=0 / 默認目標 | **全 panic**（sweep8 V1–V3） |
| mcast **自開火開** + `NICE=0`（默認目標）重跑同一配置                         | **存活** ⇒ **同一配置結果不一致**    |

⇒ **該路徑是非確定性的**（公開報告也說單發 ~25–30% 命中）。**單發結果不能作結論，每種配置必須重複 N 發。**  
另外有一發根本沒走到 plant（日誌停在 `leak ok`）⇒ 跑之前要確認日誌裡出現 `fops: route entry`。

**目前的準確狀態**

- 種植落點 ✓（MCAST 載體，判別實驗已證）、偽造 waiter 可被 walk 安全穿越 ✓（owner 開火存活）、    
  頁側 `fake_lock.owner=fake_task|1` / `fake_task.pi_waiters→W0` / `pi_blocked_on=fake_w0` ✓ 全齊。
- **寫原語（`rb_erase` 寫出 `ASHMEM_MISC_FOPS=fake_fops`）尚未被證明**：CFI 讀回只在    
  `slide_mcast_write_stage()` 返回 `fired>0`（自開火成功）時才跑，而自開火那條路徑**幾乎都 panic**    
  ⇒ 寫入即使發生，也因為 panic 重啟而丟失、無法觀測。

**下一步（兩條）**

1. **把 CFI 檢查與自開火解耦**：讓 consumer 開火**之後**由另一條線程做 `*(ASHMEM_MISC_FOPS)==fake_fops`     
   的讀回（現在它綁在自開火成功上）。這是唯一能在「不觸發自開火 panic」的前提下證明寫原語的辦法。
2. **每種配置重複 5–10 發**（`_sweep*.sh` 加迴圈），用命中率而不是單發判讀；     
   同時把 panic 前能拿到的 tripwire（`sched_pi_setprio`）與 CFI 一起記。

**3.4q 2026-09-22：**&#x66F4;正 §3.4o/§3.4p 的一個錯誤結&#x8AD6;**：reference 表形**上一輪根本沒改上\*\*（改到了死表）

**更正**：上一輪我以為把 reference 表形搬進了 MCAST —— **改錯了地方**。  
`slide_mcast_build()` 裡的 `words[]` 是**另一處（未被使用）**；真正拼 buffer 的是  
`slide_mcast_write_stage()` 裡的 `put64(buf_a/buf_b, ...)`。日誌 `plant: words w3(prio)=130
w5(pi_pc)=fake_fops w7(pi_left)=ASHMEM_MISC_FOPS` 就是證據（舊形狀：寫配對放在**棧上** pi_tree 節點、  
`task` 還是真的 `INIT_TASK`）。

**本輪真正改上的（已用日誌確認生效）**

```
plant: words w3(prio)=1 w5(pi_pc)=0 w7(pi_left)=0 w11(lock)=<fake_lock> w12(wake)=3
```

- `tree.prio = 1`（不是 130）⇒ 偽造 waiter 的優先級高於 owner(120) ⇒ 逼 walk 重新傳播優先級 ⇒ 進 [11]
- 棧上 `pi_pc/pi_right/pi_left` 全 **0**（不放指針；寫配對在**頁側** W0 的 pi_tree）
- `task` → 頁側 **`fake_task`**（不是真的 init_task）
- 另：`fake_task.pi_blocked_on`(0x938) = **`fake_w0`**（= 0 會讓 walk 在頁側那層 early-exit）
- 另外兩個接線修正：① mcast 路徑現在也發 `punch_consume_go`（否則 consumer 根本不會對受害者開火）；    
  ② **CFI 讀回與自開火解耦**（改成等 consumer 開火返回後再讀 `*(ASHMEM_MISC_FOPS)==fake_fops`），    
  這是唯一能在不觸發自開火 panic 的前提下證明寫原語的辦法。

**實測（表形修正後）**：`SLIDE_CARRIER=mcast SLIDE_MCAST_SELF_FIRE=0 NEO11_PUNCH_NICE=0`  
⇒ 日誌到 `consumer: firing` 後 panic（日誌 fsync 存活，重啟後可讀）。

**狀態（誠實版）**

- ✓ 種植落點成立（MCAST，判別實驗證）；✓ 頁側欄位齊；✓ consumer 確實開火；✓ 表形已是 reference 形狀
- ✗ **寫原語仍未證明**：walk 在頁側那層（[11] 附近）崩；且該路徑**非確定性**（同配置時而 panic 時而存活）
- ⚠ **單發結果不能作結論**：公開報告說單發 25–30% 命中 ⇒ 每種配置必須重複 5–10 發

**下一步（給接手）**

1. 每種配置重複 5–10 發，逐發記 `cfi_step` / `verified` / tripwire（`_watch2.sh`：先 leak 後開事件）。     
   **有存活且 `cfi_step=0`/verified 的那一發就是寫原語成功。**
2. 若全 panic：在頁側做二分 —— ① `NEO11_PLANT_NO_WRITE=1`（去掉寫配對）看 panic 是否消失 ⇒     
   確認是不是 erase 本身；② 把頁側 `fake_w0` 的 `task` 欄位改成 `fake_task`（頁對象）⇒     
   避免 `rt_mutex_adjust_prio(fake_task)` 去 deref 真的 init_task；③ 檢查     
   `rt_mutex_enqueue_pi(fake_task, <棧上的 waiter>)`（把**棧**節點插進頁樹）是否是崩點。
3. 工具：`_sweep*.sh`（自動等重啟/重推/判存活，每發 ~90s）、`_watch2.sh`、res readback、     
   `NEO11_PLANT_ALL`、`NEO11_PSELECT_PI_PRIO`、`NEO11_PLANT_TASK_PAGE`。

**3.4r 2026-09-22 ★★★ 找到 fault 通道（整場戰役缺的那個）—— 崩點與故障地址全都能讀了**

**通道（無 root、shell 域、world-readable）**

```
adb pull /data/log/log.db            # 36.9MB, -rw-rw-r-- root system  ✓ 可讀
python: SELECT extra FROM event_info WHERE extra LIKE '%rt_mutex%'   # 參數綁定
```

`event_info.extra` 是 JSON，關鍵欄位：**`F1NAME`（葉函數+偏移）/`F2NAME`（調用者+偏移）/  
`F3NAME`（故障虛擬地址）/`REASON`** ✓✓✓  
另外 `adb pull /data/log/reliability/faultdetect/history.log` 給出每次重啟的 `reason` 與 `category`  
（今天我們的崩全部是 `reason [page_request]` = 數據中止；9/19、9/21 那批是 `null_pointer`）。  
⚠ `event.db`（同目錄）只有 userspace faultdetect（watchdog），**沒有**內核棧 ✗；要的是 `log.db`。

**實測 6 條記錄（全部同一崩點）**

```
F1NAME = _raw_spin_trylock+0x1c/0x98
F2NAME = rt_mutex_adjust_prio_chain+0xf8/0x900
F3NAME = paging request at virtual address <隨機 64 位>
REASON = page_request
```

地址樣本：`dededededededede`（canary 那一發）、`007d0aa52bd35d00`、`a1bb4bad28200700`、  
`70bf2f5238c9c6d8`、`3dc0fbf00ce9d264`、`3ffba7d67689d264`。

**⇒ 三條結論**

1. **walk 已經過了閘門**（F2NAME 是 `rt_mutex_adjust_prio_chain`）⇒ `rt_mutex_adjust_prio` 的閘門     
   **匹配成功** ⇒ **MCAST 載體確實把 `tree.prio` 種到了槽上**（與判別實驗一致 ✓）。
2. **崩點 = walk 的第一把鎖**：`rt_mutex_adjust_prio_chain+0xf8` 在 `raw_spin_trylock(waiter->lock->wait_lock)`     
   ⇒ 讀的是 **`waiter->lock` = 我們種的 word 11**。
3. **故障地址是隨機 64 位值 ⇒ word 11 讀到的是棧上殘留垃圾，不是 `fake_lock`**     
   ⇒ **MCAST 載體的第二支（`MCAST_MSFILTER`，負責 word 5..13）根本沒落在棧上**     
   （這版內核很可能把它拷進 kmalloc 而不是棧局部）⇒ 只有第一支     
   （`MCAST_JOIN_SOURCE_GROUP`，覆蓋 word 0..4）真的種上了 ✓（與判別實驗完全吻合）。

**⇒ 下一步**

1. **word 5..13（含 `lock`/`task`/`wake_state`）換載體**：**pselect 的 res-encode 恰好覆蓋這一段**     
   （word 5..9 = res_in、word 10..13 = res_out），且本輪已端到端驗證可用（讀回 `in0..3 = 78` ✓）。     
   注意 pselect 的 verbatim 段（word 0..4）之前驗證失敗，所以可能要**兩者配合**（順序/分工要實測）。
2. **每發都讀 `log.db` 的新記錄**：`F2NAME` 告訴我們崩在 walk 的哪一步、`F3NAME` 告訴我們哪個欄位沒種對     
   ⇒ 不用再靠崩/不崩二分。這是本輪最大的方法論收穫。
3. `history.log` 的 `reason` 也能分類失敗（`page_request` = 野指針；`null_pointer` = 空指針）。

**3.4s 2026-09-23 ★★★ 突破：fpsimd 偏移是 0x120（不是 0x118）；sigreturn 510B 种植**确证落&#x5730;**、walk 完整跑通**

**一、几何错误已定位（这就是之前所有 sigreturn 失败的真因）**  
新增 `NEO11_SIGPROBE=1`（自信号 + 按 `_aarch64_ctx` 链扫 sigframe，零内核写、不会崩）：

```
sigprobe: fpsimd=1 magic=46508001 size=0x210 vregs_ok=1 magic_off=0x120
sigprobe: verdict=1
```

⇒ **fpsimd 记录在 `uc_mcontext + 0x120`**（我们一直用 **0x118** ✗，差 8 字节）。  
⇒ 载荷偏移不变：waiter word i ↔ `vregs + 0xd0 + 8i`（闸门字 = 0xe8，与 dc15 端口标定的 0xe8 **完全一致** ✓）。

**二、第一次确证「种植落到悬垂槽上」**

```
SLIDE_CARRIER=sigreturn NEO11_SIGRETURN_FILL=120 NEO11_PUNCH_NICE=0
→ consumer: firing / fired ret=0 errno=0 / sigreturn: fire done ok=1   ⇒ 存活 ✓
```

判据：整段填 120 ⇒ 若落地则 `tree.prio=120=p->prio` ⇒ 闸门 return ⇒ 不崩 ⇒ **存活 = 落地** ✓✓

**三、第一次确证「伪造 waiter 可被安全穿越、walk 完整跑完」**

```
SLIDE_CARRIER=sigreturn NEO11_SIGRETURN_TABLE=1 NEO11_PUNCH_NICE=0
→ fired ret=0 ⇒ 存活 ✓（历史记录里每一次开火都在 walk 里崩 ✗）
真实表（新增逐字日志）：
  table[0..2]=0 table[3]=0 tree.prio table[4]=0 table[5..7]=0 table[8]=1 table[9]=0
  table[10]=<page>+0x2380 (fake_task)  table[11]=<page>+0x4d0 (fake_lock)  table[12]=3
```

⇒ 表形 = reference 形状 ✓✓

**四、过程中修掉的三个错（都是我自己的）**

1. pselect guard 误用在 sigreturn 路线上（consumer 白等 60s ⇒ 信号发不出）⇒ guard 限定为 `SLIDE_CARRIER=pselect` ✓
2. sigreturn 的 TABLE 里 `task` 还写着 `text_addr(INIT_TASK)`（真任务 ✗）⇒ 改成页侧 `fake_task` ✓（改完 walk 从"提前收工"变成"走进页里"✓）
3. 页几何：sigreturn 路线要用 **`PAGE_PAYLOAD_FOPS`**（写配对 `{fake_fops, ASHMEM_MISC_FOPS, 0}`）；SLIDE 页的写目标是 0 ⇒ erase 写到地址 0 ⇒ 必崩 ✓。且**页必须在舞蹈之前准备好**（放在 carrier 阶段里重喷会打乱 dance ✗）

**五、判据教训（与 dc15 SOP 一致）**

- `cfi_step` **不可信**：dc15 端口在本机 configfs 读回**恒为 0**，他们直接 `CFI_SKIP_VERIFY=1` ✓ ⇒ 我们不要再用 CFI 判成功 ✓
- 开火后 `route returned done=0 root=0` ⇒ 说明**拿到写原语之后的后半段（fops 劫持 → cred 覆盖）还没生效** ⇒ 下一步在这
- `log.db` 的内核故障记录**已停更** ✗（最近几发都没写进去）⇒ 要用 `history.log` 的 `reason` 兜底 ✓

**下一步**

1. **验证写原语是否真的写出**：既然 CFI 不可信，改用**结果侧**验证 —— 直接试 fops 劫持后的行为（例如对 ashmem fd 做 read/ioctl，看是否走我们的假表），或跑 `pipe.c` 的 physrw 路线（`read_ok/write_ok`）✓
2. 写原语一旦确认，接 `root.c` 的 cred 覆盖 + `selinux_state.enforcing=0` + 装 su ✓

**3.4t 2026-09-23：读原语方案（劫持 random_table 条目 + 读 proc）+ 自毁约束 + 单发纪律**

**一、dc15 的读原语（`chain.c: read_kernel_u64`）—— 不需要 physrw**

```
写配对 = { 写值 = 想读的镜像地址, 写目标 = random_table[?].data 槽 }
触发一次 ⇒ 再 open("/proc/sys/kernel/random/<x>") 读 ⇒ 内核把「该地址的内容」当 UUID 文本打印
```

⇒ **纯用户态可读、shell 域可用、不需要 root 也不需要 physrw** ⇒ 一次 UAF 写换一次 8 字节读 ✓✓

**二、离线核实我们内核的 `random_table`（image off 0x229af90，条目 0x40）**

| 条目                                                                                       | procname  | data                                            |
| ---------------------------------------------------------------------------------------- | --------- | ----------------------------------------------- |
| [4]                                                                                      | `boot_id` | `0xffffffc0823db420`（= `sysctl_bootid` ✓ 实指针 ✓） |
| [5]                                                                                      | uuid      | **`0x0`** ✗（`proc_do_uuid` 走内部静态回退 ⇒ 劫持它无效 ✗）   |
| ⇒ **必须用 `boot_id`（`entry[4]`）**：写目标 = `random_table + 4*0x40 + 0x08 = 0x229b098`（镜像偏移 ✓） |           |                                                 |
| ⇒ 读 `/proc/sys/kernel/random/boot_id`（同样以 UUID 文本输出 ✓，shell 可读 ✓）                        |           |                                                 |

**三、写原语的硬约束：`rb_erase` 会在 `写值+8` 自毁写**  
⇒ 写值不能是任意常量，必须是「`+8` 良性」的合法内核地址 ✓  
（实测：写值取 `init_task+0x820`（cred 字段）⇒ 自毁打坏 `+0x828` ⇒ **panic** ✗；  
dc15 的 bank 槽位轮换（`SLIDE_BANK_SLOTS 5`）就是为这个 + "避免同一 fake_waiter 地址重复挂 PI 树" ✓）  
⇒ 我们的规避方式：写值取**我们自己页内的地址**（`page_base + 0x600`，自毁落在页内 ✓✓），  
于是可以拿"读自己页"当**双自证**（页在 0x600 是 memset 的 0 ⇒ 读回应是**全零 UUID** ✓✓）

**四、已实现的开关（都已 build）**  
`NEO11_READ_AT=<镜像偏移或 canonical>`（写值=该地址、目标=boot_id 槽、读 boot_id 打日志）、  
`NEO11_READ_PAGE=1`（写值=`page_base+0x600`、目标=boot_id 槽 ⇒ 自证模式）、  
`NEO11_SIGPROBE=1`（sigframe ctx 链自探测 ✓）、`NEO11_SIGRETURN_TASK_ALIAS=1`（**强制路径存活的关键** ✓）、  
`NEO11_WRITE_VALUE/TARGET`（页侧写配对 ✓）、`CFI_SKIP_VERIFY=1` ✓

**五、实测记录与待办**

- 同 boot 连打两发时：第二发"存活"但 boot_id **未被劫持** ✗ ⇒ 违反 dc15 SOP 的"**一个 boot 只打一发**"（写原语会扰动 PI 树，第二发行为不可信 ✗）⇒ **每发必须先 reboot、等 uptime ≥ 95s**
- 按纪律重启后的干净单发（`NEO11_READ_PAGE=1`）**panic** ✗（日志只到 `leak ok`）⇒ 待查：    
  ① 写目标该用 `text_addr` 还是 `data_addr`（别名差异）；② `plant: page pair` 诊断**插错了位置**（没被打印 ⇒ 该路径的页不是 `prepare_skb_payload` 铺的 ✗，要插到真正铺页处）
- **下一步**：修正 ①② ⇒ 干净单发 ⇒ boot_id 读回**全零 UUID** = 写+读双自证 ✓✓ ⇒ 再接 dc15 的六步 cred 链（`read_kernel_u64` 读 `init_task.cred`/`per_cpu_offset`/`current`/`comm`，`write_kernel` 写 `cred`/`real_cred` = `init_cred`，再写 `selinux_state.enforcing` 低字节 0）⇒ **uid 0 + Permissive** ✓

**3.4i 2026-09-22：找到**舞步（dance）好壞的二元判&#x64DA;**，並證明「開火」之後的鏈 walk 是死的**

四發實機（clobber 修好後的建構，每發一次重啟）：

| #   | 配置                                                                 | 結果                              | 讀法                                                                                                            |
| --- | ------------------------------------------------------------------ | ------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| A   | `SLIDE_CARRIER=pselect NEO11_FIRE_TARGET=owner NEO11_PUNCH_NICE=0` | **`consumer: fired ret=0`（不崩）** | owner 是真實等待者（`wchan=futex_lock_pi`），閘門 `waiter->tree.prio(120) == p->prio(120)` ⇒ **return 0，沒有進鏈** ⇒ 這發沒檢驗到鏈 |
| D   | 同上但 `NEO11_PUNCH_NICE=5`（`p->prio=125` ≠ 120，**閘門必然不匹配**）          | **PANIC**                       | ⇒ **真正進鏈的 `rt_mutex_adjust_prio_chain` 走我們 dance 留下的鏈 ⇒ 必崩**                                                  |
| E   | D + `NEO11_PSELECT_BLANKET=120`                                    | PANIC                           | 與 plant 無關（owner 的指針指向它自己的棧，plant 在 waiter 棧上）                                                                |
| B/C | 對 waiter 開火（`FIRE_TARGET` 默認）+ BLANKET=120 / 單字 120 / prio 0       | 全 PANIC                         | 見下                                                                                                            |

**A vs D 合起來是一個乾淨的二元判據（不需要 plant、不需要回答落點問題）**：

```
對 owner（真實 PI 等待者）開火，nice 使其 p->prio ≠ waiter->tree.prio ⇒ 閘門不匹配 ⇒ 走鏈
  存活（ret=0，不崩）  ⇒ 這條鏈是健康的（dance 沒問題）
  panic               ⇒ 這條鏈被 dance 弄壞了（**當前狀態**）
```

⇒ 現在 **D 是 panic**：**dance 之後的鏈走不了**。而基線（乾淨 PI 鏈，`poc/pi_baseline.c`）同樣形狀的走法  
**存活** ⇒ 差別在 dance，不在載體、不在落點。

**這為什麼是關鍵**：exploit 的寫原語**要求** walk 真的進鏈（閘門必須**不**匹配才會走到頁側 `rb_erase`）。  
既然「進鏈就崩」，那麼**即使 plant 完美落地也沒用** ⇒ 之前所有 panic 都可能只是這個原因，  
落點問題甚至可能**不存在**（waiter 開火那幾發的 panic 也可能是同一條死鏈）。

**下一步（每步一發、都有二元判據，不再需要猜落點）**

1. 修 dance：逐項對照 `_ghostlock/main.c`（行號見 §3.4c），用 **A/D 判據**驗收「鏈是否健康」。     
   候選差異：`pin_to_core`（他們 waiter/consumer 各釘一核）、`disable_rseq_for_thread()`（三條線程都有）、     
   多餘的 `FUTEX_WAKE`（我們的，reference 沒有）、requeue 前 `usleep(50000)` vs 我們 `100000`、     
   以及 **consumer 開火後他們立刻 `FUTEX_LOCK_PI(f_pi_target, 0)` + UNLOCK**（我們沒有）。
2. 鏈健康後再看落點：把 A/D 判據的 `NEO11_PUNCH_NICE` 換成「種 word3 = 開火 prio」的 plant，     
   存活 = 落點成立（此時才是真正的落點測試）。
3. 工具：`_sweep.sh` / `_sweep2.sh`（自動等重啟、重推 .so、跑一發、判存活/panic）。     
   新增開關：`NEO11_SIGRETURN_FILLREGS=1`（把 x0..x28 也填成載荷值，讓**整段 sigframe** 無論切哪     
   512 字節都是 120 —— 已試，仍 panic，可作為窗口上限的證據）。

**3.4h 補記（同日稍晚，實機三發）：clobber 修好了，但仍然 panic ⇒ 懸垂指針不在我們的兩個窗口內**

已修（都已 build 進 `preload.so`）：

1. `main.c`：`consumer_calls++` 從「開火前」移到 **`sched_setattr` 返回之後**（route 用它當「walk 結束」訊號）。
2. `fops.c` `do_pselect_fake_lock_route()`：**刪掉 `pselect()` 返回後、park 之前的三個診斷**     
   （`slide_note_task_state` self-state/target-state = `/proc` open+read、`pselect returned` 那條 = `write`）——     
   **這三個就是真正的覆寫源**（它們的日誌正好出現在 `consumer: firing` 前一行）。改到 park 之後（只有收攤才會跑到）。
3. route 的自旋改成 **`while (!punch_consume_stop)` 無條件 park**（不再因握手旗標/上限提前出窗）。
4. `slide.c` sigreturn：刪掉 plant 之後的 `plant in place, spinning for the fire` 那條 `write`。
5. 兩處自旋上限 4e8/2e9 → 2e10（避免在 plant 落地前就 fire）。

**修好後的日誌形狀（= plant 保證完整）**：

```
fops: attempt=1 entering pselect nfds=320
consumer: target before fire tid=… wchan=0 syscall=running
consumer: firing tid=… nice=0        ← 中間**沒有任何** route 的 syscall
```

**但仍是 panic**（2 發）：

- `SLIDE_CARRIER=pselect NEO11_PSELECT_PRIO=120 NEO11_PUNCH_NICE=0`（閘門值 120 種在 depth 0x198）
- `SLIDE_CARRIER=sigreturn NEO11_PUNCH_NICE=0`（**整段 512 字節全 120**，覆蓋 depth **0x080…0x280**）

⇒ 連「整段 512 字節填閘門值」都不過 ⇒ **閘門讀到的 `[pi_blocked_on+0x18]` 不在 0x080…0x280 之內**  
（`p->prio` 已是 120：`nice=0`，且 `/proc` 第 18 欄 = `p->prio−100` 已核實）。

**本輪另量（全部離線、無重啟成本）**

- `futex_lock_pi` @0x2cb4a8：幀 **0x1a0**，其 waiter 在 **sp+0x70** ⇒ owner 線程阻塞時的 waiter 深度    
  也是 **0x1b0**（與 WAIT_REQUEUE_PI 同深）⇒ 「開火打到 owner 的另一條深路徑」**不成立**。
- `futex_requeue` 傳給 `rt_mutex_start_proxy_lock` 的 waiter 確認為 `futex_q->rt_waiter`    
  （q+0x48；q 的基準 x28 = q+8：`[x28+0x40]`=rt_waiter、`[x28+0x10]`=q+0x18=task、`[x28+0x38]`=pi_state）    
  ⇒ 懸垂指針 = **waiter 線程自己棧上**的 rt_waiter ✓（與 plant 同一線程，`self-state`/`target` 兩行 tid 相同）。

**剩下的假設（按可能性，下一位接手直接照做）**

1. **載體窗口還不夠**：sigreturn 只到 0x280。**MCAST 覆蓋 0x258…0x358（更深）** ⇒ 先修好 mcast 的兩支     
   `setsockopt`（本機 `opt=46/48` 回 `errno=99/22`，從未成功），用它覆蓋 0x280 以下；兩者互補可涵蓋     
   0x080…0x358（分兩次跑，不能同時）。用同樣的「整段填 120 + nice=0」判存活。
2. **懸垂指針屬於另一條線程**（cross-thread）：讓 **三條線程都各自的 plant**（各自 SIGUSR1 種自己棧），     
   然後依序對 owner → main → waiter 開火；哪一發**存活**就是它。已有的 `NEO11_FIRE_TARGET` 可選目標。
3. 若兩者皆非：檢查 `CONFIG_RANDOMIZE_KSTACK_OFFSET` 是否真的關（cmdline 已無此項，但 Honor 可能在     
   DTB/bootconfig 另開；逐 syscall 隨機化會讓所有固定幾何載體必然失敗——與我們的症狀完全一致）。     
   **這條要優先排除**：若是它，本路線需要換成與深度無關的寫原語。

### 3.4h 2026-09-22：**根因找到（在我們自己的 route 時序，不在幾何）** + 三項實機新事實

**新事實 1（掃描式消融，3/3 存活）**：把「開火」這一步關掉之後（`NEO11_NO_FIRE=1` 或  
`SLIDE_MCAST_SELF_FIRE=0`），**dance + plant 拷貝 + plant 寫原語全部跑完，設備存活**：

| 配置                                                                           | 結果                            |
| ---------------------------------------------------------------------------- | ----------------------------- |
| `SLIDE_CARRIER=mcast NEO11_PLANT_NO_WRITE=1 SLIDE_MCAST_SELF_FIRE=0`         | 存活                            |
| `SLIDE_CARRIER=mcast SLIDE_MCAST_SELF_FIRE=0`（含寫）                            | 存活                            |
| `SLIDE_CARRIER=pselect NEO11_NO_FIRE=1`                                      | 存活（`pselect returned ret=85`） |
| ⇒ 崩的**只有開火那一次 `sched_setattr`**；dance 與 plant 本身都無害（§3.4g 的"dance 弄壞鏈"不是主因）。 |                               |

**新事實 2：MCAST 載體在本機從來沒種下任何東西**（默認載體就是它！）

```
plant: A opt=46 ret=-1 errno=99 (EADDRNOTAVAIL) | B opt=48 ret=-1 errno=22 (EINVAL)
plant: done rounds=200 fired=0
```

⇒ 兩支 setsockopt 全部報錯 ⇒ 本戰役所有 mcast 路線的開火都是「打在**沒被覆蓋的殘留 waiter**」上。  
「落點矛盾」在 mcast 這條線上是**假命題**（根本沒有落點）。

**新事實 3：`sched_pi_setprio` 不能當作「walk 是否跑到 [11]」的判據**  
正控（`pi_baseline`：真實 PI 阻塞 + `sched_setattr`，**存活**、ret=0、設備在線）跑完整條合法  
`rt_mutex_adjust_prio_chain`，trace 裡 **`comm=pi_baseline` 的 `sched_pi_setprio` = 0 條**  
（同窗口內其他任務有 16 條）⇒ **合法 walk 也是靜默的** ⇒ §3.4g/§3.4d 用「0 條」推出  
「walk 死在 [11] 之前」**不成立**。該事件只能做「有 = 一定走到 [11]」的單向判據。

**根因（本輪新增，最關鍵）**：**plant 之後、開火之前，route 線程自己發了 syscall，把剛種下的 waiter 覆蓋掉了。**  
`fops.c` 的 go-window 握手是「`pselect` 返回 → 置 `punch_pselect_returned` → 用戶態自旋等 consumer 開火」，  
但實測日誌顯示 **route 的自旋在開火前就結束了**：

```
fops: attempt=1 entering pselect nfds=320
fops: attempt=1 pselect returned ret=83 errno=0     ← 已經離開窗口
consumer: target before fire tid=15183 wchan=0      ← consumer 這時才要開火
consumer: firing tid=15183 nice=0                   ← panic
```

自旋退出後路線接著做 `pr_info` / `slide_diag_note`（= `write`+`fsync`）/`close`/`try_cfi_stage`  
——**內核棧是每線程的，任何 syscall 都從棧頂重新往下用**，於是 depth 0x198（= waiter+0x18 = `tree.prio`  
= 閘門字）被這些 syscall 的幀覆寫 ⇒ 開火時閘門讀到垃圾 ⇒ walk 進鏈 ⇒ panic。  
`SLIDE_CARRIER=sigreturn` 同病：`sigreturn: plant in place, spinning for the fire` 這條**日誌本身**  
就是 plant 之後的一次 `write`（覆寫窗口 0x080..0x280 中的一段）。  
⇒ 這解釋了**所有**載體/幾何探針為什麼一律 panic：**它們從來沒被檢驗過**，而且原因不在幾何。

**幾何本輪再驗（兩側都自己量過，排除"深度模型錯"）**

- futex 側：`__arm64_sys_futex` @0x119ad8 幀 **0x80**，內聯分派，直接 `bl futex_wait_requeue_pi`    
  （0x119dd4）；後者 @0x958e1c 幀 **0x1c0**，`rt_waiter` 在 **sp+0x90**（`memset(sp+0x90, 0, 0x70)`）⇒    
  **waiter 深度 0x1b0** ✓（`tree.prio` = waiter+0x18 ⇒ 深度 **0x198**）。
- pselect 側：`__arm64_sys_pselect6` @0x244230 幀 **0x90** → `bl core_sys_select`（0x243ee8，out-of-line）；    
  後者幀 **0x1e0**，`bits = stack_fds` 在 **sp+0x70**（`memset(sp+0x70, 0, 0x100)` = 256 字節    
  `SELECT_STACK_ALLOC`；nfds=320 ⇒ size=0x28 ≤ 256/6 ⇒ 走棧路徑）⇒ fdset base 深度 **0x200**，    
  in/out/ex/res\_* 依序 0x200/0x1d8/0x1b0/0x188/0x160/0x138 ⇒ waiter word 0..4 = **ex[0..4]**（逐字節可控，    
  含閘門字 word3 在 0x198）✓、word5..8 = res_in、word10..13 = res_out ✓。
- 閘門本體（`rt_mutex_adjust_pi` @0x1081438）只有一個比較：`ldr w9,[x21,#0x18]`（= waiter+0x18）    
  vs `ldr w8,[x19,#0x84]`（= p->prio），相等且 `p->prio >= 0` 就 **return 0**（不進鏈）——    
  **不比 deadline**，所以「整段填 120」的探針是有效探針。
- 漏洞點逐指令確認：`remove_waiter` @0x1080e60 內 `1080e98: mrs x20, SP_EL0` +    
  `1080ee8: str xzr, [x20, #0x938]` ⇒ **清的是 `current->pi_blocked_on`**（不是 `waiter->task`）；    
  唯一入口是 `rt_mutex_start_proxy_lock` @0x1080df4 在 `__rt_mutex_start_proxy_lock` **返回非 0（EDEADLK）**    
  時 `bl remove_waiter`；`futex_requeue` 傳給它的 waiter 是 `futex_q->rt_waiter`（= **waiter 線程自己棧上**的    
  rt_waiter，深度 0x1b0 ✓）、task 是 `futex_q->task`（= waiter 線程）⇒ **懸垂指針屬於 waiter 線程、指向    
  它自己的棧 0x1b0** ✓（與我們 plant 的目標線程一致：日誌 `self-state after pselect tid=15183` 與    
  `consumer: target before fire tid=15183` **同一 tid** ✓）。
- 附帶事實：本機 `/proc/<tid>/stat` 第 18 欄 = `p->prio − 100`（nice 0 的 `cat` 也顯示 20）    
  ⇒ 閘門值就是 **120**（`slide_self_prio()` 讀回來的值要 +100 才是 p->prio；`NEO11_PSELECT_PRIO=auto`    
  直接種 20 是**錯的**，那一發作廢）。

**下一步（按順序，第二項是真正要做的）**

1. `NEO11_PSELECT_PRIO=auto` 改成 `slide_self_prio() + 100`（或直接別用 auto，硬編 120 / 用     
   `NEO11_PUNCH_NICE` 對齊）。
2. **修 go-window 時序（關鍵）**：route 線程在 plant 之後**直到開火完成都不能有任何 syscall**——
   - 自旋條件改成「**等 `consumer_calls != 0`（開火已返回）或 `punch_consume_stop`**」，不要用固定       
     600M 次上限硬退（實測它比 consumer 的 `usleep(delay)` 先到 ⇒ 提前出窗）；
   - 把 plant 之後的所有診斷（`pr_info`/`slide_diag_note`/`close`/`try_cfi_stage`/`slide_note_task_state`）       
     全部**移到開火之後**，或改由別條線程寫；
   - `SLIDE_CARRIER=sigreturn` 同樣處理：`plant in place, spinning for the fire` 這條 note 要在 plant       
     **之前**寫（或延後到 `sig_fire_done` 之後）。
3. 修好後用**最省的一發**驗收：`SLIDE_CARRIER=pselect NEO11_PSELECT_PRIO=120 NEO11_PUNCH_NICE=0`     
   ⇒ **存活 = 落點成立**（閘門 return，不進鏈）。那之後才是真正的種植（表形 + 頁側寫原語）。

### 3.4g 2026-09-22：**重大轉折 —— 崩的不是 plant，是我們的 futex dance 留下的狀態**

1. **對 owner 線程開火（合法 walk）也崩**：owner 是**真實**的 PI 等待者（在 chain 上阻塞），對它開火走的是     
   **完全合法**的 `rt_mutex_adjust_prio_chain`（不碰我們的懸垂指針、不碰偽造 waiter）——**照樣 panic**。     
   而對**不在 PI 鏈裡**的線程開火（主線程自檢）是**存活**的。     
   ⇒ **只要 walk 涉及那條被我們的 dance 弄過的鏈，就會崩；跟 plant 一點關係都沒有。**     
   ⇒ 這一口氣解釋了為什麼**所有** plant 幾何/寬度/載體實驗都是 panic（pselect 120B、rt_sigreturn 512B、     
   各種 word 幾何…）：**它們從來沒被真正檢驗過**。
2. **去掉我們多加的那次 `FUTEX_WAKE` 不是解**（`NEO11_SKIP_WAKE=1`）：waiter 會卡在 WAIT_REQUEUE_PI     
   （數分鐘不返回；說明這個 wake 是它返回所必需的），但最終**仍然 panic** ⇒ 該 wake 不是（唯一）元兇。
3. 新開關：`NEO11_FIRE_TARGET=owner|main`（換開火目標）、`NEO11_SKIP_WAKE=1`（去掉 requeue 後的醒）。     
   trace 正控：`sched_pi_setprio` 在本機確實會響（如 `kworker/u17:5 oldprio=120 newprio=49`），     
   但**從未出現 `comm=sh`**（我們的進程）⇒ 我們的 walk 從未走到 [11]（或被 early-out 抑制，待定）。

**下一步（按價值）**

1. **基線測試：乾淨 PI 鏈上的合法 walk**——兩條線程 + 一個普通 PI futex（無懸垂指針、無偽造），     
   一條 LOCK_PI、另一條阻塞後對它 `sched_setattr`。若**存活** ⇒ 是我們的 dance 弄壞了狀態（對照     
   `ghostlock-app` 逐項比對 dance 參數：線程角色/pinning/timeout/操作順序/rseq）；若**也崩** ⇒     
   這條路線的前提在本機不成立，需要重新評估（但公開實作在同一 kernel 家族上是能跑的，故更可能是前者）。
2. dance 逐項比對（離線即可開始）：`ROUTE_WAIT_SECONDS`、`pin_to_core`、`disable_rseq`、線程數與角色、     
   `FUTEX_WAKE` 的必要性、以及 requeue 之後到開火之間的**時序**。
3. 在上述前提下，plant 的落點問題（0x1b0 vs 其他）**尚未真正被測過**——等基線乾淨後再回頭做窗口二分。

### 3.4f 2026-09-22：`rt_sigreturn` 載體已實現並端到端跑通；**它證偽了 0x1b0 深度模型**

**已实现（`SLIDE_CARRIER=sigreturn`）**：waiter 線程裝 SIGUSR1(`SA_SIGINFO`) handler → 裝載 v0..v31  
（`ldr qN`，waiter 的 14 個字 = v13..v19）→ consumer `tgkill` → handler 返回時內核走 `rt_sigreturn`  
完成 512 字節拷貝 → 之後 waiter 只做用戶態自旋（不發任何 syscall）→ consumer 開火。  
日誌逐點完整：`vregs loaded, armed` → `consumer: sending SIGUSR1` / `tgkill ret=0` →  
`sigreturn: plant in place` → `consumer: ... firing` ✓✓（流程無誤）。

**自檢（關鍵）：handler 裡從用戶態讀 sigframe**

```
sigusr1: ctx magic=00000000 size=0 | vregs: d0=...078 d8=...078 e0=...078 118=...078 130=...078
```

⇒ 內核**確實**把我們的向量寄存器寫進了 sigframe（0x78 = 120），而那正是 `rt_sigreturn` 那 512 字節拷貝  
的**來源** ⇒ **載體搬運的是我們的數據**（可重複實證）。

**但把整段 512 字節填成閘門值（120）後仍然 panic ⇒ 結論：懸垂 `pi_blocked_on` 不在 depth  
0x080…0x280 之內 ⇒ 「waiter 在 0x1b0」被證偽。**（pselect 的 120 字節窗口、以及本次 512 字節窗口  
都夠不到它。）同時 trace 顯示 `sched_pi_setprio` 全程 0 條 ⇒ walk 每次都死在 [11] 之前。

⇒ 落點問題**不在載體**，而在**waiter 的真實位置**。

**下一步（已設計好，可直接做）**：用 sigreturn 載荷做**窗口二分**——把載荷只填某段（其餘填 0）：  
存活 ⟺ waiter 的 `tree.prio` 落在那段裡。錯段會 panic（1 發/步），約 6–9 發即可把位置定位到  
512 字節窗口內；若每一段都 panic ⇒ 確認它在窗口外，改用**更深的載體**  
（`poc/_stack_depth.py` 可直接列出候選 syscall 的拷貝目的地 depth 與覆蓋區間，挑覆蓋更深的那個）。  
另需一併驗：懸垂指針是否其實落在**另一條線程**（owner/main）上——直接把開火目標換成那兩條線程試。

### 3.4e 2026-09-22：**新载体 `rt_sigreturn`（很可能是答案）** + mallory.ai/Gitee 两处外部资料的核对

**几何（本机实测，`__arm64_sys_rt_sigreturn` @0x49b2e4）**

```
帧 = 0x290（单函数：整条 restore 路径内联，无 do_* 分派帧）
49beac: add x0, sp, #0x10 ; mov w2, #0x200 ; bl __arch_copy_from_user   ← 512 字节 verbatim 拷贝
49c228: add x0, sp, #0x10 ; mov w2, #0x200 ; bl __arch_copy_from_user   ← 同一目的地（第二处）
```

- 目的地 = **sp+0x10** ⇒ 覆盖 depth **0x080 … 0x280**；悬垂 waiter 在 **0x140 … 0x1b0** ⇒ **完全被覆盖**    
  （即使我们两端深度模型有 ±0x100 的误差也仍在窗口内）。
- **waiter 字节 i ↔ 载荷字节 0xd0+i**：即 sigframe 中 `sigcontext.regs`（x0..x30 / sp / pc / pstate）一带    
  ⇒ **载荷完全由用户寄存器控制**（信号送达前设置 x0..x30）。
- **无 res 段问题、无 fd arming、无 0..319 接管** ⇒ 比 pselect 路线干净一整圈。

**可执行方案（分两步，都可判读）**

1. **对齐无关探针**：把 512 字节载荷**整段填成"开火线程的 prio"**（对应 x0..x30 全部装同一个字符串）
   - 开火 nice 设为同一 prio ⇒ **无论 waiter 真实 depth 是多少（只要在我们的几何 ±0x100 内），       
     闸门都读到该 prio ⇒ return ⇒ 存活**。存活 ⇒ 载体确实覆盖 waiter（这是比 pselect 探针更强的判据，       
     因为窗口是 512 字节而不是 120 字节）。
2. **真实种植 + 写原语判读**：把已核对过的 14-word 表（表形见 §3.4c）放到**载荷偏移 0xd0**     
   （必要时在 ±0x70 范围内试 phase），用 **CFI 阶段读回 `*(ASHMEM_MISC_FOPS) == fake_fops`** 作最终判据     
   （这是唯一"非存活/panic"也能定性写原语的判读）。

**流程要点**：waiter 线程阻塞 → 回滚留下悬垂指针 → **信号送达 + handler + `rt_sigreturn`**（这一步完成种植）  
→ 回到用户态后**不再有任何 syscall**（自旋），由 **consumer 线程**开火 ⇒ 种植不被本线程后续帧覆盖。

**外部资料核对（`mallory.ai` CVE 页 + Gitee `ytngtaoaaa/allroot` 教程）**

- 漏洞点/根因与我们完全一致（`remove_waiter` 用 `current` 而非 `waiter->task`；代理回滚路径；    
  未清 `pi_blocked_on` ⇒ 悬垂；修在 6.6.140/6.12.86 ⇒ 我们 6.6.118 在受影响区间）。
- **独立印证我的 rb_erase 读法**：OPPO PFEM10(5.10) 的 PoC 记载 8 字节写原语"**同时在 write_value+0x8 写目标指针**"    
  —— 正是我们 `str x8,[parent+8]`（parent=写值）+ `str x9,[child]` 的 self-clobber。
- ASUS ROG 5S(5.4.210) 也用 **pselect6 + nfds=320 + 零超时 + word shift 10**（与我们同参），    
  且同样**够不到 `waiter->lock`** ⇒ 我们的 res 段困境是**公开已知**的同类问题。
- 可靠性：单发约 **25–30%** 命中，公开实现同样按"概率 + 重试"处理；    
  "**多数移植因 stack-layout gap 失败/被阻塞**" ⇒ 这正是我们这一类卡点的公开化描述（说明它是公认最难的一环）。
- 载体清单：pselect fd_sets / **MCAST_JOIN_SOURCE_GROUP(0x108B)** / IPv6 多播 / `TCP_ZEROCOPY_RECEIVE`(6.1 路线) /    
  **`rt_sigreturn`** ← 我们此前未试。
- Gitee 教程另提到 `PR_SET_MM_MAP` 放置伪造 waiter —— **对我们不可用**：`prctl_set_mm_map` 需要    
  `CAP_SYS_RESOURCE`，shell 域拿不到（可能用于 exploit 的后续提权阶段）。
- 教程还提到"把日志实时落盘以抗 panic 重启"——我们早有（`slide_diag_note` + fsync），并已新增更硬的    
  tracefs 流式取证（§3.4d）。

### 3.4d 2026-09-22：两条新的无 root 观测能力 + 对 H1–H4 的核对（详见 `MEP-AN00_落点矛盾_独立分析.md`）

**新能力 1 —— `adb bugreport` 可读"本次启动"的完整内核日志**（dumpstate 域，无 root）：  
bugreport 内含 `KERNEL LOG (dmesg)` 段（实测有 Honor 格式的完整内核消息）。注意 **panic 现场拿不到**  
（崩溃结束本次启动；pstore 内容被 Honor CHR/hiview 消费且不可读；`logcat -b kernel` 被 HKS 加密；  
`/dev/kmsg`/`dmesg`/`/sys/fs/pstore` 均 Permission denied）⇒ 只适合观测**不崩**的跑法。

**新能力 2 —— tracefs 事件流式取证**（实测可用，shell 域）：  
`events/sched/{sched_pi_setprio,sched_blocked_reason,sched_switch,sched_wakeup,sched_waking}/enable` **可写**，  
`trace_pipe`/`trace` **可读**。⇒ 可把崩溃前的事件**流式导到主机**（不再随重启丢失）；  
且 `sched_pi_setprio` 在本进程里**只由 walk 的 [11] `rt_mutex_adjust_prio`** 触发  
⇒ **出现它 = plant 落对且流程走到页侧写原语**（非致命命中指示）。  
⚠ 注意 `trace_pipe` 与 exploit 的 KASLR 泄漏用的 `trace_pipe_raw` **抢读同一 ring**，必须**先让泄漏跑完再流式**  
（设备端脚本 `/data/local/tmp/watch_trace.sh` + `adb exec-out sh … > host.log`）。  
**首测（弱信号）**：开火窗口内 `sched_pi_setprio` 为零 ⇒ 若该事件在本 workload 里本来会响（正控待做），  
则说明 **walk 在到 [11] 之前就已经死了**。

**H1 核对（错）**：`waiter+0x18` 是**地址**加 0x18 ⇒ depth 变**小**：`depth(tree.prio)=0x1b0−0x18=**0x198**`  
（不是 0x1c8）；而 `stack_fds` 覆盖 depth **0x100…0x200** ⇒ **包含 0x198**（数组字节 0x68 = **ex 子数组，逐字節可控**）。  
⇒ PRIO/blanket 探针**有效**，"落点不对"的结论**不变**。word↔数组字节↔子数组对照：  
word0..4→字节0x050..0x070(**ex，可控**)；word5..9→0x078..0x098(res_in，内核回写)；word10..13→0x0a0..0x0b8(res_out，内核回写)。  
**H2 核对**：`p->prio` 确实在 `rt_mutex_adjust_pi` **之前**更新（调用点 0x16a224 在 `__setscheduler` 之后）⇒ prio 可控 ✓；  
但"种 word3=开火 prio"是刻意的**落地探针**（存活 ⟺ plant 落上），不是用错方向；不种 word3 时闸门读到陈旧垃圾 ⇒ 必走链 ⇒ 必崩。  
**H3 核对**：成立且已实测（见上）。  
**H4 核对**：终局方案（清零 `panic_on_oops`/`sig_enforce` + 覆盖 cred + `finit_module` 打 kprobe），  
**前提"可用的写原语"尚未达成** ⇒ 属拿到写原语之后的第一步。

### 3.4c 2026-09-22：外部实现 `YuKongA/ghostlock-app` 对照（已下载到 `_ghostlock/`）

同一個 CVE 的**多機型實作**（含 `6.6.118-android15-8-…-4k` 同族、Magic V5 等），6.6/6.12 用的就是  
"主線程 select/pselect + 消費線程擾動優先級"這條路 ⇒ **路線與我們一致**；其 extractor 還會  
**反彙編 `remove_waiter()` 並拒絕已修補的內核**（機器可讀地確認了漏洞點 = `remove_waiter` ✓，  
與我們"`futex_requeue` 傳 `q->task`、回滾卻清 `current` ⇒ 懸垂 `pi_blocked_on`"的結論一致）。

**他們驗證過的 6.6 非緊湊 word 表**（其索引 2..14 ≡ 我們的 0..12）：

```
我們的 word: 0  1  2  3  4   5  6  7   8  9   10        11        12
值:          0  0  0  1  0   0  0  0   1  0   fake_task fake_lock 3
名稱:      tree_pc/right/left  tree_prio  tree_dl  pi_parent/right/left  pi_prio pi_dl  task  lock  wake_state
```

⇒ **棧上的 tree/pi 全 0（或 prio 位填 1），task/lock 指向頁側對象，write 原語只來自頁側**  
（與我從 MEP walk 反彙編推出的"[11] 分支一 erase 頁側 W0 ⇒ 寫入"完全吻合）。  
而 **MEP 現在的 pselect 表把 write pair 放在棧 tree 節點上**（word0=fake_fops / word1=ASHMEM_MISC_FOPS）  
—— 這正是"一旦錯落就變野指針"的形狀 ⇒ **應移植他們的表形狀**（棧 tree/pi 只放 0/1）。

**`pselect_waiter_shift`：他們 6.6 = −2，我們 = +10 —— 差額正好是 `do_futex` 那一幀（0x60）**

- 他們的推導（`tools/extract_rs/src/derive.rs`）對 futex 側取 `[__arm64_sys_futex, do_futex, futex_wait_requeue_pi]`    
  ⇒ 幀和 0x2a0 ⇒ waiter 深 0x210 ⇒ Δ = −0x10 ⇒ shift = −2 ✓（即**他們的 build 把 futex 分派放在 out-of-line 的 `do_futex`**）。
- MEP 實測：`__arm64_sys_futex` 把分派**內聯**了——它直接 `bl futex_wait_requeue_pi`（0x119dd4），    
  全程**沒有 `bl do_futex`**（連 `android_vh_do_futex` hook 都自己調）⇒ waiter 真的在 **0x1b0** ⇒    
  **MEP 的 SHIFT=10 是對的**，照抄 −2 會再錯 12 word。
- **由此推出一個結構性差異**：因為 MEP 的 waiter 淺了 0x60，`task`/`lock` 必然落在 **res 區**    
  （fdset word 20/21）⇒ **MEP 必須用 res-encode**（本輪已修好），而他們的 build 不需要    
  （他們的同名字落在 verbatim 段）。他們的 pselect 是**阻塞在 never-ready timerfd 上**、根本不碰 res 區 ⇒    
  兩種設計的分歧根源就在這一幀。

**可移植的其它點**：雙核賽跑（waiter/consumer 各釘一核）、`reserve_standard_io/restore_standard_io`、  
"阻塞在 never-ready fd 上讓 fdsets 常駐"作為"返回+自旋"的 A/B 方案。

**本輪複測（重要）**：用**修好 ex 分支污染之後**的構建重跑閘門跳過探針  
（`NEO11_PSELECT_PRIO=120 NEO11_PUNCH_NICE=0`）——**仍然 panic**（日誌停在 `consumer: firing`）  
⇒ plant 的 word3（落在 **verbatim** 的 fdset word 13）依然沒到 walk 的 `tree.prio`  
⇒ 排除"先前 panic 只是 ex 污染所致"；落點矛盾仍在（下一步仍是掃描/日誌通道）。

### 3.4b 2026-09-22 第三輪：日誌通道/環境事實，與"多輪不重啟"的可行性

**本輪新增開關**（`fops.c`）：`NEO11_SWEEP=prio|shift`（21 輪掃描，逐輪 setenv 換參數 + 逐輪日誌 + 不再因  
`!route_signal` 提前 break）、每輪一個**一次性犧牲線程**開火（`sweep_fire_thread`，這樣一旦 oops 不再致命，  
壞的一輪只死那條線程、路線能繼續）、`NEO11_PSELECT_RAMP=<base>,<stride>`（自描述 plant：窗口內  
word j = base + j*stride，任何一次崩潰洩出的值/故障地址都能**一次解碼落點**，取代存活/panic 二分）。

**環境事實（從 `vendor_boot.img` 挖出的真實 cmdline，本輪新得）**

```
... performance sysctl.kernel.sched_pelt_multiplier=4 no-steal-acc kpti=0 swiotlb=0 ...
printk.console_no_auto_verbose=1 kasan=off rcupdate.rcu_expedited=1 rcu_nocbs=0-7
kernel.panic_on_rcu_stall=1 disable_dma32=on ...
```

⇒ 有 **`kasan=off`**（運行時 KASAN/MTE 關閉，不存在 shadow 檢查干擾）；  
**沒有 `randomize_kstack_offset`、沒有 `nokaslr`**（逐 syscall 棧隨機化關；KASLR 開）；  
`kasan=off` 也意味著沒有 `CONFIG_DEBUG_RT_MUTEXES`-類的 PI 校驗。

**日誌通道現狀（本輪逐個實測，全部不可用）**

| 通道                                                                             | 結果                                                      |
| ------------------------------------------------------------------------------ | ------------------------------------------------------- |
| `logcat -b kernel`                                                             | **被 HKS 加密屏蔽**：整個 buffer 只有 546 字節、單條 `(HKS)<hex>(HKE)` |
| `/dev/kmsg`、`dmesg`、`/sys/fs/pstore`                                           | Permission denied                                       |
| dropbox（`dumpsys dropbox`）                                                     | 只有 `SYSTEM_TOMBSTONE`，無 `SYSTEM_LAST_KMSG`              |
| `/data/log/faultlog`（全局可讀 ✓）                                                   | 只有 freeze 記錄（`WP09-TP` 等），無 panic 轉儲                    |
| `/data/log/dubai/dubai.db`（可讀 ✓，已拉本地）                                          | 無任何內核文本（無 `panic`/`Call trace`/`pc :`）                  |
| `sys.resettype`                                                                | **`abnormal:AP_S_PANIC`** ⇒ 我們的失敗是 **panic**（不是靜默看門狗復位） |
| panic 開關（`panic_on_oops`/`panic_on_warn`/`hung_task_panic`/`softlockup_panic`） | **連讀都被 SELinux 拒** ⇒ 關不掉，需 root                         |

⇒ **無 root 就没有 fault address 通道** ⇒ 自描述 plant（`NEO11_PSELECT_RAMP`）已就位但**等通道**；  
且因為失敗是 panic（配置還有 `BUG_ON_DATA_CORRUPTION=y`），單純 `panic_on_oops=0` 也未必夠。

**一個必須糾正的前提**（外部思路文檔裡的一條）：`/proc/<tid>/syscall` 的後兩個字段是  
**用戶態 SP/PC**，不是內核棧指針。本機實測（對阻塞中的 `sleep`）：  
`101 0x7fea435b18 0x0 0xa 0x1000 0xfffffffffffffff0 0x40 0x7fea435b10 0x7c6c941b48`  
—— 最後兩值都是用戶地址。所以"跨載波 sp 差分"量到的是**用戶棧**，量不出內核深度  
（仍可用的是 `syscall` 的**編號+參數**與 `wchan`，用來確認線程阻塞在哪條路徑）。

### 3.4 可行方向（2026-09-22 晚第 2 輪：pselect 路線已推到位，卡在"plant 落點"）

**本輪已做的修復與新增探針（都在 `slide.c`/`fops.c`/`main.c`）**

1. pselect 的 res-encode 修正：waiter word10..13（task/lock/wake_state/ww_ctx）落在內核回寫的     
   `res_out`/`res_in` 區，不能當數據直接寫；改成**編碼進 `out` 位圖自己的 word 0..3**     
   （內核按 fd 就緒位寫 res_out word j）⇒ 相變前 res 區全 0 ⇒ `waiter->lock = 0` ⇒     
   `raw_spin_trylock(0)` 必崩（phase-1 panic 的真因）。
2. `ex` 分支改為"**裝滿**管道 + 讀端關閉"：ex 數組同時是 waiter word0..4 的 plant，     
   其位會被 arm 成 ex-fd，而"有寫端無讀端且未滿"的管道會**多報 POLLOUT**，     
   把 res_out（task/lock）的位污染成垃圾指針 ⇒ 裝滿後 POLLOUT=0、POLLERR=1，不再污染。
3. 新探針/開關：`NEO11_PSELECT_PRIO`（把 word3=tree.prio 種成開火線程的 prio，用於"閘門跳過=存活"的正向對齊測試）、     
   `NEO11_PSELECT_BLANKET`（把可控窗口 fdset word0..14 整段填同一值）、`NEO11_PUNCH_NICE`（開火 nice）、     
   `NEO11_SELFTEST_SETATTR`（對 `pi_blocked_on==NULL` 的線程做一次普通 sched_setattr 的**對照組**）、     
   以及 `fops: attempt/pselect returned/armed/entering/spin done` 與 `consumer: firing/fired` 逐點日誌。

**本輪實測結論**

- 控制組：主線程（`pi_blocked_on==NULL`）做同樣的 `sched_setattr` → `ret=0` 且設備存活    
  ⇒ **`sched_setattr` 本身沒問題；panic 確定來自"懸垂 pi_blocked_on + walk 讀到未覆蓋的殘留 waiter"**。
- 開火前設備能完整走到 `pselect returned`（例如 ret=84/85/106）→ consumer 開始開火 → 之後無任何日誌    
  ⇒ panic 在 consumer 那次 `sched_setattr` 內。
- **對齊探針全部失敗**：`NEO11_PSELECT_PRIO=139/120`（閘門應跳過 walk）與    
  `NEO11_PSELECT_BLANKET=120 + NEO11_PUNCH_NICE=0`（把整個可控窗口填成 120，理論上 ±14..±19 word    
  的落點誤差都能命中閘門）**都仍然 panic** ⇒ **plant 確實沒落在 walk 讀的 waiter 上**，    
  且落點誤差超出該窗口（>0x68..0xa0 字節）。
- `vendor_boot.img` 已解出（`update_sd_base/image/`）：cmdline 只含    
  `video=vfb...,cpufreq.default_governor=performance bootconfig buildvariant=user`，bootconfig 只有    
  `androidboot.memcg/usbcontroller/load_modules_parallel/hypervisor.../selinux=enforcing/init_fatal_panic=true`    
  ⇒ **沒有 `randomize_kstack_offset`、沒有 `nokaslr`**；配合 `CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT`    
  未設 ⇒ **逐 syscall 棧隨機化應為關閉**（所以"隨機化導致對不上"不成立）。

**因此剩下的矛盾很具體**：兩側深度都"從反彙編算過"（futex waiter = `__arm64_sys_futex` 0x80 +  
`futex_wait_requeue_pi` 0x1c0，`rt_waiter` 在 sp+0x90 ⇒ depth 0x1b0；pselect：`stack_fds` 在  
`core_sys_select`(0x1e0) 的 sp+0x70，上游 `__arm64_sys_pselect6` 0x90 ⇒ fdset base depth 0x200），  
但實測落點不符。下一步（按優先級）：

1. **校準 futex 側**：換一個 *確定更深* 的等待路徑或直接量測——例如讓等待者用     
   `futex_waitv`/`FUTEX_LOCK_PI` 阻塞，比較落點是否隨之移動；或把 plant 做成"**階梯**"     
   （同一 syscall 內多個本地緩衝覆蓋一整段 depth），用一次開火的存活/崩潰**二分**出真實 depth。
2. **去掉 libc 包裝的不確定性**：把 `pselect(...)` 換成直接 `syscall(SYS_pselect6, ...)`     
   （bionic 的 pselect 是否走 `select` 而非 `pselect6` 未證；兩者 depth 差 0x20）。
3. 若 (1)(2) 都不動，考慮**放棄"同一線程自 plant"模型**：改用"等 0x1b0 深度處由 *另一* 線程     
   寫入"的思路（需要目標線程阻塞在同棧深處，難度更高，但不受本線程 syscall 幀佈局影響）。

**(c) 不要再做 word 幾何微調**（已被 blanket 實驗證偽）。

**判据（本段所有结论的量化形式）**：waiter 在 depths `[0x140, 0x1b0]`（word k 在 depth `0x1b0-8k`）。  
要逐字节种下它，需要一个 **≥0x70 字节的 verbatim 拷贝，目的地 depth ∈ [0x1b0, 0x1c0]**。

已测候选（`_stack_depth.py`，均含 pre-index stp 帧）：

| syscall                      | 拷贝目的地 depth       | 结论                                                                    |
| ---------------------------- | ----------------- | --------------------------------------------------------------------- |
| do_ipv6_setsockopt (MCAST)   | 0x358 / 0x460     | 深 0x1a8+，结构上够不到 ✗                                                     |
| `writev` iovstack            | 0x238             | **只差 8 字节**（覆盖 [0x1b8,0x238]，waiter 从 0x1b0 起）✗                       |
| `sendto` sockaddr            | 0x228             | 覆盖 [0x1a8,0x228] → 只有 word0 ✗                                         |
| `process_vm_writev` iovstack | 0x210             | 覆盖 [0x190,0x210] → word0..3 ✗                                         |
| `pselect` fdset 数组           | 0x200（可控段到 0x188） | **word0..5 verbatim ✓**（含 prio 闸门 word3），word10..13 落内核回写的 res 段      |
| `sendmsg` msghdr / sockaddr  | 0x1d8 / 0x168     | msghdr 覆盖 word0..6 但 word0 槽 = **iovec 用户指针**；sockaddr 覆盖 word9..13 ✓ |

**本次已实现并上机实测的 sendmsg 载体**（`slide_sendmsg_write_stage()`，`SLIDE_CARRIER=sendmsg`）：  
plant 与开火都跑到了（log 有 `plant: sendmsg ret=-1 errno=89` = EDESTADDRREQ、`plant: firing round=0`），  
但**仍然 panic**（无 `self-fire ret` 行）。原因（BTF 实测该内核的 `struct msghdr` 是 6.12 回移版：  
`msg_iter` 0x10、`msg_control` 0x40、`msg_flags` 0x44、`msg_controllen` 0x48）：  
msghdr 局部落在 waiter word0..6 上，而 **word0 正好是 `msg_iter` 里的 iovec 用户指针**  
⇒ walk 的 `rt_mutex_dequeue` 取 `parent = word0 & ~3` = 用户地址 ⇒ 内核在 PAN 下读用户内存 ⇒ panic。  
⇒ **任何让 word0 落成用户指针的载体都不能用**（word0 必须是 0 或 `&waiter->tree`）。

**唯一剩下的可行路线（推荐）**：**回 pselect 载波 + 已有的 RES_ENCODE**

- 几何已逐字节验证：`core_sys_select` 的 `stack_fds` 在 `sp+0x70`，链 `0x90+0x1e0` ⇒ fdset base depth `0x200` ⇒ **SHIFT=10 与代码一致**；
- verbatim 可控段 = in/out/ex（fdset word 0..14，即 depth `0x200..0x188`）⇒ **waiter word0..5 直接种**（含 word3 prio 闸门 ✓）；
- 需要编码的只有 task(word10)/lock(word11)/wake_state(word12)/ww_ctx，它们映射到 **res_out word 0..3 = fds 0..63/64..127/128..191/192..255 的 POLLOUT 结果位**，正好是 `slide_res_arm_bitmaps()` 干的事（代码已有）；
- word6..9 落在 res_in，**不需要**（pi_tree 那几字在本路径只被写不被读）。
- 该路线目前的拦路石是 **phase-1 panic**（本次实测 `SLIDE_CARRIER=pselect` 停在 `fops: attempt=1 shift=10`，    
  还没到 consumer 开火）——即 arming/pselect 调用阶段，需要在几何已确认的前提下重做那一段（老代码注释里    
  H80GT 观察到的 `do_select+0x690` 近 NULL 写、poll_freewait list_del 等）。

**行不通的组合**（别再试）：两发不同 syscall 分工种不同 word 段 —— 后一发 syscall 的栈帧会覆盖前一片  
（例如 sendmsg 之后跑 pselect，pselect 的帧覆盖 depth 0..0x270，正好把 sendmsg 种在 0x140..0x168 的  
那一片清掉）。除非两片恰好落在互不重叠且都不被后者帧覆盖的深度，需要逐方案验算。

**(c) 不要再做 word 几何微调**（已被 blanket 实验证伪）。

### 3.5 顺手核实的其他事实

- `ASHMEM_MISC_FOPS = ashmem_misc+0x10`；kallsyms 段界 `_sdata=0x2160000 … _edata=0x2368a00`    
  ⇒ 目标在 **.data，可写** ✓（旧文档"被 .rodata 只读反证"的说法改成实测）。
- 内核配置：`KASAN=y` + `KASAN_HW_TAGS`(MTE)、`SHADOW_CALL_STACK=y`、`VMAP_STACK=y`、    
  `PANIC_ON_OOPS=y`、`BUG_ON_DATA_CORRUPTION=y`、`INIT_ON_ALLOC_DEFAULT_ON=y`、    
  `RANDOMIZE_KSTACK_OFFSET=y`（DEFAULT 未设；`/proc/cmdline`、`/proc/bootconfig` 对 shell 均    
  Permission denied，**运行时是否开启未证** —— 若开启，任何固定栈偏移都不可行）。
- walk 入口确证：`__sched_setscheduler` 在 **0x16a224** 调 `rt_mutex_adjust_pi(p)`，    
  闸门是 `p->pi_blocked_on != NULL && waiter->tree.prio(word3,0x18) != p->prio([p+0x84])`    
  （0x10814b8–0x10814d4）；触发链因此**依赖** main.c 里那次 requeue 回滚留下的悬垂 `pi_blocked_on`。
- `rt_mutex_setprio(fake_task, pi_task)`：当 `fake_task->pi_top_task == pi_task` 时在 **0x169230 提前返回**    
  （当前页 `pi_top_task` 与 stack word10 都是 `text_addr(INIT_TASK)` ⇒ 相等 ⇒ 不会把伪造 task 丢进调度器）。
- tracefs 对 shell 只开放 `tracing_on`/`trace`/`events/sched/sched_blocked_reason/enable`    
  与 `per_cpu/*/trace_pipe_raw`（`kprobe_events` 等被 SELinux 拒）⇒ **无法内核侧插桩**，    
  panic 定位仍只能"一发一重启 + 二分"。

---

## 4. 代码与产物

改动集中在 `ref-neo11/exploit/src/targets/MEP-AN00-HONORMEP-AN00/`：

- **`slide.c`**：tracefs 泄漏三函数（主路径，`SLIDE_SKIP_TRACEFS=1` 回退 pselect）、**双发 plant 载体** `slide_mcast_write_stage()`、跨 TU 诊断通道 `slide_diag_note`（写 `/data/local/tmp/slide_child.log`，fd ≥ 320 避开 arming 对 0..319 的接管、fsync 抗 panic）、可运行时改的 shift
- **`fops.c`**：路线入口的 plant 分支（`SLIDE_CARRIER=pselect` 回退）、开火门控 `punch_pselect_returned`、逐轮诊断
- **`util.c`**：页侧 `wake_state` 0→3（dc15 硬要求）
- **`main.c`**：`run_exploit` 阶段诊断
- **`target.h`**：`P0_PHYS_OFFSET` 等（已不影响功能）

最新构建：`build/MEP-AN00-HONORMEP-AN00/bin/preload.so`（2026-09-22，含下表新开关）。

运行时开关：  
`SLIDE_CARRIER`（`mcast` 默认 · `sendmsg` 新 · `pselect`） · `SLIDE_MCAST_SELF_FIRE` · `SLIDE_MCAST_ROUNDS/GAP_US` · `SLIDE_SELF_FIRE_NICE` · `SLIDE_SENDMSG_NAMELEN`  
· `SLIDE_PLANT_OPT_A/B` · `SLIDE_PLANT_LEN_A/B`  
· `NEO11_PLANT_{NO_WRITE,TASK_ALIAS,TREE_SENTINEL,PI_AT_34,COMPACT,PI_PC_WAITER,TREE_PRIO,BLANKET}`  
· `NEO11_WRITE_VALUE/TARGET` · `NEO11_TASK_ALIAS`

本次新增（`slide.c` 的 `slide_mcast_write_stage()`）：

- `NEO11_PLANT_PI_PC_WAITER=1`：栈侧 word5（pi_tree.parent_color）改放 `fake_w0`（§3 单变量实验；在 NO_WRITE 之后生效）
- `NEO11_PLANT_TREE_PRIO=<n>`：覆盖 word3（waiter->tree.prio = walk 的 prio 闸门值）
- `NEO11_PLANT_BLANKET=<v>`：两份拷贝的每个 8 字节槽都填 `<v>`（与偏移无关的覆盖性探针）
- `SLIDE_SELF_FIRE_NICE=<n>`：自开火的 nice（prio = 120+n）；日志新增 `plant: words w3/w5/w7/w11/w12` 与 `plant: firing round/tid/nice`

离线工具（`poc/`，全部只需 `boot.img`）：  
`_tracefs_slide.py`（解 base）· `_pair_tracefs.py`（文本↔原始页配对定锚点）· `_btf_waiter.py`（BTF 结构体核对）·  
`**_stack_depth.py`（2026-09-22 新增：把 futex waiter 深度 W、各载体链深度 D、每个 copy 目的地的覆盖区间  
全部实测出来并判"能否够到 waiter"；MCAST/pselect 的结论就是它给的）\** ·  
`_walk_disasm.py`（反汇编 walk/adjust_pi/setprio/rb_erase 等并存盘）· `_mcast_shift.py`（旧：给符号出载体 delta，**帧算法漏 pre-index stp，结论 0x2d0 是错的**）· `_shift_check.py` · `_base_scan.py` · `_dtb_compare.py`

复现一发：

```
adb push ref-neo11/exploit/build/MEP-AN00-HONORMEP-AN00/bin/preload.so /data/local/tmp/p.so
adb shell 'SLIDE_DIAG=1 <开关> LD_PRELOAD=/data/local/tmp/p.so /system/bin/sh -c "echo x" > /data/local/tmp/x.log 2>&1'
adb shell cat /data/local/tmp/slide_child.log     # leak / plant / cfi 各阶段
```

注意：**panic 重启会丢掉最近 adb push 的 .so**（ext4 元数据未落盘），每次重启后要重新 push；  
而 `slide_child.log` 因为 fsync 会存活。

## 5. 外部参考

- `knowlily/cve-2026-43499-honor`（BVL-AN16，6.1.128）：判 pselect 载体"架构性不兼容"（内联 do_futex → shift=11；载体穷尽表）
- `yakidango-official/GhostLock-H80GT`（Honor 5.10，实机验证）：MCAST 载体 + 线程自开火 + KernelSU 装载
- `xrzcc/s26-m1q-ghostlock-selinux`：tracefs KASLR 移植
- `oopnv70-lab/ghostlock-honor-aak`（6.6.89）：AAK 版实现（页几何与 MEP 逐字节相同）
