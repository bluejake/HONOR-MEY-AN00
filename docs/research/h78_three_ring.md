# H78 三环对照表 · W1 槽位语义与 −8 偏移根因定案

> 生成时间：2026-10-04 20:5x · 规程：`MEY-AN00-exploit-prompt-v2.md` §三
> 所有 hex/偏移均用 Python（ctypes offsetof）复核，铁律①。

## 一、根因一句话

`f77.c` 的 W1 把 `forged_parent = &misc_list − 8` 写进 `hrtimer.node.__rb_parent_color`，
`rb_erase` 因此执行 `[&misc_list − 8] = forged_child` —— **该地址落在 `misc_list`
前一个成员的尾部，内核从不读取** ⇒ 写入成功但**永不生效** ⇒ `misc_list.next`
永不被改 ⇒ 真 `uhid` 存活 ⇒ `bridge_read64` 必 `-ENOTTY(25)`。

## 二、三环对照表（固定模板）

| 对象/函数 | 源码推断（环①，6.6.56==r17 权威基线） | 汇编实测（环②，Image-mey 基址=0） | img 反汇编差异（环③） | 一致性 | 矛盾待解项 |
|---|---|---|---|---|---|
| `struct k_itimer` 布局 | `kernel/include/linux/posix-timers.h:223-252`：`list@0x00`、`t_hash@0x10`、`it_lock@0x20`、`kclock@0x28`、`it_clock@0x30`、`it_id@0x38`、`it_active@0x3c`、`it_overrun@0x40`、`it_overrun_last@0x48`、`it_requeue_pending@0x50`、`it_sigev_notify@0x54`、`it_interval@0x58`、`it_signal@0x60`、`it_pid@0x68`、`sigq@0x70`、**`it@0x78`**、`rcu@0xd8`；`sizeof=0xe8`（ctypes 精确算） | — | 无厂商 delta（`kmem_cache_create("posix_timers_cache", sizeof(struct k_itimer), …)` at `posix-timers.c:225`，对象大小=源码 sizeof） | ✅ | — |
| **`union it @ 0x78`** | `it.real.timer`（hrtimer）/ `it.cpu`（cpu_timer）/ `it.alarm.alarmtimer` 三分支同起点 | — | — | ✅ | ★★ **`FAKE_CPU_TIMER_FIRST_OFF = 0x78` 与之精确吻合** ⇒ 槽位几何正确 |
| `struct hrtimer` | `kernel/include/linux/hrtimer.h:119-130`：`node@0x00`（timerqueue_node）、`_softexpires@0x20`、`function@0x28`、`base@0x30`、`state@0x38`；`sizeof=0x40` | — | — | ✅ | — |
| `struct timerqueue_node` | `kernel/include/linux/timerqueue.h:9-12`：`rb_node node@0x00`（`__rb_parent_color@0x0`/`rb_right@0x8`/`rb_left@0x10`）、**`expires@0x18`** | — | — | ✅ | ★★ 与 `f77.c` 写的 `+0x00=parent`/`+0x08=child`/`+0x18=expires` **三处全对齐** |
| `__remove_hrtimer` | `kernel/kernel/time/hrtimer.c:1110-1123`：`WRITE_ONCE(timer->state,newstate)`；`if(!(state&HRTIMER_STATE_ENQUEUED))return;`；`timerqueue_del(&base->active,&timer->node)` | `0xffffffc08003f49c: ldrb w8,[x0,#0x38]` ← **state@0x38 精确吻合**<br>`0x3f4a4: strb w2,[x0,#0x38]` ← WRITE_ONCE(state)<br>`0x3f4a8: tbz w8,#0,…` ← `if(!(state&ENQUEUED))return`<br>`0x3f4b4: add x0,x1,#0x20` ← **`&base->active`**（active@base+0x20）<br>`0x3f4c0: bl 0x3f7d8` ← **`timerqueue_del`** | 无 delta | ✅ **三环完全闭合** | — |
| `timerqueue_del` | `timerqueue_del()` → 检查 `node->__rb_parent_color != node` → `rb_erase(node,parent)` | `0xffffffc08003f7d8`(入口)：<br>`0x3f7e8: ldr x8,[x1]` ← `node->__rb_parent_color`<br>`0x3f7f4: cmp x8,x1 / 0x3f7f8: b.eq → 0x3f840: brk #0x800` ← **自检分支**<br>`0x3f7fc: ldr x8,[x20,#8]` ← `parent->rb_right`<br>`0x3f808: bl 0x3af24` ← `__rb_rotate_right`<br>`0x3f810: str x0,[x20,#8]` ← **写 parent->rb_right**<br>`0x3f81c: bl 0x3a9d4` ← ★★ **`bl rb_erase@0x3a9d4`（CVE-2026-64560 同一函数）**<br>`0x3f820: str x19,[x19]` ← 写 `node->__rb_parent_color=node` | 无 delta | ✅ | ★★ **W1 的写原语 = CVE-2026-64560 `rb_erase`，路线确认，非 rt_mutex/pselect** |
| 框架权威写语义 | `refs/ghostlock-x200-root/exploit/src/slide.c:130-152` `GL_TASK_W2`：`tree={pc=GL_TARGET−8, right=init_cred, left=0}` ⇒ 触发 `__rb_change_child` 的 `parent->rb_left != N` 分支 ⇒ 写 **`[GL_TARGET] = child`** | 同上 `rb_erase` 入口 | 框架针对 x200 机型，偏移不同 | ✅ 机理同构 | — |
| `misc_list` 语义 | `list_head{next@0, prev@8}`（环② `misc_open@0x4ea3fc` 已证 `adrp→0xffffffc08229b000`+`add #0x190`） | `0x4ea448: ldur w8,[x24,#−0x18]`=minor；`0x4ea454: ldur x8,[x24,#−8]`=fops | 无 delta | ✅ | ★★★ **`&misc_list−8` 落在 list_head 之前的内存，内核从不读** |

## 三、`0x108` 步长的独立隐患（不影响本次结论，但需记账）

| 项 | 值（Python 复核） |
|---|---|
| `sizeof(struct k_itimer)` | `0xe8`（232 B） |
| `FAKE_CPU_TIMER_STRIDE` | `0x108`（264 B）— **≠ 对象大小** |
| slot i 绝对偏移 | `0x78 + i*0x108`；slot0=`0x78`、slot1=`0x180`、slot30=`0x1f68` |
| slot30 末端 | `0x1f68+0x40 = 0x1fa8 < ORDER1_SIZE(0x2000)` ⇒ 不溢出 |
| `union it` 实际大小 | `0xd8 − 0x78 = 0x60`（96 B） |

⇒ `0x108` 既非 `sizeof(k_itimer)` 也非 union 大小，**槽位之间不可能都是 hrtimer 起点**。
即：31 个 slot 中**只有 slot 0（偏移 `0x78`）精确落在真实 hrtimer 上**，其余 30 个都错位。
这**不解释** 0 HIT（slot0 足够），但会显著降低有效槽位数 ⇒ 属**独立的命中率削减因素**，留待 H79 核实真实步长。

## 四、被证伪/降级的假设

| 假设 | 判定 | 依据 |
|---|---|---|
| H76-A image/physmap 域错页 | ❌ **证伪** | `domain=image_va` 精确命中地址；11 轮全 ENOTTY |
| W1 写的是 `list_head{next,prev}` | ❌ **证伪** | 实为 `timerqueue_node.rb_node`（红黑树） |
| W1 写的是 `timer_list`（hlist） | ❌ **证伪** | slab 是 `posix_timers_cache`=`struct k_itimer`，非 `timer_list` |
| W1 走 rt_mutex/pselect 路线 | ❌ **证伪** | 环②：`timerqueue_del` 内直接 `bl rb_erase` |
| `−8` 偏移使写入落在 `misc_list` 上一成员尾部 | ✅ **成立**（本轮定案） | 框架 `GL_TASK_W2` 口径 + `list_head` 布局 |
| `text=90b0292a` 是命中判据 | ⚠️ **表述错误** | 它是 `%.8s` 截断的 boot_id 文本，且打印在 MISS 分支内（`f77.c:2248-2259`） |
| 两个 `CROSSCACHE_ALLOC` base 冲突是 bug | ❌ 排除 | `f77.c:7613/7615` 分工：`page.base`=fake misc 记录区；`carrier.base`=`pipe_phys_read` |
| 日志截断 = 预算耗尽 | ❌ 排除 | `controlled_max_attempts=200` 远未用尽 ⇒ 进程被杀（写 `boot_id` 致重启，延迟 ≈2 个 stageB attempt） |

## 五、待验证（本轮实测）

**H78 核心断言**：`forged_parent` 从 `&misc_list−8` 改为 `&misc_list+0`（`off_delta=0`）后，
`rb_erase` 将执行 `[&misc_list] = forged_child`，即直接改写 `misc_list.next`
⇒ `misc_open` 遍历第 1 步即命中假节点 ⇒ `H74_IOCTL_GATE verdict=HIT`。

**实测配置**：`MEY_STAGEB_IMAGEVA=1` + `MEY_STAGEB_PARENT_OFF_DELTA=0` + `MEY_H74_IOCTL_GATE=1`
+ H72 标准运行配置（`fanout` / 两个 `EXEC_AFTER_DELETED=8000`），stage0 预算 512、stageB 200 分组短跑。

**判据**：`H74_IOCTL_GATE verdict=HIT`（无循环依赖）⇒ 桥开 ⇒ 可进 H49（text 段可写验证）。
