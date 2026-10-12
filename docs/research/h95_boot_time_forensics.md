# H95 (2026-10-05 08:25) · boot 时刻反推 —— ★★★ 改写 H90 的定性

> 规程：`MEY-AN00-exploit-prompt-v2.md` v2（111 行，本轮已完整读取）
> 激活角色：阶段一（记录官 + 实验分析）+ 阶段二（逆向）
> 全程只读，**未推任何 exploit**

---

## 0. ★★★ 本轮核心发现：用 `uptime` 反推 boot 时刻，精确对上 panic

```
now      = 2026-10-05 08:25:15
uptime   = 32876.42 s
boot     = 2026-10-04 23:17:18      ← 反推
最后一次 panic = 2026-10-04 23:17:23 (page_request, AP_S_PANIC)
间隔    = -4 秒
```

**⇒ 设备当前这个 boot 就是在 23:17:23 那次 `page_request` panic 之后重启起来的，误差仅 4 秒。**

### 这条证据的威力

| 旧认知 | 新认知（H95 定案） |
|---|---|
| 「H90 开火 23:16:13 → 23:16:48 掉 USB → 35 秒」 | **掉 USB 就是那次 panic 的直接后果** |
| 「H90 之后设备失联 9 小时」 | 设备在 **23:17:23 重启后一直正常运行至今 9 小时** |
| 「H90 的写没有生效（`enforcing=1`）」 | **不能这样判定**——重启会丢失运行时修改，`enforcing=1` 只说明**当前 boot 是干净启动**，**完全无法说明 H90 当时写没写成功** |

**★ 这是本轮最重要的一条方法论修正：H94 §2.7.4 里「H90 写未生效 ⇒ 证伪」是错误推论，已撤回。**
H90 那次开火的写**成功与否至今未知**（判据通道 `enforcing` 跨越了重启边界，不成立）。

## 1. 本轮基线（铁律②，已复核）

| 项 | 值 |
|---|---|
| **boot_id** | `635e5e40-53e8-4a00-ac0e-b325eeeeb350`（真 UUID，与 H94 一致，未再变） |
| **uptime** | `32876.42` s（≈9.13 h） |
| 反推 boot 时刻 | **2026-10-04 23:17:18** |
| `getenforce` | `Enforcing` |
| `/sys/fs/selinux/enforce` | `1` |
| 环③ 基线 | 设备 1172 次 panic 的既存事实不变（H94） |

## 2. 环② 复跑：H92 脚本（`rb_erase` 写点① 落点判定）

`analysis/scratch/h92_rb_erase_csel.py` 重跑成功，输出与 H92 记录一致：

```
写点① = 0x3aa00  str x8,[x11]   (base=x11, disp=0)
x11 的写入者（按序，3 条）：
  0x3a9e0  mov  x11, x1        ← root
  0x3a9ec  mov  x11, x10       ← pc & ~3
  0x3a9fc  csel x11, x11, x13, eq
```

真链（`0x3a9e4..0x3a9fc`）：

```asm
0x3a9e4  ands  x10, x9, #-4        ; masked_pc = pc & ~3（只掩码副本，x9 不变）
0x3a9e8  b.eq  0x3aa00             ; ★ masked_pc==0 时捷径跳写点①，x11 仍 = root
0x3a9ec  mov   x11, x10
0x3a9f0  ldr   x12, [x11, #0x10]!  ; ★ 写回 ⇒ x11 = masked_pc + 0x10
0x3a9f4  sub   x13, x11, #8        ; x13 = masked_pc + 0x08
0x3a9f8  cmp   x12, x0             ; 比较 [masked_pc+0x10] 与 node
0x3a9fc  csel  x11, x11, x13, eq   ; eq ? (mpc+0x10) : (mpc+0x08)
0x3aa00  str   x8, [x11]           ; ★写点①
```

写点② 复核：`0x3aa10 str x9,[x8]`，门控 `0x3aa04 cbnz x8`（`forged_child==0` 即跳过）✔ 与档案一致。

### 2.1 ★ H88/H90 方案的落点复算（用 H92 真链重算）

H90 赋值（`c64560/f77.c:7768-7769`）：

```c
forged_parent = enforce_alias - 8;   /* pc = ss-8 */
forged_child  = 0;
```

代入 H92 真链：

```
pc          = ss - 8
masked_pc   = (ss-8) & ~3 = ss - 8        （ss 低 2 位为 0 ⇒ 掩码无效果）
masked_pc != 0  ⇒ 不走 0x3a9e8 捷径 ✔
x11 = masked_pc + 0x10 = ss + 0x08
x13 = masked_pc + 0x08 = ss + 0x00
csel 条件：[ss+0x08] == node(伪造 rb_node 地址) ?
  等 ⇒ 落点 ss+0x08
  不等 ⇒ 落点 ss+0x00  ★ 期望分支（enforcing）
```

**⇒ H90 的落点推导在 H92 真链下依然成立，且 `fc=0` 确实跳过写点②。**
**⇒ 但落点是 `ss+0x00` 还是 `ss+0x08`，取决于 `[ss+0x08] == node` 这个运行时判定，H90 未验证过。**
若落点实际是 `ss+0x08`，则写的是 `policycap[6..7]+android_netlink_*` 区域
（`+0x8,+0x9` 是 `policycap[6],policycap[7]`，`+0xa,+0xb` 是两个 `android_netlink` 标志），
清零它们**不一定崩**（policycap 走 fallback 保守分支，见档案 §4.1）——
**这可能解释 23:17:23 的 `page_request` 不完全，也解释不了**（需下面 §2.2）。

### 2.2 ⚠ `page_request` 与写点①落点无关 —— 真因在别处

`page_request` = 缺页/野指针。写点①落点无论 `ss+0x00` 还是 `ss+0x08`，
都在内核 `.data` 段内（`selinux_state` 所在页），**写它不会缺页**。

⇒ **23:17:23 的 `page_request` 极可能不是写点①造成的，而是：**

| 候选 | 说明 |
|---|---|
| **① spray / stage0 的连带损伤** | 档案 §5.1 记有历史地雷：`STRIDE=0x108` 会把 `forged_child`（内核地址）写进相邻 `k_itimer.hrtimer.function` ⇒ **函数指针被污染后调用即 `page_request`**。H90 用的是修正后的 `0xe8`，但 `FAKE_MISC_RECORD_STRIDE` 等其他 spray 参数是否仍错配需复核。 |
| **② 伪造 rb_node 破坏了真实 rbtree** | `rb_erase` 是真调用的，会从 timer 队列里摘节点。若 `forged_node` 未真正挂在树上、或挂在错误位置，后续 timer 操作会踩野指针。 |
| **③ 写点③（Path B）意外触发** | `rb_left != 0` 时 `0x3aa2c/0x3aa40` 生效，`str x10,[x9,#0x10]` / `str x12,[x10]` 是真树的指针写。 |

**⇒ 这三条都是"真实节点操作"的连带损伤，与"往 selinux 写 0"无关。**
**⇒ 这是本轮最重要的待解项：必须先区分「写点① 是否成功」与「page_request 来自何处」。**

## 3. ★ 为什么必须做「最小化验证」—— 判据设计

**问题**：写点①成功与否**无法在事后观测**（`enforcing` 会被重启重置；重启又会抹掉一切痕迹）。

**方案（阶段三执行，本轮只设计不开火）**：

| 步 | 动作 | 判据（独立透镜） |
|---|---|---|
| 1 | 改 `forged_parent` 指向 **`boot_id` 表项尾部 8 字节**（`alias(sysctl_bootid)+0x30`，对齐），`forged_child = 0` | 写 0 到该处 ⇒ `cat /proc/sys/kernel/random/boot_id` 的**尾部 8 字节变 0**。**boot_id 是内核字符串，跨重启会被重新生成，但我们只在本 boot 内立刻回读** |
| 2 | 同一 boot 内立即 `cat boot_id` 回读 | 尾部 8 字节 = 0 ⇒ **写点①链路 + 落点判定 `[mpc+0x10]==node` 全部打通** |
| 3 | 若步 2 失败（尾部非 0） | 说明落点走了 `ss+0x08` 分支或 `masked_pc==0` ⇒ **判定条件需要重新设计**（此时要构造让 `[mpc+0x10]==node` 成立的布局） |
| 4 | 若步 2 成功 | 再把目标换回 `enforcing`，单发验证 `getenforce` |

**★ 关键纪律：`boot_id` 尾部 8 字节是"写完立刻回读"的独立透镜，且本 boot 内完成 ⇒ 不跨重启，不违反铁律②。**
**★ 风险控制：`boot_id` 尾部被清零不影响功能（内核每次启动重新生成 UUID），比写 selinux 更安全，可反复试。**

## 4. 三环对照表（本轮）

| 对象/函数 | 源码推断（GKI 核心标权威基线 6.6.56==r17） | 汇编实测（Image-mey 基址=0） | img 差异 | 一致 | 矛盾待解 |
|---|---|---|---|---|---|
| `rb_erase` 写点①落点 | 源码仅语义（`__rb_erase_augmented` 内联），无落点细节 | **H92 真链复跑确认**：`csel` 条件 = `[mpc+0x10]==node`；`mpc==0` 有捷径落 `root` | 荣耀无 `lib/rbtree.c` 改动（GKI 核心） | ✅ 环①② | 档案 §3.1「由 `fp&~3!=0` 经 csel 选 +8/+10」**表述错误**，须改为 `[mpc+0x10]==node` |
| H90 落点推导 | — | 用 H92 真链重算：`fp=ss−8, fc=0` ⇒ 落点 `ss+0x00`（条件：≠node）或 `ss+0x08` | — | ⚠️ | **落点依赖运行时判定 `[ss+0x08]==node`，H90 从未验证** |
| `enforcing` 写是否成功 | — | — | — | ⚠️ **判据不成立** | H94「`enforcing=1` ⇒ 未生效」是**错误推论**（跨重启），已撤回 |
| `page_request` 真因 | — | 写点①落点在内核 .data，**不会缺页** | — | ❌ | 真因疑在 **spray 参数错配 / 真实 rbtree 破坏 / 写点③**，三者未区分 |
| 设备稳定性基线 | — | — | 1172 次既存 panic（H94） | ✅ | 与本轮结论一致 |

## 5. ★★★ 阶段二重大突破：`page_request` 真因定位（推翻 §2.2 三候选）

### 5.1 新证据 A：spray 落点无越界（Python 逐槽核算，铁律①）

```
STRIDE=0xe8  FIRST=0x78  SLOTS=9  ORDER1_SIZE=0x2000
slot 0..8 写入区间 [0x78, 0x7d0)   越界槽数 = 0   ✔
每槽只写 24 B（parent/child/expires），槽间空洞 0xd0 B 不写
⇒ 不会碰到 +0x28 之后的 hrtimer.function（历史地雷 STRIDE=0x108 已修）
```

⇒ **§2.2 候选①（spray 参数错配）已排除。**
⇒ 另核实 `build_misc_fragments` 调用（7804 行）在 `forged_parent` 赋值（7745–7769）**之后**，
时序正确，fragment 用的是 selinux 目标值 ✔

### 5.2 新证据 B：环② 实测 `timerqueue_del` 全序列（本轮新反汇编）

```asm
timerqueue_del @0x3f7d8:
  0x3f7e8  ldr  x8, [x1]           ; x8 = node->__rb_parent_color
  0x3f7f4  cmp  x8, x1             ; ★ parent_color == node ?（self-loop 检查）
  0x3f7f8  b.eq 0x3f840            ;   是 ⇒ 提前返回
  0x3f7fc  ldr  x8, [x20, #8]      ; x8 = tq->rb_root.rb_node.right
  0x3f800  cmp  x8, x19
  0x3f804  b.ne 0x3f814
  0x3f80c  bl  0x3af24             ; __rb_erase_augmented
  0x3f810  str  x0, [x20, #8]
  0x3f814  mov  x0, x19
  0x3f818  mov  x1, x20
  0x3f81c  bl  0x3a9d4             ; ★ rb_erase(node, &tq->rb_root)
  0x3f820  str  x19, [x19]         ; ★★ 无条件写回 node->__rb_parent_color = node
  0x3f824  ldr  x8, [x20]
  0x3f828  cmp  x8, #0
  0x3f82c  cset w0, ne
```

```asm
rb_erase @0x3a9d4:
  0x3a9d4  ldp  x8, x10, [x0, #8] ; x8 = node->rb_right = forged_child = 0
                                    ; x10 = node->rb_left
  0x3a9dc  ldr  x9, [x0]           ; x9 = node->__rb_parent_color = forged_parent
```

### 5.3 ★★★ 真因：`forged_parent` 的**双重身份**被误用（可证伪链条）

| 步 | 事实 | 推论 |
|---|---|---|
| 1 | 我们把 `node->__rb_parent_color` 写成 `fp = 0xffffff802a3ba410`（= `ss−8`） | 这是**内核 .data 段内的合法地址**，本身不缺页 |
| 2 | Python 复算：`masked_pc = fp & ~3 = 0xffffff802a3ba410`；`x13 = mpc+0x08 = 0xffffff802a3ba418` | 写点①落点 = `ss+0x00` = enforcing ✔ **推导自洽** |
| 3 | csel 条件 = `[mpc+0x10] == node`；`mpc+0x10` 落在 `policycap[6]/[7]` 字节 | 该值是 0/1 布尔量，而 `node` 是**堆地址** ⇒ **条件几乎必然为假** ⇒ 走 `x13` 分支 ✔ |
| 4 | **但 `rb_erase` 返回后还有 `____rb_erase_color` 重平衡** | 它会**解引用 parent 指针**读 `rb_node.left/right` |
| 5 | `fp` 指向的 `.data` 内容是**其它内核变量**，被当作子树指针 | 读出**垃圾值** |
| 6 | 垃圾值被继续遍历 / 被当作写入目标 | **往野地址 `str` ⇒ `page_request`** |

⇒ **★ 这就是 23:17:23 那次 `page_request` 的最可能来源。**
⇒ **不是**写点①打 selinux 造成的（写 `.data` 不缺页）。
⇒ **是写原语设计层面的缺陷**：H88/H90 只考虑了「让 0x3aa00 命中目标」，
**忽略了 `rb_erase` 之后仍有重平衡代码继续【读】parent 链**。

### 5.4 ⚠️ 连带发现：`0x3f820 str x19,[x19]` 无条件写回

`timerqueue_del` 在 `rb_erase` 返回后**无条件**执行 `node->__rb_parent_color = node`。
若 `rb_erase` 内部已破坏 node 自身结构，此处往野指针写 ⇒ 第二个 `page_request` 候选。

### 5.5 落点推导的自我修正（★ 修正本文 §2.2 与 §3 的表述）

§2.2 与 §3 当时写「落点依赖运行时判定 `[ss+0x08]==node`，H90 从未验证」。
**本轮 Python 复算后可以收紧**：该判定几乎必然为假（左边是 `policycap` 的 0/1 布尔字节，
右边是堆地址）⇒ **H90 期望的 `ss+0x00` 落点是可靠的**。
§2.2 候选②（伪造 rb_node 破坏真实树）**升级为主因**，因为它是唯一能解释
「写 `.data` 不缺页却仍 `page_request`」的机制。

## 6. 三环对照表（更新）

| 对象/函数 | 源码推断（GKI 核心 6.6.56==r17 权威） | 汇编实测（Image-mey 基址=0） | img 差异 | 一致 | 矛盾待解 |
|---|---|---|---|---|---|
| `rb_erase` 写点①落点 | 源码仅语义，无落点细节 | H92 真链：`csel` 条件=`[mpc+0x10]==node`；`mpc==0` 有捷径落 `root` | 荣耀无 rbtree 改动 | ✅①② | 档案 §3.1「由 `fp&~3!=0` 经 csel 选 +8/+10」**表述错误待修** |
| H90 落点推导 | — | Python 复算：`fp=ss−8` ⇒ `mpc=ss−8`、`x13=mpc+0x08=ss+0x00`；条件几乎必然假 | — | ✅ | 无（推导自洽，§2.2 表述已收紧） |
| spray 落点 | — | Python 逐槽核算：无越界，空洞 0xd0 B | — | ✅ | **排除** §2.2 候选① |
| **`page_request` 真因** | `____rb_erase_color` 沿 parent 链重平衡 | `0x3f81c bl rb_erase` + `0x3f820 str x19,[x19]` 无条件写回 | — | ⚠️ **推断，待实测** | 需验证：构造自洽 fake parent 后是否不再 panic |
| 写点①是否成功 | — | — | — | ⚠️ 判据不成立 | 跨重启，事后不可观测 |
| 设备稳定性基线 | — | — | 1172 次既存 panic（H94） | ✅ | 与本轮结论一致 |

## 7. ★ 下一轮方案（阶段二已给完整设计，阶段三执行）

**核心思路：让 fake parent 链自洽，或让重平衡路径不成立。**

| 方案 | 做法 | 判据 |
|---|---|---|
| **A. 最小化验证（首选）** | `forged_parent` 改为指向 `alias(sysctl_bootid)+0x30`（**无害**区），`forged_child=0`，本 boot 内立刻 `cat /proc/sys/kernel/random/boot_id` 回读 | 尾部 8 字节变 0 ⇒ 写点①链路打通；不变 ⇒ 条件分支需重新设计 |
| **B. 让 parent 自洽** | fragment 里额外构造**结构完整**的 fake parent（`left/right/parent_color` 三字段自洽），使重平衡读到的都是合法可解引用地址 | 不再 `page_request` 且 boot_id 尾部确实变 0 |
| **C. 绕开重平衡** | 利用 `0x3f7f4 cmp x8,x1 / b.eq` 的 self-loop 提前返回 | **此路不通**：`b.eq` 直接跳过 `rb_erase` ⇒ 无写原语 |

**★ 风险控制：A 方案用 `boot_id` 尾部而非 selinux，风险极低（内核每次启动重新生成 UUID），可反复试。**
**★ 纪律：A/B 都在本 boot 内立刻回读，不跨重启 ⇒ 不违反铁律②。**
**★ 每次开火前后各拉一次 `history.log`（H94 新增纪律），区分我们的 panic 与既存 panic。**

## 8. 本轮产出

| 文件 | 说明 |
|---|---|
| `analysis/output/h95_boot_time_forensics.md` | 本文件（★ 含 `page_request` 真因推断） |
| `analysis/scratch/h92_rb_erase_csel.py` | 环② 复跑（输出与 H92 一致，可复用） |
| 设备侧 | `history.log`（1172 行，H94 统计） |

## 9. 结论摘要

1. ★★★ **设备 boot 时刻 = 23:17:18，与最后一次 panic 差 4 秒** ⇒ 掉 USB 是 panic 的后果，
   设备**一直正常运行至今 9 小时**，**没坏**。
2. ★★★ **撤回 H94 的「H90 写未生效」推论** —— 判据跨越了重启边界，不成立。
3. ★★ H90 落点推导在 H92 真链 + Python 复算下**成立**（`ss+0x00`，条件几乎必然为假）。
4. ★★★ **spray 参数无越界，排除**档案 §5.1 地雷与 §2.2 候选①。
5. ★★★ **`page_request` 真因高度指向 `____rb_erase_color` 沿伪造 parent 链重平衡时踩野指针**
   —— 写原语**设计层面缺陷**，不是地址算错。方案 A/B 已就绪。

