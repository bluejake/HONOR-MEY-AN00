# H165 · `h50_live_hit.log`（命中轮） vs `h163b_r5_h50geom.log`（640 发全 miss） 逐发时序比对

- 纯本地读日志，未占用设备（仅 `adb pull` 取日志）。
- 输入：`analysis/output/h50_live_hit.log`（10-04 17:22，175 KB）｜`analysis/output/h163b_r5_h50geom.log`（10-05 18:20，682 KB）
- 工具：`analysis/scratch/h165_lane_diff.py`（逐发解析 + 命中/未命中分组统计）

---

## 0. 结论速览

| # | 差异 | 命中轮 H50 | r5（全 miss） | 性质 |
|---|---|---|---|---|
| **A** | **喷射槽位数（根因）** | `FAKE_MISC_SLOTS`=**31**，`stride=0x108` ⇒ 每 8192 B 片段写 **31 组**伪造 (parent,child)，铺到 `0x1F70` | `FAKE_MISC_SLOTS`=**9**（H82 改）⇒ 只写 **9 组**，铺到 `0x8C0` | **决定性**：喷射密度 −71% |
| A′ | `SCAN_DIAG` 实测 | `forged_parent=31 zero=0`（**每发如此**） | `forged_parent=9 zero=22`（**每发如此**，639/639） | 上条的运行时铁证 |
| A″ | env 旋钮失效 | — | `MEY_FAKE_TIMER_SLOTS=31` **只改扫描窗口，不改构造** | 见 §3 |
| **B** | **`exec_after_deleted`** | **8000** | **54000**（H12"官方真值"） | 时序错位 |
| B′ | exec 触发点 | `threshold` 中位 **5.83 ms** | `threshold` 中位 **27.65 ms**（晚 **4.7×**） | 见 §2 |
| B″ | 阶段分离 | `MEY_STAGE_SPLIT ...=8000 (enabled)` | `-1 (disabled)` | 见 §2 |
| C | 结果 | **attempt=120 命中**（`BOOTID_WRITE_PASS`），命中率经验 1/120 | **640 发 0 命中** | — |
| — | `ORDER1_RECLAIM_GATE changed_nodes` | 未命中发同样 **0** | **0**（639/639） | 非判别项：两者 miss 签名相同 |

---

## 1. 逐发对照（前 8 发，`slot / forged_parent / zero / changed_nodes / threshold_ms / victim_seen_ms / exec_us / result`）

| # | H50 slot | fp | z | cn | thr_ms | seen_ms | exec_us | res | R5 slot | fp | z | cn | thr_ms | seen_ms | exec_us | res |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 13 | 31 | 0 | 0 | 7.32 | 7.33 | 8812 | MISS | 13 | 9 | 22 | 0 | 27.60 | 27.60 | 28501 | MISS |
| 2 | 32 | — | — | 0 | 4.63 | 4.65 | 6268 | MISS | 32 | — | — | 0 | 27.70 | 27.71 | 28637 | MISS |
| 3 | 21 | — | — | 0 | 4.12 | 4.13 | 5370 | MISS | 21 | — | — | 0 | 27.62 | 27.63 | 28571 | MISS |
| 4 | 1 | — | — | 0 | 5.66 | 5.69 | 7287 | MISS | 1 | — | — | 0 | 27.67 | 27.68 | 28628 | MISS |
| 5 | 13 | — | — | 0 | 8.11 | 8.12 | 9572 | MISS | 13 | — | — | 0 | 27.56 | 27.57 | 28468 | MISS |
| 6 | 32 | — | — | 0 | 8.19 | 8.20 | 9614 | MISS | 32 | — | — | 0 | 27.73 | 27.73 | 28651 | MISS |
| 7 | 21 | — | — | 0 | 5.92 | 5.94 | 7472 | MISS | 21 | — | — | 0 | 27.81 | 27.82 | 28747 | MISS |
| 8 | 1 | — | — | 0 | 5.61 | 5.62 | 7132 | MISS | 1 | — | — | 0 | 27.78 | 27.78 | 28718 | MISS |

> `timing_slot` 在两份日志里都是"第 N 发"的编号（H50 循环 1..120，r5 1..640），**语义一致**，不是差异点。
> `SCAN_DIAG` 每轮只打印前 6 次（`diag_left=6`），故只有前若干发带 fp/z 字段；两者取值全程恒定（31/0 与 9/22）。

## 2. 时序指标分组统计（中位 / [min,max]）

| 指标 | H50（n=144 miss 发） | r5（n=639 miss 发） | 倍数 |
|---|---|---|---|
| `threshold_ns` | 5.83 ms [3.70, 8.29] | **27.65 ms** [21.01, 28.12] | 4.7× |
| `victim_seen_ns` | 5.84 ms [3.71, 8.31] | 27.65 ms [21.02, 28.13] | 4.7× |
| `exec_call_ns` | 5.85 ms [3.71, 8.32] | 27.66 ms [21.03, 28.14] | 4.7× |
| `exec_delay_ns` | 4.94 ms [0.06, 9.82] | 4.99 ms [0.02, 9.99] | ≈1（同分布） |
| `delete_us` | 33.5 ms [28.1, 38.5] | 29.0 ms [22.3, 37.0] | 0.87× |
| `exec_us` | 7.3 ms [4.7, 9.8] | **28.6 ms** [22.7, 29.1] | 3.9× |
| `exec_last_us` | 9.4 ms | 30.2 ms | 3.2× |
| `seen_min_ns` | 833 ns [260, 2031] | 521 ns [208, 1354] | ≈1 |
| `prime_begin/end_ns` | 51.9 μs | 30.7 μs | 0.6× |
| `span_us`（EXEC_REPEAT） | 2.12 ms [1.64, 3.77] | 1.66 ms [1.30, 2.28] | 0.78× |

**读法**：`exec_delay_ns` 分布几乎相同（说明 victim 侧的感知延迟机制没变），但 **`threshold` 与 `exec_call` 整体右移 4.7 倍** ⇒ exec 在 delete 流里被推到**更晚的时间点**才触发，而 `delete_us` 反而略短（29 ms vs 33.5 ms）⇒ **exec 落在 delete 尾部之外**（H50 是 ~5.9 ms / 33.5 ms ≈ 17% 处；r5 是 ~27.7 ms / 29.0 ms ≈ 95% 处，几乎贴到 delete 结束甚至超出）。
⇒ **`exec_after_deleted=54000` 把 exec 推到了窗口边缘。**

## 3. ★ 根因：`MEY_FAKE_TIMER_SLOTS` 旋钮改了扫描、没改构造

`c64560/f77.c`：
```c
1739  static void build_fake_fragment(unsigned char fragment[ORDER1_SIZE]) {
1743      for (int i = 0; i < FAKE_MISC_SLOTS; i++) {          /* ← 构造用的是【宏】 */
1744          size_t offset = FAKE_CPU_TIMER_FIRST_OFF + (size_t)i * (size_t)fake_timer_stride;
1746          memcpy(fragment + offset, &forged_parent, sizeof(forged_parent));
...
2849          changed += scan_segment(fragments, (size_t)repeat * ORDER1_SIZE, fake_timer_slots); /* ← 扫描用的是【env 变量】 */
```
两版宏值：

| 宏 | H50 快照 `f77.c.bak_h50_171138` | 当前 `f77.c` |
|---|---|---|
| `FAKE_MISC_SLOTS` | **31** | **9**（`/* H82: (0x2000-0x100)/0x50 = 99 = 11*9 */`） |
| `FAKE_CPU_TIMER_STRIDE` | **0x108**（硬编码） | `0xe8` 默认（env 可设 0x108） |
| `FAKE_CPU_TIMER_FIRST_OFF` | 0x78 | 0x78 |
| `FAKE_MISC_CLASSES` / `FAKE_MISC_RECORDS` | 11 / **341** | 11 / **99** |
| `ORDER1_SIZE` / `SPRAY_REPEATS` | 0x2000 / 3 | 0x2000 / 3 |

后果链：
1. H50 命中轮：31 槽 × 0x108 stride ⇒ 伪造 (parent,child) 铺到 `0x78+30*0x108+8 = 0x1F70`，**几乎铺满 8192 B**；`SCAN_DIAG forged_parent=31 zero=0`。
2. r5：`FAKE_MISC_SLOTS=9` ⇒ 只铺到 `0x78+8*0x108+8 = 0x8C0`（**2.2 KB / 8 KB**）；env `MEY_FAKE_TIMER_SLOTS=31` 把**扫描窗口**拉到 31 槽 ⇒ `forged_parent=9 zero=22`（9+22=31，完全吻合）。
3. ⇒ **实际喷射密度只有命中轮的 29%**，命中率从经验 1/120 崩到 0/640。
4. 附带：`FAKE_MISC_RECORDS` 从 341 降到 99（bridge 载荷也缩了 71%）。

## 4. 附带确认（H50 究竟"命中"到哪一步）

H50 日志在 `BOOTID_WRITE_PASS attempt=120` 后继续跑到 `STAGE0_GATE_PASS` → `CROSSCACHE_KS leaked=… slot=6/19` → `STAGEB_FORGED_PARENT` → `MISC_BRIDGE_STAGE_BEGIN`，随后是 stage-B 阶段自己的 `ATTEMPT_MISS`（29/31/32…）⇒ **H50 证明的是"写原语命中并能改写 boot_id"，不是完整 root**。与档案一致（H50 铁证 = `rb_erase` 写原语可用），**不推翻任何既有结论**。

该 boot 的即时变量（可用于后续配方）：`slide=0x1382c00000`、`kernel_base=0xffffffd402c00000`、`parent=0xffffff802a29b188`、`target=0xffffff802a29b190`、`image_equiv=0xffffffd404e9b188`、`leaked=0xffffff8b290b9e00 / 0xffffff8b2a4d5f00`。

## 5. 修复建议（按 A/B 优先级，精确到行）

| 优先级 | 动作 | 位置 |
|---|---|---|
| **P0** | **恢复喷射槽位 31**：把 `FAKE_MISC_SLOTS` 改回 31，或让构造循环改用 `fake_timer_slots`（推荐后者，使 env 旋钮真正生效） | `f77.c:453`（宏）与 `f77.c:1743 / 1771 / 1791`（三处循环上界） |
| **P0** | 确认 `stride` 走 0x108（当前默认 0xe8；r5 已用 env 覆盖，但默认值应同步） | `f77.c:455/758` |
| **P1** | **`exec_after_deleted` 回到 8000**（命中轮实测值），并恢复 `MEY_STAGE_SPLIT` enabled | `f77.c:7247`（硬编码 54000）、env `MEY_EXEC_AFTER_DELETED`/`MEY_STAGEB_EXEC_AFTER_DELETED` |
| P2 | 再跑一发纯 A/B：P0 单改（保持 54000）vs P1 单改（保持 slots=9），把两个变量解耦 | — |
| P3 | 每次跑前自检 `SCAN_DIAG`：只要出现 `zero>0`，说明构造与扫描窗口不一致，**立即停跑**（免烧一个 boot） | 运行规程 |

> ⚠ 与现存档案冲突：工作记忆「H50 权威配方」写明「**不设** `MEY_EXEC_AFTER_DELETED`（内置 54000=H12 官方真值；**旧 8000 几何错位已作废**）」。但**命中轮日志的实测量就是 8000**，且 54000 在 r5/H163b 四轮共 0 命中。建议按 P1 重做 A/B 后再定案，不要预设结论。

## 6. 产物
`analysis/scratch/h165_lane_diff.py`（逐发解析器）｜`analysis/output/h163b_r5_h50geom.log`（已从设备取回本地）｜本文 `analysis/output/h165_lane_done_diff.md`
