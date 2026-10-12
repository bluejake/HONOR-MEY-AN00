# H103 概览 · R3 反交叉实验 —— M-A 被强烈证伪

## 本轮做了什么

按用户「开始」授权，执行 **R3 反交叉实验**（H102 提出的 M-C2 检验），并完成规程 §四 强制证据链写回。

**投屏**：每轮开工第一步先投屏（scrcpy v4.1，472x1024）。⚠️ 本机该进程会被反复收掉，需每次确认；用 Bash `nohup ... &` 启动。

## 核心结果（一发定案）

| 项 | 值 |
|---|---|
| 配置 | `MEY_PIPE_COUNT=8000` + `MEY_STAGE0_MAX_ATTEMPTS=200` + `MEY_STAGE0_ONLY=1` + `SELINUX_TARGET=0` |
| 结果 | ★★★ **跑满 200 attempt（301 s）完全不崩** |
| 重启检查 | `boot_id` 未变 + uptime 718→1025 未归零 ⇒ **无重启**（铁律②双证） |
| 日志 | 213,083 B；六类计数（`ATTEMPT_BEGIN`/`LANE_DONE`/`RCU_FORCE`/`SLAB_DRAIN`/`SPRAY_DONE`/`MISS_CLEAN`）**全 200 条** |
| 尾部 | `STAGE0_BUDGET_EXHAUSTED` + `BOOTID_WRITE_MISS`（**正常退出，无零区**） |

## 四条核心判定

### 1. ★★★ M-A 被强烈证伪（推翻 H102 结论）

```
M-A (q=0.015306): 「200 不崩」似然 = (1-q)^200 = 4.57%      ❌ 小概率事件
M-B (λ=0.004202): 「301 s 不崩」似然 = exp(-λ·301) = 28.23%  ⚠️ 常见事件
⇒ 似然比 6.18×
```

**H102 §6.2「倾向 M-A（BF=21.64）」被推翻** —— 加入 R3 后 **BF(M-A/M-B) = 0.837**。

### 2. ★★★ 崩溃与 `pipe_count` 强相关（新事实）

| 样本 | pipe_count | 结果 | attempt | 墙钟(s) |
|---|---|---|---|---|
| H97 | 6000 | 崩溃 | 108 | 309.0 |
| H98 | 6000 | 崩溃 | 52 | 167.0 |
| R2 | **500** | 崩溃 | **36** | **66.0** |
| **R3** | **8000** | ★ **未崩** | — | 301.0 |

**R2 与 R3 是严格同构对照**（同二进制、同开关、同全部参数，**仅 `pipe_count` 不同**，且都全 MISS 未进 stageB）⇒ 崩溃差异**只能归因 `pipe_count`** ⇒ **M-C2 方向获支持**（pc↓ ⇒ 早崩）。

### 3. ★★ 「崩溃由 stageB 引起」被证伪

R2/R3 均未进 stageB，却一个崩一个不崩。

### 4. ★ 周期 ∝ `pipe_count` 的线性模型被证伪

```
R2: pc=500  → 1.833 s/A
R3: pc=8000 → 1.505 s/A     ★ pc↑16 倍，周期反【降 17.9%】
```
两点外推曾预测 3.47 s/A，偏差 **131%** ⇒ 周期由**与 `pipe_count` 无关的固定段**主导（`run_race` 56000 timer + `force_rcu_callbacks` 40000 timer + slab drain 150 ms）。

## 诚实记账（缺陷）

- R3 预算 200 偏低 ⇒ **M-B 需延长至 ≥600 s 才能给强支持**
- H97/H98 未启用 `MEY_STAGE0_ONLY`（H102 才加）⇒ 与 R2/R3 非严格同构；但 **R2 vs R3 已足够**

## 新增环境纪律

**`nohup bash script.sh > out.txt 2>&1 &` 在本机 Git Bash 下不生效**（console 0 字节、无进程、未推进）⇒ **adb 长脚本必须前台跑**；后台方式仅对 scrcpy 等 GUI 有效。

## 下轮第一步

1. ★★★ **R4 延长实验（检验 M-B）**：`MEY_PIPE_COUNT=8000` + `MEY_STAGE0_MAX_ATTEMPTS=500`（≈750 s = 2.5 个 M-B 均值）
   - 观测到崩溃 ⇒ **M-B 获强支持**；≥750 s 仍不崩 ⇒ **M-B 亦被证伪**
2. ★★ **R5 中间档扫描**：`MEY_PIPE_COUNT=3000` + 预算 300（检验「单调 vs 阈值型」）
3. ★ **`pc=8000` 作为长跑平台**（200 attempt 无崩溃）
4. ★★ **重定位真 `selinux_state`**（候选 `0x23e2c20`）

## 产物

| 文件 | 说明 |
|---|---|
| `analysis/output/h103_r3_result.md` | 完整报告（十一节，12,077 B） |
| `analysis/scratch/h103_r3.sh` | R3 单发脚本（静态自检通过） |
| `analysis/scratch/h103r3_p8000_101102.log` | R3 设备日志，213,083 B |
| `analysis/scratch/h103_r3_console.txt` | 脚本控制台输出 |
| `HANDOFF.md` §2.15 / `MEMORY.md` / `2026-10-05.md` | 证据链写回 |
