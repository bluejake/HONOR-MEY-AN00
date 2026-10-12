# H102 概览 · R2 判别实验与崩溃机制判定

## 本轮做了什么

按用户「开跑」授权，执行 H101 提出的 **R2 判别实验**（区分崩溃机制 M-A 按 attempt vs M-B 按时间），并完成规程 §四 强制的证据链写回。

**投屏纪律**：本轮起每轮开工第一步先把手机投屏到电脑（scrcpy v4.1，472x1024，direct3d11）。PowerShell 沙箱会拦截，须用 Bash `nohup ... &`。

## 核心结论

### 1. R2 已执行并取证（单发单 boot）

| 项 | 值 |
|---|---|
| 配置 | `MEY_PIPE_COUNT=500` + `MEY_STAGE0_MAX_ATTEMPTS=640` + `MEY_STAGE0_ONLY=1` + `SELINUX_TARGET=0` |
| 崩溃 attempt | **36** |
| 墙钟 / 周期 | 66 s / 1.833 s/A |
| 重启确认 | `boot_id` `30f6968a…` → `2b5276d1…` + uptime 归零 |
| panic | `history.log` 724 条（+1）：`20261005095911 page_request`；开火→panic = 103 s |

### 2. ★★★ 崩溃机制判定：倾向 M-A（M-B 数量级被证伪）

```
M-A 几何分布  q=0.015306  均值65.3 attempt  logL=-15.5154
M-B 指数分布  λ=0.005535  均值180.7 s       logL=-18.5900

BF(M-A/M-B) = 21.64      ΔAIC = -6.149  ⇒ M-A 更优（中等偏强证据）
```

**决定性证据**：M-B 要求「提速 ⇒ 崩溃 attempt 变大」，其预测 R2 attempt ≈ 132；**实测 36**（偏差 268%），attempt 反而变小 ⇒ **M-B 数量级证伪**。

### 3. 崩溃点定位（计数差）

`ATTEMPT_BEGIN`/`LANE_DONE`/`RCU_FORCE` = 36 条；`SLAB_DRAIN_PASS`/`SPRAY_DONE` = **35** 条
⇒ 崩溃发生在 `f77.c:2958→2959`（`force_rcu_callbacks` 完成后、`wait_timer_slab_drain` 返回前），与 H101 定位一致。

### 4. 新增能力与排除项

- **新增开关 `MEY_STAGE0_ONLY`**（`f77.c:780/7516/7669-7674`）：stage0 通过即 `_exit(0)`，不进 stageB（避免 `hold_corrupted_state()` 死循环）
- **排除 `irq_ns`**：严格 `+20000` 线性递增是 `race_timing_slot` 的设计产物，非崩溃诱因
- **H92 非删失样本**：其日志在 304 完整结束（主动停止）⇒ 禁止代入生存分析
- **零累积第七次确认**：`delete_us`/`timers`/`deleted`/`errors`/`created` 全程恒定

### 5. ★ 自我纠错

本轮一度误判 `MEY-TECH.md`「缺失」——实际它在 `.workbuddy/memory/`（15,023 B，「MEMORY.md 的展开文件」），我按项目根目录查找才没找到。**教训**：规程索引给裸文件名时，须同查 memory 目录与项目根两处，单处未命中不得下「缺失」结论。三处已更正。

## 残留未解

**M-C2**：降 `pipe_count` 会降 spray 覆盖面积 ⇒ 崩溃提前（`f77.c:7322` 注释）⇒ 需 R3 反交叉检验（`MEY_PIPE_COUNT=8000`）。

## 下轮第一步

1. ★★★ **R3 反交叉**：`MEY_PIPE_COUNT=8000` + `MEY_STAGE0_ONLY=1`；判据：崩溃 attempt **回到 52–108 ⇒ M-C2 成立**；**仍 ≈36 ⇒ M-C2 证伪**
2. ★★ 重定位真 `selinux_state`（候选 `0x23e2c20`）
3. 写点①命中仍 INCONCLUSIVE（R2 36 次全 MISS，与 1/127 命中率自洽）

## 产物

| 文件 | 说明 |
|---|---|
| `analysis/output/h102_r2_result.md` | 完整报告（十二节，14,031 B） |
| `analysis/scratch/f77_h102_20261005_095627` | H102 二进制，2,390,088 B |
| `analysis/scratch/h102_r2.sh` | R2 单发脚本 |
| `analysis/scratch/h102r2_p500_095728_dev.log` | R2 设备日志，40,166 B |
| `tools/h102_patch_stage0_only.py` | 补丁脚本 |
| `HANDOFF.md` §2.14 / `MEMORY.md` / `2026-10-05.md` | 证据链写回 |
