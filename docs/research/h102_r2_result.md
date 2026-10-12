# H102 · R2 判别实验实测结果与崩溃机制判定

> 轮次：H102 ｜ 日期：2026-10-05 ｜ 设备：MEY-AN00 (SM8735, 6.6.118-android15-8, 4K 页)
> 权威规程：`D:\MEY-AN00-root-repro\MEY-AN00-exploit-prompt.md`（v3，六节）
> 本报告为规程 §四「阶段四 收尾」的强制写回产物。

---

## 一、阶段四写回（规程 §四）

本轮激活角色：**记录官 + 分析**（阶段四），前置为阶段三执行的 R2 单发实验。

| 项 | 内容 |
|---|---|
| 本轮验证的假设 | **M-A（按 attempt 崩） vs M-B（按时间崩）**，H101 §5.5 提出的竞争模型 |
| 验证行为 | 执行 R2：`MEY_PIPE_COUNT=500` + `MEY_STAGE0_MAX_ATTEMPTS=640` + `MEY_STAGE0_ONLY=1` + `SELINUX_TARGET=0` |
| 结果 | **倾向 M-A（BF≈21.6，ΔAIC=-6.15），但未达决定性**；同时暴露 R2 设计缺陷（提速仅 1.56×） |
| 新发现 | ① `MEY-TECH.md` **在 memory 目录**（非根目录）—— 本轮曾误判缺失并已更正（§九）；② `irq_ns` 恒定线性递增是设计量、非崩溃诱因；③ M-B 的数量级被**证伪** |
| 下轮第一步 | 见 §八 |

---

## 二、R2 实测原始数据

### 2.1 设备与开火记录

```
开火前  boot_id = 30f6968a-f79f-40e8-8884-124f4e067d55   uptime = 3002.64 s
开火后  boot_id = 2b5276d1-0df1-435a-bd5f-335a1d8e859a   uptime = 36.89 s   ← 已变化 + 归零
push 校验  local=2390088  device=2390088  magic=7f454c46
设备侧 MEY_STAGE0_ONLY 出现次数 = 1（防 H92 静默跑错路径）
单发结束 rc=255，墙钟 66 s
VERDICT = UNKNOWN（按铁律②：USB 断连与重启不可区分，不报 REBOOTED）
```

### 2.2 panic 取证（双重交叉验证）

```
history.log 累计 AP_S_PANIC = 724（上轮档案记 723 ⇒ +1）
新增条目:  time [20261005095911-44083114]  reason [page_request]  category [AP_S_PANIC]
开火 09:57:28  →  panic 09:59:11  ⇒  103 秒
```

⚠️ **注意**：`boot_id` 在 R2 取证窗口（09:59）与本次复核窗口（10:0x）**相同**（`2b5276d1`），但 uptime 仅 108 s ⇒ 说明本次复核距设备重启仅 108 s。history.log 中 R2 之后再无新 panic ⇒ **本次 108 s 的 uptime 对应的是 R2 之后的那次 panic 重启**，非新崩溃。

### 2.3 日志完整性

```
设备侧日志 40,166 B  →  已拉回  analysis/scratch/h102r2_p500_095728_dev.log
尾部为连续 0x00 零区（同 H97/H98 模式）
setvbuf(_IONBF) @ f77.c:7569 ⇒ 排除「缓冲丢失」；零区连续且位于文件末尾 ⇒ ext4 未初始化 extent（排除 pull 截断）
```

---

## 三、★ 关键发现：attempt=36 崩溃，事件序列定位

R2 日志中 `ATTEMPT_BEGIN` 共 **36 条**。第 36 条的完整事件序列：

```
ATTEMPT_BEGIN attempt=36 batch=1 pairs=500 fragments=1500 rcu_wait_us=150000
VICTIM_ROLE_GATE_PASS physical=7
DELETE_ROLE_GATE_PASS expected=0x7c observed=0x7c
EXEC_REPEAT_GATE_PASS physical=7 repeats=4 acks=4 tgid=20533 overlap=1 span_us=1583
LANE_DONE sequence=36 timing_slot=31 victim=20533 timers=56000 deleted=56000 errors=0 \
          create_errno=0 delete_errno=0 ... delete_us=30834 ...
RCU_FORCE attempt=36 created=40000 deleted=40003 errors=0
<0x00 零区>            ← ★ 崩溃点
```

**计数对照（决定性）**：

| 事件 | 条数 | 对应 attempt |
|---|---|---|
| `ATTEMPT_BEGIN` | 36 | 1–36 |
| `LANE_DONE` | 36 | 1–36 |
| `RCU_FORCE` | 36 | 1–36 |
| `SLAB_DRAIN_PASS` | **35** | **1–35** |
| `SPRAY_DONE` | **35** | **1–35** |
| `STAGE0_MISS_CLEAN` | 35 | 1–35 |
| `STAGE0_DIRTY_ARM` | 35 | 1–35 |
| `STAGE0_ONLY_EXIT` | **0** | — |

⇒ **崩溃发生在 attempt=36 的 `force_rcu_callbacks` 完成之后、`wait_timer_slab_drain` 返回之前**（`f77.c:2958→2959` 之间），与 H101 定位的 `f77.c:1480-1483 join_or_preserve(workers[i],"delete")` 属同一阶段（56000 timer 并发删除窗口）。

---

## 四、★★ 无累积趋势（与 H101 六项反证一致，再次独立验证）

| 观测量 | R2 实测 | 判定 |
|---|---|---|
| `delete_us` | 前半均值 30,603 µs / 后半均值 30,766 µs（差 0.5%） | **无趋势** |
| `irq_ns` | 严格 `attempt × 20000` 线性递增 | **设计量**（见 §五），非累积 |
| `timers` | 恒 56,000（36 次逐位相同） | 极稳定 |
| `deleted` | 恒 56,000（36 次逐位相同） | 极稳定 |
| `errors` | 恒 0（36 次） | 极稳定 |
| `RCU_FORCE created` | 恒 40,000（36 次逐位相同） | 极稳定 |
| `SLAB_DRAIN wait_ms` | 151 / 152 / 153，均值 152.0 | 极稳定 |
| `slab active` | 471 → 502（微涨，稳态波动） | **无累积** |

⇒ **第七次独立确认：崩溃不是累积性污染引起**（H100-A 维持证伪状态）。

---

## 五、`irq_ns` 线性递增的排除性判定

`irq_ns`（`f77.c:1518` 打印的 `irq_after_release_ns`）在 R2 中呈严格 +20000 步进。追源码：

- `f77.c:1518` → 打印 `irq_after_release_ns`
- `f77.c:1529` → `irq_target_ns - begin_ns`
- `f77.c:1393` → `int timing_slot = race_timing_slot(sequence);`
- `f77.c:782` → `race_timing_slot()` 用 `dada_bridge_order[] = {13,32,21,1,2,3,...,31}` 编排槽

⇒ **`irq_ns` 是 timing 编排的设计产物**（把 IRQ 相位按 attempt 错开），**与崩溃成因无关**。R2 中前 4 槽（13,32,21,1）之后的线性段是 `dada_bridge_order` 尾部连续序列的自然结果。

**★ 排除结论**：`irq_ns` **不列为崩溃诱因**（此前未显式排除，本轮补上）。

---

## 六、★★ M-A / M-B 定量判定

### 6.1 原始数列

| 样本 | 崩溃 attempt | 墙钟 (s) | 周期 (s/A) | `pipe_count` |
|---|---|---|---|---|
| H97 | 108 | 309.0 | 2.861 | 6000 |
| H98 | 52 | 167.0 | 3.212 | 6000 |
| **H102-R2** | **36** | **66.0** | **1.833** | **500** |
| H92 | 304（**完整结束，主动停止**） | — | — | 6000 |

### 6.2 似然比与 AIC（Python 复核，铁律①）

```
[M-A] 几何分布（每 attempt 独立概率 q，与周期无关）
      q = 0.015306   ⇒ 平均崩溃 attempt = 65.3
      logL = -15.5154

[M-B] 指数分布（崩溃率 λ 恒定/秒）
      λ = 0.005535 /s   ⇒ 平均存活 = 180.7 s
      logL = -18.5900

ΔlogL = 3.0745
BF(M-A / M-B) = exp(3.0745) = 21.64
AIC(M-A) = 33.031    AIC(M-B) = 39.180    ΔAIC = -6.149  ⇒ M-A 更优
```

**判定：M-A 优于 M-B，贝叶斯因子 ≈ 21.6（中等偏强证据，非强证据）。**

### 6.3 ★★★ 决定性判别：M-B 的**数量级被证伪**

M-B 的核心预测：**周期缩短 k 倍 ⇒ 崩溃 attempt 数放大 k 倍**（因为 λ 恒定、按时间累积）。

```
基线周期（H97/H98 均值）= 3.036 s/A
R2 周期（实测）        = 1.833 s/A
提速 k = 3.036 / 1.833 = 1.66×

基线 attempt 中位数 = 80

★ M-B 预测 R2 attempt ≈ 80 × 1.66 = 132
★ 实测 R2 attempt             = 36
⇒ 偏差 268%（M-B 严重高估）

★ M-A 预测 R2 attempt ≈ 65（不随周期变化）
⇒ 偏差 81%（M-A 亦有偏差，但方向一致、量级更近）
```

**关键**：M-B 要求提速后 attempt **变大**，实测反而**变小**（36 < 52 < 108）⇒ **M-B 在数量级上被证伪**。

### 6.4 ★ 残留未解项：为什么 attempt=36 比两个模型的预测都小？

实测 36 低于 M-A 预测 65，也低于 H98 的 52。三个可能：

| 假设 | 内容 | 可证伪判据 |
|---|---|---|
| **M-C1** | 崩溃由 **timer 总量**（`40000 × attempt` 相关）驱动，非纯时间；降低 pipe_count 使每 attempt 更快，但 timer 累积速度不变 ⇒ attempt 数应**不变** | 若成立，R2 attempt ≈ H97/H98 量级（52–108）；实测 36 偏小 ⇒ **不支持** |
| **M-C2** | 降低 pipe_count ⇒ spray 覆盖面积变小 ⇒ stage0 命中率下降 ⇒ 崩溃**提前**（因"脏状态"性质改变） | 需 pipe_count 扫描实验（R3 反向：8000） |
| **M-C3** | 小样本波动（n=1 的 R2 本身有 ~50% 概率落在 36±） | 需重复 R2 多次（但受"一 boot 一发"约束，成本高） |

⇒ **M-C2 是当前最值得验证的候选**（因 R2 唯一的变量就是 pipe_count，且 `f77.c:7322` 明确注释"降 pipe_count 会降 stage0 命中率"）。

### 6.5 ★★ 方法论修正：H92 不是删失样本

H92 的日志（`analysis/scratch/h90_run.log`，实为 H92 日志）**在 304 attempt 完整结束**（末行 `SPRAY_DONE attempt=304`，结尾无零区）⇒ 这是**主动停止**，不是"存活到观察期结束"。

**⇒ H92 不能作为"删失样本"代入生存分析**（删失样本假设"观察期结束仍未崩溃"，而 H92 是人为停机）。此前若有人把它当删失代入，会系统性高估存活时间、偏向 M-B。

**★ 新增禁令**：禁止把 H92 当作删失样本代入 M-A/M-B 拟合。

---

## 七、三环对照表（规程 §三）

| 对象 | ①源码推理 | ②汇编交叉验证 | ③镜像 delta | 一致 | 矛盾待解 |
|---|---|---|---|---|---|
| 崩溃窗口 | `f77.c:2958→2959`（RCU_FORCE 后、SLAB_DRAIN 前） | — | 计数差 36 vs 35 | ✅①③ | 无 |
| 崩溃点落盘 | `setvbuf(_IONBF)` @ `f77.c:7569` | — | 零区连续（ext4 extent） | ✅①③ | 无 |
| 累积污染 | — | — | **七项反证**（H101 六项 + 本轮 delete_us/timers/slab） | ❌ **证伪** | 无 |
| 固定阈值 | — | — | 36 / 52 / 108 / ≥304 浮动 | ❌ **证伪** | 无 |
| `irq_ns` 诱因 | `race_timing_slot` @ `f77.c:782` 设计量 | — | 严格线性递增 | ❌ **本轮排除** | 无 |
| **M-A vs M-B** | — | — | BF=21.6 + M-B 数量级证伪 | ⚠️ **倾向 M-A，未决定性** | 需 R3 / 重复 R2 |
| `selinux_state` 地址 | — | `0x23ba418` 7×LDRB + 0×LDR_W | — | ❌ **H99 已证伪** | 需重定位（候选 `0x23e2c20`） |

---

## 八、禁止重复动作（新增）

| 禁止项 | 依据 |
|---|---|
| ❌ 把 H92 当作删失样本代入 M-A/M-B 拟合 | §6.5 它是主动停止 |
| ❌ 主张 `irq_ns` 递增是崩溃诱因 | §五 它是 timing 设计量 |
| ❌ 主张 M-B 成立 | §6.3 数量级被证伪（预测 132 vs 实测 36） |
| ❌ 用 R2 单次结果作"决定性"判别 | §6.2 BF=21.6 属中等证据；n=3 |
| ❌ 沿用「崩溃由累积污染引起」（H100-A） | H101 六项 + 本轮七项反证 |
| ❌ 沿用「固定 attempt 阈值」 | 阈值 36–304 浮动 |
| ❌ 引用 `h90_run.log` 当 H90 日志 | H101 §2.1 它属 H92 |
| ❌ 主张日志被截断 | 零区连续性（ext4 extent） |

---

## 九、★ 基线核对（本节曾被误判，已更正）

**核查过程**：本轮一度按「`MEY-TECH.md` 应在 `D:/MEY-AN00-root-repro/` 根目录」去找，未命中 ⇒ 曾误判为「文件缺失、知识库索引缺口」。**该判定错误，现更正。**

**实际位置**（四重核查确认）：

```
$ ls -la <HOME>/WorkBuddy/2026-09-26-09-04-37/.workbuddy/memory/MEY-TECH.md
-rw-r--r-- 15023  Oct  5 08:42  MEY-TECH.md
$ head -4 MEY-TECH.md
# MEY-AN00 技术档案（详版）
> MEMORY.md 的展开文件。历史轮次日志 `.workbuddy/memory/2026-*.md`；
> 交接 `D:/MEY-AN00-root-repro/HANDOFF.md`；三环 `analysis/output/*.md`。
```

⇒ **`MEY-TECH.md` 存在且完好**（15,023 B），位于 **`.workbuddy/memory/`**（与 `MEMORY.md` 同目录），是「MEMORY.md 的展开文件」。规程 §五 索引表写的是**裸文件名**（无路径），本轮却按项目根目录查找 ⇒ **是路径假设错误，不是文件缺失**。

**★ 铁律级教训（本轮新增）**：规程索引给出**裸文件名**时，须按「同名文件可能位于 memory 目录」理解；`MEMORY.md` 与 `MEY-TECH.md` 属**同一目录的一对**。下次核对索引文件存在性时，**至少同时查 `.workbuddy/memory/` 与项目根两处**，单处未命中不得下「缺失」结论（同 H99「字符串命中 ≠ 未 strip」的阴性对照纪律）。

**内容有效**：`MEY-TECH.md` §3.1 即 `rb_erase` 三写点完整语义（含 H96 更正），与 MEMORY.md §rb_erase 一致 ⇒ 三写点基线以该文件为准。

---

## 十、可证伪判据（供下轮检验）

| 若结论成立 | 应观测到 | 若观测不到 ⇒ 结论错在 |
|---|---|---|
| M-A 成立 | 重复 R2 时崩溃 attempt 稳定在 ~36±（与周期无关） | 若 attempt 随周期漂移 ⇒ M-B 或 M-C2 |
| M-C2 成立（pipe_count 影响崩溃时机） | 提高 pipe_count 至 8000（R3），崩溃 attempt 应**回到 52–108** | 若 R3 attempt 仍 ≈36 ⇒ pipe_count 无影响，M-C3（波动）成立 |
| `0x23e2c20` 是真 `selinux_state` | 提权后读 BTF 应确认 `struct selinux_state` 偏移含该址；且该址应有 4 字节 `LDR/STR_W` | 若只有 LDRB ⇒ 再次证伪 |

---

## 十一、本轮产物

| 文件 | 说明 |
|---|---|
| `analysis/output/h102_r2_result.md` | 本报告 |
| `analysis/scratch/f77_h102_20261005_095627` | H102 二进制（含 `MEY_STAGE0_ONLY`），2,390,088 B |
| `analysis/scratch/h102_r2.sh` | R2 单发脚本（含铁律②校验 + 浮点判据修正） |
| `analysis/scratch/h102r2_p500_095728_dev.log` | R2 设备日志，40,166 B |
| `analysis/scratch/h102r2_console.txt` | R2 脚本控制台输出 |
| `tools/h102_patch_stage0_only.py` | 补丁脚本（CRLF 感知，三锚点自检） |
| `c64560/f77.c` | 7,983 → 8,001 行（+18），330,292 B，CRLF 完好 |

---

## 十二、下轮第一步

1. ★★★ **R3 反交叉实验**：`MEY_PIPE_COUNT=8000`（上限）+ `MEY_STAGE0_MAX_ATTEMPTS=640` + `MEY_STAGE0_ONLY=1`。
   - 目的：检验 M-C2（pipe_count 影响崩溃时机）
   - 判据：崩溃 attempt **回到 52–108 ⇒ M-C2 成立**；**仍 ≈36 ⇒ M-C2 证伪，M-C3（波动）占优**
2. ★★ **重定位真 `selinux_state`**：`0x23ba418` 已证伪，候选 `0x23e2c20`（962 候选中收敛）
3. ★ **核对 `MEY-TECH.md`**（本轮已确认在 `.workbuddy/memory/`，非根目录；见 §九）
4. 写点①命中验证仍 **INCONCLUSIVE**（连续三轮未进 stageB；R2 36 次全 MISS 与 1/127 命中率自洽）
5. 缺口正解 = 提权后读 `/sys/kernel/btf/vmlinux`（依赖项）
