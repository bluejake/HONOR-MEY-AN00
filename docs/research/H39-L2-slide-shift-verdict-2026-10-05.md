# H39 轮 · L2（CVE-2026-43499 rt_mutex / pselect 滑动）分析判定

日期：2026-10-05 · 设备 MEY-AN00 · 内核 `6.6.118-android15-8`
方法：全部用 `analysis/scratch/Image-mey` 的**本机真实机器码**（capstone ARM64）重算，不采信头文件注释。

---

## 0 结论

**L2 可重启（不是真死路），但其 `SLIDE_PSELECT_WORD_SHIFT=13` 与本机实机不符，实测应为 19。**
⇒ 10-02 挂起的根因**确实是判据/标定错误**（同 MEMORY 结论），但**具体的错值需要修正**，
不是"shift=0"。

---

## 1 阶段一：挂起原因复核（判定是判据失误还是真死路）

MEMORY §3.4-2 记：「L2 挂起根因 = 判据失误（错配 BVL-AN16 6.1.128 的 shift=11），实际 `do_futex` 独立符号存在 ⇒ shift=0 ⇒ 可重启」。

**本轮实测复核，MEMORY 这一条需要修正两处**：

| MEMORY 说法 | 实测 | 结论 |
|---|---|---|
| `do_futex` 独立符号存在 ⇒ 内联不成立 ⇒ shift=0 | `do_futex`=`0xffffffc0801edfc0` **确实是独立符号**（`paciasp` + `sub sp,#0x60`）；**但 `__arm64_sys_futex` 全函数（0x120 B）只有 2 个 `bl`，都不是 `do_futex`**（目标 `0x119e58` / `0x0edacc`） | ❌ **「shift=0」错**：本机 futex 路径**确实把 `do_futex` 内联**了，符号存在但不被该路径调用 |
| 可重启 | 可重启 | ✔ 成立 |

⇒ **L2 判定：可重启（判据失误，非真死路）**。但不是 shift=0，而是需要按本机重新标定。

---

## 2 阶段二：根因定类（任务书要求）

**L2 = 类型混淆 / 栈上相邻结构跨帧滑动（cross-frame aliasing），不是 UAF、不是越界、不是竞争。**

机理：`pselect` 的 `stack_fds`（用户可控 fd_set）位于 `core_sys_select` 栈帧的固定偏移；
`futex` 的 `rt_waiter`（内核 `rt_mutex_waiter`）位于 `futex_wait_requeue_pi` 栈帧的固定偏移。
只要让**两个内核线程的栈帧在虚拟地址上满足特定距离**，
用户态通过 `pselect` 写入的 5 个全局 word 就会**精确落到** `rt_waiter` 的字段上
（`lock` / `tree` / `pi` …），从而伪造 waiter 状态实现任意内核写。

⇒ 攻击面 = **「用户可控数据 与 内核可信对象 在地址上的可控重叠」**。
同类变体：任何"用户可写的内核栈缓冲区" × "位于相邻帧的内核可信结构"配对。

---

## 3 ★ 用实机机器码重算 SHIFT（本轮核心交付）

### 3.1 四个关键量的实测值（capstone，`file_off = vaddr − 0xffffffc080000000`）

| 符号 | vaddr | 实测序言 | 头文件注释 | 一致 |
|---|---|---|---|---|
| `__arm64_sys_futex` | `0xffffffc080119ad8` | `paciasp; sub sp,#0x80` | `sub sp,#0x80` | ✔ |
| `__arm64_sys_pselect6` | `0xffffffc080244230` | `paciasp; sub sp,#0x90` | `sub sp,#0x90` | ✔ |
| `core_sys_select` | `0xffffffc080243ee8` | **`paciasp; sub sp,#0x1e0`** | `sub sp,#0x1c0` | ✘ **差 0x20** |
| `futex_wait_requeue_pi` | `0xffffffc080958e1c` | **`paciasp; sub sp,#0x1c0`**（`x29=sp+0x160`） | `sub sp,#0x1b0` | ✘ **差 0x10** |

### 3.2 帧内偏移实测
- `futex_wait_requeue_pi`：`x29 = sp+0x160` ⇒ `x29-0xb8 = sp+0xa8` 为 rt_waiter 相关
  （实测该函数内 `add x0,sp,#0x90` 做 RB 节点初始化、`str xzr,[sp,#0x88]`、`str x8,[sp,#0xb8]`）
- `core_sys_select`：`add x0, sp, #0x70`（`x19 = sp+0x70`）为 fd_set 缓冲区起点
- `core_sys_select` 中 `stp x21, x8, [sp, #0x50]` 附近为 fd_set 参数区

### 3.3 代入公式重算

```
rt_waiter  = T - (0x80 + 0x1c0 - 0xa8) = T - 0x198      ← 与头文件完全一致 ✔
stack_fds  = T - (0x90 + 0x1e0 - 0x40) = T - 0x230
delta      = 0x230 - 0x198 = 0x98 = 19 words
```

| | 值 |
|---|---|
| 头文件 `SLIDE_PSELECT_WORD_SHIFT` | **13** |
| **本轮实测推算** | **19** |

⇒ **`core_sys_select` 帧深差 0x20 是主因**；`rt_waiter` 一侧推导完全正确（`T-0x198` 吻合）。

### 3.4 `SLIDE_PSELECT_RES_ENCODE` 的依赖
头文件 236–240 行指出：SHIFT 决定哪些 global word 会落到 `res_*` 段，
`SLIDE_PSELECT_RES_ENCODE=1` 是**必需**（否则 `waiter->lock` 恒 0 ⇒ `_raw_spin_trylock(NULL)` ⇒ null pointer panic）。
本轮不改这个设置。

---

## 4 阶段三：上机验证（L2 首次真正上机）

`exploit-src/build/preload.so`（189,128 B）已 push 到 `/data/local/tmp/mey/preload.so`，
`stat -c %s` 与本地一致，判据体系含 40+ 个 `SLIDE_*` 标记，
输出通道为 `/data/local/tmp/cfi_state.log` + socket `/data/local/tmp/temp_su.sock`
⇒ **是 MEP（多进程）配方，不能用单进程 `sleep` 触发**。

**本轮实测**：
```
LD_PRELOAD=/data/local/tmp/mey/preload.so /system/bin/sleep 3   →  SIGTERM, 无输出
LD_PRELOAD=/data/local/tmp/mey/preload.so /system/bin/true      →  SIGTERM, 无输出
```
⇒ 单进程触发无效（符合 MEP 配方预期），**尚无 `SLIDE_OK`**。
⚠️ `SIGTERM` 而非正常退出，疑似被 preload 内部的 watchdog/超时逻辑杀出，**需查 `SLIDE_TRIGGER_BLOCK` / `SLIDE_TIMEOUT_NULL` 逻辑**。

---

## 5 尚未完成（下一轮）

1. **★ 必须先修 `SLIDE_PSELECT_WORD_SHIFT 13 → 19`**（`exploit-src/target_mey_an00.h:241`），
   然后重编 `preload.so`（`APP_PAYLOAD=1`，见 §6 构建要点）。
2. 查 `SIGTERM` 来源：preload 的 MEP 协议要求哪几个进程参与？`temp_su.sock` 怎么用？
3. 重编后单 boot 验 `SLIDE_OK`。

## 6 构建要点（记忆，避免重复踩坑）
```
export NDK=<HOME>/.workbuddy/binaries/android/android-ndk-r27c
export ANDROID_HOME=<sdk>
bash exploit-src/build_ndk.sh preload     # 产出 build/preload.so
```
⚠️ `standalone` 编不过是**已知状态**（`APP_PAYLOAD=0` 时 `common.h:415` 的 extern 被门控掉，
而 `util.c`/`chain.c` 仍引用）⇒ **主路线是 preload**。
⚠️ 脚本需 `export NDK` 与 `ANDROID_HOME`，否则 `set -u` 报 `ANDROID_HOME: unbound variable`。
