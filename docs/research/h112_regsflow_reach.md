# H112 — 「非 `pstate` 提权路径」全树数据流扫描 + BPF/perf/非特权通道可达性实测

> **轮次**：H112（2026-10-05 12:26 → 12:35）
> **前序**：H111（`ptrace` 侧 EL1 落点判死、`badframe` 链证伪、compat 路径判死 ⇒ 「上游写 `pstate`」三向全穷尽）
> **本轮任务**（H111 §X.11）：转向「非 `pstate` 的提权路径」——找「内核带着被改写的 GPR（`regs[0..30]`+`sp`+`pc`，**无需合法 `pstate`**）执行既有提权逻辑」的落点。
> **设备**：`boot_id=2888f136-4ff1-487b-8d4c-58e02e1897e0`（全程未变，未重启）｜`uptime` 1:16→1:21｜`getenforce=Enforcing`｜`uid=2000(shell)`｜`CapInh/Prm/Eff/Amb=0`
> **产物**：本文件 ｜ `tools/h112a_regsflow_priv.py`（全树扫描）｜ `tools/h112_reach.c`+`h112b_reach2.c`（可达性探测）｜ 二进制 `h112_reach`/`h112b_reach2`

---

## 一、本轮一句话结论

**「非 `pstate` 提权路径」方向在数据流层面只找到两条候选链（`ex_handler_load_unaligned_zeropad` / `ex_handler_bpf`），而设备实测证明两者在本机 uid=2000 下均不可达 ⇒ 本方向判死。叠加 H108/H109/H111，L3 已连续 4 轮被证伪，触发规程 §一 kill criterion：L3 挂起，收尾重估攻击面。**

---

## 二、全树数据流扫描（环① 源码推理）

**脚本**：`tools/h112a_regsflow_priv.py`
**方法**：正则扫描 `arch/arm64` + `kernel` + `fs` + `security` + `mm` 五棵树，匹配 `regs->regs[N]` / `regs->sp` / `regs->pc` / `regs->pstate` / `regs->orig_x0` / `regs->syscallno` 的**读写使用点**，按文件聚合。

### 2.1 扫描结果

| 文件树 | 命中数 | 说明 |
|---|---|---|
| `arch/arm64/` | **135** | 全部使用点集中于此 |
| `kernel/` | **0** | — |
| `fs/` | **0** | — |
| `security/` | **0** | — |
| `mm/` | **0** | — |

### 2.2 结论（这是**有价值的负面结论**）

**通用内核代码从不直接读写 `pt_regs` 的通用寄存器。** 所有 arch 无关代码一律走 `syscall_get_arguments()` / `syscall_set_return_value()` 抽象层；直接摸 `regs->regs[N]` 的代码**只存在于 `arch/arm64/`**。

⇒ **推论**：想让「被改写的 GPR 流向特权操作」，**必须找到 `arch/arm64/` 里某个把 `regs->regs[N]` 当特权参数用的函数**。而 `arch/arm64/` 里的 135 处使用，绝大多数是 `ptrace`（已被 H110/H111 判死）、`signal`（已被 H108/H109 判死）、`traps`（`regs->pc += size`）、`kgdb`（未编译）、`efi`（未启用）。真正剩下**带解引用/带特权语义**的只有：`extable.c`（异常处理）与 `net/bpf_jit_comp.c`（BPF）。

---

## 三、两条候选链的源码裁定（环①）

### 3.1 候选 A：`ex_handler_load_unaligned_zeropad`（`arch/arm64/mm/extable.c:32`）

```c
static bool
ex_handler_load_unaligned_zeropad(const struct exception_table_entry *ex,
                                  struct pt_regs *regs)
{
    int reg_data = FIELD_GET(EX_DATA_REG_DATA, ex->data);   /* GENMASK(4,0)  */
    int reg_addr = FIELD_GET(EX_DATA_REG_ADDR, ex->data);   /* GENMASK(9,5)  */
    unsigned long data, addr, offset;

    addr = pt_regs_read_reg(regs, reg_addr);   /* ★ 从 pt_regs 读寄存器 */
    offset = addr & 0x7UL;
    addr &= ~0x7UL;
    data = *(unsigned long*)addr;              /* ★ 任意地址读（非对齐） */
#ifndef __AARCH64EB__
    data >>= 8 * offset;
#endif
    pt_regs_write_reg(regs, reg_data, data);   /* 读到的值写回另一个寄存器 */
    regs->pc = get_ex_fixup(ex);
    return true;
}
```

- `EX_TYPE_LOAD_UNALIGNED_ZEROPAD = 4`（`asm-extable.h:13`）
- **全镜像唯一使用点** = `arch/arm64/include/asm/word-at-a-time.h:64` 的 `load_unaligned_zeropad()`
- 调用者链：`fs/namei.c:2124/2151/2179`（路径名 hash）、`fs/dcache.c:227`（dentry name）、`lib/siphash.c:61/94/261`

**裁定：判死。** 三条理由：
1. `addr` 是**内核自己的游标**（`hash_name()` 内的 `const unsigned char *name` 指针），用户只能间接影响「路径名字符串内容」，**不能指定 `addr` 的值**；
2. `reg_addr` / `reg_data` 是**编译期常量**（来自 `_ASM_EXTABLE_LOAD_UNALIGNED_ZEROPAD` 宏展开），无法运行时改写；
3. 触发条件是**跨页读取未映射页**——需要用户精确控制 dentry name 落在页边界上，且即使触发，读到的地址也由内核游标决定，**不是任意地址读**。

### 3.2 候选 B：`ex_handler_bpf`（`arch/arm64/net/bpf_jit_comp.c:696`）

```c
bool ex_handler_bpf(const struct exception_table_entry *ex, struct pt_regs *regs)
{
    off_t offset   = FIELD_GET(BPF_FIXUP_OFFSET_MASK, ex->fixup);  /* GENMASK(26,0) */
    int   dst_reg  = FIELD_GET(BPF_FIXUP_REG_MASK,    ex->fixup);  /* GENMASK(31,27) */

    regs->regs[dst_reg] = 0;                                 /* 清 BPF 目标寄存器 */
    regs->pc = (unsigned long)&ex->fixup - offset;            /* ★ 零校验写 regs->pc */
    return true;
}
```

- `EX_TYPE_BPF = 1`；由 `add_exception_handler()` 生成，**仅当 BPF 程序使用 `BPF_PROBE_MEM` / `BPF_PROBE_MEMSX`** 且 `ctx->prog->aux->extable` 存在
- 理论上：若攻击者能控制 `ex->fixup`（BPF JIT 生成的异常表内容），可**任意设 `regs->pc`**

**裁定：理论上高价值，实测判死（见 §四）。** 前置条件是「能把 BPF 程序加载进内核并触发 `BPF_PROBE_MEM`」，而本机 uid=2000 **完全无法触碰 BPF**。

---

## 四、设备实测：非特权通道可达性（环③ img 层 + 真机）

**脚本**：`tools/h112_reach.c`（第一轮）+ `tools/h112b_reach2.c`（第二轮，errno 语义校准）
**方法**：纯用户态，只调 syscall、只读 errno；不构造任何载荷、不写内核；设备前后 `boot_id` 一致。

### 4.1 errno 语义校准组（关键对照）

| syscall | errno | 判定 | 含义 |
|---|---|---|---|
| `setuid(0)` | **1 EPERM** | CAP_DENY | 内核**已走到** capability 检查，仅因无 cap 被拒 |
| `init_module(NULL,0,0)` | **1 EPERM** | CAP_DENY | 同上 |
| `unshare(CLONE_NEWNS)` | **1 EPERM** | CAP_DENY | 同上 |

⇒ **校准确立**：本机 **capability 不足报 `EPERM(1)`**。

### 4.2 目标组（本轮实测）

| syscall | errno | 判定 | 结论 |
|---|---|---|---|
| `perf_event_open(SW cpu-clock, self)` | **13 EACCES** | **SELINUX_DENY** | 非 cap 问题 |
| `perf_event_open(HW cpu-cycles, self)` | **13 EACCES** | SELINUX_DENY | 同上 |
| `perf_event_open(HW kernel-only)` | **13 EACCES** | SELINUX_DENY | 同上 |
| `perf_event_open(pid=-1, system-wide)` | **13 EACCES** | SELINUX_DENY | 同上 |
| `bpf(BPF_MAP_CREATE, ARRAY)` | **13 EACCES** | **SELINUX_DENY** | **BPF 通道关闭** |
| `bpf(BPF_PROG_LOAD, ...)` | **13 EACCES** | SELINUX_DENY | **同** |
| `io_uring_setup(4, &params)`（合法参数） | **13 EACCES** | SELINUX_DENY | **io_uring 关闭** |
| `io_uring_setup(SQPOLL)` | **13 EACCES** | SELINUX_DENY | 同 |
| `open("/dev/kmsg")` | **13 EACCES** | SELINUX_DENY | — |
| `unshare(CLONE_NEWUSER)` | **22 EINVAL** | **NOT_SUPPORTED** | **`USER_NS` 未编译进内核** |
| `keyctl(GET_KEYRING_ID)` | 22 EINVAL | NOT_SUPPORTED | 参数问题 |
| `open("/dev/perf")` / `open("/dev/bpf")` | 2 ENOENT | — | 节点不存在 |

### 4.3 三个独立事实

1. **`perf_event_paranoid = -1` 是假象，作废。** sysctl 值确实读得到 `-1`，但 uid=2000 走 `perf_event_open()` 一律在 **LSM hook 层**（`security_perf_event_open()` → `selinux_perf_event_open()`）就被 `EACCES(13)` 拒掉——**`perf_event_paranoid` 这个 sysctl 根本没被求值到**。上一轮据此产生的「perf 方向可行性提升」判断**撤回**。
2. **BPF 通道对 shell 域完全关闭。** 且是 SELinux 域策略层面（非 capability），**即使有 cap 也无用**——要打 BPF 必须先以合法域进程身份（如 `system_server`）发起，本项目不具备。
3. **`USER_NS` 未编译**（`EINVAL` 而非 `EPERM`）⇒ 排除「userns 提 namespace cap」整类方案。
4. **`io_uring` 对 shell 域关闭** ⇒ 排除 io_uring 类提权面。

---

## 五、判死清单（本轮新增）

| # | 路径 | 判死依据 | 证据等级 |
|---|---|---|---|
| 1 | `ex_handler_load_unaligned_zeropad` 任意读 | `addr` = 内核游标，用户不可指定；`reg_addr`/`reg_data` 编译期常量 | 源码已证（环①） |
| 2 | `ex_handler_bpf` → 写 `regs->pc` | 前置 `BPF_PROG_LOAD` 在 shell 域 `EACCES(13)` | **真机实测**（环③） |
| 3 | `perf_event_open` 全谱 | 同上，SELinux LSM hook 层拒 | **真机实测** |
| 4 | `io_uring_setup` | 同上 | **真机实测** |
| 5 | `unshare(CLONE_NEWUSER)` | `EINVAL` ⇒ `USER_NS` 未编译 | **真机实测** |
| 6 | `efi_runtime_fixup_exception`（H111 遗留） | `CONFIG_EFI` 运行时服务在 Android 未启用；`/sys/firmware/efi` 不存在 | 待复核（见 §六） |
| 7 | `kgdb.c:154`（`regs->pc = pc`） | `CONFIG_KGDB` 未编译（Android GKI 默认关） | 待复核 |

---

## 六、待复核项（低优先，不投入实测）

1. **`efi_runtime_fixup_exception`**（`arch/arm64/kernel/efi.c:182`）：`regs->pc = (u64)__efi_rt_asm_recover;` —— 需确认 `CONFIG_EFI` + EFI runtime services 在本机是否启用。判据：`ls /sys/firmware/efi` 是否存在。若不存在 ⇒ 判死。
2. **H99 结论重审**：H111 发现的「`0xF0000000` 掩码形态遗漏同类风险」是否影响其他更早结论（`0x23ba418` 已证伪的结论）。属**记账**性质，不影响本轮裁定。
3. **H108/H109 表述回填**：`0x8d08b8` 应从「`compat_gpr_set+0x1fc`」改为「`compat_arch_ptrace+0x504`」（H111 已发现，HANDOFF §U.5/§V.2 待同步）。

---

## 七、本轮非提权副作用发现（备查）

| 事实 | 值 | 备注 |
|---|---|---|
| 内核构建串 | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` | `-4k` = 4K 页确认 |
| 编译器 | `clang 18.0.0` + `LLD 18.0.0`，`+pgo,+bolt,+lto,+mlgo` | 与 NDK r27c 不同代 |
| 构建时间 | `Sun May 31 12:01:53 UTC 2026` | — |
| `load average` | **21.5**（持续高位） | 设备长期高负载（与提权无关，但影响时序类实验） |
| 可读 proc 侧信道 | `/proc/self/status`、`/proc/self/maps`、`/proc/self/stat` 可读；`randomize_va_space` 被拦 | 独立透镜素材 |
| shell 域 groups | `3009(readproc)`、`3012(readtracefs)` | tracefs 可读（已知） |

---

## 八、规程 §一 kill criterion 触发

**L3 连续被证伪轮次统计**：

| 轮次 | 被证伪的子方向 |
|---|---|
| H108 | 递归投递窗口（`force_fatal_sig` 兜底） |
| H109 | `setup_rt_frame` 内核态写（22 个 `sttr` 写目标全为用户 VA） |
| H111 | `ptrace` GPR 通道 / `badframe` 链 / compat AArch32（三向全穷尽） |
| **H112** | **「非 `pstate` 提权路径」（两条候选链均不可达）** |

⇒ **4 轮连续证伪，无新变体可挖** ⇒ 按规程 §一：**L3 挂起，收尾重估攻击面，不得无限消耗轮次。**

---

## 九、重估攻击面：本轮实测产出的「域能力边界表」

> **这是本轮最有价值的可复用资产。** 它把「shell 域能做什么、不能做什么」第一次用 **errno 语义分离**钉死——后续任何攻击面调研都直接引用此表，不再重复试错。

| 能力 | shell 域（uid=2000） | 判据 |
|---|---|---|
| **任何 capability 操作** | ❌ `EPERM(1)` | 校准组 |
| **`perf_event_open()`** | ❌ `EACCES(13)`（SELinux） | 实测 |
| **`bpf()` 全部命令** | ❌ `EACCES(13)`（SELinux） | 实测 |
| **`io_uring_setup()`** | ❌ `EACCES(13)`（SELinux） | 实测 |
| **`unshare(CLONE_NEWUSER)`** | ❌ `EINVAL`（未编译） | 实测 |
| **`/dev/kmsg`、`dmesg`** | ❌ `EACCES(13)` | 实测 |
| **`/proc/sys/kernel/*` 大部分** | ❌ `EACCES(13)` | 实测 |
| **`/proc/self/{status,maps,stat}`** | ✅ 可读 | 实测 |
| **`/proc/<pid>/*`（他人进程）** | ✅ 部分（有 `readproc` group 3009） | groups 表 |
| **tracefs** | ✅ 可读（group 3012） | groups 表 |
| **自建 cdev ioctl** | ✅ 可达（`/dev` 中 0666 节点） | 历史 |
| **信号路径（`rt_sigreturn`）** | ✅ 可达但**已 4 轮证伪** | H108/H109/H111/H112 |

**重估结论**：在 shell 域能真正触碰的面里，**唯一未被穷尽的类别 = 「自建 cdev 的 ioctl 面」**（即 `/dev` 下 world-accessible 节点）。H112 的所有 SELinux 拒绝恰好把「perf / bpf / io_uring / userns / kmsg」这些**通用提权面**全部排除，反向收敛到「**厂商 `cdev` 的 ioctl 实现**」这一条——这与项目最早（H1–H100）走过的路径重合。

---

## 十、下一步（交棒建议，不在本轮执行）

按 kill criterion，**L3 挂起**。重估后的候选方向按价值排序：

1. **厂商 `cdev` ioctl 面重扫**（最高价值）：`/dev` 下 0666 / world-readable 的厂商私有节点，做 ioctl 命令号穷举 + 实现反汇编审计。判据：找到「用户可控参数 → 内核解引用/写」的点。
2. **tracefs 可读面**（新发现，零成本）：shell 域有 `readtracefs`（3012）⇒ 可读 trace 输出，可能泄漏内核符号/地址，为 KASLR 绕过提供独立透镜。**这是本轮实测意外发现的可用资产。**
3. **`/proc/<pid>/` 泄漏面**：`readproc` group 可读其他进程的 `/proc/<pid>/maps` 等，可能泄漏 ASLR 与堆布局。
4. **`efi` / `kgdb` 复核**（低优先，判据已给）。

---

## 十一、本轮产物清单

| 类型 | 路径 |
|---|---|
| 本报告 | `analysis/output/h112_regsflow_reach.md` |
| 全树扫描脚本 | `tools/h112a_regsflow_priv.py` |
| 可达性探测源码 | `tools/h112_reach.c`、`tools/h112b_reach2.c` |
| 可达性探测二进制 | `tools/h112_reach`、`tools/h112b_reach2`（已推送 `/data/local/tmp/`） |
| 设备实测原始输出 | 本轮回复内联（两轮完整 stdout） |
| HANDOFF | `HANDOFF.md` §Y |
| 知识库 | `.workbuddy/memory/MEY-TECH.md` §12 |
| 轮次日志 | `.workbuddy/memory/2026-10-05.md` §30 |
