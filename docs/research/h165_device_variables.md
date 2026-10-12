# H165 · MEY-AN00 全链设备变量表（stage0 → cross-cache → misc bridge → pipe reclaim → phys R/W → stage8）

- 设备：MEY-AN00（serial `A22C026319001339`）· `uname` = `Linux localhost 6.6.118-android15-8-gf17133276a57-abogki518694926-4k #1 SMP PREEMPT Sun May 31 12:01:53 UTC 2026 aarch64`
- 采集时间：2026-10-05 18:13–18:25（boot `74f2c351-15ca-47e3-9d3b-46571914eb2e`，uptime 1191s 起）
- **新增权威来源**：`/proc/config.gz`（shell 域 `-r--r--r--` 可读，46 KB / 7787 行）→ `analysis/output/mey_config.{gz,txt}`；kallsyms `analysis/output/kallsyms_mey_an00.txt`
- 用途：把截图全链（BOOTID_WRITE→STAGE0_GATE→CROSSCACHE_RECLAIM→MISC_BRIDGE_OPEN/RW→PIPE_RECLAIM→PHYS_READ/WRITE→STAGE8）落到本机具体数值

---

## 0. 全局基线变量（★ = 本轮新得）

| 变量 | 本机值 | 来源/校验 |
|---|---|---|
| 内核 build | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k`，`#1 SMP PREEMPT`，2026-05-31 | `uname -a` |
| ★ `CONFIG_ARM64_VA_BITS` / `PA_BITS` | **39 / 48** | config |
| `PAGE_OFFSET`(linear map) | `0xffffff8000000000` = −2³⁹，与实测 `DIRECT_MAP_BEGIN` **一致** ⇒ alias 公式几何自洽 | config + 实测 |
| 内核镜像基址 | `0xffffffc000000000`（`_text=0xffffffc080000000`） | kallsyms |
| `MEY_PHYS_DELTA`(slide) | `0x28000000` —— **每 boot 变，必须动态取** | 实测 |
| alias 公式 | `alias(off)=0xffffff8000000000 + off + slide`；已用 `boot_id`(0x229b090)/cycleC(0x217d5d0) 双值自校验 | H162 |
| ★ `NR_CPUS` / `HZ` / `PREEMPT` | 32 / 250 / `PREEMPT=y`（tick=4 ms）+ `PREEMPT_RCU` | config |
| ★ hostname | **`localhost`** —— 截图是 **`HNPPG`**，与本机不符（截图非本机的又一佐证） | `uname`/`getprop` |
| ★ 加固全集 | PAC(`PTR_AUTH`+`PTR_AUTH_KERNEL`)·kCFI(`CFI_CLANG`)·BTI·SCS·**PAN+EPAN+SW_TTBR0_PAN**·canary·`FORTIFY_SOURCE`·`HARDENED_USERCOPY`·**`KASAN=y`+`KASAN_HW_TAGS`**+`KASAN_VMALLOC`·`KFENCE`(63 obj/500 ms)·`LIST_HARDENED`·`SLAB_FREELIST_RANDOM`+`_HARDENED`·**`INIT_ON_ALLOC_DEFAULT_ON`**·`RODATA_FULL_DEFAULT_ENABLED`·`STRICT_KERNEL_RWX`·`VMAP_STACK`·`RANDOMIZE_KSTACK_OFFSET`·**`PANIC_ON_OOPS=1`+`PANIC_TIMEOUT=-1`** | config（本轮首次拿到） |
| 堆/页分配器 | `SLUB`+`SLUB_CPU_PARTIAL`+`SLUB_DEBUG`；`SPARSEMEM_VMEMMAP`；4K 页；`THP=madvise`；`CMA=16 MB`；`COMPACTION`/`MIGRATION=y`；`ZONE_DMA32` | config |
| 其它开关 | `MEMCG=y`+**`MEMCG_KMEM=y`**·`USERFAULTFD=y`·`CROSS_MEMORY_ATTACH=y`·`BPF_JIT_ALWAYS_ON`+`BPF_LSM`·`MODULES=y`·`ANDROID_DEBUG_SYMBOLS`·`SECCOMP`·`USER_NS` **未编**（已证）·`CHECKPOINT_RESTORE` **未开** | config |

---

## 1. 环节 A：stage0 / W1 写原语（`BOOTID_WRITE` 环节）

| 变量 | 值 | 状态 |
|---|---|---|
| 写原语 | `rb_erase @ 0xffffffc08003a9d4`：`*(waiter->lock + 8) = waiter->tree.rb_right` | ✅ 铁证（H50） |
| 触发链 | `rt_mutex_adjust_prio_chain @0xffffffc0810815d4` → `rb_erase`（H166 用 vmlinux-to-elf 恢复的 110992 符号复核，原值 `0xffffffc08110815d4` 为笔误，已订正） | ✅ |
| 命中率 | **1/127**（§23.4 定案） | ✅ 统计值 |
| 预算 | `max_attempts=640`（**禁设 80/200 等小预算**） | ✅ 铁律 |
| 配方 | `MEY_SPRAY_MODE=fanout`；`FAKE_TIMER_STRIDE=264`；`FAKE_TIMER_SLOTS=31`；`EXEC_AFTER_DELETED` 内置 54000 | ✅ H50 定案 |
| 判据对（boot_id 通道） | `parent=0xffffff802a29b090`（boot_id 表项 off 0x229b090）、`child=0xffffff802a17d5d0`（cycleC off 0x217d5d0 + slide） | ✅ |
| **本轮 r5 实测** | **640 发 / 639 `ATTEMPT_MISS` / `BOOTID_WRITE_MISS`** ⇒ 全 miss（＝那 0.66% 尾巴，或时序退化） | ❌ **当前第一阻断** |
| r5 几何 | fanout，`pairs=6000 fragments=18000`，`rcu_wait_us=150000`，`ORDER1_RECLAIM_GATE changed_nodes=0 received=6000` | 已记录 |

**阻断定位**：`ORDER1_RECLAIM_GATE changed_nodes=0` —— 一阶页回收网关**没有回收到任何节点**，与 H50 命中轮的日志形态需逐行对比（`h50_live_hit.log`）。命中率变量不再是"预算"问题。

---

## 2. 环节 B：cross-cache reclaim（堆）

| 变量 | 值 | 状态 |
|---|---|---|
| 分配器 | SLUB；`kmalloc_caches = 0xffffffc081698ed8`(R) | ✅ |
| ★ freelist | `SLAB_FREELIST_RANDOM=y` + `_HARDENED=y` ⇒ 顺序随机 + 指针 XOR 混淆 ⇒ **重占顺序不可预测，需大量 churn** | ⚠ 提高难度 |
| ★ `INIT_ON_ALLOC_DEFAULT_ON` | 分配即清零 ⇒ **UAF 读到的不是脏数据**；伪造对象必须在入队后**再次写入** | ⚠ 关键 |
| ★ `KASAN=y`+`KASAN_HW_TAGS`+`KFENCE`(63/500ms) | 越界/UAF 被 MTE 标记检出 ⇒ panic | ⚠ 高代价 |
| ★ `MEMCG_KMEM=y` | kmem accounting ⇒ 每 cache 有 memcg 子缓存 ⇒ **cross-cache 迁移路径存在**（需验证 shell 域能否建 cgroup） | 🟡 待验证 |
| 可用堆原语（本机实证） | `UI_SET_PHYS` = kmalloc **2..1024 B** 内容可控 + free/alloc churn；`open("/dev/uinput")` = `kzalloc(0x288)`；**≥8 路并发** | ✅ H163 |
| 页几何 | 4K 页 ⇒ kmalloc-1024 每页 4 对象；`udev`=0x288 落在 kmalloc-1024 | ✅ |
| 缺口 | 目标 victim slab/object size（取决于劫持对象：若走 fops 劫持，victim 就是我们自己的 `udev`/kmalloc-1024，无缺口） | ✅ 无缺口 |

---

## 3. 环节 C：misc bridge（fops 劫持）—— **本机最优路径**

| 变量 | 值 | 状态 |
|---|---|---|
| ★ `misc_list` | **`0xffffffc08229b190`(D)**；alias = `0xffffff802a29b190` | ✅ 新得 |
| ★ `uinput_misc` | **`0xffffffc0822c02c0`(D)** ⇒ **fops 字段 `@0xffffffc0822c02d0`，位于可写 `.data`** | ✅ |
| `uinput_fops` | `0xffffffc0812d3f98`(R) —— rodata，次优 | ✅ |
| `misc_open` 重读 fops | `0xffffffc0804ea3fc`：`ldur x8,[x24,#-8]` → `str x24,[x19,#0xc0]` ⇒ **每次 open 重读** | ✅ H163 铁证 |
| `struct miscdevice` 偏移 | `minor+0` `name+8` **fops+0x10（汇编实测）** `list+0x18`；`parent`/`this_device`/`mode` **待 offsetof 实测** | ⚠ 部分 |
| ★ kCFI 合法 `open` 候选 | **`uinput_open @0xffffffc080dc9248`(T)** —— 原型 `int uinput_open(struct inode*,struct file*)` **完全匹配** | ✅ 新得（解掉一个卡点） |
| fake `file_operations` 落点 | 需一块可写内核内存 ⇒ **直接用 `uinput_misc` 周边 .data 或把 fops 指针改指向已存在可写区**；不必另找空页 | 🟡 待定 |
| 桥接必要性 | H162：**stage0 自身不需要 misc_list 桥接**（真死结只在 bridge 探针路）⇒ 本环节是**可选**而非必经 | ⚠ 路线选择 |

---

## 4. 环节 D：pipe reclaim / PHYS_READ·PHYS_WRITE

| 变量 | 值 | 状态 |
|---|---|---|
| ★ `anon_pipe_buf_ops` | **`0xffffffc081183cc8`(R)** —— 伪造 `pipe_buffer->ops` 时的合法常量（KASLR 下需按 slide 重算） | ✅ 新得 |
| `__alloc_pages` | `0xffffffc0801c0380`(T) | ✅ |
| physmap | `DIRECT_MAP_BEGIN=0xffffff8000000000 + slide`；`alias(off)` 公式见 §0 | ✅ |
| 读写域能力 | **KI 域读✅写✅；DM 域写✅、DM 域读❌挂死** ⇒ `PHYS_READ` **必须走 KI 域** | ✅ 铁律 |
| ★ `ARM64_PAN`+`EPAN`+`SW_TTBR0_PAN` | 内核裸解引用**用户页**被硬件拦 ⇒ 重占目标必须是内核页（pipe page 满足） | ⚠ 关键 |
| `mem_section` | `0xffffffc0823af6f8`(B)；`SPARSEMEM_VMEMMAP=y` ⇒ pfn↔page 可用 vmemmap 换算（vmemmap 基址待算） | 🟡 |
| 页回收/迁移 | `COMPACTION`+`MIGRATION`+`CMA(16MB)`+`THP=madvise` ⇒ 一阶页回收具备条件（但 r5 实测 `changed_nodes=0`） | ⚠ |

---

## 5. 环节 E：stage8（cred / SELinux）—— **本轮给出的新解法**

| 变量 | 值 | 状态 |
|---|---|---|
| `selinux_state` | **`0xffffffc0823ba418`(B)**，`enforcing @ +0`（字节）；alias `0xffffff802a3ba418`；写需 `parent=0xffffff802a3ba410`、`child=0x0` | ✅ kallsyms 三证 |
| `SECURITY_SELINUX_DEVELOP=y` | 允许运行时切 permissive ⇒ 写 `enforcing=0` 合法可达 | ✅ |
| ★ `commit_creds` | **`0xffffffc080253b28`(T)** | ✅ 新得 |
| ★ `prepare_kernel_cred` | **`0xffffffc080932550`(T)** | ✅ 新得 |
| ★ `init_cred` | **`0xffffffc082190790`(D)** —— root 模板（uid/gid=0、全 caps） | ✅ 新得 |
| ★ **`init_task`** | **`0xffffffc08217e280`(D)** | ✅ 新得 |
| ★ **`current_task`** | **kallsyms 无此符号**（arm64 用 `sp_el0`）⇒ 走 `init_task.tasks` 遍历 | ✅ 结论 |
| **★ 解法：绕过"拿不到 current 地址"** | 1) 用 KI 读从 `init_task`(0x8217e280) 沿 `tasks` 链表遍历，按 `comm` 匹配 adb shell 进程名<br>2) 得到该进程 `task_struct` 地址<br>3) 写 `task+0x818 (real_cred)` 与 `task+0x820 (cred)` = `&init_cred`(`0xffffffc082190790`)<br>4) 该进程 fork/exec 出的 shell ⇒ `uid=0` + 全 caps（**无需调用 commit_creds**，避 kCFI/PAC） | 🟢 方案给出 |
| `task_struct` 已知偏移 | `real_cred+0x818` `cred+0x820`（commit_creds 反汇编复核）`canary+0x620` `pi_blocked_on+0x938` `pi_waiters+0x920` `sighand+0x880` | ✅ |
| **缺口** | `task_struct.tasks` 与 `.comm` 偏移、**`struct cred` 的 uid/gid/caps 偏移** —— 铁律 8 禁手算，**须 `offsetof`/`sizeof` 实测**（NDK 编译探针或直接改指针即可绕开） | ⚠ 待实测 |
| 备选 | 直接改 `cred` 字段 / `commit_creds(prepare_kernel_cred(0))`（需 JOP，kCFI 约束：必须是真函数） | 🟡 |

---

## 6. 判据三件套（不达标即不算 root）

1. `id` → `uid=0(root)`（当前 `uid=2000(shell)`）
2. `getenforce` → `Permissive`（当前 `Enforcing`）—— 独立透镜，禁止原语自校准回读
3. **一次受保护写**：如 `chown 0:0 /data/local/tmp/probe`（当前实测 `chown: Operation not permitted`）

---

## 7. 风险变量（本轮新增，此前完全未知）

| 变量 | 影响 |
|---|---|
| **`PANIC_ON_OOPS=1` + `PANIC_TIMEOUT=-1`** | **任何 oops 立即 panic 且不自动重启** ⇒ 每次失败可能耗掉一次人工重启（与 17:54 那次重启吻合；`AP_S_PANIC` 累计需复核） |
| **`KASAN=y`+`KASAN_HW_TAGS`** | 越界/UAF 被 MTE 检出 ⇒ 以往"静默写坏"的几何现在会直接崩 |
| **`INIT_ON_ALLOC_DEFAULT_ON`** | 堆喷/UAF 拿到的是零页 ⇒ 伪造对象必须在入队后重写 |
| **`SLAB_FREELIST_RANDOM`+`_HARDENED`** | 重占顺序随机化 ⇒ 命中率与 churn 次数强相关 |
| **`PAN`+`EPAN`** | 用户 VA 裸解引用被硬件拦 ⇒ 任何"让用户页当内核对象"的几何判死 |
| `RODATA_FULL_DEFAULT_ENABLED`+`STRICT_KERNEL_RWX` | 写 rodata 不可行 ⇒ fops 劫持只能落在 `.data`（`uinput_misc.fops`） |

---

## 8. 结论：阻断排序（找完变量后的判断）

1. **stage0 命中率/时序** —— r5 实测 640 发 0 命中、`ORDER1_RECLAIM_GATE changed_nodes=0` ⇒ **回查 `LANE_DONE` 时序 vs `h50_live_hit.log`**（工作记忆待办 3 的分支：640 全 miss）。这是当前唯一挡在前面的一环，§3/§5 的变量已经齐了。
2. **`task_struct` 地址** —— 已给出 `init_task` 遍历解法（§5），只差 `tasks`/`comm` 偏移实测；改 `real_cred`/`cred` 指 `init_cred` 可绕开 `commit_creds` 调用与 kCFI。
3. **kCFI `open` 候选** —— `uinput_open` 现成合法，卡点解除。
4. 环节 C（misc bridge）**非必经** —— H162 已判定 stage0 不需要桥接；只有在"要劫持 file_operations 做后续"时才用。

## 9. 产物
`analysis/output/mey_config.gz`｜`analysis/output/mey_config.txt`（7787 行）｜本文 `analysis/output/h165_device_variables.md`｜r5 日志 `/data/local/tmp/mey/h163b_r5_h50geom.log`（640 发全 miss）
