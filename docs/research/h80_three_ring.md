# H80 三环对照表（铁律⑤：每轮同构回填）

> 对象：L1 主线 stageB W1（假 misc 挂 `/dev/uhid`）的根因定位与修正
> 日期：2026-10-04　轮次：H80 / H81 / H82
> 权威规程：`MEY-AN00-exploit-prompt-v2.md` 第三节模板

## 1. 主对照表

| 对象/函数 | 源码推断（GKI 核心标"权威基线 6.6.56==r17"） | 汇编实测（Image-mey 基址=0） | img 反汇编差异 | 一致性 | 矛盾待解项 |
|---|---|---|---|---|---|
| `struct k_itimer` | r17 `kernel/time/posix-timers.c:225` `kmem_cache_create("posix_timers", sizeof(struct k_itimer), ...)`；ctypes offsetof：`list@0x00 t_hash@0x10 it_lock@0x20 kclock@0x28 it_clock@0x30 it_id@0x38 it_active@0x3c it_interval@0x58 it_signal@0x60 it_pid@0x68 sigq@0x70 it@0x78 rcu@0xd8`，**sizeof=0xe8**　**权威基线 6.6.56==r17** | — | 无 delta（对象大小=源码 sizeof） | ✅ | — |
| `struct hrtimer`（`union it.real.timer`） | r17 `include/linux/hrtimer.h`：`node@0x00 _softexpires@0x20 function@0x28 base@0x30 state@0x38`，**sizeof=0x40**　**权威** | `__remove_hrtimer@0x3f480` 的 `0x3f4b4: add x0,x1,#0x20` = `&base->active` | 无 | ✅ | — |
| `timerqueue_node` | r17 `include/linux/timerqueue.h:9-12`：`rb_node@0x00 expires@0x18`　**权威** | `timerqueue_del@0x3f7d8` 内 `0x3f81c: bl 0x3a9d4` = `rb_erase` | 无 | ✅ | — |
| `rb_erase` 双 Path | `lib/rbtree.c` `__rb_erase_augmented` case-1 两支：`child->__rb_parent_color = pc` / `tmp->__rb_parent_color = pc`　**权威** | 入口 `0x3a9d4: 08a840a9 ldp x8,x10,[x0,#8]` ⇒ `x8=rb_right(+8)`、`x10=rb_left(+0x10)`；`0x3a9dc: ldr x9,[x0]` = pc；**Path A** `0x3aa10: str x9,[x8]` = `*(u64*)rb_right=pc`；**Path B** `0x3ab0c: str x9,[x10]` = `*(u64*)rb_left=pc`；路径二选一 `0x3a9d8: cbnz x10` / `0x3aa18: cbz x8` | 无 | ✅ | 与 CGA-W00(6.1.157) 逐条同构（跨版本互证） |
| **`FAKE_CPU_TIMER_STRIDE`** | **`sizeof(k_itimer)=0xe8`**；4KiB 页→17 对象/页；`ORDER1_SIZE=0x2000`=2 页→**34 对象**　**权威** | — | — | ❌ **f77.c 用 0x108(264)** | **H81 已修 → 0xe8** |
| **`FAKE_MISC_RECORD_STRIDE`** | **`sizeof(miscdevice)=0x50`**：r17 `include/linux/miscdevice.h` 9 成员，ctypes offsetof `minor@0x00 name@0x08 fops@0x10 list@0x18 parent@0x28 this_device@0x30 groups@0x38 nodename@0x40 mode@0x48`　**权威** | — | **skill 记载 CGA-W00 BTF `miscdevice size=0x50`（跨设备互证）** | ❌ **f77.c 用 0x58(88)** | **H82 已修 → 0x50** |
| `misc_open` 遍历语义 | r17 `drivers/char/misc.c`：`list_for_each_entry(iter,&misc_list,list){ if (iter->minor != minor) continue; c=iter; new_fops=fops_get(iter->fops); break; }`　**权威** | — | 无 | ✅ | 关键：**内核按真 sizeof 步长遍历** ⇒ stride 错位则 record1..N 的 `minor` 读到垃圾 |
| W1 写落点 | — | H79 ROUND1 实测：`STAGEB_FORGED_PARENT parent=0xffffffe44229b190 target=...198 off_delta=0` ⇒ parent 已 = `&misc_list+0` | — | ✅ | H78 三环定案**成立**（minus-8 是错的） |
| W1 写是否执行 | — | H79 ROUND1：`MISC_BRIDGE_MISS_NOT_PROVEN changed=1` ⇒ rb 节点被改 | — | ⚠️ | **修正 H78**：写**确实执行**了，H78「写永不生效」不完全对 |

## 2. 三个 stride/几何常量的总裁决

| 常量 | 旧值 | 权威值 | 依据 | 状态 |
|---|---|---|---|---|
| `FAKE_CPU_TIMER_STRIDE` | `0x108` | **`0xe8`** | `sizeof(struct k_itimer)` | H81 已修 |
| `FAKE_MISC_SLOTS` | `31` | **34 → 再调 9** | `0x2000/0xe8=34`；配合 stride `0x50` 后 `(0x2000-0x100)/0x50=99=11×9` | H81 → H82 |
| `FAKE_MISC_RECORD_STRIDE` | `0x58` | **`0x50`** | `sizeof(struct miscdevice)`，r17 + CGA BTF 双证 | H82 已修 |

## 3. 关键失效链（H79 ROUND1 观测 ⇒ 机理）

```
f77.c 按 0x58 步长写 record 数组（minor@+0x00 / fops@+0x10 / list@+0x18）
        ↓
内核 misc_open 按【真 sizeof 0x50】步长遍历 misc_list
        ↓
record0 对齐 → minor=239 ✔ ；record1..N 全部错位 8 B → minor 落在垃圾位置
        ↓
if (iter->minor != minor) continue;   ← 假节点全被跳过
        ↓
真 uhid 仍被命中 → fops = 真 uhid_fops → ioctl(SET_NAME) = -ENOTTY(25)
        ↓
H74_IOCTL_GATE verdict=MISS（桥不开）
```

**与观测 100% 吻合**：`changed=1`（写成功）+ `verdict=MISS`（桥不开）。

## 4. 副产物：stride 错位埋下的函数指针地雷

`0x108` 步长下 30/31 槽错位，其中 **slot1/8/23/30 的 `+0x08` 把 `forged_child`（内核虚拟地址）
写进相邻 `k_itimer` 的 `hrtimer.function`**。hrtimer 一触发内核即跳到该地址
⇒ **这是 H78 B 组「从未写坏 boot_id、设备仍重启」的最可能解释：spray 自己在 slab 里埋了会引爆的函数指针。**
详见 `analysis/scratch/h80_stride_audit.py`（逐槽落点表）。

## 5. skill.zip（CGA-W00 项目）带来的方法论修正

| # | skill 结论 | 对本项目的约束 | 状态 |
|---|---|---|---|
| 1 | **一个 boot 只允许打一发**（`refusing retry on this boot`）；300+ 次「写不落地」统计的真正来源 = 同 boot 第 2 发后的必然失败 | `h79_loop.sh`（同 boot 8 轮循环）**结构性错误**，已废 | 改用 `h81_single.sh` 单发 |
| 2 | **读回通道恒返 0 不可用**；一切以 `read=0`/`verified=0` 为判据的「写原语 no-op」结论**全部作废** | `kernel_read_virtual`(f77.c:4744) 是本项目**所有**判据的唯一来源（`probe_kernel_image_write` / `probe_panic_on_oops_clear` / `verify_cred_fields` / `verify_task_cred_pair`）⇒ **H49 的 PASS/FAIL 都可能是假的** | **待验（最高优先）** |
| 3 | 唯一可信判据 = 独立通道 `/sys/fs/selinux/enforce`、`checkreqprot`、`getenforce`、`id` | 判据体系必须重建 | 待做 |
| 4 | 写原语是完整 8 字节任意写（`str x9,[x8]`），Path A/B 二选一 | 本机环②已验证同构，可直接移植 | ✅ 已闭环 |
| 5 | 写原语副作用不可避免：`*(V&~3 + 8/+0x10) = T` | 写 cred 时若 `V=init_cred`，会污染 `init_cred.gid/suid` | 记入待办 |
| 6 | 偏移地雷：AAK(6.6.118) `real_cred=0x818/cred=0x820`，CGA(6.1.157) 实测 `0x830/0x838`，差 0x18 | **本项目是 6.6.118，MEMORY 记的 `0x818/0x820` 与 AAK 一致**，但仍须 BTF/汇编实证 | 待验 |

## 6. 本轮新增铁律

- **㉖** 循环/多发设计前必须确认「单发 vs 每 boot」——同 boot 重试在 PI 树类原语上会累积破坏，统计结果无效。
- **㉗** 判据通道必须独立验证——读回通道若恒返 0，所有 PASS/FAIL 判据作废；落地判据只能用内核权威接口。
- **㉘** stride/几何常量必须用目标结构体 `sizeof` 复核——`0x108` 写 31 槽只有 1 槽有效，且错位会污染相邻对象的函数指针。
- **㉙** 补丁脚本的锚点必须**整行唯一**——两处缩进不同但其余相同的行，`replace(a,n,1)` 只会消费一次（H81 v1 被自检 6/7 拦截，未写盘）。

## 7. 产物清单（只落盘，未打开预览 — 铁律⑥）

| 文件 | 说明 |
|---|---|
| `analysis/scratch/h80_stride_audit.py` | stride 逐槽落点审计（环①） |
| `analysis/scratch/h80_rb_erase_two_path.py` | rb_erase 双 Path capstone 验证（环②） |
| `analysis/scratch/h81_miscdevice_stride.py` | miscdevice 权威布局 + 容量核算（环①） |
| `tools/h81_patch.py` / `tools/h81_patch.py.bak` | stride 修正（v2，8/8 自检） |
| `tools/h82_patch.py` | record stride 修正（7/7 自检 + 容量核算） |
| `analysis/scratch/h81_single.sh` | 单发实测脚本（skill 铁律版） |
| `analysis/scratch/f77_h81_20261004_212159` | H81 产物（stride 0xe8/34） |
| `analysis/scratch/f77_h82_20261004_212942` | H82 产物（record stride 0x50, slots 9） |
| `analysis/scratch/h81_run_20261004_212329.log` | H81 实测日志（81,358 B） |
| `c64560/f77.c.bak_h81` / `.bak_h82` | 补丁前备份 |
| `<HOME>/.workbuddy/skills/magicpad3-root-handoff` | CGA-W00 skill（43 文件，审计 P2 通过） |
