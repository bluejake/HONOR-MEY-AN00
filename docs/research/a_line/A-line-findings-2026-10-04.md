# A 线（源码 diff）执行台账 · 2026-10-04

## §AI 设备基线核验（铁律第一步）
```
adb devices        → A22C026319001339  device
boot_id            → c010a15b-1003-48f6-830c-7781fafc3de0   ← 真实 UUID，未被污染 ✓
uptime             → 539.41 2965.74                        ← 非归零，非刚重启
/proc/version      → Linux version 6.6.118-android15-8-gf17133276a57-abogki518694926-4k
                     (kleaf@build-host) #1 SMP PREEMPT Sun May 31 12:01:53 UTC 2026
```
⇒ **B 线的"版本一致性核验"已完成**：设备内核串与 kernel_src/Code_Opensource (10.0.0.175) 吻合。

## §AJ GKI-6.6.118 工作区签出成功 ★★★
痛点：`refs/google_kernel_GKI-6.6.118-android15.8` 仅有 .git，工作区未签出 ⇒ 框架最大缺口。

踩坑1：`git checkout` 报
```
error: invalid path 'drivers/gpu/drm/nouveau/nvkm/subdev/i2c/aux.c'
error: invalid path 'include/soc/arc/aux.h'
```
根因：**Windows 保留设备名 `aux`**，NTFS 拒绝创建。

踩坑2：残留 `.git/index.lock` ⇒ `fatal: Unable to create '.../index.lock': File exists.`

解法（已验证可复用）：
```bash
P=refs/google_kernel_GKI-6.6.118-android15.8
rm -f $P/.git/index.lock
git -C $P config core.protectNTFS false      # ★ 关键
git -C $P config core.longpaths true
git -C $P checkout -f HEAD -- .
```
⇒ **551 MB / 29,986 文件**（6,616 .c / 5,771 .h / 1,279 .S）
基线确认：Makefile = `SUBLEVEL=118` ⇒ 与目标机 6.6.118-android15-8 **完全一致** ✓
baseline commit：`9d973d6ae`

## §AK 方法修正：文件级 diff 失败 → 特征驱动审计
首次 diff：荣耀独有 **45,911** / GKI 独有 **4** ⇒ 数字荒谬。
排查：两树 `drivers/char` 均 172 .c（一致）⇒ GKI 是**完整树**，非裁剪树。
真因：荣耀 = Linux 6.6.56 **全量树**（含 drm/amd 491 .c、i915 等），
  GKI 6.6.118 **已删除/重构**大量非 arm64 驱动 ⇒ 45,911 绝大多数是**版本漂移噪音**。

**结论：文件清单 diff 无价值。改用特征驱动**：
① 找荣耀绝对私有标识（CONFIG_HONOR_* / ogki_honor / 闭源模块名）
② 设备实测节点反查源码
③ 只在 arm64 核心 diff

## §AL 主发现 1：荣耀 OGKI vendor-hook 体系（32 调用点全枚举）★★★
`include/trace/hooks/ogki_honor.h` —— **GKI 中不存在**（GKI `include/trace/hooks/` 为空）
⇒ 纯荣耀私有。OGKI = Honor 定制 GKI 扩展。

| 文件 | hook | 安全相关性 |
|---|---|---|
| **mm/usercopy.c** | android_rvh_ogki_audit_log_usercopy | ★★★ usercopy_abort() 内、BUG() 前 |
| **mm/vmalloc.c** | android_rvh_ogki_vmalloc_node_bypass(size,gfp,&addr) | ★★★ **可返回任意地址、跳过真实分配** |
| **mm/vmalloc.c** | android_rvh_ogki_vfree_bypass(addr,&bypass) | ★★★ 可让 vfree() 直接 return |
| **kernel/sys.c ×6** | android_vh_ogki_audit_log_setid(type,old,new) | ★★★ 位于 **commit_creds() 之前** |
| kernel/cfi.c | android_vh_ogki_audit_log_cfi | ★ CFI failure 报告点 |
| kernel/module/signing.c | android_rvh_ogki_audit_log_module_sign | ★ 模块签名 |
| kernel/sched/core.c ×4 | task_util/uclamp_task_util/get_task_tags/get_task_rsum | ○ |
| kernel/fork.c | ogki_check_vip_status | ○ |
| mm/compaction.c, mm/vmscan.c | ogki_async_psi_bypass | ○ |
| net/ipv4/tcp_input.c ×4, tcp_timer.c | ogki_tcp_* | ○ |
| fs/f2fs/{data,file,namei}.c, fs/wb_pin | ogki_f2fs_* ×5 | ○ |
| drivers/ufs/core/iomeasure.c | ogki_check_task_tags | ○ |

★ hook **实现不在开源包**（头文件只有 DECLARE_HOOK）⇒ 在**闭源 vendor 模块**。
**定位法**：在 .ko 二进制里搜 `register_trace_android_rvh_ogki_*` 字符串即可锁定模块。

## §AM 代码审计：vmalloc / usercopy 三处 hook
### (1) mm/vmalloc.c `__vmalloc_node()` L3622-3631 ★★★
```c
void *__vmalloc_node(unsigned long size, unsigned long align,
                     gfp_t gfp_mask, int node, const void *caller)
{
    void *addr = NULL;
    trace_android_rvh_ogki_vmalloc_node_bypass(size, gfp_mask, &addr);   // 私有 hook
    if (addr)
        return addr;                                                     // ★ 直接返回任意地址！
    return __vmalloc_node_range(size, align, VMALLOC_START, VMALLOC_END,
                                gfp_mask, PAGE_KERNEL, 0, node, caller);
}
```
`rvh_` = restricted hook（仅 vendor 模块可注册）⇒ 攻击者不能直接注册。
但若 vendor 实现有 bug（按 size 判断、可被诱导返回越界地址）⇒ 调用者拿到"合法"指针指向别处。
**评估：需 .ko 才能判定（B 线）。**

### (2) mm/usercopy.c `usercopy_abort()` L98
`trace_android_rvh_ogki_audit_log_usercopy(to_user, name, len); BUG();`
⇒ 纯汇报，无绕过语义。**低风险。**

### (3) mm/vmalloc.c `vfree()` L2866
`trace_android_rvh_ogki_vfree_bypass(addr, &bypass); if (bypass) return;`
⇒ 可选择性"不释放"。**低风险（仅泄漏，不越界写）。**

## §AN CONFIG_HONOR_* 全枚举：40+ 项，设备启用 30 项
### ★ 设备已启用（真实攻击面）
| CONFIG | 位置 | 备注 |
|---|---|---|
| **HONOR_VMAP_ALLOC_PAGE_ON_DEMAND** | arch/Kconfig:1306 | ★ 改写 vmalloc：允许 area->pages[i]==NULL |
| **HONOR_ALLOC_STACK_PAGE_ON_DEMAND** | arch/Kconfig:1298 | ★ 改写**内核栈**分配（VMAP_STACK && THREAD_INFO_IN_TASK）|
| HONOR_IO_MEASURE / PSI / PGO_CLANG / PRINTK_PREFIX / CPU_FREQ_POWER_STAT | init/Kconfig 等 | |
| HONOR_BLK_CGROUP_IOSMART / IOLIMIT / BLOCK_MQ_DEADLINE | block/Kconfig | |
| HONOR_MEM_STATS | mm/mem_stats/Kconfig:1 | |
| HONOR_UFS_DSM | drivers/ufs/host/Kconfig:15 | |
| HONOR_DMABUF_MEMINFO | drivers/dma-buf/heaps/Kconfig:26 | |
| **HONOR_BINDER_TRANSACTION_BRIEF / DESCRIPTOR** | drivers/android/Kconfig:40/48 | ★ binder |
| HONOR_BOOT_TIME | drivers/boottime/Kconfig:1 | /proc/boottime 0664 |
| HONOR_CACHE_DISK | fs/Kconfig:8 | |
| HONOR_F2FS_DSM / BLKFRAG / SMART_DISCARD / COMPRESSION_OPTM(+DEBUG) / RA_ALIGNMENT / HOTNESS_CLUSTERING / SIS_DISK | fs/f2fs/Kconfig | |
| HONOR_THREAD_STACK_STAT | fs/proc/Kconfig:112 | |
| **HONOR_DIE_CATCH** | — | ★ 崩溃捕获（可能改 panic 行为）|

### ○ 设备未启用（已排除，不必再查）
HONOR_CFI / _CFI_TAG / _CFI_DEBUG / _CFI_POINTER_INFO / HN_KERNEL_SECURITY_HOOK
/ HONOR_KERNEL_STACK_RANDOMIZE(_STRONG) / HONOR_KERNEL_STACK_NX / HONOR_KERNEL_MODULE_RANDOMIZE
/ HONOR_KASLR_DEBUGFS / HONOR_HIDESYMS(_DEBUGFS) / HONOR_FREELIST_RANDOM_DEBUGFS
/ HONOR_DOUBLE_FREE_CHECK_DEBUGFS / HONOR_HARDEN_DOUBLE_FREE_CHECK_DEBUGFS
/ GCC_PLUGIN_RANDSTRUCT_DEBUGFS / HONOR_ALLOC_STATS / HONOR_MEM_REPORT / HONOR_MEM_DETECT
/ HONOR_ISOLATED_DETECT / HONOR_WARN_COUNT

⇒ **★★★ 关键结论：荣耀反利用加固全部关闭**
- 无荣耀自研 CFI（仅标准 `CONFIG_CFI_CLANG=y`，`CFI_PERMISSIVE` 未设 = **严格 CFI**）
- **无模块基址随机化** ⇒ 模块加载基址可预测
- **无内核栈随机化**
- **无符号隐藏** ⇒ 与 kallsyms 110,992 行可读一致 ✓
- **无 KASLR debugfs** ⇒ `/sys/kernel/debug/kaslr` 实测不存在 ✓
- `CONFIG_RANDSTRUCT_NONE=y` ⇒ RANDSTRUCT 疑似未启用（见 §AP 冲突）

### security/cfi/Kconfig 全读
```
config HONOR_CFI_TAG   hex, default 0x0035c000, depends HONOR_CFI_DEBUG
config HONOR_CFI       bool, default n  ← "adds a word to the head of a function and checks the word"
config HONOR_CFI_DEBUG bool, default n  ← "debugfs is /proc/. which give a debugfs to **simulate jop attack**"
```
★ 若 `HONOR_CFI_DEBUG` 启用，就是**现成的 JOP 攻击模拟入口**。设备**未启用** ✓。
`security/cfi/cfi_test.c`(4,201 B) 待读。

## §AO 新发现：security/kernel_harden/ 荣耀内核加固模块（10 文件）★★★
```
security/kernel_harden/
├── Kconfig 2,163 B / Makefile 645 B
├── hn_double_free_debugfs.c         4,204 B
├── hn_freelist_random_debugfs.c     4,278 B
├── hn_harden_double_free_debugfs.c  6,844 B
├── hn_kaslr_debugfs.c               3,769 B  ← 已读，见下
├── hn_kaslr_module.c                1,456 B
├── hn_litehide_symbols.c            8,885 B  ← ★ 最大，待读
├── hn_ptrace_log.c                  1,647 B  ← ★ 引用 hn_kernel_stp_interface.h
├── hn_stack_nx.c                      882 B
└── hn_struct_rand_debugfs.c         5,113 B
```
Makefile 显示 `#obj-y += hn_ptrace_log.o` **被注释**；各文件由 `CONFIG_HONOR_*` 条件编译，
**设备均未启用**（§AN 已证）。

### hn_kaslr_debugfs.c 全文已读 ★★★
```c
extern u16 __initdata memstart_offset_seed;
kaslr_img_offset_show()    → seq_printf("0x%llx\n", img_offset);   // = abs(kimage_vaddr - KIMAGE_VADDR)
kaslr_module_offset_show() → abs(_text - module_plt_base);
kaslr_linear_seed_show()   → seq_printf("0x%x\n", linear_seed);    // = memstart_offset_seed  ★★★
debugfs_create_file("img_offset", 0444, ...) / "module_offset"(0444) / "linear_seed"(0444)
```
**★★★ 极高价值（潜在降级路径）**：
- `debugfs/kaslr/linear_seed` 直接导出 **`memstart_offset_seed`** = **`memstart_addr` 的随机化种子**！
  ⇒ 若启用，`direct_to_page()` 的缺失 offset **可直接读出**（正是 43499 路线头号阻塞）。
- `debugfs/kaslr/img_offset` = **Image VA slide 全量**。
- **设备实测 `/sys/kernel/debug/kaslr` 不存在**（debugfs 未挂载）⇒ 当前不通。
- 但记录：这是荣耀唯一泄露 slide/linear_seed 的接口，值得找"触发 debugfs 挂载"的次要路径。

## §AP 待复核：RANDSTRUCT 状态冲突 ★需澄清
- 记忆（旧）：`struct file_operations` 带 `__randomize_layout`(RANDSTRUCT) ⇒ fops 偏移必须从 Image 反推
- 设备 ikconfig：`CONFIG_CC_HAS_RANDSTRUCT=y` / **`CONFIG_RANDSTRUCT_NONE=y`** / `# CONFIG_RANDSTRUCT_FULL is not set`
- **两说冲突**。若关闭，fops 偏移 = 源码顺序，可直接用头文件算。
- 本项目实证：`uhid_misc+0x10 = &uhid_fops`、`FAKE_MISC_FOPS_OFF=0x10`、`FAKE_FOPS_OFF=0x7640`
  均从 Image 反推并**实机验证通过**。
- **判定**：以实机验证过的 Image 反推值为准；**新增结构体时**可先按源码顺序试算，失败再 Image 反推。
- 行动项：grep `__randomize_layout`；确认 `RANDSTRUCT_NONE` 语义。

## §AQ 设备侧实测：荣耀私有节点与模块全清单 ★★★
### /proc 荣耀私有（`ls /proc` 共 1,022 项中筛出）
```
/proc/honor_sched_info/                    dr-xr-xr-x root root u:object_r:proc:s0
   ├── task_state_info                      dr-xr-xr-x
   └── ioctl                               ★ 「ioctl」命名的 proc 目录项（极不寻常！）
/proc/honor_tsa_info/                      dr-xr-xr-x root root u:object_r:proc:s0
   └── stack_info/
        └── ioctl                          ★ 又一个「ioctl」节点
/proc/kernel_stp                           ★ Permission denied（受保护文件）
/proc/boottime                             （HONOR_BOOT_TIME，0664）
```
★ `honor_sched_info/ioctl` + `honor_tsa_info/stack_info/ioctl` = **极罕见设计**（proc 上以 ioctl 命名）
⇒ 用户态可对 proc 文件调 ioctl ⇒ **必须审计 cmd 分派表**。
坏消息：源码搜不到 `honor_sched_info`/`honor_tsa_info` ⇒ **闭源模块 `honor_tsa`** 提供。

### /sys/kernel 荣耀私有
```
/sys/kernel/hn_kernel_stp_kset / hn_kernel_stp_scanner   drwxr-xr-x（空，需 root 看内容）
/sys/kernel/{scm, tee, tui, va-minidump, ssrdump_reason, ipclite, hme, highload, fas, vip}
```
`hn_kernel_stp_*` 来自 `hn_ptrace_log.c` 引用的 `<security/hn_kernel_stp_interface.h>`
—— **该头文件在开源包中不存在** ⇒ STP 闭源。

### /sys/class：`/sys/class/hn_thermal`

### 设备模块：645 个，**49 个荣耀/华为私有** ★
```
hihonor_usb_dmd/_glink/_eye/_state/_oem_glink/_charger_glink
hn_halls / hn_shell_temp / hn_net_booster / hn_emcom / hn_net_opt / hn_netd
hn_haptics_wrapper / hn_network_aware_gki / hn_net_bastet / hn_wifi_link_monitor_icnss2
honor_ds28e30 / honor_charger_adsp / honor_sle95250 / honor_sh366003_battct
honor_bat_heating / honor_battery_basp / honor_vbus_monitor / honor_batt_aut_checker
honor_soc_control / honor_power_proxy / honor_battery_type_identify / honor_battery_leakage
honor_battery_micro_short_circuit / honor_battery_model / honor_batt_info / honor_charge_collect
honor_soc_decimal / honor_battery_soh / honor_coul_interface / honor_battery_basp_data_collect
honor_pmic_ocp_debug / honor_power_genl★ / honor_fas / honor_spi_ir / honor_adc
honor_tsa★★★ / honor_scm★★★ / honor_hung_task★
honor_qos_sched_gki / honor_rtg_sched_gki / honor_upsi_sched / honor_camera_utils
```
**按提权价值排序（B 线优先级）**：
1. **`honor_scm`**（36,864 B，`[permanent]`）— Secure Channel Manager / TEE 接口，历史高危
2. **`honor_tsa`**（16,384 B）— 提供 `/proc/honor_tsa_info/stack_info/ioctl`
3. **`honor_power_genl`** — genetlink（netlink 家族，经典提权面）
4. **`hn_net_* ×4 + hn_netd`** — 网络 netlink
5. **`honor_hung_task`**（24,576 B）— 与 `HONOR_DIE_CATCH=y` 相关，可能改 panic 行为
6. `hn_haptics_wrapper` / `hn_halls` / `honor_spi_ir` — ioctl 驱动候选

## §AR 阶段性结论
### 已证伪（不再花时间）
1. ❌ **文件级 diff**（6.6.56 全量 vs 6.6.118 精简）⇒ 全为版本漂移噪音。
2. ❌ **荣耀自研 CFI / 栈随机化 / 模块随机化 / 符号隐藏 / KASLR debugfs** ⇒ 设备全未启用；
   `/sys/kernel/debug/kaslr` 实测不存在。
3. ❌ **`vmalloc_map_page_atomic()`** ⇒ 有 `index >= area->nr_pages` + `pages[index]!=NULL` 双检查，无缺陷。
4. ❌ **`mm/usercopy.c` / `vfree` 的 hook** ⇒ 纯汇报/纯跳过语义，无内存破坏能力。

### 已接近满足（下一步优先）
1. **★★★ `honor_scm`（TEE/SCM）** — `[permanent]` 模块。行动：找其 `/dev/` 节点，
   `ls -lZ` 看 SELinux 标签与权限；若非 root 可访问 ⇒ 立刻 ioctl 审计/fuzz。
2. **★★★ `/proc/honor_tsa_info/stack_info/ioctl` 与 `/proc/honor_sched_info/ioctl`**
   — proc 上 ioctl 节点，语义未知。行动：`open()` 后逐个 cmd 试（先只读），配 dmesg 观察。
3. **★★ `ogki_honor` 32 hook 的闭源实现** — 重点 `rvh_ogki_vmalloc_node_bypass`。
   行动：B 线，在 .ko 里搜 `register_trace_android_rvh_ogki_*` 字符串定位注册模块。
4. **★ `honor_power_genl` / `hn_net*`** — netlink；genl family 名可经
   `/proc/net/genetlink` 或 `nlctrl` 枚举，**非 root 可读**。

### 下一轮计划
- **A 线收尾**：① 读 `security/kernel_harden/` 剩余 8 文件（尤其 `hn_litehide_symbols.c` 8.9 KB、
  `hn_harden_double_free_debugfs.c` 6.8 KB）；② grep `__randomize_layout` 澄清 §AP；
  ③ 枚举 `drivers/` 下全部 `CONFIG_HONOR_*` 新驱动。
- **B 线启动**：从 `firmware/` 两个 img 提取内核 + 模块，`vmlinux-to-elf` 恢复符号，与 §AN/§AQ
  比对；重点定位 `honor_scm` / `honor_tsa` / ogki-hook-registrar 三个模块。
- **D 线（可选）**：SM8735 平台对照（POCO F7 / 小米 Pad 8）验证 `honor_*` 之外的平台共性。
