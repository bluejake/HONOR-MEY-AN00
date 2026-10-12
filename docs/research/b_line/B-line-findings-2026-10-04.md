# B 线成果 — 内核逆向交叉印证（2026-10-04）

## 一、固件解包链（全部跑通）
```
firmware/boot.img        ANDROID! v4  kernel_size=37,128,704  ramdisk_size=0
firmware/vendor_boot.img VNDRBOOT v4  vendor_ramdisk_size=37,073,278
  └─ @4096 切出  →  analysis/output/b_line/vendor_ramdisk.bin (37,073,278 B)
  └─ LZ4 legacy frame (magic 0x184C2102) 解压
  └─ analysis/output/b_line/vendor_ramdisk.cpio (136,645,376 B)
  └─ cpio newc 严格顺序解析 → 927 条目 (bad=0, TRAILER @136,645,168)
  └─ 提取 502 个 .ko → analysis/output/b_line/kos/
```

## 二、cpio 解析要点（踩坑记录）
- **newc 格式 = 6 字节 magic `070701` + 13 个字段，每字段 8 字节 ASCII 十六进制**
  （**不是 4 字节二进制！** 误用 `<13I` 会得到 namesize=808464432=`"0000"`）
- name 起始 = `off + 6 + 13*8 = off + 110`；next = `off + align4(110+namesize) + align4(fsize)`
- 脚本：`analysis/scripts/cpio3.py <cpio> <out.txt>`（严格顺序 + resync 回退）

## 三、★★★ OGKI vendor-hook 归属全澄清（A 线 32 个调用点 → B 线注册者）
| hook | 注册模块 | 说明 |
|---|---|---|
| `rvh_ogki_audit_log_usercopy` | **kernel_stp.ko** | mm/usercopy.c BUG() 前 |
| `vh_ogki_audit_log_setid` | **kernel_stp.ko** | kernel/sys.c commit_creds() 前 |
| `vh_ogki_audit_log_cfi` | **kernel_stp.ko** | kernel/cfi.c CFI failure |
| `rvh_ogki_vmalloc_node_bypass` | **rcc.ko** | mm/vmalloc.c __vmalloc_node |
| `rvh_ogki_vfree_bypass` | **rcc.ko** | mm/vmalloc.c vfree |
| `vh_ogki_async_psi_bypass` | **rcc.ko** | mm/compaction+vmscan |
| `vh_ogki_kmem_cache_create_usercopy` | **mmtrack.ko** | kmem_cache 创建 |
| `rvh_ogki_task_util` / `uclamp_task_util` / `get_task_tags` / `get_task_rsum` / `check_task_tags` | **sched-walt.ko** | kernel/sched/core.c |
| `vh_ogki_check_vip_status` | **cpu-netlink.ko** | kernel/fork.c |
| `vh_ogki_f2fs_create` / `f2fs_submit_write_page` | **wb_pin_mode.ko** | fs/f2fs |
| `vh_ogki_f2fs_dsm` / `f2fs_dsm_get` | **ufs_honor.ko** | fs/f2fs |
| `vh_ogki_ufs_dsm` | **ufs-qcom.ko + ufs_honor.ko** | drivers/ufs |
| `vh_ogki_set_wifi_state_connect/disconnect` | **cfg80211.ko** | net/wireless |
| `vh_ogki_tcp_rcv_estab_fastpath/slowpath/rtt_update` / `tcp_retransmit_timer` / `tcp_srtt_estimator` | **hn_net_booster.ko** | net/ipv4 |
| `rvh_ogki_hievent_*` (5) | **logger_vh.ko** | 日志 |
| `vh_ogki_get_log_usertype` / `hievent_to_jank` | **logger_vh.ko** | 日志 |
| `vh_ogki_get_task_tags` 等 | **sched-walt.ko** | — |

**★ 关键：`rcc.ko` 独占 `vmalloc_node_bypass` + `vfree_bypass` 两个高危 hook（A 线头号发现）。**

## 四、★★★ 设备实际加载模块 = vendor_boot.img 提取物（实证一致）
`/proc/modules` 中：`honor_tsa 16384` / `rcc 32768 (C)` / `honor_scm 36864 [permanent]` /
`kernel_stp 28672` / 全 49 个荣耀私有模块均在。

- **`vermagic=6.6.56-android15-8-4k`** 而 `/proc/version` = `6.6.118-android15-8-...`
  ⇒ **不冲突**：Android GKI 的 vermagic 用 **KMI 版本**（`android15-8`），非 Linux 补丁号
  ⇒ **`vendor_boot.img` 里的 .ko 就是设备上运行的那一份** ✓
- 设备 `/vendor/lib/modules/` = 只读挂载 + mode 000（`-?????????`）
- `zram` 依赖 `hme,rcc,honor_scm` ⇒ **rcc 的 hook 全生命周期常驻**

## 五、★★★ rcc.ko 反汇编（A 线头号发现落地）
`.text` 中：
```
vmalloc_node_bypass   0x1980  size=68
vfree_bypass          0x19c8  size=68
async_psi_bypass      0x1970  size=12
tune_compact_finished 0x1a10  size=24
```
重定位：`0x19bc → __kmalloc` / `0x19e4 → is_vmalloc_or_module_addr` / `0x19f0 → kfree`

### `vmalloc_node_bypass(void *__data, unsigned long size, gfp_t gfp, void **addr)`
```c
if (size > 0xfff) {
    *addr = (void *)(size - 0xfff);   // ★★★ 把 size-0xfff 当指针返回！
    return;
}
*addr = __kmalloc(size, gfp);         // ≤0xfff 走 kmalloc
```
### `vfree_bypass(void *__data, void *ptr, bool *bypass)`
```c
if (is_vmalloc_or_module_addr(ptr)) return;   // 真 vmalloc 地址 → 不 bypass
kfree(ptr);                                   // 否则按 kmalloc 指针 free
*bypass = true;                               // ★ 让 vfree() 直接 return
```
**评判**：
- 这是「小对象用 kmalloc 替代 vmalloc」的**性能优化（配对使用）**
- **`*addr = size - 0xfff` 把数值当指针**是**代码异味**，但 `size` 由内核内部调用点决定，
  攻击者无法让它落在合法内核地址区间 ⇒ **不是任意地址原语**
- **可用性**：构成**内核崩点 oracle**（fault 地址 = `size - 0xfff` 泄漏调用点 size）
- **无直接提权价值**，但**证明荣耀确实在 mm 路径上做了可绕过的 hook 改写**

## 六、★★★ honor_scm.ko 定性修正（重大）
**不是 TEE/SCM（Secure Channel Manager），而是 SCM = System Cache Management！**
全部符号都是 shrinker / mem_available / watermark / reclaim / mglru，**零 TEE 调用**。

**7 个 mm reclaim hook（新攻击面）**：
```
scm_hook_do_shrink_slab               56 B
scm_hook_modify_scan_control          48 B
scm_hook_should_continue_reclaim      44 B
scm_hook_file_is_tiny_bypass          16 B   ★ "bypass"
scm_hook_si_mem_available_adjust      48 B
scm_hook_mglru_should_abort_scan      36 B
scm_hook_mglru_should_abort_scan_order 36 B
```
- 经 `/sys/kernel/scm/event` 控制（`-rw-rw---- root:root` = 0660，**dev 不可写**）
- `scm_event_store` = 624 B 解析代码（待审计）
- `[permanent]` 标记 ⇒ 无法卸载

## 七、★★★ honor_tsa.ko = 唯一可用的内核地址 oracle
`/proc/honor_tsa_info/stack_info/ioctl`（`proc_mkdir` + `proc_create`）
- 设备测试：`open()` = **EACCES(13)**（uid=2000）⇒ **DAC 拒绝（mode 0600 root）**
- `tsa_stack_info_ioctl(f, cmd, arg)`（596 B）完整还原：
```c
char buf[0x2A8];                          // sub sp, sp, #0x2b0
if (cmd != 0xc2a8ac01) return -EINVAL;    // movz #0xac01 + movk #0xc2a8
if (!arg) return -EINVAL;
memset(buf, 0, 0x2A8);
if (__arch_copy_from_user(buf, arg, 0x2A8)) return -EFAULT;
sprint_symbol(buf + 8, *(unsigned long *)buf);   // ★★★ arg[0] 当内核地址 → 符号名
if (__arch_copy_to_user(arg, buf, 0x2A8)) return -EFAULT;
```
- **`sprint_symbol(buf+8, buf[0])`** ⇒ 用户传任意 64 位值被当**内核地址**做 `kallsyms_lookup`
- **能力**：内核地址**有效性 oracle**（命中 ⇒ 输出 `name+off/size`）
- **限制**：`copy_from_user`/`copy_to_user` **长度恰等于缓冲 0x2A8** ⇒ **无溢出**；
  仅 root 可开 ⇒ **当前不可用**，但**若配合任意写改 `proc_dir_entry.mode` 即可开放**

## 八、kernel_stp.ko 三 hook 审计（全部无缺陷）
```
hook_security_audit_log_cfi       0x004  56 B
hook_security_audit_log_usercopy  0x040  112 B
hook_security_audit_log_setid     0x140  136 B
get_setids_state                  0x0ec  80 B  (EXPORT_SYMBOL)
```
### `hook_security_audit_log_setid(void *__data, u32 type, u32 old_id, u32 new_id)`
```c
if (new_id != 0) return;                 // 只统计"归零"
u8 t = (u8)type;                         // ubfx → 截成 u8 (0..255)
if ((u8)type > 0x270 /*624*/) goto tail; // ★ 永假 ⇒ 无越界
if (old_id != 0x7d0 /*2000=shell*/) goto tail;
if (*(u64*)(per_cpu + 0x820)) printk(fmt, a, b);
if ((u8)type <= 5) counter[type]++;      // checkroot_ref.1/2/3
```
**评判：纯审计，不修改 cred ⇒ 无法提权。无内存缺陷。**

### `kernel_stp_proc_write`（684 B）
```c
kmalloc(0x400 /*1024*/, 0xdc0 /*GFP_KERNEL*/);
if (count > 0x7ff) ...    // sub x8,count,#0x400; adds x8,#0x3ff; b.cs
```
**有长度检查 ⇒ 无溢出。** `/proc/kernel_stp` 设备侧 EACCES。

## 九、开源包交叉印证
**`kernel_src/Code_Opensource`（Linux 6.6.56）中完全找不到** `honor_tsa` / `honor_scm` /
`kernel_stp` / `rcc` 的源码 ⇒ **证实它们是闭源 vendor 模块**，只在 vendor_boot ramdisk 中以 .ko 发布
⇒ **A 线的 32 个 hook 调用点（已合入主线）↔ B 线的 20+ 个注册者（全闭源 .ko）** 形成完整闭环。

## 十、结论与下一步
**B 线核心目标已达成**：固件解包 ✓ / .ko 全量提取 ✓ / hook 归属全澄清 ✓ /
设备一致性实证 ✓ / 开源包交叉印证 ✓

**提权价值排序（经逆向修正后）**：
1. **`honor_tsa.ko`** — `sprint_symbol` 地址 oracle（**唯一可直接利用的信息泄露点**），
   阻塞 = `proc_create` mode 0600。若取得**任意写 1 字节**能力 ⇒ 改 mode ⇒ 开 oracle
2. **`rcc.ko`** — 2 个 vmalloc hook，**全局 vmalloc 劫持**，当前判定**非任意地址**，
   但**待验证**：`size-0xfff` 在**特定内核调用点**（如 ioctl 传入 size）是否可控
3. **`honor_scm.ko`** — 7 个 mm reclaim hook，`/sys/kernel/scm/event` 0660，待审 `scm_event_store`
4. `kernel_stp.ko` — 已审计完，**无缺陷**

**立即下一步**：
- **(a) 审计 `rcc.ko` 的 `size` 来源**：哪些内核路径把**用户可控 size** 传给 `vmalloc()`？
  （已知 `__vmalloc_node` 被 hook，需查 `callers`）
- **(b) 审计 `scm_event_store`（624 B）** 与 `honor_scm.ko` 的 `g_scm_task_counts` 数组索引
- **(c) 回到 f77 主线**：B 线未改变 stageB 结论，但确认了**不存在"现成的一击提权"闭源驱动**
