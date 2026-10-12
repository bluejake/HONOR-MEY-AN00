# H171 · boot.img → vmlinux-to-elf 完整实跑报告

日期：2026-10-05
基线：MEY-AN00 / SM8735 / 6.6.118-android15 / `_text = 0xffffffc080000000`
脚本：`analysis/scratch/h166_bootimg_to_elf.py`（已内建 ★20 / ★24 修正）
venv：`<HOME>/.workbuddy/binaries/python/envs/default/Scripts/python.exe`（`vmlinux-to-elf --no-deps` + `peewee` + `pyelftools 0.33`）

## 1. 命令

```bash
cd D:/MEY-AN00-root-repro
python analysis/scratch/h166_bootimg_to_elf.py \
    firmware/boot.img \
    analysis/scratch/boot_from_bootimg.elf \
    analysis/output/kallsyms_from_bootimg.txt
```

> 与 H170 不同：本次**保留产物**（H170 验证后删除），文件名改为 `boot_from_bootimg.*` / `kallsyms_from_bootimg.txt`，避免覆盖既有权威产物。

## 2. 输入解析（实测值）

| 项 | 值 | 来源 |
|---|---|---|
| 文件大小 | `100663296` (96 MB) | `ls` |
| magic | `ANDROID!` | offset 0 |
| `kernel_size` | `0x02368a00` | 头 offset 8，**已按 ★24 切片** |
| `page_size` | `0x00000000` | 头 offset 36，**被清零 ⇒ 头解析路径不可用** |
| 实际内核 offset | `0x1000` | **magic 扫描**（★20 回退分支） |
| offset 0x1000 处 | `MZ` | Image 起始 |
| offset 0x1038 处 | `ARMd` | arm64 镜像头标识 |
| kernel blob | `37128704` 字节 | = `0x2368a00` |

**★20 复现确认**：本页 `page_size = 0`，若直接喂给 `vmlinux-to-elf` 会命中其 `assert page_size > 0x200` 而**静默失败**（不抛异常、产出空/坏 ELF）。脚本的 magic 扫描回退分支是唯一可行路径，不可删。

## 3. 流水线输出

```
[+] boot.img  100663296 bytes
[+] kernel    offset=0x1000  size=0x2368a00  (via magic scan)
[+] kernel    blob 37128704 bytes
[+] ELF        -> analysis/scratch/boot_from_bootimg.elf
[+] symbols    110992 -> analysis/output/kallsyms_from_bootimg.txt
[+] file-backed 区 [_text, 0xffffffc082368a00)  .bss 起点 0xffffffc082368a00
[+] 自检（20 个关键符号）:
    mem_section                  0xffffffc0823af6f8  [B]  ← .bss，镜像内无实体
    selinux_state                0xffffffc0823ba418  [B]  ← .bss，镜像内无实体
[+] 结果       OK
```

**20/20 自检通过**（★21：WARNING 属正常，必须靠 20 符号交叉校验后才采信）。

## 4. md5 四重逐位复现（决定性验证）

| 产物 | md5 | 判定 |
|---|---|---|
| `analysis/scratch/boot_from_bootimg.elf`（本次 boot.img 路线） | `2cbc4d627c186ef2b06a91ffa0d34394` | — |
| `analysis/scratch/Image-mey.symtab.elf`（H166 裸 Image 路线） | `2cbc4d627c186ef2b06a91ffa0d34394` | **IDENTICAL** |
| `analysis/output/kallsyms_from_bootimg.txt`（本次） | `c81bcd4700add37e6964ca91a4e0af32` | — |
| `analysis/output/mey_6.6.118.kallsyms.txt`（H166） | `c81bcd4700add37e6964ca91a4e0af32` | **IDENTICAL** |

`cmp -s` 逐位比对：ELF **IDENTICAL**、MAP **IDENTICAL**。

⇒ 独立二次证实 H166 的 `offset=0x1000` / `kernel_size=0x2368a00` 判定，**非单次侥幸**。
⇒ **boot.img 路线与裸 Image 路线产出同一 ELF**，两条独立输入路径互为交叉验证。

## 5. ELF 结构校验（pyelftools 0.33）

```
file size  42467854
class 64  bit LE  machine EM_AARCH64 (183)  type ET_EXEC
entry  0xffffffc080888c8c
SEG PT_LOAD  vaddr=0xffffffc080000000 filesz=0x02368a00 memsz=0x02368a00 flags=7
SEG PT_LOAD  vaddr=0xffffffc082368a00 filesz=0x00000000 memsz=0x01000000 flags=7
SEC[1] .kernel   addr=0xffffffc080000000 size=0x02368a00 type=SHT_PROGBITS
SEC[2] .bss      addr=0xffffffc082368a00 size=0x01000000 type=SHT_NOBITS
SEC[3] .symtab   size=0x0028a580 type=SHT_SYMTAB   entries 110992
SEC[4] .strtab   size=0x0028d036
```

- `.bss` 是 `SHT_NOBITS`、`filesz = 0` ⇒ **`selinux_state` / `mem_section` 等 .bss 符号在文件里没有实体**（★25），静态分析阶段读不到是预期的，不是流水线缺陷。
- `base = 0xffffffc080000000`，与本机 `_text` 一致 ⇒ **KASLR 前的裸基址已在 ELF 中固定**，偏移可直接套用。
- `entry = 0xffffffc080888c8c`。

## 6. 反汇编闭环（从新 ELF 的 `.kernel` 段直接取字节）

不依赖裸 Image 路线，直接从本次产出的 ELF 段内反汇编：

`remove_waiter@0xffffffc081080e60` 的唯一 `rb_erase` 调用点：
```
0xffffffc081080ed4: mov  x0, x23            ; node = waiter+0x00 (tree)
0xffffffc081080ed8: mov  x1, x22            ; root = lock+0x08
0xffffffc081080edc: bl   #0xffffffc08003a9d4
0xffffffc081080ee0: str  x23, [x23]         ; RB_CLEAR_NODE
0xffffffc081080ee4: mov  x0, x21
0xffffffc081080ee8: str  xzr, [x20, #0x938]  ; current->pi_blocked_on = NULL
0xffffffc081080eec: bl   #0xffffffc081083520  ; raw_spin_unlock(&current->pi_lock)
0xffffffc081080ef0: cmp  x24, x23            ; is_top_waiter ?
```

`rb_erase` Path B 写点：
```
0xffffffc08003ab04: ldr  x9, [x0]           ; x9 = node->__rb_parent_color
0xffffffc08003ab08: ands x8, x9, #-4        ; x8 = parent
0xffffffc08003ab0c: str  x9, [x10]          ; ★ 写 *(node->rb_left) = pc
0xffffffc08003ab10: b.eq #0xffffffc08003ac0c
0xffffffc08003ab14: ldr  x9, [x8, #0x10]
0xffffffc08003ab18: cmp  x9, x0
```

⇒ 与 `dis_mey.py`（裸 Image 路线）**逐指令一致**，工具链可信。

## 7. 本轮附带发现：`remove_waiter` 存在比 `owner==0` 更强的单发门

在核对 `0xffffffc081080e60` 全函数（0xe60–0xf88）时读出：

```
0xffffffc081080e7c: ldr  x24, [x0, #0x10]   ; x24 = lock->waiters.rb_leftmost (top_waiter)
0xffffffc081080e88: cbz  x24, #0x...e98      ; ★ leftmost == NULL ⇒ 跳过 BUG_ON 校验
0xffffffc081080e8c: ldr  x8, [x24, #0x58]    ; top_waiter->lock
0xffffffc081080e90: cmp  x8, x19
0xffffffc081080e94: b.ne #0x...f8c           ; BUG_ON(w->lock != lock) -> brk
...
0xffffffc081080ef0: cmp  x24, x23            ; is_top_waiter = (leftmost == waiter)
0xffffffc081080ef4: b.ne #0x...f70           ; ★ 干净出口 A（直接 epilogue 返回）
0xffffffc081080ef8: and  x21, x25, #0xfe     ; owner = lock->owner & ~1
0xffffffc081080efc: cbz  x21, #0x...f70      ; ★ 干净出口 B（owner == 0）
0xffffffc081080f00: add  x22, x21, #0x90c    ; ↓ 以下 owner->pi_lock / dequeue_pi 全部跳过
```

**新结论（★27 候选）**：只要 `lock->waiters.rb_leftmost == 0`，
1. `0xe88` 的 `cbz` 跳过 `top_waiter->lock` 的 BUG_ON 解引用 ⇒ **不需要伪造一个合法 waiter 挂在 leftmost 上**；
2. `0xef0` 的 `cmp x24(0), x23(waiter≠0)` 必然不等 ⇒ `b.ne` 命中 ⇒ **无条件走干净出口 A，`owner` 字段完全不必读**。

这比 H169 对 `adjust_prio_chain` 要求的 `owner == 0` 单发门**更强**：
- `owner` 是 `lock+0x18`，要它为 0 就得挑一个真正空闲的 `rt_mutex_base`（H169 未闭合项 P1）；
- 而 `leftmost == 0` 只是 `lock+0x10` 一个字段，且 `remove_waiter` 在 erase 前后**都不再读它**（除 `0xeb8` 的 `cmp` 与条件性 `rb_next`）。

⇒ **P1 的性质从"找一个空闲 rt_mutex 地址"降级为"把 `lock+0x10` 写成 0"**，若 `lock` 本身可指向我方已构造的内存（h143c_restack3 的画布），P1 可能与 P2–P5 一起被同一份 fpsimd 画布覆盖 ⇒ **原本分处两地的 P1 与 waiter 几何有望合并成一次栈写**。

**置信度：汇编已证未实测。** 逐指令证据已闭合（0xe60–0xf88 全读），但"leftmost=0 ⇒ 走出口 A ⇒ 不解引用 owner"这条链尚未在真机触发过；且尚未逐一枚举真实调用点 `rtmutex.c:1707` 处 `lock` 的来源（是内核真实 rt_mutex 还是我方伪造 ⇒ 决定 `lock+0x10` 是否可控）。**下一步必须先答"lock 从哪来"，否则几何仍是空中楼阁。**

## 8. 可证伪判据

- 若 §7 结论成立 ⇒ 令 `lock->waiters.rb_leftmost = 0` 后触发 `remove_waiter`，应观测到：唯一一次 `rb_erase` 生效、**无** `owner->pi_lock` 相关的任何内存写（即 `lock+0x18` 即使是垃圾值也不崩）、函数从 `0xf70` 正常返回。
- 若观测到 `brk #0x800`（`0xf8c` 的 BUG_ON）⇒ 说明 `leftmost != 0` 且 `leftmost->lock != lock`，即写画布没盖住 `lock+0x10`。
- 若观测到 page fault 落在 `owner+0x90c` 附近 ⇒ 说明走了出口 A 之后的路径，条件判断有误。

## 9. 产物清单

| 路径 | 大小 | 说明 |
|---|---|---|
| `analysis/scratch/boot_from_bootimg.elf` | 42,467,854 | 本次产出，md5 与既有 ELF 逐位相同 |
| `analysis/output/kallsyms_from_bootimg.txt` | 4,832,627 | 本次产出，110,992 行 |
| `analysis/scratch/Image-mey.symtab.elf` | 42,467,854 | H166 既有权威 ELF（未改动） |
| `analysis/output/mey_6.6.118.kallsyms.txt` | 4,832,627 | H166 既有权威符号表（未改动） |
| `analysis/scratch/h166_bootimg_to_elf.py` | 4,680 | 流水线脚本，★20/★24 修正内建，**勿删** |
